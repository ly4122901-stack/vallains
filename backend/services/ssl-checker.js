/**
 * SSL/TLS Certificate Checker
 * Analyzes SSL/TLS certificates and configuration
 */

const tls = require('tls');
const axios = require('axios');

// Common SSL grades
const GRADE_WEIGHTS = {
  'A+': 100,
  'A': 95,
  'A-': 90,
  'B': 80,
  'C': 70,
  'D': 60,
  'E': 50,
  'F': 0
};

// SSL Labs API (limited)
const SSL_LABS_API = 'https://api.ssllabs.com/api/v3/analyze';

/**
 * Parse certificate details
 */
function parseCertificate(cert) {
  const result = {
    subject: {},
    issuer: {},
    validFrom: null,
    validTo: null,
    serialNumber: null,
    fingerprint: null,
    signatureAlgorithm: null,
    keyAlgorithm: null,
    keySize: null,
    sans: [],
    version: null
  };

  if (!cert || !cert.subject) {
    return result;
  }

  // Parse subject
  if (cert.subject) {
    result.subject = {
      commonName: cert.subject.CN,
      organization: cert.subject.O,
      organizationalUnit: cert.subject.OU,
      locality: cert.subject.L,
      state: cert.subject.ST,
      country: cert.subject.C
    };
  }

  // Parse issuer
  if (cert.issuer) {
    result.issuer = {
      commonName: cert.issuer.CN,
      organization: cert.issuer.O,
      country: cert.issuer.C
    };
  }

  // Parse validity
  if (cert.valid_from) {
    result.validFrom = new Date(cert.valid_from);
  }
  if (cert.valid_to) {
    result.validTo = new Date(cert.valid_to);
  }

  // Parse other details
  result.serialNumber = cert.serialNumber;
  result.fingerprint = cert.fingerprint || cert.fingerprint256;
  result.signatureAlgorithm = cert.signatureAlgorithm;
  result.version = cert.version;

  // Parse public key info
  if (cert.puc) {
    result.keyAlgorithm = cert.puc.type;
    result.keySize = cert.puc.size;
  } else if (cert.pubkey) {
    result.keyAlgorithm = cert.pubkey.type;
    result.keySize = cert.pubkey.size;
  }

  // Parse SANs
  if (cert.subjectaltname) {
    result.sans = cert.subjectaltname.split(', ').map(san => {
      const parts = san.split(':');
      return {
        type: parts[0],
        value: parts[1] || parts[0]
      };
    });
  }

  return result;
}

/**
 * Calculate days until certificate expires
 */
function daysUntilExpiry(validTo) {
  if (!validTo) return null;
  const now = new Date();
  const expiry = new Date(validTo);
  const diff = expiry - now;
  return Math.ceil(diff / (1000 * 60 * 60 * 24));
}

/**
 * Calculate SSL grade
 */
function calculateGrade(info) {
  let score = 100;
  const issues = [];

  // Check expiration
  const daysLeft = daysUntilExpiry(info.validTo);
  if (daysLeft !== null) {
    if (daysLeft < 0) {
      score = 0;
      issues.push('Certificate expired');
    } else if (daysLeft < 30) {
      score -= 20;
      issues.push(`Certificate expires in ${daysLeft} days`);
    } else if (daysLeft < 90) {
      score -= 10;
      issues.push(`Certificate expires in ${daysLeft} days`);
    }
  }

  // Check key size
  if (info.keySize) {
    if (info.keySize < 2048) {
      score -= 30;
      issues.push(`Weak key size: ${info.keySize} bits`);
    } else if (info.keySize === 2048) {
      score -= 10;
      issues.push(`Key size: ${info.keySize} bits (could be stronger)`);
    }
  }

  // Check signature algorithm
  if (info.signatureAlgorithm) {
    const sigAlg = info.signatureAlgorithm.toLowerCase();
    if (sigAlg.includes('md5')) {
      score -= 50;
      issues.push('Weak signature algorithm: MD5');
    } else if (sigAlg.includes('sha1')) {
      score -= 20;
      issues.push('Weak signature algorithm: SHA1');
    }
  }

  // Check certificate chain
  if (info.issuer && info.subject) {
    if (info.issuer.commonName === info.subject.commonName) {
      score -= 15;
      issues.push('Self-signed certificate');
    }
  }

  // Convert score to grade
  let grade;
  if (score >= 95) grade = 'A+';
  else if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'A-';
  else if (score >= 70) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 50) grade = 'D';
  else grade = 'F';

  return { grade, score, issues };
}

/**
 * Check SSL certificate for a domain
 */
async function checkSSL(domain, port = 443) {
  const result = {
    success: false,
    domain,
    port,
    error: null,
    timestamp: new Date().toISOString()
  };

  // Clean domain
  let cleanDomain = domain.replace(/^https?:\/\//, '');
  cleanDomain = cleanDomain.split('/')[0];
  
  // Extract port if specified in domain
  const domainParts = cleanDomain.split(':');
  if (domainParts.length === 2) {
    cleanDomain = domainParts[0];
    port = parseInt(domainParts[1], 10);
  }

  try {
    // Connect to get certificate
    const certInfo = await new Promise((resolve, reject) => {
      const options = {
        host: cleanDomain,
        port: port,
        servername: cleanDomain,
        rejectUnauthorized: false, // Don't reject self-signed
        timeout: 10000
      };

      const socket = tls.connect(options, () => {
        const cert = socket.getPeerCertificate();
        resolve(cert);
        socket.end();
      });

      socket.on('error', (err) => {
        reject(err);
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Connection timeout'));
      });
    });

    if (!certInfo || !certInfo.subject) {
      throw new Error('No certificate received');
    }

    // Parse certificate
    const parsedCert = parseCertificate(certInfo);
    const daysLeft = daysUntilExpiry(parsedCert.validTo);
    const gradeInfo = calculateGrade(parsedCert);

    // Get cipher info
    const cipher = socket.getCipher ? socket.getCipher() : null;

    result.success = true;
    result.issuer = parsedCert.issuer;
    result.subject = parsedCert.subject;
    result.validFrom = parsedCert.validFrom;
    result.validTo = parsedCert.validTo;
    result.daysLeft = daysLeft;
    result.sans = parsedCert.sans;
    result.grade = gradeInfo.grade;
    result.gradeScore = gradeInfo.score;
    result.issues = gradeInfo.issues;
    result.keyAlgorithm = parsedCert.keyAlgorithm;
    result.keySize = parsedCert.keySize;
    result.signatureAlgorithm = parsedCert.signatureAlgorithm;
    result.version = parsedCert.version;
    result.serialNumber = parsedCert.serialNumber;
    result.fingerprint = parsedCert.fingerprint;
    result.cipher = cipher ? cipher.name : null;

  } catch (error) {
    result.error = error.message;
    
    // Try HTTP endpoint as fallback
    try {
      const response = await axios.get(`https://${cleanDomain}`, {
        timeout: 5000,
        validateStatus: () => true
      });
      
      // Check for certificate headers
      const certHeader = response.request?.socket?.getPeerCertificate?.();
      if (certHeader) {
        result.success = true;
        const parsedCert = parseCertificate(certHeader);
        const daysLeft = daysUntilExpiry(parsedCert.validTo);
        const gradeInfo = calculateGrade(parsedCert);
        
        result.issuer = parsedCert.issuer;
        result.subject = parsedCert.subject;
        result.validFrom = parsedCert.validFrom;
        result.validTo = parsedCert.validTo;
        result.daysLeft = daysLeft;
        result.sans = parsedCert.sans;
        result.grade = gradeInfo.grade;
        result.gradeScore = gradeInfo.score;
        result.issues = gradeInfo.issues;
        result.keySize = parsedCert.keySize;
        result.error = null;
      }
    } catch (e) {
      // Fallback failed
    }
  }

  return result;
}

/**
 * Check multiple SSL-related aspects
 */
async function checkSSLFull(domain) {
  const results = {
    domain,
    timestamp: new Date().toISOString(),
    https: null,
    http: null,
    certificate: null
  };

  // Check HTTPS
  try {
    results.https = await checkSSL(domain, 443);
  } catch (e) {
    results.https = { success: false, error: e.message };
  }

  // Check HTTP (redirect to HTTPS?)
  try {
    const response = await axios.get(`http://${domain}`, {
      timeout: 5000,
      maxRedirects: 0,
      validateStatus: () => true
    });
    results.http = {
      success: true,
      statusCode: response.status,
      location: response.headers.location || null,
      redirectsToHTTPS: response.headers.location?.includes('https')
    };
  } catch (e) {
    results.http = { success: false, error: e.message };
  }

  // Check alternative HTTPS port
  try {
    results.certificate = await checkSSL(domain, 8443);
  } catch (e) {
    results.certificate = { success: false };
  }

  return results;
}

module.exports = {
  checkSSL,
  checkSSLFull,
  calculateGrade,
  daysUntilExpiry
};