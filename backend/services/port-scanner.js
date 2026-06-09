/**
 * Port Scanner
 * Scans for open ports on target systems
 */

const net = require('net');

// Common ports to scan
const COMMON_PORTS = [
  21,   // FTP
  22,   // SSH
  23,   // Telnet
  25,   // SMTP
  53,   // DNS
  80,   // HTTP
  110,  // POP3
  143,  // IMAP
  443,  // HTTPS
  465,  // SMTPS
  587,  // Submission
  993,  // IMAPS
  995,  // POP3S
  1433, // MSSQL
  1521, // Oracle
  3306, // MySQL
  3389, // RDP
  5432, // PostgreSQL
  5900, // VNC
  6379, // Redis
  8080, // HTTP Alt
  8443, // HTTPS Alt
  27017 // MongoDB
];

// Service names
const PORT_SERVICES = {
  20: 'FTP-Data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPC',
  119: 'NNTP',
  123: 'NTP',
  135: 'MSRPC',
  137: 'NetBIOS-NS',
  138: 'NetBIOS-DGM',
  139: 'NetBIOS-SSN',
  143: 'IMAP',
  161: 'SNMP',
  162: 'SNMP-Trap',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'Syslog',
  515: 'LPD',
  587: 'Submission',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  1723: 'PPTP',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  5901: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  8888: 'HTTP-Alt',
  9000: 'PHP-FPM',
  9200: 'Elasticsearch',
  27017: 'MongoDB',
  27018: 'MongoDB',
  27019: 'MongoDB'
};

/**
 * Scan a single port
 */
function scanPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      const duration = Date.now() - startTime;
      socket.destroy();
      resolve({
        port,
        service: PORT_SERVICES[port] || 'Unknown',
        status: 'open',
        responseTime: duration
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        port,
        service: PORT_SERVICES[port] || 'Unknown',
        status: 'closed',
        responseTime: timeout
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        port,
        service: PORT_SERVICES[port] || 'Unknown',
        status: 'closed',
        error: err.message
      });
    });

    socket.connect(port, host);
  });
}

/**
 * Scan multiple ports with concurrency control
 */
async function scanPorts(host, ports = COMMON_PORTS, concurrency = 10) {
  const results = [];
  const portQueue = [...ports];
  
  // Process ports in batches
  while (portQueue.length > 0) {
    const batch = portQueue.splice(0, concurrency);
    const batchResults = await Promise.all(
      batch.map(port => scanPort(host, port))
    );
    results.push(...batchResults);
  }

  return {
    success: true,
    host,
    timestamp: new Date().toISOString(),
    ports: results,
    openPorts: results.filter(r => r.status === 'open'),
    closedPorts: results.filter(r => r.status === 'closed'),
    scanDuration: results.reduce((sum, r) => sum + (r.responseTime || 0), 0) / results.length
  };
}

/**
 * Quick scan for common ports only
 */
async function quickScan(host) {
  return scanPorts(host, [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080
  ]);
}

/**
 * Scan for specific service ports
 */
async function scanForService(host, service) {
  const servicePorts = {
    'web': [80, 443, 8080, 8443, 8888],
    'database': [1433, 1521, 3306, 5432, 6379, 27017],
    'mail': [25, 110, 143, 465, 587, 993, 995],
    'remote': [22, 23, 3389, 5900, 5901],
    'file': [20, 21, 69, 445, 2049]
  };

  const ports = servicePorts[service.toLowerCase()] || [80, 443];
  return scanPorts(host, ports);
}

/**
 * Full port scan (all common ports)
 */
async function fullScan(host) {
  // Extended port list
  const extendedPorts = [];
  
  // Add all well-known ports (0-1023)
  for (let i = 0; i <= 1023; i++) {
    extendedPorts.push(i);
  }
  
  // Add common registered ports
  const registeredPorts = [
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9000, 9200, 27017
  ];
  
  extendedPorts.push(...registeredPorts);
  
  // Remove duplicates and sort
  const uniquePorts = [...new Set(extendedPorts)].sort((a, b) => a - b);
  
  return scanPorts(host, uniquePorts, 50); // Higher concurrency for full scan
}

/**
 * Scan for common vulnerabilities on open ports
 */
async function scanVulnerablePorts(host) {
  const results = await quickScan(host);
  const openPorts = results.openPorts;
  
  const vulnerabilities = [];
  
  for (const port of openPorts) {
    if (port.port === 21) {
      vulnerabilities.push({
        port: port.port,
        service: 'FTP',
        risk: 'medium',
        issue: 'FTP sends credentials in clear text'
      });
    }
    
    if (port.port === 23) {
      vulnerabilities.push({
        port: port.port,
        service: 'Telnet',
        risk: 'high',
        issue: 'Telnet sends credentials in clear text'
      });
    }
    
    if (port.port === 3306) {
      vulnerabilities.push({
        port: port.port,
        service: 'MySQL',
        risk: 'medium',
        issue: 'MySQL port open to network'
      });
    }
    
    if (port.port === 6379) {
      vulnerabilities.push({
        port: port.port,
        service: 'Redis',
        risk: 'high',
        issue: 'Redis may be accessible without authentication'
      });
    }
    
    if (port.port === 27017) {
      vulnerabilities.push({
        port: port.port,
        service: 'MongoDB',
        risk: 'medium',
        issue: 'MongoDB port open to network'
      });
    }
  }
  
  return {
    ...results,
    vulnerabilities
  };
}

module.exports = {
  scanPorts,
  scanPort,
  quickScan,
  scanForService,
  fullScan,
  scanVulnerablePorts,
  COMMON_PORTS,
  PORT_SERVICES
};