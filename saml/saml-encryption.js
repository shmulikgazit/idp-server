const crypto = require('crypto');
const { DOMParser, XMLSerializer } = require('xmldom');
const fs = require('fs');
const path = require('path');

/**
 * Load LivePerson encryption certificate
 * @returns {string|null} Certificate content or null if not found
 */
function loadLivePersonCertificate() {
    try {
        const certPath = path.join(__dirname, '..', 'certs', 'lpsso2026.pem');
        if (fs.existsSync(certPath)) {
            const cert = fs.readFileSync(certPath, 'utf8');
            console.log('✅ LivePerson encryption certificate loaded');
            return cert;
        } else {
            console.log('⚠ LivePerson certificate not found at:', certPath);
            return null;
        }
    } catch (error) {
        console.error('❌ Error loading LivePerson certificate:', error.message);
        return null;
    }
}

/**
 * Encrypt SAML assertion using AES-256 + RSA hybrid encryption
 * @param {string} xml - SAML XML to encrypt
 * @param {string} encryptionCert - LivePerson encryption certificate
 * @returns {string} Encrypted SAML XML
 */
function encryptSAMLAssertion(xml, encryptionCert) {
    try {
        console.log('🔐 Starting SAML assertion encryption...');
        console.log('📄 Input XML length:', xml.length);
        console.log('📄 First 500 chars of XML:', xml.substring(0, 500));
        
        // Check if the XML is Base64 encoded (doesn't start with '<')
        let actualXml = xml;
        if (!xml.trim().startsWith('<')) {
            console.log('🔍 XML appears to be Base64 encoded, decoding...');
            try {
                actualXml = Buffer.from(xml, 'base64').toString('utf8');
                console.log('✅ Successfully decoded Base64 to XML');
                console.log('📄 Decoded XML length:', actualXml.length);
                console.log('📄 First 500 chars of decoded XML:', actualXml.substring(0, 500));
            } catch (decodeError) {
                console.log('❌ Failed to decode as Base64, using original:', decodeError.message);
                actualXml = xml;
            }
        }
        
        // Parse the XML
        const doc = new DOMParser().parseFromString(actualXml);
        
        console.log('🔍 Parsed XML document:', !!doc);
        console.log('🔍 Document element:', doc.documentElement ? doc.documentElement.tagName : 'null');
        
        // Find the assertion element to encrypt
        let assertions = doc.getElementsByTagName('saml2:Assertion');
        console.log('🔍 Found saml2:Assertion elements:', assertions.length);
        
        if (assertions.length === 0) {
            // Try with saml: namespace (samlify uses this)
            assertions = doc.getElementsByTagName('saml:Assertion');
            console.log('🔍 Found saml:Assertion elements:', assertions.length);
        }
        
        // Also try without namespace prefix
        if (assertions.length === 0) {
            assertions = doc.getElementsByTagName('Assertion');
            console.log('🔍 Found Assertion elements (no namespace):', assertions.length);
        }
        
        // Debug: List all elements in the document
        if (assertions.length === 0) {
            console.log('🔍 Debugging: All elements in document:');
            const allElements = doc.getElementsByTagName('*');
            for (let i = 0; i < Math.min(allElements.length, 10); i++) {
                console.log(`   ${i}: ${allElements[i].tagName}`);
            }
        }
        
        if (assertions.length === 0) {
            throw new Error('No SAML assertion found to encrypt (tried saml:, saml2:, and no namespace)');
        }
        
        const assertion = assertions[0];
        const assertionId = assertion.getAttribute('ID');
        
        console.log('🔒 Encrypting assertion with ID:', assertionId);
        
        // Extract assertion XML
        const serializer = new XMLSerializer();
        const assertionXml = serializer.serializeToString(assertion);
        
        console.log('📏 Assertion XML length:', assertionXml.length);
        console.log('🔍 First 200 chars of assertion:', assertionXml.substring(0, 200));
        
        // Generate symmetric key for AES encryption
        const symmetricKey = crypto.randomBytes(32); // 256-bit key for AES-256
        const iv = crypto.randomBytes(16); // 128-bit IV
        
        console.log('🔑 Generated symmetric key and IV');
        
        // Encrypt assertion with AES using modern API
        const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
        let encryptedData = cipher.update(assertionXml, 'utf8', 'base64');
        encryptedData += cipher.final('base64');
        
        console.log('🔐 Assertion encrypted with AES');
        console.log('📏 Encrypted data length:', encryptedData.length);
        
        // Encrypt symmetric key with RSA (LivePerson certificate)
        const publicKey = crypto.createPublicKey(encryptionCert);
        const encryptedKey = crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, symmetricKey);
        
        console.log('🔑 Symmetric key encrypted with RSA');
        console.log('📏 Encrypted key length:', encryptedKey.length);
        
        // Create EncryptedAssertion structure
        const encryptedAssertionXml = `
        <saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
                <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <xenc:EncryptedKey>
                        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
                        <xenc:CipherData>
                            <xenc:CipherValue>${encryptedKey.toString('base64')}</xenc:CipherValue>
                        </xenc:CipherData>
                    </xenc:EncryptedKey>
                </ds:KeyInfo>
                <xenc:CipherData>
                    <xenc:CipherValue>${encryptedData}</xenc:CipherValue>
                </xenc:CipherData>
            </xenc:EncryptedData>
        </saml2:EncryptedAssertion>`;
        
        console.log('📝 Created encrypted assertion XML structure');
        
        // Replace assertion with encrypted assertion
        const parent = assertion.parentNode;
        parent.removeChild(assertion);
        
        // Parse and insert encrypted assertion
        const encryptedDoc = new DOMParser().parseFromString(encryptedAssertionXml);
        const encryptedElement = encryptedDoc.documentElement;
        const importedElement = doc.importNode(encryptedElement, true);
        parent.appendChild(importedElement);
        
        const finalXml = serializer.serializeToString(doc);
        
        console.log('✅ SAML assertion encrypted successfully');
        console.log('📏 Encrypted XML length:', finalXml.length, 'characters');
        console.log('🔍 Contains EncryptedAssertion:', finalXml.includes('EncryptedAssertion'));
        console.log('🔍 Contains EncryptedData:', finalXml.includes('EncryptedData'));
        console.log('🔍 Contains CipherValue:', finalXml.includes('CipherValue'));
        
        return finalXml;
        
    } catch (error) {
        console.error('❌ SAML encryption failed:', error.message);
        console.error('Stack:', error.stack);
        throw error;
    }
}

module.exports = {
    loadLivePersonCertificate,
    encryptSAMLAssertion
}; 