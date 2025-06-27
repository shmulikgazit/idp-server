import saml from 'samlify';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { loadLivePersonCertificate, encryptSAMLAssertion } from './saml-encryption.js';

// ES module equivalent of __dirname
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// SAML Identity Provider and Service Provider instances
let identityProvider = null;
let serviceProvider = null;

/**
 * Validate certificate with Node.js crypto
 * @param {string} certPem - Certificate in PEM format
 * @param {string} certName - Name for logging
 * @returns {boolean} True if valid
 */
function validateCertificateWithNodeCrypto(certPem, certName) {
    try {
        console.log(`🔍 Validating ${certName} with Node.js crypto...`);
        
        // Try to create a public key from the certificate
        const publicKey = crypto.createPublicKey(certPem);
        
        console.log(`✅ ${certName} is valid - key type:`, publicKey.asymmetricKeyType);
        console.log(`✅ ${certName} key size:`, publicKey.asymmetricKeySize);
        
        // Try to get the certificate details
        const x509 = new crypto.X509Certificate(certPem);
        console.log(`✅ ${certName} subject:`, x509.subject);
        console.log(`✅ ${certName} issuer:`, x509.issuer);
        console.log(`✅ ${certName} valid from:`, x509.validFrom);
        console.log(`✅ ${certName} valid to:`, x509.validTo);
        
        return true;
    } catch (error) {
        console.error(`❌ ${certName} validation failed:`, error.message);
        return false;
    }
}

/**
 * Load signing certificate
 * @returns {string|null} Certificate content or null
 */
function loadSigningCertificate() {
    console.log('🔍 loadSigningCertificate() called');
    try {
        const certPath = path.join(__dirname, '..', 'certs', 'signing-cert.pem');
        console.log('🔍 Checking for certificate at:', certPath);
        console.log('🔍 File exists:', fs.existsSync(certPath));
        
        if (fs.existsSync(certPath)) {
            let cert = fs.readFileSync(certPath, 'utf8');
            
            // Clean the certificate - remove extra whitespace and ensure proper format
            cert = cert.trim();
            
            // Ensure it has proper BEGIN/END markers
            if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
                console.log('❌ Certificate missing BEGIN marker');
                return null;
            }
            if (!cert.includes('-----END CERTIFICATE-----')) {
                console.log('❌ Certificate missing END marker');
                return null;
            }
            
            // Clean up the certificate format - remove extra spaces and normalize line endings
            const lines = cert.split(/\r?\n/);
            const cleanedLines = [];
            
            for (let line of lines) {
                // Remove trailing spaces from each line
                line = line.replace(/\s+$/, '');
                if (line.length > 0) {
                    cleanedLines.push(line);
                }
            }
            
            cert = cleanedLines.join('\n');
            
            // Ensure it ends with a newline
            if (!cert.endsWith('\n')) {
                cert += '\n';
            }
            
            console.log('✅ Signing certificate loaded (signing-cert.pem)');
            console.log('🔍 Certificate length:', cert.length);
            console.log('🔍 Certificate starts with:', cert.substring(0, 50));
            console.log('🔍 Certificate ends with:', cert.substring(cert.length - 50));
            return cert;
        }
        
        console.log('❌ SAML signing certificate (signing-cert.pem) not found');
        console.log('   Please ensure the certificate file exists in the certs directory');
        return null;
    } catch (error) {
        console.error('❌ Error loading signing certificate:', error.message);
        return null;
    }
}

/**
 * Load signing private key
 * @returns {string|null} Private key content or null
 */
function loadSigningPrivateKey() {
    console.log('🔍 loadSigningPrivateKey() called');
    try {
        const keyPath = path.join(__dirname, '..', 'certs', 'signing-private.pem');
        console.log('🔍 Checking for private key at:', keyPath);
        console.log('🔍 File exists:', fs.existsSync(keyPath));
        
        if (fs.existsSync(keyPath)) {
            let key = fs.readFileSync(keyPath, 'utf8');
            
            // Clean the private key - remove extra whitespace and ensure proper format
            key = key.trim();
            
            // Ensure it has proper BEGIN/END markers
            if (!key.includes('-----BEGIN') || !key.includes('-----END')) {
                console.log('❌ Private key missing BEGIN/END markers');
                return null;
            }
            
            // Clean up the key format - remove extra spaces and normalize line endings
            const lines = key.split(/\r?\n/);
            const cleanedLines = [];
            
            for (let line of lines) {
                // Remove trailing spaces from each line
                line = line.replace(/\s+$/, '');
                if (line.length > 0) {
                    cleanedLines.push(line);
                }
            }
            
            key = cleanedLines.join('\n');
            
            // Ensure it ends with a newline
            if (!key.endsWith('\n')) {
                key += '\n';
            }
            
            console.log('✅ Signing private key loaded (signing-private.pem)');
            console.log('🔍 Key length:', key.length);
            console.log('🔍 Key starts with:', key.substring(0, 50));
            return key;
        }
        
        console.log('❌ SAML signing private key (signing-private.pem) not found');
        console.log('   Please ensure the private key file exists in the certs directory');
        return null;
    } catch (error) {
        console.error('❌ Error loading signing private key:', error.message);
        return null;
    }
}

/**
 * Initialize SAML Identity Provider and Service Provider
 * @returns {boolean} True if successful
 */
function initializeSAML() {
    try {
        console.log('🔧 Initializing SAML with samlify library...');
        
        // Load certificates with debugging
        const signingCert = loadSigningCertificate();
        const signingKey = loadSigningPrivateKey();
        const encryptionCert = loadLivePersonCertificate('der'); // Try DER format first for samlify compatibility
        
        console.log('🔍 Certificate debugging:');
        console.log('  Signing cert type:', typeof signingCert, 'length:', signingCert ? signingCert.length : 'null');
        console.log('  Signing key type:', typeof signingKey, 'length:', signingKey ? signingKey.length : 'null');
        console.log('  Encryption cert type:', typeof encryptionCert, 'length:', encryptionCert ? encryptionCert.length : 'null');
        
        if (signingCert) {
            console.log('  Signing cert preview:', signingCert.substring(0, 100) + '...');
        }
        if (encryptionCert) {
            if (Buffer.isBuffer(encryptionCert)) {
                console.log('  Encryption cert preview (hex):', encryptionCert.slice(0, 50).toString('hex') + '...');
            } else {
                console.log('  Encryption cert preview:', encryptionCert.substring(0, 100) + '...');
            }
        }
        
        if (!signingCert || !signingKey) {
            throw new Error('Signing certificate or private key not available - required for SAML');
        }
        
        // Validate certificates with Node.js crypto before passing to samlify
        console.log('🔍 Validating certificates with Node.js crypto...');
        const signingCertValid = validateCertificateWithNodeCrypto(signingCert, 'Signing Certificate');
        
        if (!signingCertValid) {
            throw new Error('Signing certificate failed Node.js crypto validation');
        }
        
        if (encryptionCert) {
            if (Buffer.isBuffer(encryptionCert)) {
                console.log('🔍 Skipping Node.js crypto validation for DER certificate (binary format)');
            } else {
                const encryptionCertValid = validateCertificateWithNodeCrypto(encryptionCert, 'Encryption Certificate');
                if (!encryptionCertValid) {
                    console.log('⚠ Encryption certificate failed validation - proceeding without encryption');
                }
            }
        }
        
        // Validate certificate formats before passing to samlify
        console.log('🔍 Validating certificate formats...');
        
        // Validate signing certificate (PEM format with headers)
        if (!signingCert || signingCert.length < 100) {
            throw new Error('Signing certificate format is invalid - too short or empty');
        }
        
        if (!signingCert.includes('-----BEGIN CERTIFICATE-----') || !signingCert.includes('-----END CERTIFICATE-----')) {
            throw new Error('Signing certificate format is invalid - missing proper BEGIN/END markers');
        }
        
        console.log('✅ Signing certificate format is valid');
        
        // Validate private key (PEM format with headers)
        if (!signingKey.includes('-----BEGIN') || !signingKey.includes('-----END')) {
            throw new Error('Private key format is invalid - missing proper BEGIN/END markers');
        }
        
        console.log('✅ Private key format is valid');
        
        // Create Identity Provider using the correct samlify format
        console.log('🔍 Creating Identity Provider with certificates...');
        
        // Build IdP metadata with encryption support if available
        let idpMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.liveperson.com">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${signingCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '')}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>`;

        // Add encryption key descriptor if encryption certificate is available
        if (encryptionCert) {
            console.log('🔍 Adding encryption certificate to IdP metadata...');
            
            let certForIdPMetadata;
            if (Buffer.isBuffer(encryptionCert)) {
                // DER format - convert to base64 for XML
                certForIdPMetadata = encryptionCert.toString('base64');
                console.log('🔍 Converted DER to base64 for IdP metadata, length:', certForIdPMetadata.length);
            } else {
                // PEM format - extract base64 content
                certForIdPMetadata = encryptionCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '');
                console.log('🔍 Extracted base64 from PEM for IdP metadata, length:', certForIdPMetadata.length);
            }
            
            idpMetadata += `
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${certForIdPMetadata}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>`;
        }

        idpMetadata += `
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.liveperson.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
        
        // Configure IdP with encryption certificate in proper format for samlify
        const idpConfig = {
            privateKey: signingKey,
            metadata: idpMetadata,
            loginResponseTemplate: {
                context: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}">
        <saml:Issuer>{Issuer}</saml:Issuer>
        <saml:Subject>
            <saml:NameID SPNameQualifier="{SPNameQualifier}" Format="{NameIDFormat}">{NameID}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectConfirmationDataRecipient}" InResponseTo="{InResponseTo}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
            <saml:AudienceRestriction>
                <saml:Audience>{Audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="loginName">
                <saml:AttributeValue xsi:type="xs:string">{loginName}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="siteId">
                <saml:AttributeValue xsi:type="xs:string">{siteId}</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
        <saml:AuthnStatement AuthnInstant="{AuthnInstant}" SessionIndex="{SessionIndex}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>`
            }
        };

        // Do NOT configure encryption at IdP initialization
        // Encryption should be controlled at runtime via the shouldEncrypt parameter
        console.log('🔍 Encryption certificate available:', !!encryptionCert);
        console.log('🔍 Encryption will be controlled at runtime via shouldEncrypt parameter');
        
        // Always disable encryption at IdP level - it will be handled per-request
        idpConfig.isAssertionEncrypted = false;

        identityProvider = saml.IdentityProvider(idpConfig);
        
        console.log('✅ Identity Provider created successfully');
        
        // Create Service Provider (for testing/validation)
        serviceProvider = saml.ServiceProvider({
            metadata: `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.liveperson.com">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.liveperson.com/acs" index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>`
        });
        
        console.log('✅ Service Provider created successfully');
        console.log('✅ SAML initialization completed successfully');
        
        return true;
        
    } catch (error) {
        console.error('❌ SAML initialization failed:', error.message);
        console.error('Stack trace:', error.stack);
        return false;
    }
}

/**
 * Get the initialized Identity Provider
 * @returns {object|null} Identity Provider instance
 */
function getIdentityProvider() {
    return identityProvider;
}

/**
 * Get the initialized Service Provider
 * @returns {object|null} Service Provider instance
 */
function getServiceProvider() {
    return serviceProvider;
}

/**
 * Create a temporary Identity Provider with encryption enabled
 * @param {Buffer} encryptionCert - Encryption certificate in DER format
 * @returns {object} Identity Provider with encryption enabled
 */
async function createEncryptionEnabledIdP(encryptionCert) {
    console.log('🔧 Creating encryption-enabled Identity Provider...');
    
    // Load the existing signing certificates
    const signingCert = loadSigningCertificate();
    const signingKey = loadSigningPrivateKey();
    
    if (!signingCert || !signingKey) {
        throw new Error('Signing certificate or private key not available - required for SAML');
    }
    
    // Convert encryption cert to base64 for metadata
    let certForMetadata;
    if (Buffer.isBuffer(encryptionCert)) {
        certForMetadata = encryptionCert.toString('base64');
    } else {
        // If it's PEM, extract base64 content
        certForMetadata = encryptionCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '');
    }
    
    // Build IdP metadata with encryption certificate
    const idpMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.liveperson.com">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${signingCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '')}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${certForMetadata}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.liveperson.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
    
    // Configure IdP with encryption enabled
    const idpConfig = {
        privateKey: signingKey,
        metadata: idpMetadata,
        isAssertionEncrypted: true, // Enable encryption!
        loginResponseTemplate: {
            context: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}">
        <saml:Issuer>{Issuer}</saml:Issuer>
        <saml:Subject>
            <saml:NameID SPNameQualifier="{SPNameQualifier}" Format="{NameIDFormat}">{NameID}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectConfirmationDataRecipient}" InResponseTo="{InResponseTo}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
            <saml:AudienceRestriction>
                <saml:Audience>{Audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
            <saml:Attribute Name="loginName">
                <saml:AttributeValue xsi:type="xs:string">{loginName}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="siteId">
                <saml:AttributeValue xsi:type="xs:string">{siteId}</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
        <saml:AuthnStatement AuthnInstant="{AuthnInstant}" SessionIndex="{SessionIndex}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>`
        }
    };
    
    // Create the encryption-enabled Identity Provider
    const encryptionIdP = saml.IdentityProvider(idpConfig);
    
    console.log('✅ Encryption-enabled Identity Provider created');
    return encryptionIdP;
}

export {
    initializeSAML,
    getIdentityProvider,
    getServiceProvider,
    validateCertificateWithNodeCrypto,
    loadSigningCertificate,
    loadSigningPrivateKey,
    createEncryptionEnabledIdP
}; 