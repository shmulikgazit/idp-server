const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jose = require('jose');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const axios = require('axios'); // For API calls to LivePerson
const saml = require('samlify');

const app = express();
const PORT = process.env.PORT || 3000;

// Encryption toggle state
let encryptionEnabled = false;

// OAuth flow type state
let flowType = 'implicit'; // 'implicit', 'code', or 'codepkce'

// SAML state management
let samlEncryptionEnabled = false;
let samlEncryptionCertificate = null;

// In-memory store for authorization codes (in production, use Redis or database)
const authorizationCodes = new Map();

// SAML Identity Provider and Service Provider instances
let identityProvider = null;
let serviceProvider = null;

// PKCE helper functions
function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}

function verifyCodeChallenge(codeVerifier, codeChallenge, method) {
    if (method === 'S256') {
        const hash = sha256(codeVerifier);
        const challenge = base64URLEncode(hash);
        return challenge === codeChallenge;
    } else if (method === 'plain') {
        return codeVerifier === codeChallenge;
    }
    return false;
}

// Add certificate validation function
function validateCertificateWithNodeCrypto(certPem, certName) {
    try {
        console.log(`🔍 Validating ${certName} with Node.js crypto...`);
        
        // Try to create a public key from the certificate
        const crypto = require('crypto');
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

// SAML Configuration using samlify library
function initializeSAML() {
    try {
        console.log('🔧 Initializing SAML with samlify library...');
        
        // Load certificates with debugging
        const signingCert = loadSigningCertificate();
        const signingKey = loadSigningPrivateKey();
        const encryptionCert = loadLivePersonCertificate();
        
        console.log('🔍 Certificate debugging:');
        console.log('  Signing cert type:', typeof signingCert, 'length:', signingCert ? signingCert.length : 'null');
        console.log('  Signing key type:', typeof signingKey, 'length:', signingKey ? signingKey.length : 'null');
        console.log('  Encryption cert type:', typeof encryptionCert, 'length:', encryptionCert ? encryptionCert.length : 'null');
        
        if (signingCert) {
            console.log('  Signing cert preview:', signingCert.substring(0, 100) + '...');
        }
        if (encryptionCert) {
            console.log('  Encryption cert preview:', encryptionCert.substring(0, 100) + '...');
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
            const encryptionCertValid = validateCertificateWithNodeCrypto(encryptionCert, 'Encryption Certificate');
            if (!encryptionCertValid) {
                console.log('⚠ Encryption certificate failed validation - proceeding without encryption');
                encryptionCert = null;
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
        
        // Validate encryption certificate if present (PEM format with headers)
        if (encryptionCert) {
            if (encryptionCert.length < 100) {
                console.log('⚠ Encryption certificate format is invalid - will proceed without encryption');
                encryptionCert = null;
            } else if (!encryptionCert.includes('-----BEGIN CERTIFICATE-----') || !encryptionCert.includes('-----END CERTIFICATE-----')) {
                console.log('⚠ Encryption certificate format is invalid - will proceed without encryption');
                encryptionCert = null;
            } else {
                console.log('✅ Encryption certificate format is valid');
            }
        }
        
        console.log('✅ Certificate formats validated');
        
        // Create Identity Provider configuration
        console.log('🔍 Creating Identity Provider with:');
        console.log('  - signingCert type:', typeof signingCert, 'length:', signingCert ? signingCert.length : 'null');
        console.log('  - privateKey type:', typeof signingKey, 'length:', signingKey ? signingKey.length : 'null');
        console.log('  - encryptCert type:', typeof encryptionCert, 'length:', encryptionCert ? encryptionCert.length : 'null');
        
        // Try to create the identity provider with error handling
        try {
            console.log('🔍 Creating Identity Provider with certificates...');
            console.log('🔍 Signing cert sample:', signingCert.substring(0, 20) + '...');
            console.log('🔍 Private key sample:', signingKey.substring(0, 50) + '...');
            if (encryptionCert) {
                console.log('🔍 Encryption cert sample:', encryptionCert.substring(0, 20) + '...');
            }
            
            // Create Identity Provider using the correct samlify format
            // Based on official documentation: use privateKey and metadata approach
            identityProvider = saml.IdentityProvider({
                privateKey: signingKey,
                isAssertionEncrypted: false,  // Always disable samlify encryption to avoid certificate parsing issues
                metadata: `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.liveperson.com">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${signingCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '')}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.liveperson.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
                loginResponseTemplate: {
                    context: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}">
        <saml:Issuer>{Issuer}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
            <saml:AudienceRestriction>
                <saml:Audience>{Audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{AuthnInstant}" SessionIndex="{SessionIndex}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="loginName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue xsi:type="xs:string">{LoginName}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="siteId" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue xsi:type="xs:string">{SiteId}</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>`,
                }
            });
            
            console.log('✅ Identity Provider created successfully');
            
            // Verify the certificates were properly set
            console.log('🔍 Verifying Identity Provider certificate configuration...');
            console.log('🔍 IDP entityMeta signingCert type:', typeof identityProvider.entityMeta?.signingCert);
            console.log('🔍 IDP entityMeta privateKey type:', typeof identityProvider.entityMeta?.privateKey);
            console.log('🔍 IDP entityMeta encryptCert type:', typeof identityProvider.entityMeta?.encryptCert);
            
            // Check the metadata includes the certificate
            const metadata = identityProvider.getMetadata();
            console.log('🔍 Generated metadata includes KeyDescriptor:', metadata.includes('KeyDescriptor'));
            console.log('🔍 Generated metadata includes X509Certificate:', metadata.includes('X509Certificate'));
            
        } catch (idpError) {
            console.error('❌ Failed to create Identity Provider:', idpError.message);
            console.error('🔍 IDP Error details:', idpError.stack);
            throw new Error(`Identity Provider creation failed: ${idpError.message}`);
        }
        
        // Create a generic Service Provider configuration for LivePerson
        try {
            console.log('🔍 Creating Service Provider...');
            
            // Build SP metadata XML with encryption certificate if available
            let spMetadataXml = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="LEna2">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`;

            // Add encryption KeyDescriptor if encryption certificate is available
            if (encryptionCert) {
                console.log('🔍 Adding encryption certificate to SP metadata...');
                spMetadataXml += `
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${encryptionCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '')}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>`;
            }

            spMetadataXml += `
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://placeholder.liveperson.com/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>`;

            console.log('🔍 SP metadata XML includes encryption KeyDescriptor:', spMetadataXml.includes('use="encryption"'));
            
            serviceProvider = saml.ServiceProvider({
                metadata: spMetadataXml
            });
            console.log('✅ Service Provider created successfully with encryption certificate in metadata');
        } catch (spError) {
            console.error('❌ Failed to create Service Provider:', spError.message);
            console.error('🔍 SP Error details:', spError.stack);
            throw new Error(`Service Provider creation failed: ${spError.message}`);
        }
        
        console.log('✅ SAML initialized successfully with samlify');
        console.log('🔐 Signing certificate loaded:', !!signingCert);
        console.log('🔑 Private key loaded:', !!signingKey);
        console.log('🔒 Encryption certificate loaded:', !!encryptionCert);
        
        return true;
        
    } catch (error) {
        console.error('❌ Failed to initialize SAML:', error.message);
        console.error('📋 SAML functionality will not be available');
        console.error('🔍 Full error stack:', error.stack);
        identityProvider = null;
        serviceProvider = null;
        return false;
    }
}

async function createSAMLResponse(siteId, loginName, destinationUrl, shouldEncrypt = false) {
    console.log('🔧 Creating SAML Response with samlify library...');
    console.log('📍 Destination URL:', destinationUrl);
    console.log('🔐 Encryption requested:', shouldEncrypt);
    
    if (!identityProvider || !serviceProvider) {
        throw new Error('SAML not properly initialized - standard library required');
    }
    
    // Update service provider ACS URL dynamically
    const spConfig = serviceProvider.getMetadata();
    spConfig.assertionConsumerService = [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: destinationUrl
    }];
    
    // Create updated service provider with correct destination
    const encryptionCert = shouldEncrypt ? loadLivePersonCertificate() : undefined;
    console.log('🔍 Encryption certificate loaded:', !!encryptionCert);
    
    // Build dynamic SP metadata XML with encryption certificate if needed
    let dynamicSpMetadataXml = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="LEna2">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`;

    // Add encryption KeyDescriptor if encryption is requested
    if (shouldEncrypt && encryptionCert) {
        console.log('🔍 Adding encryption certificate to dynamic SP metadata...');
        dynamicSpMetadataXml += `
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${encryptionCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '')}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>`;
    }

    dynamicSpMetadataXml += `
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${destinationUrl}"/>
  </SPSSODescriptor>
</EntityDescriptor>`;

    console.log('🔍 Dynamic SP metadata includes encryption KeyDescriptor:', dynamicSpMetadataXml.includes('use="encryption"'));
    
    const dynamicSP = saml.ServiceProvider({
        metadata: dynamicSpMetadataXml
    });
    
    console.log('🔍 Service Provider created with encryption certificate in metadata:', shouldEncrypt && !!encryptionCert);
    
    // Create user attributes
    const user = {
        nameID: loginName,
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        attributes: {
            'loginName': loginName,
            'siteId': siteId
        }
    };
    
    console.log('👤 User object for SAML generation:', JSON.stringify(user, null, 2));
    
    // Create the customTagReplacement function
    const customTagReplacementFunction = (template) => {
        console.log('🔧 customTagReplacement called with template length:', template.length);
        
        // Replace all the template variables
        let processedTemplate = template
            .replace(/{ID}/g, 'response_' + Math.random().toString(36).substr(2, 9))
            .replace(/{AssertionID}/g, 'assertion_' + Math.random().toString(36).substr(2, 9))
            .replace(/{IssueInstant}/g, new Date().toISOString())
            .replace(/{Destination}/g, destinationUrl)
            .replace(/{Issuer}/g, 'https://idp.liveperson.com')
            .replace(/{StatusCode}/g, 'urn:oasis:names:tc:SAML:2.0:status:Success')
            .replace(/{NameIDFormat}/g, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
            .replace(/{NameID}/g, loginName)
            .replace(/{SubjectConfirmationDataNotOnOrAfter}/g, new Date(Date.now() + 5 * 60 * 1000).toISOString())
            .replace(/{SubjectRecipient}/g, destinationUrl)
            .replace(/{InResponseTo}/g, '')
            .replace(/{ConditionsNotBefore}/g, new Date().toISOString())
            .replace(/{ConditionsNotOnOrAfter}/g, new Date(Date.now() + 5 * 60 * 1000).toISOString())
            .replace(/{Audience}/g, 'LEna2')
            .replace(/{AuthnInstant}/g, new Date().toISOString())
            .replace(/{SessionIndex}/g, 'session_' + Math.random().toString(36).substr(2, 9))
            .replace(/{LoginName}/g, loginName)
            .replace(/{SiteId}/g, siteId);
        
        console.log('✅ Template processed, contains LoginName:', processedTemplate.includes(loginName));
        console.log('✅ Template processed, contains SiteId:', processedTemplate.includes(siteId));
        console.log('✅ Template processed, contains AttributeStatement:', processedTemplate.includes('AttributeStatement'));
        
        return {
            id: 'custom_response_id_' + Math.random().toString(36).substr(2, 9),
            context: processedTemplate
        };
    };

    // Call createLoginResponse with correct parameter order
    console.log('🔍 Calling samlify createLoginResponse...');
    const responseResult = await identityProvider.createLoginResponse(
        dynamicSP,
        null,
        'post',
        user,
        customTagReplacementFunction,  // 5th parameter: customTagReplacement function
        shouldEncrypt,                 // 6th parameter: encryptThenSign (boolean)
        null                          // 7th parameter: relayState
    );
    
    console.log('🔍 Samlify createLoginResponse completed');
    console.log('🔍 Response result type:', typeof responseResult);
    console.log('🔍 Response result keys:', responseResult ? Object.keys(responseResult) : 'null');
    
    // Extract the actual SAML response from the result
    let samlResponse;
    if (responseResult && responseResult.context) {
        samlResponse = responseResult.context;
    } else if (typeof responseResult === 'string') {
        samlResponse = responseResult;
    } else if (responseResult && responseResult.samlContent) {
        samlResponse = responseResult.samlContent;
    } else {
        throw new Error('Unable to extract SAML response from samlify result - invalid response structure');
    }
    
    if (!samlResponse || typeof samlResponse !== 'string') {
        throw new Error('SAML response is invalid or empty');
    }
    
    console.log('✅ SAML Response created with samlify');
    console.log('📏 Response length:', samlResponse.length, 'characters');
    console.log('🔐 Encryption status:', shouldEncrypt ? 'ENCRYPTED' : 'UNENCRYPTED');
    console.log('🔐 Signing status: SIGNED');
    
    // Debug: Check if the response is XML or Base64
    console.log('🔍 SAML Response first 100 chars:', samlResponse.substring(0, 100));
    console.log('🔍 SAML Response starts with XML:', samlResponse.trim().startsWith('<'));
    
    // Samlify returns Base64 encoded XML in the context field, so we need to decode it
    let actualXmlResponse = samlResponse;
    if (!samlResponse.trim().startsWith('<')) {
        console.log('🔍 Response appears to be Base64 encoded, attempting to decode...');
        try {
            actualXmlResponse = Buffer.from(samlResponse, 'base64').toString('utf8');
            console.log('✅ Successfully decoded Base64 to XML');
            console.log('🔍 Decoded XML first 100 chars:', actualXmlResponse.substring(0, 100));
        } catch (decodeError) {
            console.log('❌ Failed to decode as Base64:', decodeError.message);
            console.log('🔍 Using original response as-is');
            actualXmlResponse = samlResponse;
        }
    }
    
    // Debug: Check for attribute statements in the XML
    console.log('🔍 Checking for AttributeStatement in SAML...');
    console.log('🔍 Contains AttributeStatement:', actualXmlResponse.includes('AttributeStatement'));
    console.log('🔍 Contains loginName:', actualXmlResponse.includes('loginName'));
    console.log('🔍 Contains siteId:', actualXmlResponse.includes('siteId'));
    
    // Debug: Check for encryption in the XML
    console.log('🔍 Checking for encryption in SAML...');
    console.log('🔍 Contains EncryptedAssertion:', actualXmlResponse.includes('EncryptedAssertion'));
    console.log('🔍 Contains EncryptedData:', actualXmlResponse.includes('EncryptedData'));
    console.log('🔍 Contains CipherValue:', actualXmlResponse.includes('CipherValue'));
    
    // Determine if the response is actually encrypted
    const isActuallyEncrypted = actualXmlResponse.includes('EncryptedAssertion') || 
                               actualXmlResponse.includes('EncryptedData');
    
    const method = isActuallyEncrypted ? 'SAMLIFY_SIGNED_ENCRYPTED' : 'SAMLIFY_SIGNED';
    console.log('🔍 Final method determined:', method);
    
    return {
        samlResponse: actualXmlResponse,
        method: method
    };
}

// Custom SAML generation fallback function
async function createCustomSAMLResponse(siteId, loginName, destinationUrl, shouldEncrypt = false) {
    console.log('🔧 Creating custom SAML Response (fallback method)...');
    console.log('📍 Destination URL:', destinationUrl);
    console.log('🔐 Encryption requested:', shouldEncrypt);
    
    try {
        // Generate unique IDs
        const responseId = 'response_' + Math.random().toString(36).substr(2, 9);
        const assertionId = 'assertion_' + Math.random().toString(36).substr(2, 9);
        const sessionIndex = 'session_' + Math.random().toString(36).substr(2, 9);
        
        // Generate timestamps
        const now = new Date();
        const issueInstant = now.toISOString();
        const notBefore = new Date(now.getTime() - 5 * 60 * 1000).toISOString(); // 5 minutes ago
        const notOnOrAfter = new Date(now.getTime() + 10 * 60 * 1000).toISOString(); // 10 minutes from now
        
        // Create SAML Response XML with Okta-compatible format
        const samlResponseXml = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
                 xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                 xmlns:xs="http://www.w3.org/2001/XMLSchema"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 ID="${responseId}" 
                 Version="2.0" 
                 IssueInstant="${issueInstant}" 
                 Destination="${destinationUrl}">
    <saml2:Issuer>https://idp.liveperson.com</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </saml2p:Status>
    <saml2:Assertion ID="${assertionId}" 
                     Version="2.0" 
                     IssueInstant="${issueInstant}">
        <saml2:Issuer>https://idp.liveperson.com</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${loginName}</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" 
                                               Recipient="${destinationUrl}"/>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
            <saml2:AudienceRestriction>
                <saml2:Audience>LEna2</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${sessionIndex}">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute Name="loginName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml2:AttributeValue xsi:type="xs:string">${loginName}</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name="siteId" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml2:AttributeValue xsi:type="xs:string">${siteId}</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>`;

        // Sign the SAML assertion
        const signedXml = await signXMLAssertion(samlResponseXml);
        
        // Encrypt if requested
        let finalXml = signedXml;
        if (shouldEncrypt) {
            const encryptionCert = loadLivePersonCertificate();
            if (encryptionCert) {
                console.log('🔐 Encrypting SAML assertion...');
                finalXml = await encryptSAMLAssertion(signedXml, encryptionCert);
            } else {
                console.log('⚠ Encryption requested but no encryption certificate available');
            }
        }
        
        console.log('✅ Custom SAML Response created successfully');
        console.log('📏 Response length:', finalXml.length, 'characters');
        console.log('🔐 Encryption status:', shouldEncrypt && finalXml.includes('EncryptedAssertion') ? 'ENCRYPTED' : 'UNENCRYPTED');
        console.log('🔐 Signing status: SIGNED');
        
        const method = shouldEncrypt && finalXml.includes('EncryptedAssertion') ? 'CUSTOM_SIGNED_ENCRYPTED' : 'CUSTOM_SIGNED';
        
        return {
            samlResponse: finalXml,
            method: method
        };
        
    } catch (error) {
        console.error('❌ Custom SAML generation failed:', error.message);
        console.error('Stack:', error.stack);
        throw error;
    }
}

// XML signing function using xml-crypto
async function signXMLAssertion(xmlString) {
    console.log('🔐 Signing XML assertion with xml-crypto...');
    
    try {
        const crypto = require('crypto');
        const { DOMParser, XMLSerializer } = require('xmldom');
        const xmlCrypto = require('xml-crypto');
        
        // Load signing certificate and private key
        const signingCert = loadSigningCertificate();
        const signingKey = loadSigningPrivateKey();
        
        if (!signingCert || !signingKey) {
            throw new Error('Signing certificate or private key not available');
        }
        
        // Parse the XML
        const doc = new DOMParser().parseFromString(xmlString);
        const assertion = doc.getElementsByTagName('saml2:Assertion')[0];
        
        if (!assertion) {
            throw new Error('No SAML assertion found in XML');
        }
        
        // Create signature
        const sig = new xmlCrypto.SignedXml();
        sig.addReference("//*[local-name(.)='Assertion']", 
                        ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", 
                         "http://www.w3.org/2001/10/xml-exc-c14n#"], 
                        "http://www.w3.org/2001/04/xmlenc#sha256");
        
        sig.signingKey = signingKey;
        sig.keyInfoProvider = {
            getKeyInfo: function() {
                const certBase64 = signingCert
                    .replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '')
                    .replace(/\s/g, '');
                
                return `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;
            }
        };
        
        // Sign the assertion
        sig.computeSignature(xmlString, {
            location: { reference: "//*[local-name(.)='Assertion']", action: "prepend" }
        });
        
        console.log('✅ XML assertion signed successfully');
        return sig.getSignedXml();
        
    } catch (error) {
        console.error('❌ XML signing failed:', error.message);
        console.error('Stack:', error.stack);
        throw error;
    }
}

async function signSAMLAssertion(assertion, destinationUrl, shouldEncrypt = false) {
    console.log('🔐 Creating SAML assertion with samlify...');
    console.log('📍 Destination URL:', destinationUrl);
    console.log('🔐 Encryption requested:', shouldEncrypt);
    
    // Always generate unencrypted SAML first (since we disabled samlify encryption)
    const result = await createSAMLResponse(
        assertion.siteId || 'a41244303', 
        assertion.loginName || 'testuser', 
        destinationUrl, 
        false  // Always false since we handle encryption manually
    );
    
    let finalXml = result.samlResponse;
    let method = result.method;
    
    // If encryption is requested, encrypt the SAML manually
    if (shouldEncrypt) {
        console.log('🔍 Encryption requested - checking for encryption certificate...');
        const encryptionCert = loadLivePersonCertificate();
        console.log('🔍 Encryption certificate loaded:', !!encryptionCert);
        if (encryptionCert) {
            console.log('🔐 Applying manual encryption to SAML assertion...');
            try {
                finalXml = encryptSAMLAssertionSimple(finalXml, encryptionCert);
                method = method.replace('SIGNED', 'SIGNED_ENCRYPTED');
                console.log('✅ Manual encryption applied successfully');
            } catch (encryptError) {
                console.error('❌ Manual encryption failed:', encryptError.message);
                console.log('🔄 Continuing with unencrypted SAML');
            }
        } else {
            console.log('⚠ Encryption requested but no encryption certificate available');
        }
    } else {
        console.log('🔍 Encryption not requested (shouldEncrypt = false)');
    }
                
    return {
        xml: finalXml,
        base64: Buffer.from(finalXml).toString('base64'),
        method: method
    };
}

// Cleanup expired authorization codes every 5 minutes
setInterval(() => {
    const now = Date.now();
    let cleanedCount = 0;
    
    for (const [code, data] of authorizationCodes.entries()) {
        if (now > data.expiresAt) {
            authorizationCodes.delete(code);
            cleanedCount++;
        }
    }
    
    if (cleanedCount > 0) {
        console.log(`🧹 Cleaned up ${cleanedCount} expired authorization codes`);
    }
}, 5 * 60 * 1000); // 5 minutes

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Request logging array
const requestLogs = [];

// Custom logging middleware
app.use((req, res, next) => {
    // Skip logging for dashboard requests to reduce clutter
    if (req.url === '/') {
        return next();
    }
    
    const logEntry = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: req.body,
        query: req.query,
        ip: req.ip,
        encryptionMode: encryptionEnabled ? 'SIGNING + ENCRYPTION (JWE)' : 'SIGNING ONLY (JWT)',
        flowType: flowType.toUpperCase(),
        issuer: `https://mature-mackerel-golden.ngrok-free.app/${flowType}`,
        response: null
    };
    
    // Capture response data
    const originalSend = res.send;
    const originalJson = res.json;
    
    res.send = function(data) {
        logEntry.response = {
            statusCode: res.statusCode,
            data: data,
            contentType: res.get('Content-Type') || 'text/html'
        };
        return originalSend.call(this, data);
    };
    
    res.json = function(data) {
        logEntry.response = {
            statusCode: res.statusCode,
            data: data,
            contentType: 'application/json'
        };
        
        // Add token analysis for token responses
        if (data && (data.id_token || data.access_token)) {
            logEntry.tokenAnalysis = {
                id_token_length: data.id_token ? data.id_token.length : 0,
                id_token_format: data.id_token ? (data.id_token.split('.').length === 3 ? 'JWT (3 parts)' : data.id_token.split('.').length === 5 ? 'JWE (5 parts)' : 'Unknown') : 'N/A',
                access_token_length: data.access_token ? data.access_token.length : 0,
                access_token_format: data.access_token ? (data.access_token.split('.').length === 3 ? 'JWT (3 parts)' : 'Unknown') : 'N/A'
            };
        }
        
        return originalJson.call(this, data);
    };
    
    // Add to logs when response is finished
    res.on('finish', () => {
        requestLogs.push(logEntry);
        
        // Keep only last 100 requests
        if (requestLogs.length > 100) {
            requestLogs.shift();
        }
    });
    
    // Enhanced console logging with POST body details
    let logMessage = `[${logEntry.timestamp}] ${req.method} ${req.url}`;
    
    // Add query parameters if present
    if (req.query && Object.keys(req.query).length > 0) {
        logMessage += `\n  Query: ${JSON.stringify(req.query)}`;
    }
    
    // Add POST body if present
    if (req.method === 'POST' && req.body && Object.keys(req.body).length > 0) {
        logMessage += `\n  Body: ${JSON.stringify(req.body, null, 2)}`;
    }
    
    // Add relevant headers for authentication requests
    if (req.headers.authorization) {
        logMessage += `\n  Authorization: ${req.headers.authorization}`;
    }
    
    console.log(logMessage);
    next();
});

// Load keys
let signingPrivateKey, signingPublicKey, lpEncryptionPublicKey;

function loadKeys() {
    try {
        // Load required signing keys
        signingPrivateKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-private.pem'), 'utf8');
        signingPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-public.pem'), 'utf8');
        console.log('✓ Signing keys loaded successfully');
        
        // Try to load LivePerson encryption certificate
        try {
            lpEncryptionPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'lpsso2026.pem'), 'utf8');
            console.log('✓ LivePerson encryption certificate (lpsso2026.pem) loaded');
        } catch (error) {
            console.log('⚠ LivePerson encryption certificate (lpsso2026.pem) not found - place it in ./certs/ for JWE encryption');
            lpEncryptionPublicKey = null;
        }
        
        // Initialize SAML after keys are loaded
        const samlInitialized = initializeSAML();
        if (samlInitialized) {
            console.log('✓ SAML library initialized successfully');
        } else {
            console.log('⚠ SAML library initialization failed - using legacy implementation');
        }
        
        console.log('✓ Key loading completed');
    } catch (error) {
        console.error('Error loading required signing keys:', error.message);
        console.log('Please run: npm run generate-keys');
        process.exit(1);
    }
}

// Convert PEM to JWK format for JWKS endpoint
function pemToJwk(pemKey, use, alg, kid) {
    const keyData = pemKey
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\n/g, '');
    
    // This is a simplified JWK conversion - in production you'd use a proper library
    // For now, we'll return the PEM in a custom format that LivePerson can handle
    return {
        kty: 'RSA',
        use: use,
        alg: alg,
        kid: kid,
        x5c: [keyData] // Certificate chain
    };
}

// Routes

// Home page with request logs and encryption toggle
app.get('/', (req, res) => {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson IDP Server</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .log-entry { border: 1px solid #ccc; margin: 10px 0; padding: 10px; background: #f9f9f9; }
            .timestamp { font-weight: bold; color: #666; }
            .method { color: #007bff; font-weight: bold; }
            .url { color: #28a745; }
            pre { background: #f8f9fa; padding: 10px; overflow-x: auto; }
            .header { background: #007bff; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
            .status { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 20px 0; }
            .encryption-toggle { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .toggle-switch { position: relative; display: inline-block; width: 60px; height: 34px; }
            .toggle-switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
            input:checked + .slider { background-color: #2196F3; }
            input:checked + .slider:before { transform: translateX(26px); }
            .encryption-status { font-weight: bold; color: ${encryptionEnabled ? '#28a745' : '#dc3545'}; }
        </style>
        <script>
            function refreshLogs() {
                location.reload();
            }
            
            function toggleEncryption() {
                const enabled = document.getElementById('encryptionToggle').checked;
                fetch('/toggle-encryption', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: enabled })
                }).then(() => {
                    setTimeout(refreshLogs, 500);
                });
            }
            
            function toggleFlowType(type) {
                fetch('/toggle-flow-type', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ flowType: type })
                }).then(() => {
                    setTimeout(refreshLogs, 500);
                });
            }
            
            setInterval(refreshLogs, 10000); // Auto-refresh every 10 seconds
        </script>
    </head>
    <body>
        <div class="header">
            <h1>LivePerson IDP Server</h1>
            <p>Local Identity Provider for testing LivePerson consumer authentication and Denver Agent SSO</p>
        </div>
        
        <div class="encryption-toggle">
            <h3>🔐 Encryption Control (JWT + SAML)</h3>
            <label class="toggle-switch">
                <input type="checkbox" id="encryptionToggle" ${encryptionEnabled ? 'checked' : ''} onchange="toggleEncryption()">
                <span class="slider"></span>
            </label>
            <span class="encryption-status">
                ${encryptionEnabled ? '✓ ENCRYPTION ENABLED' : '✗ ENCRYPTION DISABLED (Signing Only)'}
            </span>
            <p><strong>Status:</strong> ${encryptionEnabled ? 
                (lpEncryptionPublicKey ? 'Ready for JWE encryption (consumer auth) and SAML encryption (Denver Agent SSO) with LivePerson certificate (kid: lpsso2026)' : 
                'Encryption enabled but lpsso2026.pem not found in ./certs/') :
                'Currently using JWT signing only (RS256) for consumer auth and SAML signing only for Denver Agent SSO - easier for initial testing'
            }</p>
            
            <h3 style="margin-top: 25px;">🔄 OAuth Flow Type</h3>
            <div style="margin: 15px 0;">
                <label style="margin-right: 20px;">
                    <input type="radio" name="flowType" value="implicit" ${flowType === 'implicit' ? 'checked' : ''} onchange="toggleFlowType('implicit')">
                    <strong>Implicit Flow</strong> (response_type=id_token)
                </label>
                <label style="margin-right: 20px;">
                    <input type="radio" name="flowType" value="code" ${flowType === 'code' ? 'checked' : ''} onchange="toggleFlowType('code')">
                    <strong>Authorization Code Flow</strong> (response_type=code)
                </label>
                <label>
                    <input type="radio" name="flowType" value="codepkce" ${flowType === 'codepkce' ? 'checked' : ''} onchange="toggleFlowType('codepkce')">
                    <strong>Code Flow + PKCE</strong> (response_type=code + PKCE)
                </label>
            </div>
            <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; border-radius: 4px;">
                <strong>Current Flow:</strong> <span style="color: #007bff; font-weight: bold;">${flowType.toUpperCase()}</span><br>
                <strong>Issuer (iss):</strong> <code style="font-size: 11px;">https://mature-mackerel-golden.ngrok-free.app/${flowType}</code><br>
                <strong>LivePerson Config:</strong> Use different issuer URLs to test multiple IdP configurations
            </div>
        </div>
        
        <div class="status">
            <h3>Server Status: ✓ Running on port ${PORT}</h3>
            <p><strong>Available Endpoints:</strong></p>
            <ul>
                <li><code>GET /</code> - This page (request logs)</li>
                <li><code>GET /test</code> - <a href="/test" style="color: #007bff;">LivePerson Test Page</a> (with chat widget, no auto-refresh)</li>
                <li><code>GET /agentsso-denver</code> - <a href="/agentsso-denver" style="color: #007bff;">Denver SAML SSO Testing Page</a></li>
                <li><code>GET /.well-known/jwks.json</code> - JWKS endpoint for public keys</li>
                <li><code>GET /authorize</code> - OAuth authorization endpoint (both implicit and code flow)</li>
                <li><code>POST /token</code> - OAuth token endpoint (code exchange)</li>
                <li><code>POST /token-direct</code> - Direct token endpoint (testing only)</li>
                <li><code>GET /oauth-callback.html</code> - OAuth callback page (implicit flow)</li>
                <li><code>GET /encryption-public-key</code> - Public encryption key for LivePerson</li>
                <li><code>POST /toggle-encryption</code> - Toggle JWE encryption on/off</li>
            </ul>
        </div>
        
        <h2>Recent Requests (${requestLogs.length})</h2>
        <button onclick="refreshLogs()">Refresh Logs</button>
        
        ${requestLogs.slice(-20).reverse().map(log => `
            <div class="log-entry">
                <div class="timestamp">${log.timestamp}</div>
                <div><span class="method">${log.method}</span> <span class="url">${log.url}</span></div>
                <div><strong>🔐 Mode:</strong> <span style="color: ${log.encryptionMode.includes('ENCRYPTION') ? '#28a745' : '#dc3545'};">${log.encryptionMode}</span></div>
                <div><strong>🔄 Flow:</strong> <span style="color: #007bff;">${log.flowType}</span> | <strong>🏷️ Issuer:</strong> <code style="font-size: 11px;">${log.issuer}</code></div>
                ${log.query && Object.keys(log.query).length > 0 ? `<div><strong>Query:</strong> <pre>${JSON.stringify(log.query, null, 2)}</pre></div>` : ''}
                ${log.body && Object.keys(log.body).length > 0 ? `<div><strong>Body:</strong> <pre>${JSON.stringify(log.body, null, 2)}</pre></div>` : ''}
                ${log.response ? `
                    <div><strong>📤 Response (${log.response.statusCode}):</strong></div>
                    ${log.tokenAnalysis ? `
                        <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin: 5px 0; border-radius: 4px;">
                            <strong>🔍 Token Analysis:</strong><br>
                            🆔 ID Token: ${log.tokenAnalysis.id_token_length} chars, ${log.tokenAnalysis.id_token_format}<br>
                            🔑 Access Token: ${log.tokenAnalysis.access_token_length} chars, ${log.tokenAnalysis.access_token_format}
                        </div>
                    ` : ''}
                    ${log.response.contentType === 'application/json' ? 
                        `<pre style="max-height: 200px; overflow-y: auto;">${JSON.stringify(log.response.data, null, 2)}</pre>` : 
                        `<div style="max-height: 100px; overflow-y: auto; background: #f8f9fa; padding: 5px; font-family: monospace; font-size: 12px;">${typeof log.response.data === 'string' ? log.response.data.substring(0, 500) + (log.response.data.length > 500 ? '...' : '') : JSON.stringify(log.response.data)}</div>`
                    }
                ` : ''}
            </div>
        `).join('')}
    </body>
    </html>
    `;
    res.send(html);
});

// OAuth callback page for implicit flow
app.get('/oauth-callback.html', (req, res) => {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth Callback</title>
    </head>
    <body>
        <script>
            // Extract parameters from URL
            const urlParams = new URLSearchParams(window.location.search);
            const hash = window.location.hash.substring(1);
            const hashParams = new URLSearchParams(hash);
            
            // Check for authorization code (ssoKey parameter for LivePerson)
            const ssoKey = urlParams.get('ssoKey');
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            
            // Check for implicit flow tokens (from hash)
            const id_token = hashParams.get('id_token');
            const error = hashParams.get('error') || urlParams.get('error');
            const error_description = hashParams.get('error_description') || urlParams.get('error_description');
            
            console.log('OAuth callback received:', {
                ssoKey: ssoKey,
                code: code,
                id_token: id_token ? 'present' : 'none',
                error: error,
                state: state
            });
            
            // Send result back to parent window
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({
                    type: 'oauth_callback',
                    ssoKey: ssoKey,
                    code: code,
                    id_token: id_token,
                    error: error,
                    error_description: error_description,
                    state: state
                }, window.location.origin);
            }
        </script>
        <p>Processing OAuth callback...</p>
        <p id="status"></p>
        <script>
            // Show status
            const statusEl = document.getElementById('status');
            if (ssoKey) {
                statusEl.textContent = 'Authorization code (ssoKey) received: ' + ssoKey.substring(0, 8) + '...';
            } else if (id_token) {
                statusEl.textContent = 'ID token received (implicit flow)';
            } else if (error) {
                statusEl.textContent = 'Error: ' + error;
            } else {
                statusEl.textContent = 'No valid parameters found';
            }
        </script>
    </body>
    </html>
    `;
    res.send(html);
});

// LivePerson Test Page (without auto-refresh)
app.get('/test', (req, res) => {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson IDP Server - Test Page</title>
        
        <!-- LivePerson Authenticated Identity Configuration - MUST be before lpTag -->
        <script type="text/javascript">
            // Initialize the lpTag namespace and the identity array, if the identity function is placed above the tag.
            var lpTag = {};
            lpTag.identities = [];

            lpTag.identities.push(identityFn);
            function identityFn(callback) {
                // Get current flow type to determine the correct issuer
                fetch('/health')
                    .then(response => response.json())
                    .then(healthData => {
                        const currentFlowType = healthData.flowType || 'implicit';
                        const issuer = 'https://mature-mackerel-golden.ngrok-free.app/' + currentFlowType;
                        
                        console.log('LivePerson identity function - Current flow:', currentFlowType);
                        console.log('LivePerson identity function - Using issuer:', issuer);
                        
                        callback({
                            iss: issuer,  // Dynamic issuer based on current flow type
                            acr: "loa1",
                            sub: "test-user-123"  // Must match JWT subject
                        });
                    })
                    .catch(error => {
                        console.error('Error getting flow type for identity function:', error);
                        // Fallback to default issuer
                        callback({
                            iss: "https://mature-mackerel-golden.ngrok-free.app/implicit",
                            acr: "loa1",
                            sub: "test-user-123"
                        });
                    });
            }
            
            console.log('LivePerson authenticated identity function configured with dynamic issuer');
        </script>
        
        <!-- BEGIN LivePerson Monitor. -->
        <script type="text/javascript">window.lpTag=window.lpTag||{},'undefined'==typeof window.lpTag._tagCount?(window.lpTag={wl:lpTag.wl||null,scp:lpTag.scp||null,site:'a41244303'||'',section:lpTag.section||'',tagletSection:lpTag.tagletSection||null,autoStart:lpTag.autoStart!==!1,ovr:lpTag.ovr||{domain: 'lptag-a.liveperson.net', tagjs: 'tags-a.liveperson.net'},_v:'1.10.0',_tagCount:1,protocol:'https:',events:{bind:function(t,e,i){lpTag.defer(function(){lpTag.events.bind(t,e,i)},0)},trigger:function(t,e,i){lpTag.defer(function(){lpTag.events.trigger(t,e,i)},1)}},defer:function(t,e){0===e?(this._defB=this._defB||[],this._defB.push(t)):1===e?(this._defT=this._defT||[],this._defT.push(t)):(this._defL=this._defL||[],this._defL.push(t))},load:function(t,e,i){var n=this;setTimeout(function(){n._load(t,e,i)},0)},_load:function(t,e,i){var n=t;t||(n=this.protocol+'//'+(this.ovr&&this.ovr.domain?this.ovr.domain:'lptag.liveperson.net')+'/tag/tag.js?site='+this.site);var o=document.createElement('script');o.setAttribute('charset',e?e:'UTF-8'),i&&o.setAttribute('id',i),o.setAttribute('src',n),document.getElementsByTagName('head').item(0).appendChild(o)},init:function(){this._timing=this._timing||{},this._timing.start=(new Date).getTime();var t=this;window.attachEvent?window.attachEvent('onload',function(){t._domReady('domReady')}):(window.addEventListener('DOMContentLoaded',function(){t._domReady('contReady')},!1),window.addEventListener('load',function(){t._domReady('domReady')},!1)),'undefined'===typeof window._lptStop&&this.load()},start:function(){this.autoStart=!0},_domReady:function(t){this.isDom||(this.isDom=!0,this.events.trigger('LPT','DOM_READY',{t:t})),this._timing[t]=(new Date).getTime()},vars:lpTag.vars||[],dbs:lpTag.dbs||[],ctn:lpTag.ctn||[],sdes:lpTag.sdes||[],hooks:lpTag.hooks||[],identities:lpTag.identities||[],ev:lpTag.ev||[]},lpTag.init()):window.lpTag._tagCount+=1;</script>
        <!-- END LivePerson Monitor. -->
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
            .header { background: #007bff; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
            .content { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .info-box { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .nav-link { color: #007bff; text-decoration: none; margin-right: 15px; }
            .nav-link:hover { text-decoration: underline; }
            .user-info { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 5px; }
        </style>
        <script>
            // LivePerson Authentication Token Function
            function lpgetToken(callback) {
                console.log('LivePerson requesting authentication token...');
                
                // Get current flow type from server
                fetch('/health')
                    .then(response => response.json())
                    .then(healthData => {
                        const currentFlowType = healthData.flowType || 'implicit';
                        console.log('Current flow type:', currentFlowType);
                        
                        if (currentFlowType === 'code') {
                            // Authorization Code Flow
                            console.log('Using Authorization Code Flow...');
                            
                            const params = new URLSearchParams({
                                response_type: 'code',
                                client_id: 'liveperson-client',
                                scope: 'openid profile email',
                                state: 'liveperson-test',
                                nonce: Math.random().toString(36).substring(7)
                            });
                            
                            // Get authorization code (ssoKey) - LivePerson will handle token exchange
                            fetch('/authorize?' + params.toString(), {
                                method: 'GET',
                                headers: {
                                    'Accept': 'application/json',
                                    'Content-Type': 'application/json'
                                }
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.ssoKey) {
                                    console.log('✅ Authorization code (ssoKey) received:', data.ssoKey);
                                    console.log('🔄 Passing ssoKey to LivePerson - LP IdP will call /token endpoint');
                                    console.log('📋 LivePerson should treat this as authorization code, not id_token');
                                    // Pass the ssoKey to LivePerson - they will handle the token exchange
                                    callback(data.ssoKey);
                                } else if (data.error) {
                                    console.error('❌ OAuth error:', data.error, data.error_description);
                                    callback(null);
                                } else {
                                    console.error('❌ No ssoKey in response');
                                    callback(null);
                                }
                            })
                            .catch(error => {
                                console.error('❌ Error in Authorization Code Flow:', error);
                                callback(null);
                            });
                            
                        } else if (currentFlowType === 'codepkce') {
                            // Authorization Code Flow with PKCE
                            console.log('Using Authorization Code Flow with PKCE...');
                            console.log('🔐 LivePerson will handle PKCE challenge/verifier generation automatically');
                            
                            // For PKCE flow, LivePerson handles the PKCE parameters automatically
                            // We just need to be ready to receive the code_challenge parameters
                            // and verify the code_verifier when LivePerson calls /token
                            
                            // Note: In a real PKCE implementation, the client would generate:
                            // 1. code_verifier (cryptographically random string)
                            // 2. code_challenge = base64url(sha256(code_verifier))
                            // 3. Send code_challenge with /authorize request
                            // 4. Send code_verifier with /token request
                            
                            // But LivePerson handles this automatically, so we just inform the user
                            console.log('📋 PKCE flow requires LivePerson to generate challenge/verifier');
                            console.log('📋 Our server will receive code_challenge in /authorize and code_verifier in /token');
                            console.log('❌ Cannot test PKCE flow directly from browser - requires LivePerson integration');
                            
                            // For testing purposes, show that PKCE flow is selected but cannot be executed directly
                            alert('PKCE flow selected. This flow requires LivePerson to handle PKCE parameters automatically. Use the LivePerson chat widget to test this flow.');
                            callback(null);
                            
                        } else {
                            // Implicit Flow (default)
                            console.log('Using Implicit Flow...');
                            
                            const params = new URLSearchParams({
                                response_type: 'id_token',
                                client_id: 'liveperson-client',
                                scope: 'openid profile email',
                                state: 'liveperson-test',
                                nonce: Math.random().toString(36).substring(7)
                            });
                            
                            fetch('/authorize?' + params.toString(), {
                                method: 'GET',
                                headers: {
                                    'Accept': 'application/json',
                                    'Content-Type': 'application/json'
                                }
                            })
                            .then(response => response.json())
                            .then(data => {
                                console.log('OAuth Implicit Flow response:', data);
                                if (data.id_token) {
                                    console.log('✅ Calling LivePerson callback with ID token from Implicit Flow');
                                    console.log('Token format:', data.id_token.split('.').length === 3 ? 'JWT (3 parts)' : data.id_token.split('.').length === 5 ? 'JWE (5 parts)' : 'Unknown');
                                    callback(data.id_token);
                                } else if (data.error) {
                                    console.error('❌ OAuth error:', data.error, data.error_description);
                                    callback(null);
                                } else {
                                    console.error('❌ No ID token in response');
                                    callback(null);
                                }
                            })
                            .catch(error => {
                                console.error('❌ Error in Implicit Flow:', error);
                                callback(null);
                            });
                        }
                    })
                    .catch(error => {
                        console.error('❌ Error getting flow type:', error);
                        callback(null);
                    });
            }
            
            // Test function to manually trigger token retrieval
            function testTokenRetrieval() {
                lpgetToken(function(token) {
                    if (token) {
                        document.getElementById('tokenDisplay').innerHTML = 
                            '<strong>Token Retrieved:</strong><br><textarea readonly style="width:100%;height:100px;">' + token + '</textarea>';
                    } else {
                        document.getElementById('tokenDisplay').innerHTML = '<strong style="color:red;">Failed to retrieve token</strong>';
                    }
                });
            }
        </script>
    </head>
    <body>
        <div class="header">
            <h1>🧪 LivePerson IDP Server - Test Page</h1>
            <p>Testing LivePerson Chat Integration with Authentication</p>
        </div>
        
        <div class="content">
            <nav style="margin-bottom: 20px;">
                <a href="/" class="nav-link">← Back to Dashboard</a>
                <a href="/health" class="nav-link">Health Check</a>
                <a href="/.well-known/jwks.json" class="nav-link">JWKS</a>
            </nav>
            
            <div class="info-box">
                <h3>✅ LivePerson Chat Integration Active</h3>
                <p>This page includes the LivePerson lpTag script and should display the chat widget.</p>
                <p><strong>Site ID:</strong> a41244303</p>
                <p><strong>Domain:</strong> lptag-a.liveperson.net</p>
                <p><strong>Status:</strong> Chat widget should appear in the bottom right corner</p>
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-top: 10px; border-radius: 4px; font-size: 12px;">
                    <strong>⚠️ Note:</strong> You may see console errors from <code>web-client-content-script.js</code> - these are from LivePerson's own code and can be safely ignored. They don't affect authentication functionality.
                </div>
            </div>
            
            <div class="info-box" style="background: #e7f3ff; border: 1px solid #b3d9ff;">
                <h3>🔐 Authenticated Identity Function Configured</h3>
                <p>This page includes the authenticated identity function in <code>lpTag.identities</code> (placed BEFORE the lpTag script):</p>
                <ul>
                    <li><strong>Issuer (iss):</strong> <code>Dynamic based on current flow type</code></li>
                    <li><strong>Implicit Flow:</strong> <code>https://mature-mackerel-golden.ngrok-free.app/implicit</code></li>
                    <li><strong>Code Flow:</strong> <code>https://mature-mackerel-golden.ngrok-free.app/code</code></li>
                    <li><strong>Subject (sub):</strong> <code>test-user-123</code></li>
                    <li><strong>ACR (Authentication Context Class Reference):</strong> <code>loa1</code></li>
                </ul>
                <p><strong>✅ Dynamic Issuer Matching:</strong> The identity function automatically detects the current flow type and uses the matching issuer URL.</p>
                <p><strong>📋 Implementation:</strong> Uses the correct LivePerson identity function format that calls a callback with the identity object.</p>
                <p>This tells LivePerson which IdP configuration to use based on the current flow type.</p>
            </div>
            
            <div class="user-info">
                <h3>👤 JWT Token Claims</h3>
                <p>When testing authentication, this JWT will be generated with the following claims:</p>
                
                <h4>🔐 Standard JWT Claims:</h4>
                <ul>
                    <li><strong>Issuer (iss):</strong> <code>https://mature-mackerel-golden.ngrok-free.app</code></li>
                    <li><strong>Subject (sub):</strong> test-user-123</li>
                    <li><strong>Audience (aud):</strong> liveperson-client (or client_id from request)</li>
                    <li><strong>Expires (exp):</strong> 1 hour from issue time</li>
                    <li><strong>Issued At (iat):</strong> Current timestamp</li>
                    <li><strong>Algorithm:</strong> RS256 (RSA Signature with SHA-256)</li>
                    <li><strong>Key ID (kid):</strong> signing-key-1</li>
                </ul>
                
                <h4>👤 User Profile Claims:</h4>
                <ul>
                    <li><strong>Name:</strong> Test User</li>
                    <li><strong>Given Name:</strong> Test</li>
                    <li><strong>Family Name:</strong> User</li>
                    <li><strong>Email:</strong> test.user@example.com</li>
                    <li><strong>Phone:</strong> +1234567890</li>
                </ul>
                
                <h4>🏢 LivePerson SDES Claims:</h4>
                <ul>
                    <li><strong>Customer ID:</strong> test-user-123 (matches user_id)</li>
                    <li><strong>Customer Type:</strong> premium</li>
                    <li><strong>Account Balance:</strong> $1,500.00</li>
                    <li><strong>Account Number:</strong> ACC-123123 (derived from user_id)</li>
                </ul>
                
                <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin-top: 15px; border-radius: 4px;">
                    <strong>💡 Note:</strong> When using ngrok, update the issuer (iss) to your ngrok URL for production testing.
                </div>
            </div>
            
            <div class="content">
                <h3>🔐 OAuth 2.0 Authentication Flows</h3>
                <p>This IDP server supports both standard OAuth 2.0 flows:</p>
                
                <div style="background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4>📋 Authorization Code Flow (Recommended):</h4>
                    <ol>
                        <li><strong>Step 1:</strong> <code>GET /authorize?response_type=code&client_id=...&redirect_uri=...</code></li>
                        <li><strong>Step 2:</strong> <code>POST /token</code> with authorization code</li>
                    </ol>
                    
                    <h4>📋 Authorization Code Flow + PKCE:</h4>
                    <ol>
                        <li><strong>Step 1:</strong> <code>GET /authorize?response_type=code&code_challenge=...&code_challenge_method=S256</code></li>
                        <li><strong>Step 2:</strong> <code>POST /token</code> with authorization code + code_verifier</li>
                        <li><strong>PKCE Verification:</strong> Server verifies SHA256(code_verifier) == code_challenge</li>
                    </ol>
                    
                    <h4>📋 Implicit Flow:</h4>
                    <ol>
                        <li><strong>Step 1:</strong> <code>GET /authorize?response_type=id_token&client_id=...&redirect_uri=...</code></li>
                        <li>Tokens returned directly in URL fragment</li>
                    </ol>
                    
                    <h4>🧪 Direct Token (Testing Only):</h4>
                    <ul>
                        <li><strong>Endpoint:</strong> <code>POST /token-direct</code></li>
                        <li><strong>Purpose:</strong> Simplified testing without OAuth flow</li>
                        <li><strong>Usage:</strong> Send user_id and client_id directly</li>
                    </ul>
                </div>
                
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4>🧪 Test Authentication Function:</h4>
                    <p>Click the button below to test the <code>lpgetToken(callback)</code> function that LivePerson will call:</p>
                    <button onclick="testTokenRetrieval()" style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 10px 0;">
                        🔑 Test Token Retrieval
                    </button>
                    <div id="tokenDisplay" style="margin-top: 15px; font-family: monospace; font-size: 12px;"></div>
                    <p style="margin-top: 10px; font-size: 12px; color: #666;">
                        <strong>Note:</strong> Now using proper OAuth 2.0 <code>/authorize</code> endpoint with implicit flow. The endpoint detects AJAX requests and returns tokens directly as JSON.
                    </p>
                </div>
            </div>
            
            <div class="content">
                <h3>🔧 LivePerson Configuration</h3>
                <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4>📋 For Production Use:</h4>
                    <ul>
                        <li><strong>Authorization URL:</strong> <code>https://your-domain.com/authorize</code></li>
                        <li><strong>Token URL:</strong> <code>https://your-domain.com/token</code></li>
                        <li><strong>JWKS URL:</strong> <code>https://your-domain.com/.well-known/jwks.json</code></li>
                        <li><strong>Client ID:</strong> <code>clientid</code></li>
                        <li><strong>Client Secret:</strong> <code>1234567890</code></li>
                        <li><strong>Authentication:</strong> HTTP Basic Auth header</li>
                        <li><strong>Flow:</strong> Authorization Code Flow (recommended)</li>
                        <li><strong>Callback Parameter:</strong> <code>ssoKey</code> (LivePerson format)</li>
                    </ul>
                </div>
                
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4>🧪 For Testing (Current Setup):</h4>
                    <ul>
                        <li><strong>Authorization URL:</strong> <code>http://localhost:${PORT}/authorize</code></li>
                        <li><strong>Token URL:</strong> <code>http://localhost:${PORT}/token</code></li>
                        <li><strong>Direct Token URL:</strong> <code>http://localhost:${PORT}/token-direct</code> (testing only)</li>
                        <li><strong>JWKS URL:</strong> <code>http://localhost:${PORT}/.well-known/jwks.json</code></li>
                        <li><strong>Client ID:</strong> <code>clientid</code></li>
                        <li><strong>Client Secret:</strong> <code>1234567890</code></li>
                        <li><strong>Authentication:</strong> HTTP Basic Auth (Authorization: Basic base64(clientid:1234567890))</li>
                        <li><strong>JS Method:</strong> <code>lpgetToken</code> (auto-detects current flow type)</li>
                        <li><strong>OAuth Callback:</strong> <code>http://localhost:${PORT}/oauth-callback.html</code></li>
                        <li><strong>Current Flow:</strong> <span style="color: #007bff; font-weight: bold;">${flowType.toUpperCase()}</span></li>
                        <li><strong>Current Issuer:</strong> <code style="font-size: 11px;">https://mature-mackerel-golden.ngrok-free.app/${flowType}</code></li>
                        <li><strong>Encryption Mode:</strong> ${encryptionEnabled ? 'JWE Encryption Enabled' : 'JWT Signing Only'}</li>
                    </ul>
                    <p style="margin-top: 10px; font-size: 12px; color: #666;">
                        <strong>💡 LivePerson Integration:</strong> 
                        <br>• <strong>Code Flow:</strong> Uses popup with <code>ssoKey</code> callback parameter (LivePerson standard)
                        <br>• <strong>Code + PKCE Flow:</strong> LivePerson handles PKCE challenge/verifier automatically
                        <br>• <strong>Implicit Flow:</strong> Direct AJAX call for testing
                        <br>• <strong>Client Auth:</strong> LivePerson IdP will use clientid/1234567890 credentials
                        <br>• <strong>Multiple IdPs:</strong> Different issuers allow testing multiple configurations
                    </p>
                </div>
            </div>
            
            <div class="info-box">
                <h4>💡 Pro Tip</h4>
                <p>This page doesn't auto-refresh, so the LivePerson chat widget will maintain its state. 
                Use this page for testing chat functionality while monitoring requests on the main dashboard.</p>
            </div>
        </div>
    </body>
    </html>
    `;
    res.send(html);
});

// Toggle encryption endpoint
app.post('/toggle-encryption', (req, res) => {
    const { enabled } = req.body;
    encryptionEnabled = !!enabled;
    console.log(`Encryption ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    res.json({ 
        success: true, 
        encryptionEnabled: encryptionEnabled,
        lpCertificateAvailable: !!lpEncryptionPublicKey
    });
});

// Toggle flow type endpoint
app.post('/toggle-flow-type', (req, res) => {
    const { flowType: newFlowType } = req.body;
    if (['implicit', 'code', 'codepkce'].includes(newFlowType)) {
        flowType = newFlowType;
        console.log(`OAuth Flow Type changed to: ${flowType.toUpperCase()}`);
        res.json({ 
            success: true, 
            flowType: flowType,
            issuer: `https://mature-mackerel-golden.ngrok-free.app/${flowType}`
        });
    } else {
        res.status(400).json({ 
            error: 'invalid_flow_type', 
            error_description: 'Supported flow types: implicit, code, codepkce' 
        });
    }
});

// JWKS endpoint for public key distribution
app.get('/.well-known/jwks.json', async (req, res) => {
    try {
        // Import the public key using modern jose library
        const publicKey = await jose.importSPKI(signingPublicKey, 'RS256');
        
        // Export as JWK with proper formatting
        const jwk = await jose.exportJWK(publicKey);
        
        // Add the required fields for our key
        jwk.use = 'sig';
        jwk.alg = 'RS256';
        jwk.kid = 'signing-key-1';
        
        const jwks = {
            keys: [jwk]
        };
        
        console.log('JWKS generated successfully with modern jose library');
        res.json(jwks);
    } catch (error) {
        console.error('Error generating JWKS:', error);
        res.status(500).json({ error: 'Failed to generate JWKS' });
    }
});

// Get encryption public key (for LivePerson configuration)
app.get('/encryption-public-key', (req, res) => {
    try {
        // Return LivePerson certificate if available
        const keyToReturn = lpEncryptionPublicKey;
        
        if (!keyToReturn) {
            return res.status(404).json({ 
                error: 'No encryption key available',
                message: 'LivePerson certificate (lpsso2026.pem) not found in ./certs/ directory'
            });
        }
        
        res.type('text/plain').send(keyToReturn);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load encryption public key' });
    }
});

// Create JWT token (with optional JWE encryption)
async function createToken(payload, issuer) {
    try {
        console.log(`\n🔐 TOKEN CREATION MODE: ${encryptionEnabled ? 'SIGNING + ENCRYPTION (JWE)' : 'SIGNING ONLY (JWT)'}`);
        console.log(`📜 LivePerson cert available: ${!!lpEncryptionPublicKey}`);
        console.log(`🏷️  Issuer: ${issuer}`);
        
        // Add issuer to payload
        const tokenPayload = {
            ...payload,
            iss: issuer
        };
        
        // Convert PKCS#1 to PKCS#8 format using Node.js crypto
        const keyObject = crypto.createPrivateKey(signingPrivateKey);
        const pkcs8Key = keyObject.export({ type: 'pkcs8', format: 'pem' });
        
        // Import the private key for signing
        const privateKey = await jose.importPKCS8(pkcs8Key, 'RS256');
        
        // Create the signed JWT using modern jose library
        const signedToken = await new jose.SignJWT(tokenPayload)
            .setProtectedHeader({ alg: 'RS256', kid: 'signing-key-1' })
            .setIssuedAt()
            .setExpirationTime('1h')
            .sign(privateKey);
        
        console.log(`✓ JWT signed successfully (${signedToken.length} chars)`);
        console.log(`📝 JWT preview: ${signedToken.substring(0, 50)}...`);
        
        // If encryption is disabled, return the signed JWT
        if (!encryptionEnabled || !lpEncryptionPublicKey) {
            console.log(`📤 Returning signed JWT (encryption disabled or no LP cert)`);
            return signedToken;
        }
        
        try {
            console.log(`🔒 Starting JWE encryption with LivePerson certificate...`);
            
            // Import the LivePerson certificate (X.509 format) for encryption
            const publicKey = await jose.importX509(lpEncryptionPublicKey, 'RSA-OAEP-256');
            console.log(`✓ LivePerson certificate imported for encryption`);
            
            // Create JWE by encrypting the signed JWT string
            const encoder = new TextEncoder();
            const jwe = await new jose.FlattenedEncrypt(encoder.encode(signedToken))
                .setProtectedHeader({ 
                    alg: 'RSA-OAEP-256',  // Algorithm for key encryption
                    enc: 'A256GCM',       // Algorithm for content encryption
                    kid: 'lpsso2026',     // Key ID for LivePerson certificate
                    cty: 'JWT'            // Content type is JWT
                })
                .encrypt(publicKey);
            
            // Convert to compact serialization
            const compactJWE = `${jwe.protected}.${jwe.encrypted_key}.${jwe.iv}.${jwe.ciphertext}.${jwe.tag}`;
            
            console.log(`✅ JWE encryption successful!`);
            console.log(`📏 JWE length: ${compactJWE.length} chars (vs JWT: ${signedToken.length} chars)`);
            console.log(`🔐 JWE preview: ${compactJWE.substring(0, 50)}...`);
            console.log(`📤 Returning encrypted JWE token`);
            
            return compactJWE;
            
        } catch (error) {
            console.error(`❌ JWE encryption failed: ${error.message}`);
            console.log(`📤 Falling back to signed JWT`);
            return signedToken;
        }
        
    } catch (error) {
        console.error('❌ Error creating token:', error.message);
        throw error;
    }
}

// OAuth Authorization endpoint (both implicit and authorization code flow)
app.get('/authorize', async (req, res) => {
    const { 
        client_id, 
        redirect_uri, 
        response_type, 
        scope, 
        state, 
        nonce,
        code_challenge,
        code_challenge_method
    } = req.query;
    
    console.log('Authorization request received:', req.query);
    console.log(`Encryption mode: ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    
    // Check if this is an AJAX request (from lpgetToken)
    const isAjaxRequest = req.headers['x-requested-with'] === 'XMLHttpRequest' || 
                         req.headers['accept']?.includes('application/json') ||
                         req.query.format === 'json';
    
    // PKCE validation for codepkce flow
    const isPKCEFlow = flowType === 'codepkce' || (code_challenge && code_challenge_method);
    if (isPKCEFlow) {
        if (!code_challenge || !code_challenge_method) {
            const error = {
                error: 'invalid_request',
                error_description: 'PKCE flow requires code_challenge and code_challenge_method parameters'
            };
            console.log('❌ PKCE parameters missing:', error);
            return res.status(400).json(error);
        }
        
        if (code_challenge_method !== 'S256' && code_challenge_method !== 'plain') {
            const error = {
                error: 'invalid_request',
                error_description: 'Unsupported code_challenge_method. Supported: S256, plain'
            };
            console.log('❌ Invalid PKCE method:', error);
            return res.status(400).json(error);
        }
        
        console.log('✅ PKCE parameters validated:');
        console.log('   code_challenge:', code_challenge);
        console.log('   code_challenge_method:', code_challenge_method);
    }
    
    if (!response_type || !['code', 'id_token', 'token'].includes(response_type)) {
        const error = { 
            error: 'unsupported_response_type',
            error_description: 'Supported response types: code (authorization code flow), id_token (implicit flow)'
        };
        
        if (isAjaxRequest) {
            return res.status(400).json(error);
        } else {
            return res.status(400).json(error);
        }
    }
    
    try {
        // Create user payload
        const now = Math.floor(Date.now() / 1000);
        const issuer = `https://mature-mackerel-golden.ngrok-free.app/${flowType}`;
        
        const payload = {
            // iss will be added by createToken function
            sub: 'test-user-123',
            aud: client_id || 'liveperson-client',
            exp: now + 3600,
            iat: now,
            nonce: nonce,
            
            // Custom claims for LivePerson
            email: 'test.user@example.com',
            name: 'Test User',
            given_name: 'Test',
            family_name: 'User',
            phone_number: '+1234567890',
            
            // LivePerson specific claims
            lp_sdes: {
                customerInfo: {
                    customerId: 'test-customer-123',
                    customerType: 'premium',
                    balance: 1500.00,
                    accountNumber: 'ACC-789456123'
                },
                personalInfo: {
                    name: 'Test User',
                    email: 'test.user@example.com',
                    phone: '+1234567890'
                }
            }
        };
        
        console.log(`🔄 Using ${flowType.toUpperCase()} flow with issuer: ${issuer}`);
        console.log(`📤 Expected LivePerson behavior:`);
        console.log(`   - Implicit Flow: LP treats response as id_token directly`);
        console.log(`   - Code Flow: LP should call /token endpoint with ssoKey`);
        
        if (response_type === 'code') {
            // Authorization Code Flow
            const code = uuidv4();
            
            // Store the payload with the code (expires in 10 minutes)
            const codeData = {
                payload: { ...payload, iss: issuer },
                expiresAt: Date.now() + (10 * 60 * 1000), // 10 minutes
                clientId: client_id || 'liveperson-client'
            };
            
            // Add PKCE parameters if present
            if (isPKCEFlow) {
                codeData.codeChallenge = code_challenge;
                codeData.codeChallengeMethod = code_challenge_method;
                console.log('🔐 PKCE parameters stored with authorization code');
            }
            
            authorizationCodes.set(code, codeData);
            
            console.log(`📝 === AUTHORIZATION CODE CREATED ===`);
            console.log(`🔑 Code: ${code}`);
            console.log(`⏰ Expires at: ${new Date(Date.now() + (10 * 60 * 1000)).toISOString()}`);
            console.log(`👤 User: ${payload.sub}`);
            console.log(`🏷️  Issuer: ${issuer}`);
            console.log(`🔐 PKCE: ${isPKCEFlow ? 'YES' : 'NO'}`);
            if (isPKCEFlow) {
                console.log(`   Challenge: ${code_challenge}`);
                console.log(`   Method: ${code_challenge_method}`);
            }
            console.log(`📊 Total stored codes: ${authorizationCodes.size}`);
            console.log(`🎯 LivePerson should call /token with this code`);
            console.log(`=======================================`);
            
            if (isAjaxRequest) {
                // Return code directly for AJAX requests
                console.log('Authorization Code Flow - Returning code directly (AJAX)');
                res.json({
                    ssoKey: code
                });
            } else {
                // LivePerson expects callback with ssoKey parameter
                const redirectUrl = new URL(redirect_uri);
                redirectUrl.searchParams.set('ssoKey', code); // LivePerson uses ssoKey instead of code
                if (state) redirectUrl.searchParams.set('state', state);
                
                console.log(`Authorization Code Flow - Redirecting to: ${redirectUrl.toString()}`);
                res.redirect(redirectUrl.toString());
            }
            
        } else if (response_type === 'id_token') {
            // Implicit Flow
            const idToken = await createToken(payload, issuer);
            
            if (isAjaxRequest) {
                // Return token directly for AJAX requests (perfect for lpgetToken!)
                console.log('Implicit Flow - Returning token directly (AJAX)');
                res.json({
                    id_token: idToken,
                    token_type: 'Bearer',
                    state: state,
                    expires_in: 3600
                });
            } else {
                // Traditional redirect for browser requests
                const redirectUrl = new URL(redirect_uri);
                redirectUrl.hash = `id_token=${idToken}&token_type=Bearer&state=${state || ''}`;
                
                console.log('Implicit Flow - Redirecting with tokens');
                res.redirect(redirectUrl.toString());
            }
        }
        
    } catch (error) {
        console.error('Error in authorization endpoint:', error);
        const errorResponse = { 
            error: 'server_error',
            error_description: 'Failed to process authorization request'
        };
        
        if (isAjaxRequest) {
            res.status(500).json(errorResponse);
        } else {
            res.status(500).json(errorResponse);
        }
    }
});

// OAuth Token endpoint (for authorization code flow)
app.post('/token', async (req, res) => {
    const { grant_type, code, client_id, client_secret, redirect_uri, code_verifier } = req.body;
    
    console.log('\n🔥 === TOKEN ENDPOINT CALLED ===');
    console.log('📅 Timestamp:', new Date().toISOString());
    console.log('🌐 Request Headers:', JSON.stringify(req.headers, null, 2));
    console.log('📝 Request Body:', JSON.stringify(req.body, null, 2));
    console.log('🔐 Encryption mode:', encryptionEnabled ? 'ENABLED' : 'DISABLED');
    console.log('🔄 Current flow type:', flowType);
    console.log('🏷️  Current issuer:', `https://mature-mackerel-golden.ngrok-free.app/${flowType}`);
    console.log('🔐 PKCE code_verifier:', code_verifier ? 'PRESENT' : 'NOT PRESENT');
    
    if (grant_type !== 'authorization_code') {
        console.log('❌ Invalid grant type:', grant_type);
        return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: 'Only authorization_code grant type is supported'
        });
    }
    
    if (!code) {
        console.log('❌ Missing authorization code');
        return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing required parameter: code'
        });
    }
    
    // Validate client credentials (LivePerson IdP will use these)
    console.log('🔑 Validating client credentials...');
    
    let receivedClientId, receivedClientSecret;
    
    // Check for Basic Authentication header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [headerClientId, headerClientSecret] = credentials.split(':');
        
        console.log('📋 Using Basic Authentication from header');
        console.log('   Authorization header:', authHeader);
        console.log('   Decoded credentials:', `${headerClientId}:${headerClientSecret ? '[PRESENT]' : '[MISSING]'}`);
        
        receivedClientId = headerClientId;
        receivedClientSecret = headerClientSecret;
    } else {
        // Fallback to body parameters (for testing)
        console.log('📋 Using credentials from request body (fallback)');
        receivedClientId = client_id;
        receivedClientSecret = client_secret;
    }
    
    console.log('   Expected client_id: clientid');
    console.log('   Received client_id:', receivedClientId);
    console.log('   Expected client_secret: 1234567890');
    console.log('   Received client_secret:', receivedClientSecret ? '[PRESENT]' : '[MISSING]');
    
    if (receivedClientId !== 'clientid' || receivedClientSecret !== '1234567890') {
        console.log(`❌ Invalid client credentials: ${receivedClientId}/${receivedClientSecret}`);
        return res.status(401).json({
            error: 'invalid_client',
            error_description: 'Invalid client credentials'
        });
    }
    
    console.log('✅ Client credentials validated');
    
    try {
        // Retrieve and validate authorization code
        console.log('🔍 Looking up authorization code:', code);
        console.log('📊 Current stored codes:', authorizationCodes.size);
        
        const codeData = authorizationCodes.get(code);
        
        if (!codeData) {
            console.log(`❌ Authorization code not found: ${code}`);
            console.log('📋 Available codes:', Array.from(authorizationCodes.keys()));
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Invalid or expired authorization code'
            });
        }
        
        // Check if code has expired
        if (Date.now() > codeData.expiresAt) {
            console.log(`❌ Authorization code expired: ${code}`);
            console.log(`   Expired at: ${new Date(codeData.expiresAt).toISOString()}`);
            console.log(`   Current time: ${new Date().toISOString()}`);
            authorizationCodes.delete(code); // Clean up expired code
            return res.status(400).json({
                error: 'invalid_grant',
                error_description: 'Authorization code has expired'
            });
        }
        
        // Clean up the code (one-time use)
        authorizationCodes.delete(code);
        console.log(`✅ Authorization code validated and consumed: ${code}`);
        
        // PKCE verification if required
        if (codeData.codeChallenge && codeData.codeChallengeMethod) {
            console.log('🔐 === PKCE VERIFICATION ===');
            console.log('   Stored challenge:', codeData.codeChallenge);
            console.log('   Stored method:', codeData.codeChallengeMethod);
            console.log('   Received verifier:', code_verifier ? 'PRESENT' : 'MISSING');
            
            if (!code_verifier) {
                console.log('❌ PKCE verification failed: code_verifier missing');
                return res.status(400).json({
                    error: 'invalid_grant',
                    error_description: 'PKCE verification failed: code_verifier required'
                });
            }
            
            const isValidPKCE = verifyCodeChallenge(code_verifier, codeData.codeChallenge, codeData.codeChallengeMethod);
            
            if (!isValidPKCE) {
                console.log('❌ PKCE verification failed: code_verifier does not match code_challenge');
                console.log('   Expected challenge (from verifier):', base64URLEncode(sha256(code_verifier)));
                console.log('   Stored challenge:', codeData.codeChallenge);
                return res.status(400).json({
                    error: 'invalid_grant',
                    error_description: 'PKCE verification failed: invalid code_verifier'
                });
            }
            
            console.log('✅ PKCE verification successful');
        } else if (code_verifier) {
            console.log('⚠️  code_verifier provided but no PKCE challenge stored (non-PKCE flow)');
        }
        
        const payload = codeData.payload;
        console.log(`👤 Creating tokens for user: ${payload.sub}`);
        console.log(`🏷️  Using issuer from code: ${payload.iss}`);
        
        // Create tokens
        const idToken = await createToken(payload, payload.iss);
        
        // Create access token
        const keyObject = crypto.createPrivateKey(signingPrivateKey);
        const pkcs8Key = keyObject.export({ type: 'pkcs8', format: 'pem' });
        const privateKey = await jose.importPKCS8(pkcs8Key, 'RS256');
        const accessToken = await new jose.SignJWT({
            iss: payload.iss,
            sub: payload.sub,
            aud: payload.aud,
            scope: 'openid profile email'
        })
            .setProtectedHeader({ alg: 'RS256', kid: 'signing-key-1' })
            .setIssuedAt()
            .setExpirationTime('1h')
            .sign(privateKey);
        
        const response = {
            access_token: accessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'openid profile email'
        };
        
        console.log(`\n🎉 === TOKEN RESPONSE SUCCESS ===`);
        console.log(`👤 User: ${payload.sub}`);
        console.log(`🔑 Access Token: ${accessToken.length} chars`);
        console.log(`🆔 ID Token: ${idToken.length} chars`);
        console.log(`📊 Token Type: ${response.token_type}, Expires: ${response.expires_in}s`);
        console.log(`🎯 ID Token Format: ${idToken.split('.').length === 3 ? 'JWT (3 parts)' : idToken.split('.').length === 5 ? 'JWE (5 parts)' : 'Unknown format'}`);
        console.log(`📤 Sending response to LivePerson IdP`);
        
        res.json(response);
        
    } catch (error) {
        console.error('💥 Error exchanging code for tokens:', error);
        console.error('Stack trace:', error.stack);
        res.status(500).json({
            error: 'server_error',
            error_description: 'Failed to exchange code for tokens'
        });
    }
});

// Direct token endpoint (for testing/simplified flow)
app.post('/token-direct', async (req, res) => {
    const { user_id, client_id } = req.body;
    
    console.log('Direct token request received:', req.body);
    console.log(`Encryption mode: ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    console.log('⚠️  Using direct token endpoint - not standard OAuth flow');
    
    // Determine user identifier - either from user_id or default test user
    const userId = user_id || 'test-user-123';
    const clientId = client_id || 'liveperson-client';
    
    console.log(`Creating token for user: ${userId}, client: ${clientId}`);
    
    try {
        const now = Math.floor(Date.now() / 1000);
        const issuer = `https://mature-mackerel-golden.ngrok-free.app/${flowType}`;
        
        const payload = {
            // iss will be added by createToken function
            sub: userId,
            aud: clientId,
            exp: now + 3600,
            iat: now,
            
            // Test user data (can be customized based on user_id)
            email: `${userId}@example.com`,
            name: userId === 'test-user-123' ? 'Test User' : `User ${userId}`,
            given_name: userId === 'test-user-123' ? 'Test' : 'User',
            family_name: userId === 'test-user-123' ? 'User' : userId,
            phone_number: '+1234567890',
            
            // LivePerson specific claims
            lp_sdes: {
                customerInfo: {
                    customerId: userId,
                    customerType: 'premium',
                    balance: 1500.00,
                    accountNumber: `ACC-${userId.replace(/[^0-9]/g, '')}123`
                },
                personalInfo: {
                    name: userId === 'test-user-123' ? 'Test User' : `User ${userId}`,
                    email: `${userId}@example.com`,
                    phone: '+1234567890'
                }
            }
        };
        
        console.log(`🔄 Using ${flowType.toUpperCase()} flow with issuer: ${issuer}`);
        
        // Create signed JWT or JWE based on encryption setting
        const idToken = await createToken(payload, issuer);
        
        // Create access token (simple JWT for testing)
        const keyObject = crypto.createPrivateKey(signingPrivateKey);
        const pkcs8Key = keyObject.export({ type: 'pkcs8', format: 'pem' });
        const privateKey = await jose.importPKCS8(pkcs8Key, 'RS256');
        const accessToken = await new jose.SignJWT({
            iss: issuer,
            sub: userId,
            aud: clientId,
            scope: 'openid profile email'
        })
            .setProtectedHeader({ alg: 'RS256', kid: 'signing-key-1' })
            .setIssuedAt()
            .setExpirationTime('1h')
            .sign(privateKey);
        
        const response = {
            access_token: accessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'openid profile email'
        };
        
        console.log(`\n📤 TOKEN RESPONSE for user: ${userId}`);
        console.log(`🔑 Access Token (${accessToken.length} chars): ${accessToken.substring(0, 50)}...`);
        console.log(`🆔 ID Token (${idToken.length} chars): ${idToken.substring(0, 50)}...`);
        console.log(`📊 Token Type: ${response.token_type}, Expires: ${response.expires_in}s`);
        console.log(`🎯 ID Token Format: ${idToken.split('.').length === 3 ? 'JWT (3 parts)' : idToken.split('.').length === 5 ? 'JWE (5 parts)' : 'Unknown format'}`);
        
        res.json(response);
        
    } catch (error) {
        console.error('Error creating tokens:', error);
        res.status(500).json({
            error: 'server_error',
            error_description: 'Failed to create tokens'
        });
    }
});

// Test PKCE endpoint (for debugging)
app.post('/test-pkce', (req, res) => {
    const { code_verifier, code_challenge, code_challenge_method } = req.body;
    
    console.log('\n🧪 === PKCE TEST ===');
    console.log('Body:', JSON.stringify(req.body, null, 2));
    
    if (!code_verifier) {
        return res.status(400).json({
            error: 'Missing code_verifier'
        });
    }
    
    // Generate challenge from verifier
    const hash = sha256(code_verifier);
    const computedChallenge = base64URLEncode(hash);
    
    console.log('PKCE Test Results:');
    console.log('   code_verifier:', code_verifier);
    console.log('   computed_challenge:', computedChallenge);
    console.log('   provided_challenge:', code_challenge);
    console.log('   method:', code_challenge_method);
    
    const isValid = code_challenge ? verifyCodeChallenge(code_verifier, code_challenge, code_challenge_method || 'S256') : true;
    
    res.json({
        success: true,
        code_verifier: code_verifier,
        computed_challenge: computedChallenge,
        provided_challenge: code_challenge,
        method: code_challenge_method || 'S256',
        verification_result: isValid,
        message: isValid ? 'PKCE verification successful' : 'PKCE verification failed'
    });
});

// Test Basic Auth endpoint (for debugging)
app.post('/test-basic-auth', (req, res) => {
    console.log('\n🧪 === BASIC AUTH TEST ===');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Body:', JSON.stringify(req.body, null, 2));
    
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [clientId, clientSecret] = credentials.split(':');
        
        console.log('✅ Basic Auth decoded successfully:');
        console.log('   Base64:', base64Credentials);
        console.log('   Decoded:', credentials);
        console.log('   Client ID:', clientId);
        console.log('   Client Secret:', clientSecret);
        
        res.json({
            success: true,
            authHeader: authHeader,
            base64: base64Credentials,
            decoded: credentials,
            clientId: clientId,
            clientSecret: clientSecret,
            valid: clientId === 'clientid' && clientSecret === '1234567890'
        });
    } else {
        console.log('❌ No Basic Auth header found');
        res.status(400).json({
            error: 'No Basic Auth header',
            headers: req.headers
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        saml: {
            initialized: !!(identityProvider && serviceProvider),
            encryption: !!loadLivePersonCertificate()
        }
    });
});

// Initialize SAML on server startup
function startServer() {
    // Initialize SAML
    const samlInitialized = initializeSAML();
    if (!samlInitialized) {
        console.error('❌ Failed to initialize SAML - server may not function properly');
    }
    
    // Load keys for JWT functionality
    loadKeys();
    
    app.listen(PORT, () => {
        console.log(`🚀 IDP Server running on port ${PORT}`);
        console.log(`📋 Available endpoints:`);
        console.log(`   • GET  /health - Health check`);
        console.log(`   • GET  / - Main page with endpoint list`);
        console.log(`   • GET  /agentsso-denver - Denver SAML SSO Testing Page`);
        console.log(`   • POST /generate-saml-assertion - Generate SAML assertion`);
        console.log(`   • POST /discover-denver-domain - Discover Denver domain`);
        console.log(`🔐 SAML Status: ${samlInitialized ? 'Initialized' : 'Failed'}`);
        console.log(`🔒 Encryption: ${!!loadLivePersonCertificate() ? 'Available' : 'Not Available'}`);
    });
}

// Start the server
startServer();

// Denver SAML SSO page
app.get('/agentsso-denver', (req, res) => {
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson Denver SAML SSO - IDP Server</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
            input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
            textarea { height: 100px; font-family: monospace; }
            .switch { position: relative; display: inline-block; width: 60px; height: 34px; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
            input:checked + .slider { background-color: #007bff; }
            input:checked + .slider:before { transform: translateX(26px); }
            .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin: 10px 5px; }
            .btn:hover { background: #0056b3; }
            .btn-secondary { background: #6c757d; }
            .btn-secondary:hover { background: #545b62; }
            .info-box { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 15px 0; border-radius: 4px; }
            .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 15px 0; border-radius: 4px; }
            .status { margin: 20px 0; padding: 15px; border-radius: 4px; }
            .status.success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
            .status.error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
            .status.warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
            .status.info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
            #baseUriResult { margin-top: 10px; font-family: monospace; background: #f8f9fa; padding: 10px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 LivePerson Denver SAML SSO</h1>
            
            <div class="info-box">
                <h3>📋 Denver SAML Authentication</h3>
                <p>This page allows you to test LivePerson's legacy Denver SAML SSO authentication.</p>
                <ul>
                    <li><strong>Required Attributes:</strong> siteId, loginName</li>
                    <li><strong>Signing:</strong> Uses RSA private key for assertion signing</li>
                    <li><strong>Encryption:</strong> Optional assertion encryption with LP certificate</li>
                    <li><strong>Auto-Discovery:</strong> Automatically finds Denver domain for site ID</li>
                </ul>
            </div>
            
            <form id="samlForm">
                <div class="form-group">
                    <label for="siteId">LivePerson Site ID:</label>
                    <input type="text" id="siteId" name="siteId" value="a41244303" required>
                    <button type="button" class="btn btn-secondary" onclick="discoverBaseUri()">Discover Denver Domain</button>
                    <div id="baseUriResult"></div>
                </div>
                
                <div class="form-group">
                    <label for="loginName">Login Name (Agent Username):</label>
                    <input type="text" id="loginName" name="loginName" value="test.agent@example.com" required>
                </div>
                
                <div class="form-group">
                    <label>Signing Configuration:</label>
                    <div class="warning-box">
                        <strong>⚠️ Note:</strong> Using existing RSA private key for signing. 
                        You'll need to provide the corresponding public certificate to LivePerson for signature verification.
                    </div>
                </div>
                
                <div class="form-group">
                    <label>
                        <span style="margin-right: 15px;">SAML Encryption Status:</span>
                        <span id="samlEncryptionStatus" style="font-weight: bold; color: ` + (encryptionEnabled ? '#28a745' : '#dc3545') + `;">
                            ` + (encryptionEnabled ? '🔒 ENABLED (controlled by main toggle)' : '🔓 DISABLED (controlled by main toggle)') + `
                        </span>
                    </label>
                    <p style="font-size: 12px; color: #666; margin-top: 5px;">
                        Use the main encryption toggle at the top of the page to control both JWT and SAML encryption.
                    </p>
                </div>
                
                <div class="form-group" id="encryptionCertGroup" style="display: none;">
                    <label for="encryptionCert">LivePerson Encryption Certificate (PEM format):</label>
                    <textarea id="encryptionCert" name="encryptionCert" placeholder="-----BEGIN CERTIFICATE-----
...certificate content...
-----END CERTIFICATE-----"></textarea>
                </div>
                
                <div class="form-group">
                    <button type="button" class="btn" onclick="generateSAMLAssertion()">Generate SAML Assertion</button>
                    <button type="button" class="btn" onclick="loginWithDenver()">Login with Denver SSO</button>
                </div>
            </form>
            
            <div id="assertionResult" style="display: none;">
                <h3>📄 Generated SAML Assertion:</h3>
                
                <div style="margin: 15px 0;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #555;">
                        🔍 Decoded XML (Human Readable):
                    </label>
                    <textarea id="assertionXML" readonly style="height: 200px; font-family: monospace; width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px; background: #f8f9fa;"></textarea>
                </div>
                
                <div style="margin: 15px 0;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #555;">
                        📦 Base64 Encoded (For POST to LivePerson):
                    </label>
                    <textarea id="assertionBase64" readonly style="height: 100px; font-family: monospace; width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px; background: #fff3cd;"></textarea>
                </div>
                
                <!-- Keep the old field for backward compatibility but hide it -->
                <textarea id="assertionContent" readonly style="display: none;"></textarea>
            </div>
            
            <div id="statusMessage"></div>
        </div>
        
        <script>
            let discoveredBaseUri = null;
            
            // Function to format XML for better readability
            function formatXML(xml) {
                try {
                    const parser = new DOMParser();
                    const xmlDoc = parser.parseFromString(xml, 'text/xml');
                    const serializer = new XMLSerializer();
                    
                    // Simple indentation - add line breaks and spaces
                    let formatted = serializer.serializeToString(xmlDoc);
                    const newline = String.fromCharCode(10);
                    formatted = formatted.replace(/></g, '>' + newline + '<');
                    
                    // Add basic indentation
                    const lines = formatted.split(newline);
                    let indentLevel = 0;
                    const indentedLines = lines.map(line => {
                        const trimmed = line.trim();
                        if (trimmed.startsWith('</')) {
                            indentLevel = Math.max(0, indentLevel - 1);
                        }
                        const indented = '  '.repeat(indentLevel) + trimmed;
                        if (trimmed.startsWith('<') && !trimmed.startsWith('</') && !trimmed.endsWith('/>')) {
                            indentLevel++;
                        }
                        return indented;
                    });
                    
                    return indentedLines.join(newline);
                } catch (e) {
                    // If formatting fails, return original
                    return xml;
                }
            }
            
            async function discoverBaseUri() {
                const siteId = document.getElementById('siteId').value;
                if (!siteId) {
                    showStatus('Please enter a Site ID first', 'error');
                    return;
                }
                
                try {
                    showStatus('Discovering Denver domain...', 'info');
                    const response = await fetch('/discover-denver-domain', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ siteId: siteId })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        discoveredBaseUri = result.baseURI;
                        document.getElementById('baseUriResult').innerHTML = 
                            '<strong>✅ Denver Domain:</strong> ' + result.baseURI;
                        showStatus('Denver domain discovered successfully: ' + result.baseURI, 'success');
                    } else {
                        showStatus('Failed to discover Denver domain: ' + result.error, 'error');
                    }
                } catch (error) {
                    showStatus('Error discovering Denver domain: ' + error.message, 'error');
                }
            }
            
            async function generateSAMLAssertion() {
                const siteId = document.getElementById('siteId').value;
                const loginName = document.getElementById('loginName').value;
                
                if (!siteId || !loginName) {
                    showStatus('Please fill in Site ID and Login Name', 'error');
                    return;
                }
                
                // Check if Denver domain has been discovered
                if (!discoveredBaseUri) {
                    showStatus('Warning: Denver domain not discovered. Please discover Denver domain first for proper destination URL.', 'warning');
                }
                
                try {
                    showStatus('Generating SAML assertion...', 'info');
                    
                    const requestBody = {
                        siteId: siteId,
                        loginName: loginName,
                        baseURI: discoveredBaseUri, // Pass the discovered Denver domain
                        shouldEncrypt: ` + encryptionEnabled + ` // Pass the current encryption setting
                    };
                    
                    const response = await fetch('/generate-saml-assertion', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestBody)
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        document.getElementById('assertionXML').value = formatXML(result.xml);
                        document.getElementById('assertionBase64').value = result.base64;
                        // Maintain backward compatibility
                        document.getElementById('assertionContent').value = result.xml;
                        document.getElementById('assertionResult').style.display = 'block';
                        
                        // Show destination URL and method used
                        let successMessage = 'SAML assertion generated successfully';
                        if (result.method) {
                            successMessage += ' using ' + result.method;
                        }
                        if (result.destination) {
                            successMessage += '. Destination: ' + result.destination;
                        }
                        if (result.encrypted) {
                            successMessage += ' (ENCRYPTED)';
                        }
                        showStatus(successMessage, 'success');
                    } else {
                        showStatus('Failed to generate SAML assertion: ' + result.error, 'error');
                    }
                } catch (error) {
                    showStatus('Error generating SAML assertion: ' + error.message, 'error');
                }
            }
            
            async function loginWithDenver() {
                if (!discoveredBaseUri) {
                    showStatus('Please discover Denver domain first', 'error');
                    return;
                }
                
                const siteId = document.getElementById('siteId').value;
                const assertionBase64 = document.getElementById('assertionBase64').value;
                
                if (!assertionBase64) {
                    showStatus('Please generate SAML assertion first', 'error');
                    return;
                }
                
                // Create form and submit to Denver
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = 'https://' + discoveredBaseUri + '/hc/s-' + siteId + '/web/m-LP/samlAssertionMembersArea/home.jsp?lpservice=liveEngage&servicepath=a%2F~~accountid~~%2F%23%2C~~ssokey~~';
                form.target = '_blank';
                
                const samlInput = document.createElement('input');
                samlInput.type = 'hidden';
                samlInput.name = 'SAMLResponse';
                samlInput.value = assertionBase64;
                
                form.appendChild(samlInput);
                document.body.appendChild(form);
                form.submit();
                document.body.removeChild(form);
                
                showStatus('Redirecting to Denver SSO...', 'success');
            }
            
            function showStatus(message, type) {
                const statusDiv = document.getElementById('statusMessage');
                statusDiv.innerHTML = '<div class="status ' + type + '">' + message + '</div>';
                setTimeout(() => {
                    statusDiv.innerHTML = '';
                }, 5000);
            }
        </script>
    </body>
    </html>
    `;
    res.send(html);
});

// Denver domain discovery endpoint
app.post('/discover-denver-domain', async (req, res) => {
    const { siteId } = req.body;
    
    console.log('🔍 Discovering Denver domain for site ID:', siteId);
    
    try {
        const apiUrl = `https://api.liveperson.net/api/account/${siteId}/service/adminArea/baseURI.json?version=1.0`;
        console.log('📡 Calling LivePerson API:', apiUrl);
        
        const response = await axios.get(apiUrl);
        const data = response.data;
        
        console.log('✅ LivePerson API response:', data);
        
        if (data.baseURI) {
            res.json({
                success: true,
                baseURI: data.baseURI,
                service: data.service,
                account: data.account
            });
        } else {
            res.json({
                success: false,
                error: 'No baseURI found in response'
            });
        }
    } catch (error) {
        console.error('❌ Error discovering Denver domain:', error.message);
        res.json({
            success: false,
            error: error.message
        });
    }
});

// SAML assertion generation endpoint
app.post('/generate-saml-assertion', async (req, res) => {
    const { siteId, loginName, encrypt, shouldEncrypt, encryptionCert, baseURI, destinationUrl } = req.body;
    
    // Use shouldEncrypt if provided, otherwise fall back to encrypt
    const requestEncryption = shouldEncrypt !== undefined ? shouldEncrypt : encrypt;
    
    console.log('🔐 Generating SAML assertion for:', { siteId, loginName, encrypt, shouldEncrypt, requestEncryption, baseURI, destinationUrl });
    console.log('🔍 Request body received:', JSON.stringify(req.body, null, 2));
    
    // Check if SAML is properly initialized
    if (!identityProvider || !serviceProvider) {
        console.error('❌ SAML not initialized - cannot generate assertion');
        return res.json({
            success: false,
            error: 'SAML not properly initialized. Standard library initialization failed.'
        });
    }
    
    try {
        // Use provided destinationUrl or construct the proper Denver destination URL
        let finalDestinationUrl = destinationUrl || 'https://mature-mackerel-golden.ngrok-free.app'; // fallback
        if (!destinationUrl && baseURI && siteId) {
            finalDestinationUrl = `https://${baseURI}/hc/s-${siteId}/web/m-LP/samlAssertionMembersArea/home.jsp?lpservice=liveEngage&servicepath=a%2F~~accountid~~%2F%23%2C~~ssokey~~`;
        }
        
        console.log('📍 SAML Response Destination:', finalDestinationUrl);
        console.log('🔐 Encryption requested:', requestEncryption);
        
        // Create assertion object for signSAMLAssertion
        const assertionData = {
            siteId: siteId,
            loginName: loginName
        };
        
        // Generate SAML response using the updated signSAMLAssertion function with encryption support
        const result = await signSAMLAssertion(assertionData, finalDestinationUrl, requestEncryption);
        
        let finalAssertion, assertionBase64, method;
        
        if (result && result.xml) {
            finalAssertion = result.xml;
            assertionBase64 = result.base64;
            method = result.method;
            
            console.log('✅ SAML assertion generated successfully');
            console.log('🔧 Method used:', method);
            console.log('📏 Response length:', finalAssertion.length, 'chars');
            console.log('📏 Base64 length:', assertionBase64.length, 'chars');
            console.log('🔐 Encryption status:', method.includes('ENCRYPTED') ? 'ENCRYPTED' : 'UNENCRYPTED');
        } else {
            throw new Error('Failed to generate SAML assertion - no result returned');
        }
        
        res.json({
            success: true,
            xml: finalAssertion,
            base64: assertionBase64,
            encrypted: method.includes('ENCRYPTED'),
            destination: finalDestinationUrl,
            method: method,
            encryptionUsed: requestEncryption && method.includes('ENCRYPTED')
        });
        
    } catch (error) {
        console.error('❌ Error generating SAML assertion:', error.message);
        console.error('Stack trace:', error.stack);
        res.json({
            success: false,
            error: error.message
        });
    }
});

// Health check endpoint

function loadLivePersonCertificate() {
    try {
        const certPath = path.join(__dirname, 'certs', 'lpsso2026.pem');
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

function encryptSAMLAssertion(xml, encryptionCert) {
    try {
        const { DOMParser, XMLSerializer } = require('xmldom');
        const xmlCrypto = require('xml-crypto');
        
        console.log('🔐 Starting SAML assertion encryption...');
        
        // Parse the XML
        const doc = new DOMParser().parseFromString(xml);
        
        // Find the assertion element to encrypt
        let assertions = doc.getElementsByTagName('saml2:Assertion');
        if (assertions.length === 0) {
            // Try with saml: namespace (samlify uses this)
            assertions = doc.getElementsByTagName('saml:Assertion');
        }
        if (assertions.length === 0) {
            throw new Error('No SAML assertion found to encrypt (tried both saml: and saml2: namespaces)');
        }
        
        const assertion = assertions[0];
        const assertionId = assertion.getAttribute('ID');
        
        console.log('🔒 Encrypting assertion with ID:', assertionId);
        
        // Create encrypted XML using xml-crypto
        const encryptedXml = new xmlCrypto.EncryptedXml();
        
        // Configure encryption algorithms
        encryptedXml.encryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
        encryptedXml.keyEncryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
        
        // Set the encryption certificate
        encryptedXml.publicCert = encryptionCert;
        
        // Encrypt the assertion element
        const encryptedAssertion = encryptedXml.encrypt(assertion);
        
        // Replace the original assertion with encrypted assertion
        const parent = assertion.parentNode;
        parent.removeChild(assertion);
        
        // Create EncryptedAssertion element
        const encryptedAssertionElement = doc.createElement('saml2:EncryptedAssertion');
        encryptedAssertionElement.setAttribute('xmlns:saml2', 'urn:oasis:names:tc:SAML:2.0:assertion');
        encryptedAssertionElement.appendChild(encryptedAssertion);
        
        parent.appendChild(encryptedAssertionElement);
        
        const serializer = new XMLSerializer();
        const encryptedXmlString = serializer.serializeToString(doc);
        
        console.log('✅ SAML assertion encrypted successfully');
        console.log('📏 Encrypted XML length:', encryptedXmlString.length, 'characters');
        
        return encryptedXmlString;
        
    } catch (error) {
        console.error('❌ SAML encryption failed:', error.message);
        console.error('Stack:', error.stack);
        throw error;
    }
}

// Alternative simpler encryption approach using Node.js crypto
function encryptSAMLAssertionSimple(xml, encryptionCert) {
    try {
        const crypto = require('crypto');
        const { DOMParser, XMLSerializer } = require('xmldom');
        
        console.log('🔐 Starting simple SAML assertion encryption...');
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
            throw new Error('No SAML assertion found to encrypt (tried both saml: and saml2: namespaces)');
        }
        
        const assertion = assertions[0];
        const assertionId = assertion.getAttribute('ID');
        
        console.log('🔒 Encrypting assertion with ID:', assertionId);
        
        // Extract assertion XML
        const serializer = new XMLSerializer();
        const assertionXml = serializer.serializeToString(assertion);
        
        // Generate symmetric key for AES encryption
        const symmetricKey = crypto.randomBytes(32); // 256-bit key for AES-256
        const iv = crypto.randomBytes(16); // 128-bit IV
        
        // Encrypt assertion with AES using modern API
        const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
        let encryptedData = cipher.update(assertionXml, 'utf8', 'base64');
        encryptedData += cipher.final('base64');
        
        // Encrypt symmetric key with RSA (LivePerson certificate)
        const publicKey = crypto.createPublicKey(encryptionCert);
        const encryptedKey = crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, symmetricKey);
        
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
        
        // Replace assertion with encrypted assertion
        const parent = assertion.parentNode;
        parent.removeChild(assertion);
        
        // Parse and insert encrypted assertion
        const encryptedDoc = new DOMParser().parseFromString(encryptedAssertionXml);
        const encryptedElement = encryptedDoc.documentElement;
        const importedElement = doc.importNode(encryptedElement, true);
        parent.appendChild(importedElement);
        
        const finalXml = serializer.serializeToString(doc);
        
        console.log('✅ SAML assertion encrypted successfully (simple method)');
        console.log('📏 Encrypted XML length:', finalXml.length, 'characters');
        
        return finalXml;
        
    } catch (error) {
        console.error('❌ Simple SAML encryption failed:', error.message);
        console.error('Stack:', error.stack);
        throw error;
    }
}

// Certificate loading helper functions
function loadSigningCertificate() {
    console.log('🔍 loadSigningCertificate() called');
    try {
        // Use the samlify signing certificate (no fallback - SAML needs consistent cert)
        const certPath = path.join(__dirname, 'certs', 'samlify-signing-cert.pem');
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
            
            console.log('✅ Signing certificate loaded (samlify-signing-cert.pem)');
            console.log('🔍 Certificate length:', cert.length);
            console.log('🔍 Certificate starts with:', cert.substring(0, 50));
            console.log('🔍 Certificate ends with:', cert.substring(cert.length - 50));
            return cert;
        }
        
        console.log('❌ SAML signing certificate (samlify-signing-cert.pem) not found');
        console.log('   Please ensure the certificate file exists in the certs directory');
        return null;
    } catch (error) {
        console.error('❌ Error loading signing certificate:', error.message);
        return null;
    }
}

function loadSigningPrivateKey() {
    console.log('🔍 loadSigningPrivateKey() called');
    try {
        // Use the samlify private key (no fallback - SAML needs consistent key pair)
        const keyPath = path.join(__dirname, 'certs', 'samlify-private.pem');
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
            
            console.log('✅ Signing private key loaded (samlify-private.pem)');
            console.log('🔍 Key length:', key.length);
            console.log('🔍 Key starts with:', key.substring(0, 50));
            return key;
        }
        
        console.log('❌ SAML signing private key (samlify-private.pem) not found');
        console.log('   Please ensure the private key file exists in the certs directory');
        return null;
    } catch (error) {
        console.error('❌ Error loading signing private key:', error.message);
        return null;
    }
}

function loadLivePersonCertificate() {
    try {
        const certPath = path.join(__dirname, 'certs', 'lpsso2026.pem');
        if (fs.existsSync(certPath)) {
            let cert = fs.readFileSync(certPath, 'utf8');
            
            // Clean the certificate - remove extra whitespace and ensure proper format
            cert = cert.trim();
            
            // Ensure it has proper BEGIN/END markers
            if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
                console.log('❌ LivePerson certificate missing BEGIN marker');
                return null;
            }
            if (!cert.includes('-----END CERTIFICATE-----')) {
                console.log('❌ LivePerson certificate missing END marker');
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
            
            console.log('✅ LivePerson encryption certificate loaded');
            console.log('🔍 Certificate length:', cert.length);
            console.log('🔍 Certificate starts with:', cert.substring(0, 50));
            console.log('🔍 Certificate ends with:', cert.substring(cert.length - 50));
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
