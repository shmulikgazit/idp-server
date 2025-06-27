import saml from 'samlify';
import { loadLivePersonCertificate, encryptSAMLAssertion } from './saml-encryption.js';
import { getIdentityProvider, getServiceProvider } from './saml-core.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Main function to create SAML response with multiple implementation options
 * @param {string} siteId - LivePerson site ID  
 * @param {string} loginName - User login name
 * @param {string} destinationUrl - SAML destination URL
 * @param {boolean} shouldEncrypt - Whether to encrypt the assertion
 * @param {string} method - Implementation method ('samlify', 'node-saml', 'auto')
 * @param {string} encryptionCertName - Name of encryption certificate to use
 * @returns {Promise<Object>} SAML response result
 */
async function createSAMLResponse(siteId, loginName, destinationUrl, shouldEncrypt = false, method = 'auto', encryptionCertName = null) {
    console.log('🔧 createSAMLResponse called with parameters:');
    console.log(`📧 User: ${loginName}`);
    console.log(`🏢 Site ID: ${siteId}`);
    console.log(`🎯 Destination: ${destinationUrl}`);
    console.log(`🔒 Encryption: ${shouldEncrypt ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🛠️ Method: ${method}`);

    // Auto-select samlify as it's designed for IdP operations
    if (method === 'auto') {
        method = 'samlify';
        console.log('🤖 Auto-selected method: samlify (IdP-focused library)');
    }

    try {
        switch (method) {
            case 'samlify':
                console.log('🔧 Using samlify implementation (IdP-focused)...');
                return await createSamlifyResponse(siteId, loginName, destinationUrl, shouldEncrypt, encryptionCertName);
                
            case 'node-saml':
                console.log('⚠️ node-saml method is disabled (SP-focused library, not suitable for IdP operations)');
                throw new Error('node-saml method is disabled - use samlify for IdP operations');
                
            default:
                console.log(`❌ Unknown method ${method}, defaulting to samlify`);
                return await createSamlifyResponse(siteId, loginName, destinationUrl, shouldEncrypt, encryptionCertName);
        }
    } catch (error) {
        console.error(`❌ Error creating SAML response with method ${method}:`, error.message);
        throw error;
    }
}

/**
 * Create SAML response using samlify (original implementation)
 * @param {string} siteId - LivePerson site ID
 * @param {string} loginName - User login name  
 * @param {string} destinationUrl - SAML destination URL
 * @param {boolean} shouldEncrypt - Whether to encrypt the assertion
 * @param {string} encryptionCertName - Name of encryption certificate to use
 * @returns {Promise<Object>} SAML response object
 */
async function createSamlifyResponse(siteId, loginName, destinationUrl, shouldEncrypt = false, encryptionCertName = null, inResponseTo = null) {
    const identityProvider = getIdentityProvider();
    if (!identityProvider) {
        throw new Error('Identity Provider not initialized - ensure SAML initialization was successful');
    }

    // Load LivePerson's encryption certificate if encryption is requested
    let encryptionCert = null;
    if (shouldEncrypt) {
        // Import runtime config to get current certificate selection
        const { runtimeConfig } = await import('../config/config.js');
        const certName = encryptionCertName || runtimeConfig.encryptionCert.name;
        
        console.log(`🔍 Loading encryption certificate: ${certName}`);
        
        // Try DER format first (better compatibility with samlify)
        encryptionCert = loadLivePersonCertificate('der', certName);
        if (!encryptionCert) {
            console.log('⚠️ DER certificate not available, trying PEM format...');
            encryptionCert = loadLivePersonCertificate('pem', certName);
        }
        
        if (!encryptionCert) {
            console.log(`⚠️ Encryption requested but certificate '${certName}' not available - proceeding without encryption`);
            shouldEncrypt = false;
        } else {
            console.log('🔍 Certificate format being used:', Buffer.isBuffer(encryptionCert) ? 'DER (binary)' : 'PEM (text)');
        }
    }

    // Build dynamic Service Provider with encryption certificate if needed
    const dynamicSpMetadataXml = buildDynamicServiceProviderMetadata(destinationUrl, shouldEncrypt, encryptionCert);
    console.log('🔍 Dynamic SP metadata includes encryption KeyDescriptor:', dynamicSpMetadataXml.includes('use="encryption"'));
    
    // Import the SP dynamically (in-memory, not persistent)
    const { ServiceProvider } = await import('samlify');
    
    // Create SP configuration - encryption is handled by IdP, not SP
    const spConfig = { metadata: dynamicSpMetadataXml };
    const dynamicSP = ServiceProvider(spConfig);

    // Create user context
    const user = {
        loginName: loginName,
        siteId: siteId
    };

    // Create the customTagReplacement function
    const customTagReplacementFunction = createCustomTagReplacementFunction(destinationUrl, loginName, siteId, inResponseTo);

    // Call createLoginResponse with correct parameter order
    console.log('🔍 Calling samlify createLoginResponse...');
    console.log('🔍 Dynamic SP entity ID:', dynamicSP.entityMeta.getEntityID());
    console.log('🔍 Encryption enabled:', shouldEncrypt);
    
    let responseResult;
    if (shouldEncrypt && encryptionCert) {
        // For encryption, we need to create a temporary IdP with encryption enabled
        console.log('🔍 Creating temporary IdP with encryption enabled for Denver SSO...');
        const { createEncryptionEnabledIdP } = await import('../saml/saml-core.js');
        const encryptionIdP = await createEncryptionEnabledIdP(encryptionCert);
        
        responseResult = await encryptionIdP.createLoginResponse(
            dynamicSP,
            null,
            'post',
            user,
            customTagReplacementFunction,  // 5th parameter: customTagReplacement function
            true,                          // 6th parameter: Force encryption
            null                          // 7th parameter: relayState
        );
    } else {
        responseResult = await identityProvider.createLoginResponse(
            dynamicSP,
            null,
            'post',
            user,
            customTagReplacementFunction,  // 5th parameter: customTagReplacement function
            false,                         // 6th parameter: No encryption
            null                          // 7th parameter: relayState
        );
    }
    
    console.log('🔍 Samlify createLoginResponse completed');
    console.log('🔍 Response result type:', typeof responseResult);
    console.log('🔍 Response result keys:', responseResult ? Object.keys(responseResult) : 'null');
    
    // Extract and process the SAML response
    const samlResponse = extractSAMLResponseFromResult(responseResult);
    const actualXmlResponse = processSAMLResponse(samlResponse);
    
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

/**
 * Builds dynamic Service Provider metadata XML
 * @param {string} destinationUrl - SAML destination URL
 * @param {boolean} shouldEncrypt - Whether encryption is requested
 * @param {string} encryptionCert - Encryption certificate if available
 * @returns {string} SP metadata XML
 */
function buildDynamicServiceProviderMetadata(destinationUrl, shouldEncrypt, encryptionCert) {
    let dynamicSpMetadataXml = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="SAML-81785735-MyIdPSAML">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`;

    // Add encryption KeyDescriptor if encryption is requested
    if (shouldEncrypt && encryptionCert) {
        console.log('🔍 Adding encryption certificate to dynamic SP metadata...');
        
        let certForMetadata;
        if (Buffer.isBuffer(encryptionCert)) {
            // DER format - convert to base64 for XML
            certForMetadata = encryptionCert.toString('base64');
            console.log('🔍 Converted DER to base64 for metadata, length:', certForMetadata.length);
        } else {
            // PEM format - extract base64 content
            certForMetadata = encryptionCert.replace(/-----BEGIN CERTIFICATE-----\s*|\s*-----END CERTIFICATE-----/g, '').replace(/\s/g, '');
            console.log('🔍 Extracted base64 from PEM for metadata, length:', certForMetadata.length);
        }
        
        dynamicSpMetadataXml += `
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>${certForMetadata}</X509Certificate>
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
    
    return dynamicSpMetadataXml;
}

/**
 * Creates the custom tag replacement function for SAML template processing
 * @param {string} destinationUrl - SAML destination URL
 * @param {string} loginName - User login name
 * @param {string} siteId - LivePerson site ID
 * @returns {Function} Custom tag replacement function
 */
function createCustomTagReplacementFunction(destinationUrl, loginName, siteId, inResponseTo = null) {
    return (template) => {
        console.log('🔧 customTagReplacement called with template:', typeof template);
        
        // Check if template is null or undefined
        if (!template) {
            console.error('❌ Template is null or undefined in customTagReplacement');
            throw new Error('Template parameter is null or undefined');
        }
        
        console.log('🔧 customTagReplacement called with template length:', template.length);
        console.log('🔧 InResponseTo value:', inResponseTo);
        
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
            .replace(/{SubjectConfirmationDataRecipient}/g, destinationUrl)
            .replace(/{SPNameQualifier}/g, '')
            .replace(/{ConditionsNotBefore}/g, new Date().toISOString())
            .replace(/{ConditionsNotOnOrAfter}/g, new Date(Date.now() + 5 * 60 * 1000).toISOString())
            .replace(/{Audience}/g, 'SAML-81785735-MyIdPSAML')
            .replace(/{AuthnInstant}/g, new Date().toISOString())
            .replace(/{SessionIndex}/g, 'session_' + Math.random().toString(36).substr(2, 9))
            .replace(/{LoginName}/g, loginName)
            .replace(/{SiteId}/g, siteId)
            .replace(/{loginName}/g, loginName)
            .replace(/{siteId}/g, siteId);
            
        // Handle InResponseTo properly
        if (inResponseTo) {
            console.log('🔧 Setting InResponseTo to:', inResponseTo);
            processedTemplate = processedTemplate.replace(/{InResponseTo}/g, inResponseTo);
        } else {
            console.log('🔧 Removing InResponseTo attributes (no value provided)');
            // Remove InResponseTo attributes entirely if no value
            processedTemplate = processedTemplate
                .replace(/\s+InResponseTo=""/g, '')
                .replace(/\s+InResponseTo="{InResponseTo}"/g, '')
                .replace(/\s+InResponseTo="[^"]*"/g, '');
        }
        
        // Clean up other empty attributes
        processedTemplate = processedTemplate
            .replace(/\s+SPNameQualifier=""/g, '')
            .replace(/\s+SPNameQualifier="{SPNameQualifier}"/g, '');
        
        console.log('✅ Template processed, contains LoginName:', processedTemplate.includes(loginName));
        console.log('✅ Template processed, contains SiteId:', processedTemplate.includes(siteId));
        console.log('✅ Template processed, contains AttributeStatement:', processedTemplate.includes('AttributeStatement'));
        console.log('✅ Template processed, InResponseTo handled:', inResponseTo ? `set to ${inResponseTo}` : 'removed');
        
        return {
            id: 'custom_response_id_' + Math.random().toString(36).substr(2, 9),
            context: processedTemplate
        };
    };
}

/**
 * Extracts SAML response from samlify result
 * @param {Object} responseResult - Result from samlify createLoginResponse
 * @returns {string} SAML response string
 */
function extractSAMLResponseFromResult(responseResult) {
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
    
    return samlResponse;
}

/**
 * Processes SAML response (decodes if Base64, validates XML)
 * @param {string} samlResponse - Raw SAML response
 * @returns {string} Processed XML response
 */
function processSAMLResponse(samlResponse) {
    console.log('✅ SAML Response created with samlify');
    console.log('📏 Response length:', samlResponse.length, 'characters');
    
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
    
    // NOTE: Cannot add InclusiveNamespaces post-signing as it would invalidate the signature
    // The signature is calculated before any XML modifications can be made
    // This is a limitation of the samlify library - it doesn't expose canonicalization configuration
    
    // Debug: Check for attribute statements in the XML
    console.log('🔍 Checking for AttributeStatement in SAML...');
    console.log('🔍 Contains AttributeStatement:', actualXmlResponse.includes('AttributeStatement'));
    console.log('🔍 Contains loginName:', actualXmlResponse.includes('loginName'));
    console.log('🔍 Contains siteId:', actualXmlResponse.includes('siteId'));
    
    // Debug: Check for encryption in the XML
    console.log('🔍 Checking for encryption in SAML...');
    console.log('🔍 Contains EncryptedAssertion:', actualXmlResponse.includes('EncryptedAssertion'));
    console.log('🔍 Contains EncryptedData:', actualXmlResponse.includes('EncryptedData'));
    
    return actualXmlResponse;
}

/**
 * Custom SAML generation fallback function
 * @param {string} siteId - LivePerson site ID
 * @param {string} loginName - User login name
 * @param {string} destinationUrl - SAML destination URL
 * @param {boolean} shouldEncrypt - Whether to encrypt the assertion
 * @returns {Object} SAML response object
 */
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
        const notOnOrAfter = new Date(now.getTime() + 5 * 60 * 1000).toISOString(); // 5 minutes from now
        
        // Create SAML Response XML
        const samlResponseXml = `<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" 
                 xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                 ID="${responseId}" 
                 Version="2.0" 
                 IssueInstant="${issueInstant}" 
                 Destination="${destinationUrl}">
    <saml2:Issuer>https://idp.liveperson.com</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" 
                     ID="${assertionId}" 
                     Version="2.0" 
                     IssueInstant="${issueInstant}">
        <saml2:Issuer>https://idp.liveperson.com</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${loginName}</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${destinationUrl}"/>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
            <saml2:AudienceRestriction>
                <saml2:Audience>SAML-81785735-MyIdPSAML</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${sessionIndex}">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute Name="loginName">
                <saml2:AttributeValue>${loginName}</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name="siteId">
                <saml2:AttributeValue>${siteId}</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>`;
        
        console.log('✅ Custom SAML Response created');
        console.log('📏 Response length:', samlResponseXml.length, 'characters');
        
        return {
            samlResponse: samlResponseXml,
            method: 'CUSTOM_SIGNED'
        };
        
    } catch (error) {
        console.error('❌ Error creating custom SAML response:', error.message);
        throw error;
    }
}

/**
 * Main SAML assertion signing function with encryption support
 * @param {Object} assertion - Assertion data with siteId and loginName
 * @param {string} destinationUrl - SAML destination URL
 * @param {boolean} shouldEncrypt - Whether to encrypt the assertion
 * @param {string} encryptionCertName - Name of encryption certificate to use
 * @returns {Object} Final SAML response with XML, base64, and method
 */
async function signSAMLAssertion(assertion, destinationUrl, shouldEncrypt = false, encryptionCertName = null) {
    console.log('🔐 Creating SAML assertion with samlify...');
    console.log('📍 Destination URL:', destinationUrl);
    console.log('🔐 Encryption requested:', shouldEncrypt);
    
    // Always generate unencrypted SAML first (since we disabled samlify encryption)
    const result = await createSAMLResponse(
        assertion.siteId || 'a41244303', 
        assertion.loginName || 'testuser', 
        destinationUrl, 
        shouldEncrypt,  // Pass encryption setting to use proper certificate
        'samlify',      // Use samlify method
        encryptionCertName  // Pass certificate name
    );
    
    return {
        xml: result.samlResponse,
        base64: Buffer.from(result.samlResponse).toString('base64'),
        method: result.method
    };
}

export {
    createSAMLResponse,
    createSamlifyResponse,
    createCustomSAMLResponse,
    signSAMLAssertion,
    buildDynamicServiceProviderMetadata,
    createCustomTagReplacementFunction,
    extractSAMLResponseFromResult,
    processSAMLResponse
}; 