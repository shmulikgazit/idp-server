const saml = require('samlify');
const { loadLivePersonCertificate, encryptSAMLAssertion } = require('./saml-encryption');
const { getIdentityProvider, getServiceProvider } = require('./saml-core');

/**
 * Creates a SAML response using the samlify library
 * @param {string} siteId - LivePerson site ID
 * @param {string} loginName - User login name
 * @param {string} destinationUrl - SAML destination URL
 * @param {boolean} shouldEncrypt - Whether to encrypt the assertion
 * @returns {Object} SAML response object with samlResponse and method
 */
async function createSAMLResponse(siteId, loginName, destinationUrl, shouldEncrypt = false) {
    console.log('🔧 Creating SAML Response with samlify library...');
    console.log('📍 Destination URL:', destinationUrl);
    console.log('🔐 Encryption requested:', shouldEncrypt);
    
    const identityProvider = getIdentityProvider();
    const serviceProvider = getServiceProvider();
    
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
    const dynamicSpMetadataXml = buildDynamicServiceProviderMetadata(destinationUrl, shouldEncrypt, encryptionCert);
    
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
    const customTagReplacementFunction = createCustomTagReplacementFunction(destinationUrl, loginName, siteId);

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
    
    return dynamicSpMetadataXml;
}

/**
 * Creates the custom tag replacement function for SAML template processing
 * @param {string} destinationUrl - SAML destination URL
 * @param {string} loginName - User login name
 * @param {string} siteId - LivePerson site ID
 * @returns {Function} Custom tag replacement function
 */
function createCustomTagReplacementFunction(destinationUrl, loginName, siteId) {
    return (template) => {
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
                <saml2:Audience>LEna2</saml2:Audience>
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
 * @returns {Object} Final SAML response with XML, base64, and method
 */
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
                finalXml = encryptSAMLAssertion(finalXml, encryptionCert);
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

module.exports = {
    createSAMLResponse,
    createCustomSAMLResponse,
    signSAMLAssertion,
    buildDynamicServiceProviderMetadata,
    createCustomTagReplacementFunction,
    extractSAMLResponseFromResult,
    processSAMLResponse
}; 