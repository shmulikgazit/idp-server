const axios = require('axios');
const { encryptSAMLAssertion, loadLivePersonCertificate } = require('./saml-encryption');
const { signSAMLAssertion } = require('./saml-core');

/**
 * Setup Denver SSO related routes
 * @param {Express} app - Express application instance
 */
function setupDenverSSORoutes(app) {
    
    // Denver SAML SSO testing page
    app.get('/agentsso-denver', (req, res) => {
        // Get encryption status from global state (would need to be passed in)
        const encryptionEnabled = global.encryptionEnabled || false;
        
        const html = generateDenverSSOPage(encryptionEnabled);
        res.send(html);
    });
    
    // Denver domain discovery endpoint
    app.post('/discover-denver-domain', async (req, res) => {
        const { siteId } = req.body;
        
        console.log('🔍 Discovering Denver domain for site ID:', siteId);
        
        try {
            const result = await discoverDenverDomain(siteId);
            res.json(result);
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
        
        try {
            const result = await generateSAMLAssertion({
                siteId,
                loginName,
                shouldEncrypt: shouldEncrypt !== undefined ? shouldEncrypt : encrypt,
                baseURI,
                destinationUrl
            });
            
            res.json(result);
        } catch (error) {
            console.error('❌ Error generating SAML assertion:', error.message);
            res.json({
                success: false,
                error: error.message
            });
        }
    });
}

/**
 * Discover Denver domain for a given site ID
 * @param {string} siteId - LivePerson site ID
 * @returns {Object} Discovery result
 */
async function discoverDenverDomain(siteId) {
    const apiUrl = `https://api.liveperson.net/api/account/${siteId}/service/adminArea/baseURI.json?version=1.0`;
    console.log('📡 Calling LivePerson API:', apiUrl);
    
    const response = await axios.get(apiUrl);
    const data = response.data;
    
    console.log('✅ LivePerson API response:', data);
    
    if (data.baseURI) {
        return {
            success: true,
            baseURI: data.baseURI,
            service: data.service,
            account: data.account
        };
    } else {
        return {
            success: false,
            error: 'No baseURI found in response'
        };
    }
}

/**
 * Generate SAML assertion for Denver SSO
 * @param {Object} params - Generation parameters
 * @returns {Object} Generation result
 */
async function generateSAMLAssertion({ siteId, loginName, shouldEncrypt, baseURI, destinationUrl }) {
    // Use provided destinationUrl or construct the proper Denver destination URL
    let finalDestinationUrl = destinationUrl || 'https://mature-mackerel-golden.ngrok-free.app'; // fallback
    if (!destinationUrl && baseURI && siteId) {
        finalDestinationUrl = `https://${baseURI}/hc/s-${siteId}/web/m-LP/samlAssertionMembersArea/home.jsp?lpservice=liveEngage&servicepath=a%2F~~accountid~~%2F%23%2C~~ssokey~~`;
    }
    
    console.log('📍 SAML Response Destination:', finalDestinationUrl);
    console.log('🔐 Encryption requested:', shouldEncrypt);
    
    // Create assertion object for signSAMLAssertion
    const assertionData = {
        siteId: siteId,
        loginName: loginName
    };
    
    // Generate SAML response using the signSAMLAssertion function with encryption support
    const result = await signSAMLAssertion(assertionData, finalDestinationUrl, shouldEncrypt);
    
    if (result && result.xml) {
        console.log('✅ SAML assertion generated successfully');
        console.log('🔧 Method used:', result.method);
        console.log('📏 Response length:', result.xml.length, 'chars');
        console.log('📏 Base64 length:', result.base64.length, 'chars');
        console.log('🔐 Encryption status:', result.method.includes('ENCRYPTED') ? 'ENCRYPTED' : 'UNENCRYPTED');
        
        return {
            success: true,
            xml: result.xml,
            base64: result.base64,
            encrypted: result.method.includes('ENCRYPTED'),
            destination: finalDestinationUrl,
            method: result.method,
            encryptionUsed: shouldEncrypt && result.method.includes('ENCRYPTED')
        };
    } else {
        throw new Error('Failed to generate SAML assertion - no result returned');
    }
}

/**
 * Generate the Denver SSO testing page HTML
 * @param {boolean} encryptionEnabled - Whether encryption is enabled
 * @returns {string} HTML content
 */
function generateDenverSSOPage(encryptionEnabled) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson Denver SAML SSO - IDP Server</title>
        <style>
            /* CSS styles would be here */
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 LivePerson Denver SAML SSO</h1>
            <!-- Page content would be here -->
            <script>
                // JavaScript for the page would be here
                // Including the shouldEncrypt: ${encryptionEnabled} parameter
            </script>
        </div>
    </body>
    </html>
    `;
}

module.exports = {
    setupDenverSSORoutes,
    discoverDenverDomain,
    generateSAMLAssertion
}; 