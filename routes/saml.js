// SAML routes for LivePerson IDP Server
import express from 'express';
import axios from 'axios';
import config from '../config/config.js';

// Import SAML modules
import { loadLivePersonCertificate } from '../saml/saml-encryption.js';
import { getIdentityProvider, getServiceProvider } from '../saml/saml-core.js';
import { signSAMLAssertion } from '../saml/saml-response.js';

const router = express.Router();

// Denver SAML SSO page
router.get('/agentsso-denver', (req, res) => {
    // Get current state from main app
    const { encryptionEnabled } = req.app.locals;
    
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
                    <input type="text" id="siteId" name="siteId" value="${config.livePerson.defaultSiteId}" required>
                    <div id="baseUriResult"></div>
                </div>
                
                <div class="form-group">
                    <label for="loginName">Login Name (Agent Username):</label>
                    <input type="text" id="loginName" name="loginName" value="${config.livePerson.defaultAgentEmail}" required>
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
                        <span id="samlEncryptionStatus" style="font-weight: bold; color: ${encryptionEnabled ? '#28a745' : '#dc3545'};">
                            ${encryptionEnabled ? '🔒 ENABLED (controlled by main toggle)' : '🔓 DISABLED (controlled by main toggle)'}
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
                    <button type="button" class="btn" onclick="loginWithDenver()">🚀 Login with Denver SSO</button>
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
                
                try {
                    // Step 1: Discover Denver domain first
                    showStatus('Step 1/2: Discovering Denver domain...', 'info');
                    const domainResponse = await fetch('/discover-denver-domain', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ siteId: siteId })
                    });
                    
                    const domainResult = await domainResponse.json();
                    
                    if (!domainResult.success) {
                        let errorMessage = 'Failed to discover Denver domain: ' + domainResult.error;
                        
                        // Add HTTP status to error message if available
                        if (domainResult.httpStatus) {
                            errorMessage += ' (HTTP ' + domainResult.httpStatus + ')';
                        }
                        
                        // Log detailed error information to console for debugging
                        console.error('❌ Domain Discovery Failed:', domainResult);
                        
                        // Log API response data if available
                        if (domainResult.responseData) {
                            console.error('❌ API Response Data:', domainResult.responseData);
                        }
                        
                        showStatus(errorMessage, 'error');
                        return; // HALT: Stop the assertion generation process
                    }
                    
                    discoveredBaseUri = domainResult.baseURI;
                    document.getElementById('baseUriResult').innerHTML = 
                        '<strong>✅ Denver Domain:</strong> ' + domainResult.baseURI;
                    
                    // Step 2: Generate SAML assertion
                    showStatus('Step 2/2: Generating SAML assertion...', 'info');
                    
                    const requestBody = {
                        siteId: siteId,
                        loginName: loginName,
                        baseURI: discoveredBaseUri,
                        shouldEncrypt: ${encryptionEnabled}
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
                        document.getElementById('assertionContent').value = result.xml;
                        document.getElementById('assertionResult').style.display = 'block';
                        
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
                    showStatus('Error: ' + error.message, 'error');
                }
            }
            
            async function loginWithDenver() {
                const siteId = document.getElementById('siteId').value;
                const loginName = document.getElementById('loginName').value;
                
                if (!siteId || !loginName) {
                    showStatus('Please fill in Site ID and Login Name', 'error');
                    return;
                }
                
                try {
                    // Step 1: Discover Denver domain
                    showStatus('Step 1/3: Discovering Denver domain...', 'info');
                    const domainResponse = await fetch('/discover-denver-domain', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ siteId: siteId })
                    });
                    
                    const domainResult = await domainResponse.json();
                    
                    if (!domainResult.success) {
                        let errorMessage = 'Failed to discover Denver domain: ' + domainResult.error;
                        
                        // Add HTTP status to error message if available
                        if (domainResult.httpStatus) {
                            errorMessage += ' (HTTP ' + domainResult.httpStatus + ')';
                        }
                        
                        // Log detailed error information to console for debugging
                        console.error('❌ Domain Discovery Failed:', domainResult);
                        
                        // Log API response data if available
                        if (domainResult.responseData) {
                            console.error('❌ API Response Data:', domainResult.responseData);
                        }
                        
                        showStatus(errorMessage, 'error');
                        return; // HALT: Stop the login process
                    }
                    
                    discoveredBaseUri = domainResult.baseURI;
                    document.getElementById('baseUriResult').innerHTML = 
                        '<strong>✅ Denver Domain:</strong> ' + domainResult.baseURI;
                    
                    // Step 2: Generate SAML assertion
                    showStatus('Step 2/3: Generating SAML assertion...', 'info');
                    
                    const requestBody = {
                        siteId: siteId,
                        loginName: loginName,
                        baseURI: discoveredBaseUri,
                        shouldEncrypt: ${encryptionEnabled}
                    };
                    
                    const assertionResponse = await fetch('/generate-saml-assertion', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestBody)
                    });
                    
                    const assertionResult = await assertionResponse.json();
                    
                    if (!assertionResult.success) {
                        showStatus('Failed to generate SAML assertion: ' + assertionResult.error, 'error');
                        return;
                    }
                    
                    // Update the UI with the generated assertion
                    document.getElementById('assertionXML').value = formatXML(assertionResult.xml);
                    document.getElementById('assertionBase64').value = assertionResult.base64;
                    document.getElementById('assertionContent').value = assertionResult.xml;
                    document.getElementById('assertionResult').style.display = 'block';
                    
                    // Step 3: Login with Denver SSO
                    showStatus('Step 3/3: Redirecting to Denver SSO...', 'info');
                    
                    // Create form and submit to Denver
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = 'https://' + discoveredBaseUri + '/hc/s-' + siteId + '/web/m-LP/samlAssertionMembersArea/home.jsp?lpservice=liveEngage&servicepath=a%2F~~accountid~~%2F%23%2C~~ssokey~~';
                    form.target = '_blank';
                    
                    const samlInput = document.createElement('input');
                    samlInput.type = 'hidden';
                    samlInput.name = 'SAMLResponse';
                    samlInput.value = assertionResult.base64;
                    
                    form.appendChild(samlInput);
                    document.body.appendChild(form);
                    form.submit();
                    document.body.removeChild(form);
                    
                    let successMessage = '🚀 Successfully logged in to Denver SSO';
                    if (assertionResult.method) {
                        successMessage += ' using ' + assertionResult.method;
                    }
                    if (assertionResult.encrypted) {
                        successMessage += ' (ENCRYPTED)';
                    }
                    showStatus(successMessage, 'success');
                    
                } catch (error) {
                    showStatus('Error during login process: ' + error.message, 'error');
                }
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
router.post('/discover-denver-domain', async (req, res) => {
    const { siteId } = req.body;
    
    console.log('🔍 Discovering Denver domain for site ID:', siteId);
    
    try {
        const apiUrl = `${config.livePerson.apiBaseUrl}/api/account/${siteId}/service/adminArea/baseURI.json?version=1.0`;
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
            console.error('❌ No baseURI found in API response:', data);
            res.json({
                success: false,
                error: 'No baseURI found in response',
                responseData: data
            });
        }
    } catch (error) {
        console.error('❌ Error discovering Denver domain:', error.message);
        
        let errorResponse = {
            success: false,
            error: error.message
        };
        
        // Add HTTP error details if available
        if (error.response) {
            errorResponse.httpStatus = error.response.status;
            errorResponse.httpStatusText = error.response.statusText;
            errorResponse.responseData = error.response.data;
            
            console.error('❌ HTTP Error Details:', {
                status: error.response.status,
                statusText: error.response.statusText,
                data: error.response.data
            });
        }
        
        res.json(errorResponse);
    }
});

// SAML assertion generation endpoint
router.post('/generate-saml-assertion', async (req, res) => {
    const { siteId, loginName, encrypt, shouldEncrypt, encryptionCert, baseURI, destinationUrl } = req.body;
    
    // Get current state from main app
    const { encryptionEnabled } = req.app.locals;
    
    // Use shouldEncrypt if provided, otherwise fall back to encrypt, then to global setting
    const requestEncryption = shouldEncrypt !== undefined ? shouldEncrypt : 
                             encrypt !== undefined ? encrypt : encryptionEnabled;
    
    console.log('🔐 Generating SAML assertion for:', { 
        siteId, 
        loginName, 
        encrypt, 
        shouldEncrypt, 
        requestEncryption, 
        globalEncryption: encryptionEnabled,
        baseURI, 
        destinationUrl 
    });
    console.log('🔍 Request body received:', JSON.stringify(req.body, null, 2));
    
    // Check if SAML is properly initialized
    const identityProvider = getIdentityProvider();
    const serviceProvider = getServiceProvider();
    
    if (!identityProvider || !serviceProvider) {
        console.error('❌ SAML not initialized - cannot generate assertion');
        return res.json({
            success: false,
            error: 'SAML not properly initialized. Standard library initialization failed.'
        });
    }
    
    try {
        // Use provided destinationUrl or construct the proper Denver destination URL
        let finalDestinationUrl = destinationUrl || config.server.baseUrl; // fallback
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

export { router as samlRoutes }; 