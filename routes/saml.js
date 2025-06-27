// SAML routes for LivePerson IDP Server
import express from 'express';
import axios from 'axios';
import config, { runtimeConfig } from '../config/config.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Import SAML modules
import { loadLivePersonCertificate } from '../saml/saml-encryption.js';
import { getIdentityProvider, getServiceProvider } from '../saml/saml-core.js';
import { createSAMLResponse } from '../saml/saml-response.js';

const router = express.Router();

// Denver SAML SSO page
router.get('/agentsso-denver', (req, res) => {
    const encryptionEnabled = req.app.locals.encryptionEnabled || false;
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson Denver SAML SSO</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 15px 0; }
            .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
            .form-group input, .form-group textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
            .btn:hover { background: #0056b3; }
            .info-box { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
            .account-section { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .account-current { background: #f8f9fa; border: 1px solid #dee2e6; padding: 12px; margin: 10px 0; border-radius: 4px; }
            .account-form { background: #fff; border: 1px solid #dee2e6; padding: 12px; margin: 10px 0; border-radius: 4px; }
            .account-badge { background: #28a745; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
            .nav-link { color: #007bff; text-decoration: none; margin-right: 15px; font-weight: bold; }
            .nav-link:hover { text-decoration: underline; }
        </style>
        <script>
            let currentAccount = ${JSON.stringify(runtimeConfig.currentAccount)};
            let denverEncryptionEnabled = false;
            
            // Initialize Denver encryption toggle
            function initializeDenverEncryption() {
                const toggle = document.getElementById('denverEncryptionToggle');
                const status = document.getElementById('denverEncryptionStatus');
                const certSelect = document.getElementById('encryptionCertName');
                
                // Set initial state
                updateDenverEncryptionStatus();
                
                // Add event listener for toggle changes
                toggle.addEventListener('change', function() {
                    denverEncryptionEnabled = this.checked;
                    updateDenverEncryptionStatus();
                    console.log('🔐 Denver encryption toggled:', denverEncryptionEnabled ? 'ENABLED' : 'DISABLED');
                });
                
                // Add event listener for certificate selection changes
                if (certSelect) {
                    certSelect.addEventListener('change', function() {
                        updateDenverEncryptionStatus();
                        console.log('🔐 Denver encryption certificate changed to:', this.value);
                    });
                }
            }
            
            function updateDenverEncryptionStatus() {
                const toggle = document.getElementById('denverEncryptionToggle');
                const status = document.getElementById('denverEncryptionStatus');
                const certSelector = document.getElementById('encryptionCertSelector');
                const certSelect = document.getElementById('encryptionCertName');
                
                toggle.checked = denverEncryptionEnabled;
                
                if (denverEncryptionEnabled) {
                    const selectedCert = certSelect ? certSelect.value : 'lpsso2026';
                    status.textContent = '🔒 ENABLED (' + selectedCert + ')';
                    status.style.color = '#007bff';
                    if (certSelector) certSelector.style.display = 'block';
                } else {
                    status.textContent = '🔓 DISABLED';
                    status.style.color = '#dc3545';
                    if (certSelector) certSelector.style.display = 'none';
                }
            }
            
            async function loadAccountInfo() {
                try {
                    const response = await fetch('/api/account');
                    const data = await response.json();
                    if (data.success) {
                        currentAccount = data.currentAccount;
                        updateAccountDisplay();
                        // Note: Not overriding form fields to preserve hardcoded defaults
                    }
                } catch (error) {
                    console.error('Failed to load account info:', error);
                }
            }
            
            function updateAccountDisplay() {
                document.getElementById('currentAccountName').textContent = currentAccount.name;
                document.getElementById('currentAccountSiteId').textContent = currentAccount.siteId;
                document.getElementById('currentAccountDesc').textContent = currentAccount.description;
            }
            
            async function updateAccount() {
                const siteId = document.getElementById('newSiteId').value.trim();
                const name = document.getElementById('newAccountName').value.trim();
                const description = document.getElementById('newAccountDesc').value.trim();
                
                if (!siteId) {
                    showAccountMessage('Site ID is required', 'error');
                    return;
                }
                
                try {
                    const response = await fetch('/api/account', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ siteId, name, description })
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        currentAccount = data.currentAccount;
                        updateAccountDisplay();
                        showAccountMessage(data.message, 'success');
                        
                        // Clear form
                        document.getElementById('newSiteId').value = '';
                        document.getElementById('newAccountName').value = '';
                        document.getElementById('newAccountDesc').value = '';
                    } else {
                        showAccountMessage('Failed to update account', 'error');
                    }
                } catch (error) {
                    showAccountMessage('Error updating account: ' + error.message, 'error');
                }
            }
            
            function showAccountMessage(message, type) {
                const messageDiv = document.getElementById('accountMessage');
                messageDiv.textContent = message;
                messageDiv.style.color = type === 'error' ? '#dc3545' : '#28a745';
                messageDiv.style.fontWeight = 'bold';
                setTimeout(() => {
                    messageDiv.textContent = '';
                }, 3000);
            }
            
            // Load account info and initialize Denver encryption on page load
            window.addEventListener('load', function() {
                loadAccountInfo();
                initializeDenverEncryption();
            });
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🔐 LivePerson Denver SAML SSO</h1>
            
            <nav style="margin-bottom: 20px;">
                <a href="/" class="nav-link">🏠 Back to Dashboard</a>
                <a href="/agentsso-auth0" class="nav-link">🔑 Auth0 SAML</a>
                <a href="/test" class="nav-link">🧪 Consumer Test Page</a>
                <a href="/health" class="nav-link">❤️ Health Check</a>
            </nav>
            
            <div class="account-section">
                <h3>🏢 Default Denver SSO Settings</h3>
                <div class="account-current">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="account-badge">DEFAULT</span>
                        <strong>Denver Test Account</strong>
                        <span style="color: #666;">|</span>
                        <span style="font-family: monospace; color: #007bff; font-weight: bold;">Site ID: 50922448</span>
                        <span style="color: #666;">|</span>
                        <span style="font-family: monospace; color: #28a745; font-weight: bold;">Username: supportteam</span>
                    </div>
                    <div style="margin-top: 5px; color: #666; font-size: 12px;">
                        Default values for Denver SAML SSO testing - you can override these in the form below
                    </div>
                </div>
            </div>
            
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
                    <input type="text" id="siteId" name="testSiteId" value="50922448" data-lpignore="true" required>
                    <div id="baseUriResult"></div>
                </div>
                
                <div class="form-group">
                    <label for="loginName">Login Name (Agent Username):</label>
                    <input type="text" id="loginName" name="testLoginName" value="supportteam" data-lpignore="true" required>
                </div>
                
                <div class="form-group">
                    <label for="samlMethod">SAML Implementation Method:</label>
                    <select id="samlMethod" name="samlMethod" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        <option value="samlify" selected>🔧 samlify (Testing signing & encryption)</option>
                    </select>
                    <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin-top: 5px; border-radius: 4px; font-size: 12px;">
                        <strong>🧪 Testing samlify for all functionality:</strong><br>
                        • <strong>Signing:</strong> Using our local signing certificate and private key<br>
                        • <strong>Encryption:</strong> Using configurable LivePerson certificate when Denver encryption is enabled<br>
                        • <strong>Status:</strong> Testing to ensure both signing and encryption work correctly before cleanup
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Signing Configuration:</label>
                    <div class="warning-box">
                        <strong>⚠️ Note:</strong> Using existing RSA private key for signing. 
                        You'll need to provide the corresponding public certificate to LivePerson for signature verification.
                    </div>
                </div>
                
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-weight: bold;">🔐 Denver SAML Encryption:</span>
                        <label class="switch" style="position: relative; display: inline-block; width: 60px; height: 34px;">
                            <input type="checkbox" id="denverEncryptionToggle" style="opacity: 0; width: 0; height: 0;">
                            <span class="slider round" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: 0.4s; border-radius: 34px;"></span>
                        </label>
                        <span id="denverEncryptionStatus" style="font-weight: bold; color: #dc3545;">🔓 DISABLED</span>
                    </label>
                    <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin-top: 5px; border-radius: 4px; font-size: 12px;">
                        <strong>🔑 Encryption Details:</strong><br>
                        • <strong>Certificate:</strong> Uses selected LivePerson encryption certificate<br>
                        • <strong>Purpose:</strong> Encrypts SAML assertion content for secure transmission<br>
                        • <strong>Override:</strong> This setting overrides the global encryption toggle for Denver SAML only<br>
                        • <strong>Requirement:</strong> LivePerson must have the corresponding private key to decrypt
                    </div>
                </div>
                
                <div class="form-group" id="encryptionCertSelector" style="display: none;">
                    <label for="encryptionCertName">🔐 Encryption Certificate:</label>
                    <select id="encryptionCertName" name="encryptionCertName" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        <option value="lpsso2026">lpsso2026 - LivePerson 2026 Certificate (Default)</option>
                        <option value="lpsso2027">lpsso2027 - LivePerson 2027 Certificate</option>
                        <option value="lpsso2028">lpsso2028 - LivePerson 2028 Certificate</option>
                                          </select>
                </div>
                
                <style>
                    .switch input:checked + .slider {
                        background-color: #007bff;
                    }
                    .switch input:focus + .slider {
                        box-shadow: 0 0 1px #007bff;
                    }
                    .switch input:checked + .slider:before {
                        transform: translateX(26px);
                    }
                    .slider:before {
                        position: absolute;
                        content: "";
                        height: 26px;
                        width: 26px;
                        left: 4px;
                        bottom: 4px;
                        background-color: white;
                        transition: 0.4s;
                        border-radius: 50%;
                    }
                </style>
                
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
            let encryptionEnabled = ${encryptionEnabled};
            
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
                    
                    const encryptionCertName = document.getElementById('encryptionCertName') ? 
                        document.getElementById('encryptionCertName').value : null;
                    
                    const requestBody = {
                        siteId: siteId,
                        loginName: loginName,
                        baseURI: discoveredBaseUri,
                        shouldEncrypt: denverEncryptionEnabled,
                        method: document.getElementById('samlMethod').value,
                        encryptionCertName: encryptionCertName
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
                    
                    const encryptionCertName = document.getElementById('encryptionCertName') ? 
                        document.getElementById('encryptionCertName').value : null;
                    
                    const requestBody = {
                        siteId: siteId,
                        loginName: loginName,
                        baseURI: discoveredBaseUri,
                        shouldEncrypt: denverEncryptionEnabled,
                        method: document.getElementById('samlMethod').value,
                        encryptionCertName: encryptionCertName
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
    const { siteId, loginName, encrypt, shouldEncrypt, encryptionCert, baseURI, destinationUrl, method } = req.body;
    
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
        
        // Generate SAML response using the updated createSAMLResponse function with method support
        const samlMethod = method || config.saml.implementation || 'auto';
        console.log('🛠️ Using SAML method:', samlMethod);
        
        const result = await createSAMLResponse(siteId, loginName, finalDestinationUrl, requestEncryption, samlMethod);
        
        let finalAssertion, assertionBase64, usedMethod;
        
        if (result && result.samlResponse) {
            finalAssertion = result.samlResponse;
            assertionBase64 = Buffer.from(result.samlResponse).toString('base64');
            usedMethod = result.method;
            
            console.log('✅ SAML assertion generated successfully');
            console.log('🔧 Method used:', usedMethod);
            console.log('📏 Response length:', finalAssertion.length, 'chars');
            console.log('📏 Base64 length:', assertionBase64.length, 'chars');
            console.log('🔐 Encryption status:', usedMethod.includes('ENCRYPTED') ? 'ENCRYPTED' : 'UNENCRYPTED');
        } else {
            throw new Error('Failed to generate SAML assertion - no result returned');
        }
        
        res.json({
            success: true,
            xml: finalAssertion,
            base64: assertionBase64,
            encrypted: usedMethod.includes('ENCRYPTED'),
            destination: finalDestinationUrl,
            method: usedMethod,
            encryptionUsed: requestEncryption && usedMethod.includes('ENCRYPTED')
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

// Auth0 SAML SSO page
router.get('/agentsso-auth0', (req, res) => {
    const encryptionEnabled = req.app.locals.encryptionEnabled || false;
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson Auth0 SAML SSO</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 15px 0; }
            .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
            .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
            .btn:hover { background: #0056b3; }
            .info-box { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
            .auth0-section { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .auth0-current { background: #f8f9fa; border: 1px solid #dee2e6; padding: 12px; margin: 10px 0; border-radius: 4px; }
            .auth0-form { background: #fff; border: 1px solid #dee2e6; padding: 12px; margin: 10px 0; border-radius: 4px; }
            .auth0-badge { background: #28a745; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
            .nav-link { color: #007bff; text-decoration: none; margin-right: 15px; font-weight: bold; }
            .nav-link:hover { text-decoration: underline; }
            .switch { position: relative; display: inline-block; width: 60px; height: 34px; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
            input:checked + .slider { background-color: #007bff; }
            input:checked + .slider:before { transform: translateX(26px); }
            .status { padding: 10px; margin: 10px 0; border-radius: 4px; font-weight: bold; }
            .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .status.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        </style>
        <script>
            let auth0EncryptionEnabled = false;
            
            // Initialize Auth0 encryption toggle
            function initializeAuth0Encryption() {
                const toggle = document.getElementById('auth0EncryptionToggle');
                const status = document.getElementById('auth0EncryptionStatus');
                const certSelect = document.getElementById('auth0EncryptionCertName');
                
                // Set initial state
                updateAuth0EncryptionStatus();
                
                // Add event listener for toggle changes
                toggle.addEventListener('change', function() {
                    auth0EncryptionEnabled = this.checked;
                    updateAuth0EncryptionStatus();
                    console.log('🔐 Auth0 encryption toggled:', auth0EncryptionEnabled ? 'ENABLED' : 'DISABLED');
                });
                
                // Add event listener for certificate selection changes
                if (certSelect) {
                    certSelect.addEventListener('change', function() {
                        updateAuth0EncryptionStatus();
                        console.log('🔐 Auth0 encryption certificate changed to:', this.value);
                    });
                }
            }
            
            function updateAuth0EncryptionStatus() {
                const toggle = document.getElementById('auth0EncryptionToggle');
                const status = document.getElementById('auth0EncryptionStatus');

                const urlDiv = document.getElementById('auth0EncryptionUrl');
                const envSelect = document.getElementById('auth0Environment');
                
                toggle.checked = auth0EncryptionEnabled;
                
                // Environment to domain mapping
                const envDomains = {
                    'alpha': 'auth-z1-a.liveperson.net',
                    'north-america': 'auth-z1.liveperson.net',
                    'europe': 'auth-z2.liveperson.net',
                    'asia-pacific': 'auth-z3.liveperson.net'
                };
                
                const selectedEnv = envSelect ? envSelect.value : 'alpha';
                const domain = envDomains[selectedEnv];
                const certUrl = 'https://' + domain + '/cer?cert=connection';
                
                if (auth0EncryptionEnabled) {
                    status.textContent = 'ENABLED';
                    status.style.color = '#007bff';
                    urlDiv.innerHTML = '📥 Certificate URL: <a href="' + certUrl + '" target="_blank" style="color: #007bff;">' + certUrl + '</a>';
                } else {
                    status.textContent = 'DISABLED';
                    status.style.color = '#dc3545';
                    urlDiv.innerHTML = '📥 Certificate URL: <span style="color: #666;">' + certUrl + '</span>';
                }
            }
            
            // Initialize Auth0 encryption on page load
            window.addEventListener('load', function() {
                initializeAuth0Encryption();
                initializeAuth0Environment();
            });

            // Function to update encryption field before form submission
            function updateEncryptionField() {
                const encryptionField = document.getElementById('shouldEncryptField');
                if (encryptionField) {
                    encryptionField.value = auth0EncryptionEnabled ? 'true' : 'false';
                    console.log('🔐 Setting shouldEncrypt field to:', encryptionField.value);
                }
                return true; // Allow form submission to continue
            }
            
            // Initialize Auth0 environment dropdown
            function initializeAuth0Environment() {
                const envSelect = document.getElementById('auth0Environment');
                const callbackInput = document.getElementById('auth0CallbackUrl');
                const connectionInput = document.getElementById('auth0Connection');
                
                // Environment to domain mapping
                const envDomains = {
                    'alpha': 'auth-z1-a.liveperson.net',
                    'north-america': 'auth-z1.liveperson.net',
                    'europe': 'auth-z2.liveperson.net',
                    'asia-pacific': 'auth-z3.liveperson.net'
                };
                
                // Add event listener for environment changes
                envSelect.addEventListener('change', function() {
                    const selectedEnv = this.value;
                    const domain = envDomains[selectedEnv];
                    const connection = connectionInput.value;
                    
                    if (domain && connection) {
                        const newCallbackUrl = 'https://' + domain + '/login/callback?connection=' + connection;
                        callbackInput.value = newCallbackUrl;
                        console.log('🌍 Environment changed to:', selectedEnv, '- Updated callback URL to:', newCallbackUrl);
                    }
                    
                    // Update encryption status to refresh certificate URL
                    updateAuth0EncryptionStatus();
                });
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🔐 LivePerson Auth0 SAML SSO</h1>
            
            <nav style="margin-bottom: 20px;">
                <a href="/" class="nav-link">🏠 Back to Dashboard</a>
                <a href="/agentsso-denver" class="nav-link">🔒 Denver SAML</a>
                <a href="/test" class="nav-link">🧪 Consumer Test Page</a>
                <a href="/health" class="nav-link">❤️ Health Check</a>
            </nav>
            
            <div class="auth0-section">
                <h3>🔑 Default Auth0 SAML Settings</h3>
                <div class="auth0-current">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="auth0-badge">DEFAULT</span>
                        <strong>LivePerson Alpha Environment</strong>
                        <span style="color: #666;">|</span>
                        <span style="font-family: monospace; color: #007bff; font-weight: bold;">Account: 81785735</span>
                        <span style="color: #666;">|</span>
                        <span style="font-family: monospace; color: #28a745; font-weight: bold;">Username: admin</span>
                    </div>
                    <div style="margin-top: 5px; color: #666; font-size: 12px;">
                        Default values for Auth0 SAML SSO testing with LivePerson alpha environment
                    </div>
                </div>
            </div>
            
            <div class="info-box">
                <h3>📋 Auth0 SAML SP-Initiated Authentication</h3>
                <p>This page allows you to test SP-initiated SAML authentication flow with LivePerson and Auth0.</p>
                <ul>
                    <li><strong>Flow Type:</strong> SP-Initiated (LivePerson starts the authentication)</li>
                    <li><strong>Entry Point:</strong> <a href="https://authentication.liveperson.net/accountSelection.html?stId=81785735&prompt=none" target="_blank" style="color: #007bff;">LivePerson Authentication Service</a></li>
                    <li><strong>Environment:</strong> LivePerson Alpha (auth-z1-a.liveperson.net)</li>
                    <li><strong>Connection:</strong> SAML-81785735-MyIdPSAML</li>
                    <li><strong>Integration:</strong> MyIdPSAML</li>
                    <li><strong>Flow:</strong> LP Auth → Our IdP → SAML Response → LP Login</li>
                    <li><strong>IdP URL:</strong> <code style="background: #f8f9fa; padding: 2px 4px;">https://mature-mackerel-golden.ngrok-free.app/sso/saml</code></li>
                </ul>
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-top: 10px; border-radius: 4px; font-size: 12px;">
                    <strong>📝 Setup Note:</strong> Configure LivePerson to use <code>https://mature-mackerel-golden.ngrok-free.app/sso/saml</code> as the SAML IdP endpoint for the MyIdPSAML integration.
                </div>
            </div>
            
            <form id="auth0SamlForm">
                <div class="form-group">
                    <label for="auth0Account">LivePerson Account ID:</label>
                    <input type="text" id="auth0Account" name="auth0Account" value="81785735" data-lpignore="true" required>
                </div>
                
                <div class="form-group">
                    <label for="auth0Username">Agent Username:</label>
                    <input type="text" id="auth0Username" name="auth0Username" value="admin" data-lpignore="true" required>
                </div>
                
                <div class="form-group">
                    <label for="auth0Connection">LivePerson Connection Name:</label>
                    <input type="text" id="auth0Connection" name="auth0Connection" value="SAML-81785735-MyIdPSAML" data-lpignore="true" required>
                </div>
                
                <div class="form-group">
                    <label for="auth0Environment">LivePerson Environment:</label>
                    <select id="auth0Environment" name="auth0Environment" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        <option value="alpha" selected>Alpha (auth-z1-a.liveperson.net)</option>
                        <option value="north-america">North America (auth-z1.liveperson.net)</option>
                        <option value="europe">Europe (auth-z2.liveperson.net)</option>
                        <option value="asia-pacific">Asia Pacific (auth-z3.liveperson.net)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="auth0CallbackUrl">Auth0 Callback URL:</label>
                    <input type="text" id="auth0CallbackUrl" name="auth0CallbackUrl" value="https://auth-z1-a.liveperson.net/login/callback?connection=SAML-81785735-MyIdPSAML" data-lpignore="true" required>
                </div>
                
                <div class="form-group">
                    <label for="auth0SamlMethod">SAML Implementation Method:</label>
                    <select id="auth0SamlMethod" name="auth0SamlMethod" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        <option value="samlify" selected>🔧 samlify (Auth0 Compatible)</option>
                    </select>
                    <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin-top: 5px; border-radius: 4px; font-size: 12px;">
                        <strong>🧪 Auth0 SAML Compatibility:</strong><br>
                        • <strong>Signing:</strong> Using our local signing certificate and private key<br>
                        • <strong>Encryption:</strong> Optional using configurable LivePerson certificate<br>
                        • <strong>NameID Format:</strong> Unspecified (compatible with Auth0 requirements)<br>
                        • <strong>Destination:</strong> Auth0 callback URL for SP-initiated flow
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Signing Configuration:</label>
                    <div class="warning-box">
                        <strong>⚠️ Note:</strong> Using existing RSA private key for signing. 
                        You'll need to provide the corresponding public certificate to Auth0 for signature verification.
                    </div>
                </div>
                
                <div class="form-group">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-weight: bold;">🔐 Auth0 SAML Encryption:</span>
                        <label class="switch">
                            <input type="checkbox" id="auth0EncryptionToggle">
                            <span class="slider"></span>
                        </label>
                        <span id="auth0EncryptionStatus" style="font-weight: bold; color: #dc3545;">🔓 DISABLED</span>
                    </label>
                    <div id="auth0EncryptionUrl" style="background: #f8f9fa; border: 1px solid #dee2e6; padding: 8px; margin-top: 5px; border-radius: 4px; font-size: 12px; font-family: monospace;">
                        <!-- Certificate URL will be populated here -->
                    </div>
                </div>
                

                
                <div class="form-group">
                    <button type="button" class="btn" onclick="generateAuth0SAMLAssertion()">Generate SAML Assertion (Testing)</button>
                    <button type="button" class="btn" onclick="initiateAuth0SAML()">🚀 Start SP-Initiated SAML Flow</button>
                </div>
            </form>
            
            <div id="auth0AssertionResult" style="display: none;">
                <h3>📄 Generated Auth0 SAML Assertion:</h3>
                
                <div style="margin: 15px 0;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #555;">
                        🔍 Decoded XML (Human Readable):
                    </label>
                    <textarea id="auth0AssertionXML" readonly style="height: 200px; font-family: monospace; width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px; background: #f8f9fa;"></textarea>
                </div>
                
                <div style="margin: 15px 0;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold; color: #555;">
                        📦 Base64 Encoded (For POST to Auth0):
                    </label>
                    <textarea id="auth0AssertionBase64" readonly style="height: 100px; font-family: monospace; width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px; background: #fff3cd;"></textarea>
                </div>
            </div>
            
            <div id="auth0StatusMessage"></div>
        </div>
        
        <script>
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
            
            async function generateAuth0SAMLAssertion() {
                const account = document.getElementById('auth0Account').value;
                const username = document.getElementById('auth0Username').value;
                const callbackUrl = document.getElementById('auth0CallbackUrl').value;
                
                if (!account || !username || !callbackUrl) {
                    showAuth0Status('Please fill in Account ID, Username, and Callback URL', 'error');
                    return;
                }
                
                try {
                    showAuth0Status('Generating Auth0 SAML assertion...', 'info');
                    
                    const encryptionCertName = document.getElementById('auth0EncryptionCertName') ? 
                        document.getElementById('auth0EncryptionCertName').value : null;
                    
                    const requestBody = {
                        siteId: account,
                        loginName: username,
                        destinationUrl: callbackUrl,
                        shouldEncrypt: auth0EncryptionEnabled,
                        method: document.getElementById('auth0SamlMethod').value,
                        encryptionCertName: encryptionCertName,
                        samlType: 'auth0'
                    };
                    
                    const response = await fetch('/generate-auth0-saml-assertion', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestBody)
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        document.getElementById('auth0AssertionXML').value = formatXML(result.xml);
                        document.getElementById('auth0AssertionBase64').value = result.base64;
                        document.getElementById('auth0AssertionResult').style.display = 'block';
                        
                        let successMessage = 'Auth0 SAML assertion generated successfully';
                        if (result.method) {
                            successMessage += ' using ' + result.method;
                        }
                        if (result.destination) {
                            successMessage += '. Destination: ' + result.destination;
                        }
                        if (result.encrypted) {
                            successMessage += ' (ENCRYPTED)';
                        }
                        showAuth0Status(successMessage, 'success');
                    } else {
                        showAuth0Status('Failed to generate Auth0 SAML assertion: ' + result.error, 'error');
                    }
                } catch (error) {
                    showAuth0Status('Error: ' + error.message, 'error');
                }
            }
            
            async function initiateAuth0SAML() {
                const account = document.getElementById('auth0Account').value;
                
                if (!account) {
                    showAuth0Status('Please fill in Account ID', 'error');
                    return;
                }
                
                try {
                    // First, store the encryption setting in localStorage for the SP-initiated flow
                    localStorage.setItem('auth0EncryptionEnabled', auth0EncryptionEnabled ? 'true' : 'false');
                    console.log('🔐 Stored encryption setting for SP-initiated flow:', auth0EncryptionEnabled);
                    
                    // SP-Initiated flow: Redirect to LivePerson authentication service
                    showAuth0Status('🚀 Initiating SP-initiated SAML flow...', 'info');
                    
                    // Construct LivePerson authentication URL
                    const authUrl = 'https://authentication.liveperson.net/accountSelection.html?stId=' + account + '&prompt=none';
                    
                    // Open in new tab for SP-initiated flow
                    window.open(authUrl, '_blank');
                    
                    showAuth0Status('✅ SP-initiated SAML flow started! Check the new tab for authentication.', 'success');
                    
                } catch (error) {
                    showAuth0Status('Error during SP-initiated SAML flow: ' + error.message, 'error');
                }
            }
            
            function showAuth0Status(message, type) {
                const statusDiv = document.getElementById('auth0StatusMessage');
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

// SAML SSO endpoint for SP-initiated flow (Auth0/LivePerson)
router.get('/sso/saml', async (req, res) => {
    const { SAMLRequest, RelayState } = req.query;
    
    console.log('🔍 Received SP-initiated SAML request:', { SAMLRequest: SAMLRequest ? 'present' : 'none', RelayState });
    
    if (!SAMLRequest) {
        return res.status(400).send('Missing SAMLRequest parameter');
    }
    
    try {
        // Decode the SAML request
        const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf-8');
        console.log('📋 Decoded SAML Request:', decodedRequest);
        
        // For now, show a simple form to enter credentials
        // In a real implementation, this would parse the request and authenticate the user
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>SAML Authentication</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
                .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .form-group { margin: 15px 0; }
                .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
                .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; }
                .btn:hover { background: #0056b3; }
                .info-box { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 20px 0; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 SAML Authentication</h1>
                
                <div class="info-box">
                    <h3>SP-Initiated SAML Request Received</h3>
                    <p>LivePerson is requesting authentication. Please enter the agent credentials.</p>
                </div>
                
                <form method="POST" action="/sso/saml/response" onsubmit="updateEncryptionFieldFromStorage()">
                    <input type="hidden" name="SAMLRequest" value="${SAMLRequest}">
                    <input type="hidden" name="RelayState" value="${RelayState || ''}">
                    <input type="hidden" name="shouldEncrypt" id="shouldEncryptField" value="false">
                    
                    <div class="form-group">
                        <label for="username">Agent Username:</label>
                        <input type="text" id="username" name="username" value="admin" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="accountId">Account ID:</label>
                        <input type="text" id="accountId" name="accountId" value="81785735" required>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn">🚀 Authenticate with SAML</button>
                    </div>
                </form>
            </div>
            
            <script>
                // Function to update encryption field from localStorage (for SP-initiated flow)
                function updateEncryptionFieldFromStorage() {
                    const encryptionField = document.getElementById('shouldEncryptField');
                    const storedEncryption = localStorage.getItem('auth0EncryptionEnabled');
                    
                    if (encryptionField && storedEncryption) {
                        encryptionField.value = storedEncryption;
                        console.log('🔐 Setting shouldEncrypt field from localStorage to:', storedEncryption);
                    } else {
                        console.log('🔐 No encryption setting found in localStorage, using default: false');
                        if (encryptionField) encryptionField.value = 'false';
                    }
                    
                    return true; // Allow form submission to continue
                }
                
                // Set encryption field on page load
                window.addEventListener('load', function() {
                    updateEncryptionFieldFromStorage();
                    
                    // Also display the encryption status to the user
                    const storedEncryption = localStorage.getItem('auth0EncryptionEnabled');
                    if (storedEncryption === 'true') {
                        document.body.insertAdjacentHTML('afterbegin', 
                            '<div style="background: #28a745; color: white; padding: 10px; text-align: center; font-weight: bold;">🔒 SAML Encryption: ENABLED</div>'
                        );
                    } else {
                        document.body.insertAdjacentHTML('afterbegin', 
                            '<div style="background: #dc3545; color: white; padding: 10px; text-align: center; font-weight: bold;">🔓 SAML Encryption: DISABLED</div>'
                        );
                    }
                });
            </script>
        </body>
        </html>
        `;
        
        res.send(html);
        
    } catch (error) {
        console.error('❌ Error processing SAML request:', error.message);
        res.status(500).send('Error processing SAML request: ' + error.message);
    }
});

// SAML response endpoint for SP-initiated flow
router.post('/sso/saml/response', async (req, res) => {
    const { SAMLRequest, RelayState, username, accountId, shouldEncrypt } = req.body;
    
    console.log('🔐 Generating SAML response for SP-initiated flow:', { username, accountId, RelayState, shouldEncrypt });
    
    try {
        // Parse the original SAML request to extract request ID
        let inResponseTo = null;
        if (SAMLRequest) {
            try {
                const decodedRequest = Buffer.from(SAMLRequest, 'base64').toString('utf-8');
                console.log('📋 Parsing SAML Request for InResponseTo...');
                
                // Extract the ID from the AuthnRequest
                const idMatch = decodedRequest.match(/ID="([^"]+)"/);
                if (idMatch) {
                    inResponseTo = idMatch[1];
                    console.log('✅ Extracted InResponseTo:', inResponseTo);
                } else {
                    console.log('⚠️ No ID found in SAML request');
                }
            } catch (parseError) {
                console.log('⚠️ Error parsing SAML request:', parseError.message);
            }
        }
        
        // Create modified createSAMLResponse that handles InResponseTo
        const encryptionEnabled = shouldEncrypt === 'true' || shouldEncrypt === true;
        console.log('🔐 Encryption enabled for this request:', encryptionEnabled);
        const result = await createSAMLResponseWithInResponseTo(accountId, username, 'https://auth-z1-a.liveperson.net/login/callback', encryptionEnabled, 'samlify', inResponseTo);
        
        if (result && result.samlResponse) {
            const samlResponseBase64 = Buffer.from(result.samlResponse).toString('base64');
            
            // Create auto-submit form to post back to LivePerson
            const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>SAML Response</title>
            </head>
            <body>
                <form id="samlForm" method="POST" action="https://auth-z1-a.liveperson.net/login/callback">
                    <input type="hidden" name="SAMLResponse" value="${samlResponseBase64}">
                    ${RelayState ? `<input type="hidden" name="RelayState" value="${RelayState}">` : ''}
                </form>
                <script>
                    document.getElementById('samlForm').submit();
                </script>
                <p>Redirecting to LivePerson...</p>
            </body>
            </html>
            `;
            
            res.send(html);
            console.log('✅ SAML response sent for SP-initiated flow');
        } else {
            throw new Error('Failed to generate SAML response');
        }
        
    } catch (error) {
        console.error('❌ Error generating SAML response:', error.message);
        res.status(500).send('Error generating SAML response: ' + error.message);
    }
});

// Helper function to create SAML response with InResponseTo
async function createSAMLResponseWithInResponseTo(siteId, loginName, destinationUrl, shouldEncrypt = false, method = 'samlify', inResponseTo = null) {
    const { createSAMLResponse } = await import('../saml/saml-response.js');
    
    // Use the updated createSAMLResponse function that now supports InResponseTo
    return await createSAMLResponseWithInResponseToSupport(siteId, loginName, destinationUrl, shouldEncrypt, method, inResponseTo);
}

// Updated SAML response function that properly handles InResponseTo with signing
async function createSAMLResponseWithInResponseToSupport(siteId, loginName, destinationUrl, shouldEncrypt = false, method = 'samlify', inResponseTo = null) {
    console.log('🔧 createSAMLResponseWithInResponseToSupport called with InResponseTo:', inResponseTo);
    
    console.log('🔧 Encryption setting for this request:', shouldEncrypt);
    
    // Import the SAML modules
    const { getIdentityProvider, getServiceProvider } = await import('../saml/saml-core.js');
    const { createSAMLResponse } = await import('../saml/saml-response.js');
    
    // Check if SAML is properly initialized
    const identityProvider = getIdentityProvider();
    const serviceProvider = getServiceProvider();
    
    if (!identityProvider || !serviceProvider) {
        console.error('❌ SAML not initialized - cannot generate assertion');
        throw new Error('SAML not properly initialized. Standard library initialization failed.');
    }
    
    try {
        // Build dynamic Service Provider with the updated entity ID
        const dynamicSpMetadataXml = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="SAML-81785735-MyIdPSAML">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${destinationUrl}"/>
  </SPSSODescriptor>
</EntityDescriptor>`;
        
        // Import the SP dynamically
        const { ServiceProvider } = await import('samlify');
        const spConfig = { metadata: dynamicSpMetadataXml };
        const dynamicSP = ServiceProvider(spConfig);
        
        // Create user context
        const user = {
            loginName: loginName,
            siteId: siteId
        };
        
                 // Create custom tag replacement function that handles InResponseTo
         const customTagReplacementFunction = (template) => {
             console.log('🔧 Custom tag replacement with InResponseTo support');
             console.log('🔍 Template type:', typeof template);
             console.log('🔍 Template length:', template ? template.length : 'null/undefined');
             
             if (!template) {
                 console.error('❌ Template is null or undefined');
                 throw new Error('Template parameter is null or undefined');
             }
             
             try {
                 console.log('🔍 Starting template replacements...');
                 let processedTemplate = template;
                 
                 // Verify template is still valid before starting
                 if (!processedTemplate || typeof processedTemplate !== 'string') {
                     throw new Error('Template is null or not a string at start of replacements');
                 }
                 
                 // Do replacements step by step with null checks
                 console.log('🔍 Step 1: ID replacement');
                 if (!processedTemplate || typeof processedTemplate.replace !== 'function') {
                     throw new Error('processedTemplate is null or has no replace method before ID replacement');
                 }
                 processedTemplate = processedTemplate.replace(/{ID}/g, 'response_' + Math.random().toString(36).substr(2, 9));
                 if (!processedTemplate) throw new Error('Template became null after ID replacement');
                 
                 console.log('🔍 Step 2: AssertionID replacement');
                 processedTemplate = processedTemplate.replace(/{AssertionID}/g, 'assertion_' + Math.random().toString(36).substr(2, 9));
                 if (!processedTemplate) throw new Error('Template became null after AssertionID replacement');
                 
                 console.log('🔍 Step 3: IssueInstant replacement');
                 processedTemplate = processedTemplate.replace(/{IssueInstant}/g, new Date().toISOString());
                 if (!processedTemplate) throw new Error('Template became null after IssueInstant replacement');
                 
                 console.log('🔍 Step 4: Destination replacement');
                 processedTemplate = processedTemplate.replace(/{Destination}/g, destinationUrl);
                 if (!processedTemplate) throw new Error('Template became null after Destination replacement');
                 
                 console.log('🔍 Step 5: Issuer replacement');
                 processedTemplate = processedTemplate.replace(/{Issuer}/g, 'https://idp.liveperson.com');
                 if (!processedTemplate) throw new Error('Template became null after Issuer replacement');
                 
                 console.log('🔍 Step 6: StatusCode replacement');
                 processedTemplate = processedTemplate.replace(/{StatusCode}/g, 'urn:oasis:names:tc:SAML:2.0:status:Success');
                 if (!processedTemplate) throw new Error('Template became null after StatusCode replacement');
                 
                 console.log('🔍 Step 7: NameIDFormat replacement');
                 processedTemplate = processedTemplate.replace(/{NameIDFormat}/g, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
                 if (!processedTemplate) throw new Error('Template became null after NameIDFormat replacement');
                 
                 console.log('🔍 Step 8: NameID replacement');
                 processedTemplate = processedTemplate.replace(/{NameID}/g, loginName);
                 if (!processedTemplate) throw new Error('Template became null after NameID replacement');
                 
                 console.log('🔍 Step 9: SubjectConfirmationDataNotOnOrAfter replacement');
                 processedTemplate = processedTemplate.replace(/{SubjectConfirmationDataNotOnOrAfter}/g, new Date(Date.now() + 5 * 60 * 1000).toISOString());
                 if (!processedTemplate) throw new Error('Template became null after SubjectConfirmationDataNotOnOrAfter replacement');
                 
                 console.log('🔍 Step 10: SubjectRecipient replacement');
                 processedTemplate = processedTemplate.replace(/{SubjectRecipient}/g, destinationUrl);
                 if (!processedTemplate) throw new Error('Template became null after SubjectRecipient replacement');
                 
                 console.log('🔍 Step 11: SubjectConfirmationDataRecipient replacement');
                 processedTemplate = processedTemplate.replace(/{SubjectConfirmationDataRecipient}/g, destinationUrl);
                 if (!processedTemplate) throw new Error('Template became null after SubjectConfirmationDataRecipient replacement');
                 
                 console.log('🔍 Step 12: SPNameQualifier replacement');
                 processedTemplate = processedTemplate.replace(/{SPNameQualifier}/g, '');
                 if (!processedTemplate) throw new Error('Template became null after SPNameQualifier replacement');
                 
                 console.log('🔍 Step 13: ConditionsNotBefore replacement');
                 processedTemplate = processedTemplate.replace(/{ConditionsNotBefore}/g, new Date().toISOString());
                 if (!processedTemplate) throw new Error('Template became null after ConditionsNotBefore replacement');
                 
                 console.log('🔍 Step 14: ConditionsNotOnOrAfter replacement');
                 processedTemplate = processedTemplate.replace(/{ConditionsNotOnOrAfter}/g, new Date(Date.now() + 5 * 60 * 1000).toISOString());
                 if (!processedTemplate) throw new Error('Template became null after ConditionsNotOnOrAfter replacement');
                 
                 console.log('🔍 Step 15: Audience replacement');
                 processedTemplate = processedTemplate.replace(/{Audience}/g, 'SAML-81785735-MyIdPSAML');
                 if (!processedTemplate) throw new Error('Template became null after Audience replacement');
                 
                 console.log('🔍 Step 16: AuthnInstant replacement');
                 processedTemplate = processedTemplate.replace(/{AuthnInstant}/g, new Date().toISOString());
                 if (!processedTemplate) throw new Error('Template became null after AuthnInstant replacement');
                 
                 console.log('🔍 Step 17: SessionIndex replacement');
                 processedTemplate = processedTemplate.replace(/{SessionIndex}/g, 'session_' + Math.random().toString(36).substr(2, 9));
                 if (!processedTemplate) throw new Error('Template became null after SessionIndex replacement');
                 
                 console.log('🔍 Step 18: LoginName replacement');
                 processedTemplate = processedTemplate.replace(/{LoginName}/g, loginName);
                 if (!processedTemplate) throw new Error('Template became null after LoginName replacement');
                 
                 console.log('🔍 Step 19: SiteId replacement');
                 processedTemplate = processedTemplate.replace(/{SiteId}/g, siteId);
                 if (!processedTemplate) throw new Error('Template became null after SiteId replacement');
                 
                 console.log('🔍 Step 20: loginName replacement');
                 processedTemplate = processedTemplate.replace(/{loginName}/g, loginName);
                 if (!processedTemplate) throw new Error('Template became null after loginName replacement');
                 
                 console.log('🔍 Step 21: siteId replacement');
                 processedTemplate = processedTemplate.replace(/{siteId}/g, siteId);
                 if (!processedTemplate) throw new Error('Template became null after siteId replacement');
                 
                 console.log('🔍 Main replacements completed successfully');
                 
                 // Handle InResponseTo properly
                 if (inResponseTo) {
                     console.log('🔧 Setting InResponseTo to:', inResponseTo);
                     processedTemplate = processedTemplate.replace(/{InResponseTo}/g, inResponseTo);
                     if (!processedTemplate) throw new Error('Template became null after InResponseTo replacement');
                 } else {
                     console.log('🔧 Removing InResponseTo attributes');
                     processedTemplate = processedTemplate.replace(/\s+InResponseTo=""/g, '');
                     if (!processedTemplate) throw new Error('Template became null after InResponseTo="" removal');
                     
                     processedTemplate = processedTemplate.replace(/\s+InResponseTo="{InResponseTo}"/g, '');
                     if (!processedTemplate) throw new Error('Template became null after InResponseTo="{InResponseTo}" removal');
                     
                     processedTemplate = processedTemplate.replace(/\s+InResponseTo="[^"]*"/g, '');
                     if (!processedTemplate) throw new Error('Template became null after InResponseTo pattern removal');
                 }
                 
                 // Clean up other empty attributes
                 console.log('🔍 Cleaning up empty attributes');
                 processedTemplate = processedTemplate.replace(/\s+SPNameQualifier=""/g, '');
                 if (!processedTemplate) throw new Error('Template became null after SPNameQualifier="" removal');
                 
                 processedTemplate = processedTemplate.replace(/\s+SPNameQualifier="{SPNameQualifier}"/g, '');
                 if (!processedTemplate) throw new Error('Template became null after SPNameQualifier="{SPNameQualifier}" removal');
                 
                 console.log('✅ Template processed with InResponseTo support successfully');
                 
                 return {
                     id: 'custom_response_id_' + Math.random().toString(36).substr(2, 9),
                     context: processedTemplate
                 };
                 
             } catch (error) {
                 console.error('❌ Error in custom tag replacement:', error.message);
                 console.error('❌ Template at error point:', processedTemplate ? processedTemplate.substring(0, 200) + '...' : 'null');
                 throw error;
             }
         };
        
        // Use Auth0-specific SAML response generation with dynamic certificate loading
        console.log('🔍 Calling Auth0 SAML response generation...');
        console.log('🔍 Parameters:');
        console.log('  - siteId:', siteId);
        console.log('  - loginName:', loginName);
        console.log('  - destinationUrl:', destinationUrl);
        console.log('  - shouldEncrypt:', shouldEncrypt);
        console.log('  - inResponseTo:', inResponseTo);
        
        let responseResult;
        try {
            // Create Auth0-specific SAML response with dynamic certificate loading
            responseResult = await createAuth0SAMLResponse(
                siteId,
                loginName,
                destinationUrl,
                shouldEncrypt,
                inResponseTo
            );
            
            console.log('🔍 Auth0 SAML response generation completed');
            console.log('🔍 Response result type:', typeof responseResult);
            console.log('🔍 Response result:', responseResult ? 'exists' : 'null/undefined');
            console.log('🔍 Response result keys:', responseResult ? Object.keys(responseResult) : 'N/A');
            
        } catch (samlifyError) {
            console.error('❌ Auth0 SAML response generation threw an error:', samlifyError.message);
            console.error('❌ Full error:', samlifyError);
            throw new Error('Auth0 SAML response generation failed: ' + samlifyError.message);
        }
        
        // Extract the SAML response from Auth0 SAML response generation result
        if (!responseResult || !responseResult.samlResponse) {
            console.error('❌ Auth0 SAML response generation returned invalid result');
            console.error('❌ ResponseResult structure:', responseResult);
            throw new Error('Auth0 SAML response generation returned invalid result - missing samlResponse');
        }
        
        const samlResponse = responseResult.samlResponse;
        const method = responseResult.method || 'SAMLIFY_SIGNED';
        
        console.log('🔍 SAML response length:', samlResponse.length);
        console.log('🔍 SAML response first 100 chars:', samlResponse.substring(0, 100));
        
        // Determine if the response is actually encrypted/signed
        const isActuallyEncrypted = samlResponse.includes('EncryptedAssertion') || 
                                   samlResponse.includes('EncryptedData');
        const isSigned = samlResponse.includes('Signature');
        
        console.log('🔍 Final method from Auth0 SAML response generation:', method);
        console.log('🔍 Response includes signature:', isSigned);
        console.log('🔍 Response includes encryption:', isActuallyEncrypted);
        
        return {
            samlResponse: samlResponse,
            method: method
        };
        
    } catch (error) {
        console.error('❌ Error creating signed SAML response with InResponseTo:', error.message);
        console.error('❌ Full error details:', error);
        
        // Re-throw the original error for debugging
        throw error;
    }
}

// Auth0-specific SAML response generation with dynamic certificate loading
async function createAuth0SAMLResponse(siteId, loginName, destinationUrl, shouldEncrypt = false, inResponseTo = null) {
    console.log('🔧 createAuth0SAMLResponse called');
    console.log('🔧 Parameters:', { siteId, loginName, destinationUrl, shouldEncrypt, inResponseTo });
    
    // Import the SAML modules
    const { getIdentityProvider } = await import('../saml/saml-core.js');
    const identityProvider = getIdentityProvider();
    
    if (!identityProvider) {
        console.error('❌ SAML not initialized - cannot generate assertion');
        throw new Error('SAML not properly initialized. Identity Provider not available.');
    }

    // Load encryption certificate dynamically if encryption is requested
    let encryptionCert = null;
    if (shouldEncrypt) {
        try {
            console.log('🔍 Loading Auth0 encryption certificate dynamically...');
            
            // Generate certificate URL (defaulting to alpha environment)
            const certUrl = 'https://auth-z1-a.liveperson.net/cer?cert=connection';
            console.log('🔍 Certificate URL:', certUrl);
            
            // Import the certificate download function
            const { downloadAndConvertCertificate } = await import('../saml/saml-encryption.js');
            
                    // Download and convert the certificate
        const certificateData = await downloadAndConvertCertificate(certUrl);
        if (certificateData) {
            encryptionCert = certificateData;
            console.log('✅ Successfully downloaded and converted certificate to DER format');
            console.log('🔍 Certificate length:', encryptionCert.length, 'bytes');
            console.log('🔍 Certificate type:', Buffer.isBuffer(encryptionCert) ? 'DER (Buffer)' : 'PEM (String)');
        } else {
            console.error('❌ ENCRYPTION REQUIRED BUT CERTIFICATE DOWNLOAD FAILED');
            console.error('❌ Certificate URL:', certUrl);
            throw new Error('SAML encryption is enabled but failed to download certificate from: ' + certUrl + '. Please check the certificate URL or disable encryption.');
        }
        } catch (certError) {
            console.error('❌ CRITICAL ERROR: Auth0 encryption certificate loading failed');
            console.error('❌ Error details:', certError.message);
            console.error('❌ Encryption was requested but cannot be completed');
            throw new Error('SAML encryption failed: ' + certError.message + '. Cannot proceed with encryption enabled. Please disable encryption or fix the certificate issue.');
        }
    }

    // Build dynamic Service Provider metadata with encryption certificate if needed
    const { buildDynamicServiceProviderMetadata } = await import('../saml/saml-response.js');
    const dynamicSpMetadataXml = buildDynamicServiceProviderMetadata(destinationUrl, shouldEncrypt, encryptionCert);
    console.log('🔍 Dynamic SP metadata includes encryption KeyDescriptor:', dynamicSpMetadataXml.includes('use="encryption"'));
    
    // Import the SP dynamically
    const { ServiceProvider } = await import('samlify');
    const spConfig = { metadata: dynamicSpMetadataXml };
    const dynamicSP = ServiceProvider(spConfig);

    // Create user context
    const user = {
        loginName: loginName,
        siteId: siteId
    };

    // Create the customTagReplacement function
    const { createCustomTagReplacementFunction } = await import('../saml/saml-response.js');
    const customTagReplacementFunction = createCustomTagReplacementFunction(destinationUrl, loginName, siteId, inResponseTo);

    // Call createLoginResponse with correct parameter order
    console.log('🔍 Calling samlify createLoginResponse for Auth0...');
    console.log('🔍 Dynamic SP entity ID:', dynamicSP.entityMeta.getEntityID());
    console.log('🔍 Encryption enabled:', shouldEncrypt);
    
    let responseResult;
    if (shouldEncrypt && encryptionCert) {
        // For encryption, we need to create a temporary IdP with encryption enabled
        console.log('🔍 Creating temporary IdP with encryption enabled...');
        const { createEncryptionEnabledIdP } = await import('../saml/saml-core.js');
        const encryptionIdP = await createEncryptionEnabledIdP(encryptionCert);
        
        responseResult = await encryptionIdP.createLoginResponse(
            dynamicSP,
            null,
            'post',
            user,
            customTagReplacementFunction,
            true, // Force encryption
            null
        );
    } else {
        responseResult = await identityProvider.createLoginResponse(
            dynamicSP,
            null,
            'post',
            user,
            customTagReplacementFunction,
            false, // No encryption
            null
        );
    }
    
    console.log('🔍 Samlify createLoginResponse completed for Auth0');
    
    // Extract and process the SAML response
    const { extractSAMLResponseFromResult, processSAMLResponse } = await import('../saml/saml-response.js');
    const samlResponse = extractSAMLResponseFromResult(responseResult);
    const actualXmlResponse = processSAMLResponse(samlResponse);
    
    // Determine if the response is actually encrypted
    const isActuallyEncrypted = actualXmlResponse.includes('EncryptedAssertion') || 
                               actualXmlResponse.includes('EncryptedData');
    
    const method = isActuallyEncrypted ? 'SAMLIFY_SIGNED_ENCRYPTED' : 'SAMLIFY_SIGNED';
    console.log('🔍 Auth0 SAML method determined:', method);
    
    return {
        samlResponse: actualXmlResponse,
        method: method
    };
}



// Auth0 SAML assertion generation endpoint
router.post('/generate-auth0-saml-assertion', async (req, res) => {
    const { siteId, loginName, destinationUrl, shouldEncrypt, method, encryptionCertName, samlType } = req.body;
    
    // Get current state from main app
    const { encryptionEnabled } = req.app.locals;
    
    // Use shouldEncrypt if provided, otherwise fall back to global setting
    const requestEncryption = shouldEncrypt !== undefined ? shouldEncrypt : encryptionEnabled;
    
    console.log('🔐 Generating Auth0 SAML assertion for:', { 
        siteId, 
        loginName, 
        destinationUrl,
        requestEncryption, 
        globalEncryption: encryptionEnabled,
        samlType
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
        // Use the provided destinationUrl for Auth0
        const finalDestinationUrl = destinationUrl || 'https://auth-z1-a.liveperson.net/login/callback';
        
        console.log('📍 Auth0 SAML Response Destination:', finalDestinationUrl);
        console.log('🔐 Encryption requested:', requestEncryption);
        
        // Generate SAML response for Auth0 using the createSAMLResponse function
        const samlMethod = method || config.saml.implementation || 'auto';
        console.log('🛠️ Using SAML method for Auth0:', samlMethod);
        
        const result = await createSAMLResponse(siteId, loginName, finalDestinationUrl, requestEncryption, samlMethod);
        
        let finalAssertion, assertionBase64, usedMethod;
        
        if (result && result.samlResponse) {
            finalAssertion = result.samlResponse;
            assertionBase64 = Buffer.from(result.samlResponse).toString('base64');
            usedMethod = result.method;
            
            console.log('✅ Auth0 SAML assertion generated successfully');
            console.log('🔧 Method used:', usedMethod);
            console.log('📏 Response length:', finalAssertion.length, 'chars');
            console.log('📏 Base64 length:', assertionBase64.length, 'chars');
            console.log('🔐 Encryption status:', usedMethod.includes('ENCRYPTED') ? 'ENCRYPTED' : 'UNENCRYPTED');
        } else {
            throw new Error('Failed to generate Auth0 SAML assertion - no result returned');
        }
        
        res.json({
            success: true,
            xml: finalAssertion,
            base64: assertionBase64,
            encrypted: usedMethod.includes('ENCRYPTED'),
            destination: finalDestinationUrl,
            method: usedMethod,
            encryptionUsed: requestEncryption && usedMethod.includes('ENCRYPTED'),
            samlType: 'auth0'
        });
        
    } catch (error) {
        console.error('❌ Error generating Auth0 SAML assertion:', error.message);
        console.error('Stack trace:', error.stack);
        res.json({
            success: false,
            error: error.message
        });
    }
});

// OIDC Auth0 testing page
router.get('/agentsso-oidc-auth0', (req, res) => {
    const html = generateOIDCAuth0Page();
    res.send(html);
});

// OIDC Front Channel Flow initiation
router.post('/oidc/front-channel/initiate', (req, res) => {
    const { accountId, username, connectionName } = req.body;
    
    console.log('🚀 OIDC Front Channel Flow initiation:', {
        accountId,
        username, 
        connectionName
    });
    
    // Construct LivePerson Auth URL for OIDC
    const authUrl = `https://authentication.liveperson.net/accountSelection.html?stId=${accountId}&prompt=none`;
    
    console.log('🔗 Redirecting to LivePerson Auth URL:', authUrl);
    
    // Return JSON response with redirect URL
    res.json({
        success: true,
        authUrl: authUrl,
        message: 'OIDC Front Channel flow initiated'
    });
});

// OIDC Back Channel Flow initiation endpoint
router.post('/oidc/back-channel/initiate', (req, res) => {
    const { accountId, username, connectionName } = req.body;
    
    console.log('🔒 OIDC Back Channel Flow initiated:', {
        accountId,
        username, 
        connectionName
    });
    
    // Construct LivePerson Auth URL for OIDC (same as front channel for SP-initiated)
    const authUrl = `https://authentication.liveperson.net/accountSelection.html?stId=${accountId}&prompt=none`;
    
    console.log('🔗 Redirecting to LivePerson Auth URL for Back Channel:', authUrl);
    
    // Return JSON response with redirect URL
    res.json({
        success: true,
        authUrl: authUrl,
        message: 'OIDC Back Channel flow initiated'
    });
});

/**
 * Generate OIDC Auth0 testing page HTML
 * @returns {string} HTML content
 */
function generateOIDCAuth0Page() {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>LivePerson OIDC Auth0 SSO</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }
            .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .form-group { margin: 15px 0; }
            .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
            .form-group input, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
            .btn:hover { background: #0056b3; }
            .btn-secondary { background: #6c757d; }
            .btn-secondary:hover { background: #5a6268; }
            .info-box { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 20px 0; border-radius: 5px; }
            .success-box { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; margin: 20px 0; border-radius: 5px; color: #155724; }
            .error-box { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; margin: 20px 0; border-radius: 5px; color: #721c24; }
            .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
            .nav-link { color: #007bff; text-decoration: none; margin-right: 15px; font-weight: bold; }
            .nav-link:hover { text-decoration: underline; }
            .config-section { background: #f8f9fa; border: 1px solid #dee2e6; padding: 20px; margin: 20px 0; border-radius: 5px; }
            .config-item { background: white; border: 1px solid #dee2e6; padding: 10px; margin: 5px 0; border-radius: 3px; font-family: monospace; }
            .flow-tabs { display: flex; margin-bottom: 20px; border-bottom: 1px solid #dee2e6; }
            .flow-tab { padding: 10px 20px; cursor: pointer; border: none; background: none; border-bottom: 2px solid transparent; }
            .flow-tab.active { border-bottom-color: #007bff; font-weight: bold; }
            .flow-content { display: none; }
            .flow-content.active { display: block; }
        </style>
        <script>
            function switchFlow(flowType) {
                // Hide all flow content
                document.querySelectorAll('.flow-content').forEach(content => {
                    content.classList.remove('active');
                });
                
                // Remove active class from all tabs
                document.querySelectorAll('.flow-tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Show selected flow content and activate tab
                document.getElementById(flowType + '-flow').classList.add('active');
                document.getElementById(flowType + '-tab').classList.add('active');
                
                console.log('🔄 Switched to', flowType, 'flow');
            }
            
            async function startFrontChannelFlow() {
                const accountId = document.getElementById('fc-accountId').value;
                const username = document.getElementById('fc-username').value;
                const connectionName = document.getElementById('fc-connectionName').value;
                
                if (!accountId || !username || !connectionName) {
                    showMessage('Please fill in all required fields', 'error');
                    return;
                }
                
                console.log('🚀 Starting OIDC Front Channel Flow');
                
                try {
                    const response = await fetch('/oidc/front-channel/initiate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ accountId, username, connectionName })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showMessage('Redirecting to LivePerson authentication...', 'success');
                        console.log('🔗 Opening auth URL:', result.authUrl);
                        
                        // Open in new window/tab
                        window.open(result.authUrl, '_blank');
                    } else {
                        showMessage('Failed to initiate flow: ' + (result.error || 'Unknown error'), 'error');
                    }
                } catch (error) {
                    console.error('❌ Error starting front channel flow:', error);
                    showMessage('Error: ' + error.message, 'error');
                }
            }
            
            async function startBackChannelFlow() {
                const accountId = document.getElementById('bc-accountId').value;
                const username = document.getElementById('bc-username').value;
                const connectionName = document.getElementById('bc-connectionName').value;
                
                if (!accountId || !username || !connectionName) {
                    showMessage('Please fill in all required fields', 'error');
                    return;
                }
                
                console.log('🔒 Starting OIDC Back Channel Flow');
                
                try {
                    const response = await fetch('/oidc/back-channel/initiate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ accountId, username, connectionName })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showMessage('Redirecting to LivePerson authentication...', 'success');
                        console.log('🔗 Opening auth URL:', result.authUrl);
                        
                        // Open in new window/tab
                        window.open(result.authUrl, '_blank');
                    } else {
                        showMessage('Failed to initiate flow: ' + (result.error || 'Unknown error'), 'error');
                    }
                } catch (error) {
                    console.error('❌ Error starting back channel flow:', error);
                    showMessage('Error: ' + error.message, 'error');
                }
            }
            
            function showMessage(message, type) {
                const messageDiv = document.getElementById('message');
                messageDiv.textContent = message;
                messageDiv.className = type + '-box';
                messageDiv.style.display = 'block';
                
                setTimeout(() => {
                    messageDiv.style.display = 'none';
                }, 5000);
            }
            
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    console.log('📋 Copied to clipboard:', text);
                });
            }
            
            // Populate URLs with actual domain
            function populateUrls() {
                const baseUrl = window.location.origin;
                
                // Update individual endpoints
                document.getElementById('issuerUrl').textContent = baseUrl;
                document.getElementById('authUrl').textContent = baseUrl + '/authorize';
                document.getElementById('tokenUrl').textContent = baseUrl + '/token';
                document.getElementById('jwksUrl').textContent = baseUrl + '/.well-known/jwks.json';
                
                console.log('✅ OIDC URLs populated with base URL:', baseUrl);
            }
            
            // Copy text from element by ID
            function copyFromElement(elementId) {
                const element = document.getElementById(elementId);
                if (element) {
                    copyToClipboard(element.textContent);
                } else {
                    console.error('Element not found:', elementId);
                }
            }
            
            // Initialize page
            window.addEventListener('load', function() {
                switchFlow('front-channel'); // Default to front channel
                populateUrls(); // Populate actual URLs
            });
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🔐 LivePerson OIDC Auth0 SSO</h1>
            
            <nav style="margin-bottom: 20px;">
                <a href="/" class="nav-link">🏠 Back to Dashboard</a>
                <a href="/agentsso-denver" class="nav-link">🔑 Denver SAML</a>
                <a href="/agentsso-auth0" class="nav-link">🔑 Auth0 SAML</a>
                <a href="/test" class="nav-link">🧪 Consumer Test Page</a>
                <a href="/.well-known/openid-configuration" class="nav-link">⚙️ OIDC Configuration</a>
            </nav>
            
            <div class="info-box">
                <h3>📋 OIDC (OpenID Connect) Authentication</h3>
                <p>This page allows you to test LivePerson's OIDC SSO authentication flows.</p>
                <ul>
                    <li><strong>Front Channel:</strong> Implicit flow with ID tokens</li>
                    <li><strong>Back Channel:</strong> Authorization code flow with token exchange</li>
                    <li><strong>Connection Name:</strong> MyIdPOIDCFC (for LivePerson Front Channel configuration)</li>
                    <li><strong>Scopes:</strong> openid, profile, email</li>
                </ul>
            </div>
            
            <!-- Flow Selection Tabs -->
            <div class="flow-tabs">
                <button id="front-channel-tab" class="flow-tab active" onclick="switchFlow('front-channel')">
                    🔄 Front Channel (Implicit)
                </button>
                <button id="back-channel-tab" class="flow-tab" onclick="switchFlow('back-channel')">
                    🔒 Back Channel (Code)
                </button>
            </div>
            
            <!-- Front Channel Flow -->
            <div id="front-channel-flow" class="flow-content active">
                <div class="info-box">
                    <h3>🔄 Front Channel Flow (Implicit)</h3>
                    <p>Direct ID token response without token exchange.</p>
                </div>
                
                <div class="form-group">
                    <label for="fc-accountId">Account ID:</label>
                    <input type="text" id="fc-accountId" value="81785735" placeholder="LivePerson Account ID">
                </div>
                
                <div class="form-group">
                    <label for="fc-username">Username:</label>
                    <input type="text" id="fc-username" value="admin" placeholder="Agent Username">
                </div>
                
                <div class="form-group">
                    <label for="fc-connectionName">Connection Name:</label>
                    <input type="text" id="fc-connectionName" value="MyIdPOIDCFC" placeholder="OIDC Connection Name">
                </div>
                
                <button class="btn" onclick="startFrontChannelFlow()">🚀 Start Front Channel Flow</button>
                
                <div class="warning-box">
                    <strong>Note:</strong> This will open LivePerson authentication in a new tab.
                </div>
            </div>
            
            <!-- Back Channel Flow -->
            <div id="back-channel-flow" class="flow-content">
                <div class="info-box">
                    <h3>🔒 Back Channel Flow (Authorization Code)</h3>
                    <p>Authorization code with token exchange for enhanced security.</p>
                </div>
                
                <div class="form-group">
                    <label for="bc-accountId">Account ID:</label>
                    <input type="text" id="bc-accountId" value="81785735" placeholder="LivePerson Account ID">
                </div>
                
                <div class="form-group">
                    <label for="bc-username">Username:</label>
                    <input type="text" id="bc-username" value="admin" placeholder="Agent Username">
                </div>
                
                <div class="form-group">
                    <label for="bc-connectionName">Connection Name:</label>
                    <input type="text" id="bc-connectionName" value="MyIdPOIDCBC" placeholder="OIDC Connection Name">
                </div>
                
                <button class="btn" onclick="startBackChannelFlow()">🚀 Start Back Channel Flow</button>
                
                <div class="warning-box">
                    <strong>Note:</strong> This will open LivePerson authentication in a new tab using authorization code flow.
                </div>
            </div>
            
            <div id="message" style="display: none;"></div>
            
            <div class="config-section">
                <h3>🔧 OIDC Configuration</h3>
                <p>Use these endpoints to configure LivePerson OIDC connection:</p>
                
                <div class="config-item">
                    <strong>Issuer:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;" id="issuerUrl">Loading...</span>
                    <button onclick="copyFromElement('issuerUrl')" style="margin-left: 8px; padding: 4px 8px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;" title="Copy Issuer URL">📋 Copy</button>
                </div>
                <div class="config-item">
                    <strong>Authorization Endpoint:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;" id="authUrl">Loading...</span>
                    <button onclick="copyFromElement('authUrl')" style="margin-left: 8px; padding: 4px 8px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;" title="Copy Authorization Endpoint">📋 Copy</button>
                </div>
                <div class="config-item">
                    <strong>Token Endpoint:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;" id="tokenUrl">Loading...</span>
                    <button onclick="copyFromElement('tokenUrl')" style="margin-left: 8px; padding: 4px 8px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;" title="Copy Token Endpoint">📋 Copy</button>
                </div>
                <div class="config-item">
                    <strong>JWKS URL:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;" id="jwksUrl">Loading...</span>
                    <button onclick="copyFromElement('jwksUrl')" style="margin-left: 8px; padding: 4px 8px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;" title="Copy JWKS URL">📋 Copy</button>
                </div>
                <div class="config-item">
                    <strong>Client ID:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;">MyIdPOIDC</span>
                    <button onclick="copyToClipboard('MyIdPOIDC')" style="margin-left: 8px; padding: 4px 8px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;" title="Copy Client ID">📋 Copy</button>
                </div>
                <div class="config-item">
                    <strong>Client Secret:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;">client-secret-123</span>
                    <button onclick="copyToClipboard('client-secret-123')" style="margin-left: 8px; padding: 4px 8px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;" title="Copy Client Secret">📋 Copy</button>
                </div>
                <div class="config-item">
                    <strong>Scopes:</strong> <span onclick="copyToClipboard(this.textContent)" style="cursor: pointer;">openid profile email</span>
                </div>
                        </div>
        </div>
    </body>
    </html>
    `;
}

export { router as samlRoutes }; 