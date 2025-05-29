const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jose = require('jose');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Encryption toggle state
let encryptionEnabled = false;

// OAuth flow type state
let flowType = 'implicit'; // 'implicit', 'code', or 'codepkce'

// In-memory store for authorization codes (in production, use Redis or database)
const authorizationCodes = new Map();

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
        const computedChallenge = base64URLEncode(hash);
        return computedChallenge === codeChallenge;
    } else if (method === 'plain') {
        return codeVerifier === codeChallenge;
    }
    return false;
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
let signingPrivateKey, signingPublicKey, encryptionPublicKey, lpEncryptionPublicKey;

function loadKeys() {
    try {
        // Load required signing keys
        signingPrivateKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-private.pem'), 'utf8');
        signingPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-public.pem'), 'utf8');
        console.log('✓ Signing keys loaded successfully');
        
        // Try to load optional encryption keys
        try {
            encryptionPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'encryption-public.pem'), 'utf8');
            console.log('✓ Encryption keys loaded');
        } catch (error) {
            console.log('⚠ Encryption keys not found - JWE encryption will be unavailable');
            encryptionPublicKey = null;
        }
        
        // Try to load LivePerson encryption certificate
        try {
            lpEncryptionPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'lpsso2026.pem'), 'utf8');
            console.log('✓ LivePerson encryption certificate (lpsso2026.pem) loaded');
        } catch (error) {
            console.log('⚠ LivePerson encryption certificate (lpsso2026.pem) not found - place it in ./certs/ for JWE encryption');
            lpEncryptionPublicKey = null;
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
            <p>Local Identity Provider for testing LivePerson consumer authentication</p>
        </div>
        
        <div class="encryption-toggle">
            <h3>🔐 JWE Encryption Control</h3>
            <label class="toggle-switch">
                <input type="checkbox" id="encryptionToggle" ${encryptionEnabled ? 'checked' : ''} onchange="toggleEncryption()">
                <span class="slider"></span>
            </label>
            <span class="encryption-status">
                ${encryptionEnabled ? '✓ ENCRYPTION ENABLED' : '✗ ENCRYPTION DISABLED (Signing Only)'}
            </span>
            <p><strong>Status:</strong> ${encryptionEnabled ? 
                (lpEncryptionPublicKey ? 'Ready for JWE encryption with LivePerson certificate (kid: lpsso2026)' : 
                'Encryption enabled but lpsso2026.pem not found in ./certs/') :
                'Currently using JWT signing only (RS256) - easier for initial testing'
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
                        const issuer = \`https://mature-mackerel-golden.ngrok-free.app/\${currentFlowType}\`;
                        
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
        // Return LivePerson certificate if available, otherwise our generated one
        const keyToReturn = lpEncryptionPublicKey || encryptionPublicKey;
        
        if (!keyToReturn) {
            return res.status(404).json({ 
                error: 'No encryption key available',
                message: 'Neither LivePerson certificate (lpsso2026.pem) nor generated encryption keys are available'
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
        uptime: process.uptime(),
        encryptionEnabled: encryptionEnabled,
        lpCertificateAvailable: !!lpEncryptionPublicKey,
        flowType: flowType,
        issuer: `https://mature-mackerel-golden.ngrok-free.app/${flowType}`
    });
});

// Start server
function startServer() {
    loadKeys();
    
    app.listen(PORT, () => {
        console.log(`\n🚀 LivePerson IDP Server running on http://localhost:${PORT}`);
        console.log(`📋 View request logs at: http://localhost:${PORT}`);
        console.log(`🔑 JWKS endpoint: http://localhost:${PORT}/.well-known/jwks.json`);
        console.log(`🔐 Encryption public key: http://localhost:${PORT}/encryption-public-key`);
        console.log(`\n💡 To expose via ngrok: ngrok http ${PORT}`);
        console.log(`\nEndpoints for LivePerson configuration:`);
        console.log(`- Authorization URL: http://localhost:${PORT}/authorize (OAuth 2.0 - both code and implicit flow)`);
        console.log(`- Token URL: http://localhost:${PORT}/token (OAuth 2.0 - code exchange)`);
        console.log(`- Direct Token URL: http://localhost:${PORT}/token-direct (Testing only - not OAuth standard)`);
        console.log(`- JWKS URL: http://localhost:${PORT}/.well-known/jwks.json`);
        console.log(`\n🔐 Encryption: ${encryptionEnabled ? 'ENABLED' : 'DISABLED (Signing Only)'}`);
        console.log(`📜 LivePerson cert: ${lpEncryptionPublicKey ? 'LOADED (lpsso2026.pem)' : 'NOT FOUND (place lpsso2026.pem in ./certs/)'}`);
    });
}

startServer(); 