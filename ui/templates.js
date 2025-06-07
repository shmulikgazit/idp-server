// UI Templates for LivePerson IDP Server
import config from '../config/config.js';

/**
 * Generate the main dashboard HTML page
 */
export function generateDashboardHTML(options = {}) {
    const {
        PORT = config.server.port,
        encryptionEnabled = false,
        flowType = 'implicit',
        lpEncryptionPublicKey = null,
        requestLogs = []
    } = options;

    return `
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
            <h3> Encryption Control (JWT + SAML)</h3>
            <label class="toggle-switch">
                <input type="checkbox" id="encryptionToggle" ${encryptionEnabled ? 'checked' : ''} onchange="toggleEncryption()">
                <span class="slider"></span>
            </label>
            <span class="encryption-status">
                ${encryptionEnabled ? 'OK ENCRYPTION ENABLED' : 'WARN ENCRYPTION DISABLED (Signing Only)'}
            </span>
            <p><strong>Status:</strong> ${encryptionEnabled ? 
                (lpEncryptionPublicKey ? 'OK Ready for JWE encryption (consumer auth) and SAML encryption (Denver Agent SSO) with LivePerson certificate (kid: lpsso2026)' : 
                'Encryption enabled but lpsso2026.pem not found in ./certs/') :
                'Currently using JWT signing only (RS256) for consumer auth and SAML signing only for Denver Agent SSO - easier for initial testing'
            }</p>
            
            <h3 style="margin-top: 25px;"> OAuth Flow Type</h3>
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
            <h3>Server Status: OK Running on port ${PORT}</h3>
            <p><strong>Available Endpoints:</strong></p>
            <ul>
                <li><code>GET /</code> - This page (request logs)</li>
                <li><code>GET /test</code> - <a href="/test" target="_blank" style="color: #007bff;">LivePerson Test Page</a> (with chat widget, no auto-refresh)</li>
                <li><code>GET /agentsso-denver</code> - <a href="/agentsso-denver" target="_blank" style="color: #007bff;">Denver SAML SSO Testing Page</a></li>
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
                <div><strong> Mode:</strong> <span style="color: ${log.encryptionMode.includes('ENCRYPTION') ? '#28a745' : '#dc3545'};">${log.encryptionMode}</span></div>
                <div><strong> Flow:</strong> <span style="color: #007bff;">${log.flowType}</span> | <strong> Issuer:</strong> <code style="font-size: 11px;">${log.issuer}</code></div>
                ${log.clientCredentials ? `
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 8px; margin: 5px 0; border-radius: 4px;">
                        <strong> Client Auth:</strong> ${log.clientCredentials.type}
                        ${log.clientCredentials.type === 'Basic' ? `
                            | <strong>Client ID:</strong> <code style="color: #007bff;">${log.clientCredentials.clientId}</code>
                            | <strong>Secret:</strong> <code style="color: #6c757d;">${log.clientCredentials.clientSecret}</code>
                        ` : log.clientCredentials.type === 'Bearer' ? `
                            | <strong>Token:</strong> <code style="color: #28a745;">${log.clientCredentials.token}</code>
                        ` : `
                            | <strong>Value:</strong> <code style="color: #dc3545;">${log.clientCredentials.value || log.clientCredentials.error}</code>
                        `}
                    </div>
                ` : ''}
                ${log.query && Object.keys(log.query).length > 0 ? `<div><strong>Query:</strong> <pre>${JSON.stringify(log.query, null, 2)}</pre></div>` : ''}
                ${log.body && Object.keys(log.body).length > 0 ? `<div><strong>Body:</strong> <pre>${JSON.stringify(log.body, null, 2)}</pre></div>` : ''}
                ${log.response ? `
                    <div><strong> Response (${log.response.statusCode}):</strong></div>
                    ${log.tokenAnalysis ? `
                        <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin: 5px 0; border-radius: 4px;">
                            <strong> Token Analysis:</strong><br>
                            ID Token: ${log.tokenAnalysis.id_token_length} chars, ${log.tokenAnalysis.id_token_format}<br>
                            Access Token: ${log.tokenAnalysis.access_token_length} chars, ${log.tokenAnalysis.access_token_format}
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
}

/**
 * Generate the OAuth callback HTML page
 */
export function generateOAuthCallbackHTML() {
    return `
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
}

/**
 * Generate the LivePerson test page HTML
 */
export function generateTestPageHTML(options = {}) {
    const {
        PORT = config.server.port,
        encryptionEnabled = false,
        flowType = 'implicit'
    } = options;

    return `
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
            function lpgetToken(callback, code_challenge) {
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
                                    console.log('OK Authorization code (ssoKey) received:', data.ssoKey);
                                    console.log(' Token Passing ssoKey to LivePerson - LP IdP will call /token endpoint');
                                    console.log(' Token LivePerson should treat this as authorization code, not id_token');
                                    // Pass the ssoKey to LivePerson - they will handle the token exchange
                                    callback(data.ssoKey);
                                } else if (data.error) {
                                    console.error('WARN OAuth error:', data.error, data.error_description);
                                    callback(null);
                                } else {
                                    console.error('WARN No ssoKey in response');
                                    callback(null);
                                }
                            })
                            .catch(error => {
                                console.error('WARN Error in Authorization Code Flow:', error);
                                callback(null);
                            });
                            
                        } else if (currentFlowType === 'codepkce') {
                            // Authorization Code Flow with PKCE
                            console.log('Using Authorization Code Flow with PKCE...');
                            
                            if (code_challenge) {
                                console.log(' Token OK Received code_challenge from LivePerson:', code_challenge);
                            } else {
                                console.error(' Token WARN No code_challenge provided by LivePerson');
                                callback(null, new Error('No code_challenge provided'));
                                return;
                            }
                            
                            const params = new URLSearchParams({
                                response_type: 'code',
                                client_id: 'liveperson-client',
                                scope: 'openid profile email',
                                state: 'liveperson-test',
                                redirect_uri: window.location.origin + '/oauth-callback.html',
                                code_challenge: code_challenge,
                                code_challenge_method: 'S256'
                            });
                            
                            console.log(' Token Sending PKCE parameters to /authorize:', {
                                code_challenge: code_challenge.substring(0, 20) + '...',
                                code_challenge_method: 'S256'
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
                                console.log('OAuth Code+PKCE Flow response:', data);
                                if (data.ssoKey) {
                                    console.log('OK Authorization code received from PKCE flow');
                                    console.log(' Token Returning ssoKey to LivePerson - LP IdP will call /token with code_verifier');
                                    
                                    // For PKCE flow, just return the authorization code
                                    // LivePerson will handle the token exchange with code_verifier
                                    callback(data.ssoKey);
                                } else if (data.error) {
                                    console.error('WARN PKCE OAuth error:', data.error, data.error_description);
                                    callback(null);
                                } else {
                                    console.error('WARN No authorization code in PKCE response');
                                    callback(null);
                                }
                            })
                            .catch(error => {
                                console.error('WARN Error in Code+PKCE Flow:', error);
                                callback(null);
                            });
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
                                    console.log('OK Calling LivePerson callback with ID token from Implicit Flow');
                                    console.log('Token format:', data.id_token.split('.').length === 3 ? 'JWT (3 parts)' : data.id_token.split('.').length === 5 ? 'JWE (5 parts)' : 'Unknown');
                                    callback(data.id_token);
                                } else if (data.error) {
                                    console.error('WARN OAuth error:', data.error, data.error_description);
                                    callback(null);
                                } else {
                                    console.error('WARN No ID token in response');
                                    callback(null);
                                }
                            })
                            .catch(error => {
                                console.error('WARN Error in Implicit Flow:', error);
                                callback(null);
                            });
                        }
                    })
                    .catch(error => {
                        console.error('WARN Error getting flow type:', error);
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
            <h1> LivePerson IDP Server - Test Page</h1>
            <p>Testing LivePerson Chat Integration with Authentication</p>
        </div>
        
        <div class="content">
            <nav style="margin-bottom: 20px;">
                <a href="/" class="nav-link"> Back to Dashboard</a>
                <a href="/health" class="nav-link">Health Check</a>
                <a href="/.well-known/jwks.json" class="nav-link">JWKS</a>
            </nav>
            
            <div class="info-box">
                <h3> OK LivePerson Chat Integration Active</h3>
                <p>This page includes the LivePerson lpTag script and should display the chat widget.</p>
                <p><strong>Site ID:</strong> a41244303</p>
                <p><strong>Domain:</strong> lptag-a.liveperson.net</p>
                <p><strong>Status:</strong> Chat widget should appear in the bottom right corner</p>
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin-top: 10px; border-radius: 4px; font-size: 12px;">
                    <strong> WARN Note:</strong> You may see console errors from <code>web-client-content-script.js</code> - these are from LivePerson's own code and can be safely ignored. They don't affect authentication functionality.
                </div>
            </div>
            
            <div class="info-box" style="background: #e7f3ff; border: 1px solid #b3d9ff;">
                <h3> Token Authenticated Identity Function Configured</h3>
                <p>This page includes the authenticated identity function in <code>lpTag.identities</code> (placed BEFORE the lpTag script):</p>
                <ul>
                    <li><strong>Issuer (iss):</strong> <code>Dynamic based on current flow type</code></li>
                    <li><strong>Implicit Flow:</strong> <code>https://mature-mackerel-golden.ngrok-free.app/implicit</code></li>
                    <li><strong>Code Flow:</strong> <code>https://mature-mackerel-golden.ngrok-free.app/code</code></li>
                    <li><strong>Subject (sub):</strong> <code>test-user-123</code></li>
                    <li><strong>ACR (Authentication Context Class Reference):</strong> <code>loa1</code></li>
                </ul>
                <p><strong> OK Dynamic Issuer Matching:</strong> The identity function automatically detects the current flow type and uses the matching issuer URL.</p>
                <p><strong> Token Implementation:</strong> Uses the correct LivePerson identity function format that calls a callback with the identity object.</p>
                <p>This tells LivePerson which IdP configuration to use based on the current flow type.</p>
            </div>
            
            <div class="user-info">
                <h3> Token JWT Token Claims</h3>
                <p>When testing authentication, this JWT will be generated with the following claims:</p>
                
                <h4> Token Standard JWT Claims:</h4>
                <ul>
                    <li><strong>Issuer (iss):</strong> <code>https://mature-mackerel-golden.ngrok-free.app</code></li>
                    <li><strong>Subject (sub):</strong> test-user-123</li>
                    <li><strong>Audience (aud):</strong> liveperson-client (or client_id from request)</li>
                    <li><strong>Expires (exp):</strong> 1 hour from issue time</li>
                    <li><strong>Issued At (iat):</strong> Current timestamp</li>
                    <li><strong>Algorithm:</strong> RS256 (RSA Signature with SHA-256)</li>
                    <li><strong>Key ID (kid):</strong> signing-key-1</li>
                </ul>
                
                <h4> Token User Profile Claims:</h4>
                <ul>
                    <li><strong>Name:</strong> Test User</li>
                    <li><strong>Given Name:</strong> Test</li>
                    <li><strong>Family Name:</strong> User</li>
                    <li><strong>Email:</strong> test.user@example.com</li>
                    <li><strong>Phone:</strong> +1234567890</li>
                </ul>
                
                <h4> Token LivePerson SDES Claims:</h4>
                <ul>
                    <li><strong>Customer ID:</strong> test-user-123 (matches user_id)</li>
                    <li><strong>Customer Type:</strong> premium</li>
                    <li><strong>Account Balance:</strong> $1,500.00</li>
                    <li><strong>Account Number:</strong> ACC-123123 (derived from user_id)</li>
                </ul>
                
                <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 10px; margin-top: 15px; border-radius: 4px;">
                    <strong> Token Note:</strong> When using ngrok, update the issuer (iss) to your ngrok URL for production testing.
                </div>
            </div>
            
            <div class="content">
                <h3> Token OAuth 2.0 Authentication Flows</h3>
                <p>This IDP server supports both standard OAuth 2.0 flows:</p>
                
                <div style="background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4> Token Authorization Code Flow (Recommended):</h4>
                    <ol>
                        <li><strong>Step 1:</strong> <code>GET /authorize?response_type=code&client_id=...&redirect_uri=...</code></li>
                        <li><strong>Step 2:</strong> <code>POST /token</code> with authorization code</li>
                    </ol>
                    
                    <h4> Token Authorization Code Flow + PKCE:</h4>
                    <ol>
                        <li><strong>Step 1:</strong> <code>GET /authorize?response_type=code&code_challenge=...&code_challenge_method=S256</code></li>
                        <li><strong>Step 2:</strong> <code>POST /token</code> with authorization code + code_verifier</li>
                        <li><strong>PKCE Verification:</strong> Server verifies SHA256(code_verifier) == code_challenge</li>
                    </ol>
                    
                    <h4> Token Implicit Flow:</h4>
                    <ol>
                        <li><strong>Step 1:</strong> <code>GET /authorize?response_type=id_token&client_id=...&redirect_uri=...</code></li>
                        <li>Tokens returned directly in URL fragment</li>
                    </ol>
                    
                    <h4> Token Direct Token (Testing Only):</h4>
                    <ul>
                        <li><strong>Endpoint:</strong> <code>POST /token-direct</code></li>
                        <li><strong>Purpose:</strong> Simplified testing without OAuth flow</li>
                        <li><strong>Usage:</strong> Send user_id and client_id directly</li>
                    </ul>
                </div>
                
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4> Token Test Authentication Function:</h4>
                    <p>Click the button below to test the <code>lpgetToken(callback)</code> function that LivePerson will call:</p>
                    <button onclick="testTokenRetrieval()" style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 10px 0;">
                        Token Test Token Retrieval
                    </button>
                    <div id="tokenDisplay" style="margin-top: 15px; font-family: monospace; font-size: 12px;"></div>
                    <p style="margin-top: 10px; font-size: 12px; color: #666;">
                        <strong>Note:</strong> Now using proper OAuth 2.0 <code>/authorize</code> endpoint with implicit flow. The endpoint detects AJAX requests and returns tokens directly as JSON.
                    </p>
                </div>
            </div>
            
            <div class="content">
                <h3> Token LivePerson Configuration</h3>
                <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; margin: 15px 0; border-radius: 5px;">
                    <h4> Token For Production Use:</h4>
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
                    <h4> Token For Testing (Current Setup):</h4>
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
                        <strong> OK LivePerson Integration:</strong> 
                        <br> Token Authorization Code Flow: Uses popup with <code>ssoKey</code> callback parameter (LivePerson standard)
                        <br> Token Code + PKCE Flow: LivePerson handles PKCE challenge/verifier automatically
                        <br> Token Implicit Flow: Direct AJAX call for testing
                        <br> Token Client Auth: LivePerson IdP will use clientid/1234567890 credentials
                        <br> Token Multiple IdPs: Different issuers allow testing multiple configurations
                    </p>
                </div>
            </div>
            
            <div class="info-box">
                <h4> Token Pro Tip</h4>
                <p>This page doesn't auto-refresh, so the LivePerson chat widget will maintain its state. 
                Use this page for testing chat functionality while monitoring requests on the main dashboard.</p>
            </div>
        </div>
    </body>
    </html>
    `;
} 