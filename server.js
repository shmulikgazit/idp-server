/**
 * LivePerson IDP Server - Modular Architecture
 * 
 * A comprehensive Identity Provider server supporting:
 * - OAuth 2.0 flows (Implicit, Authorization Code, Authorization Code + PKCE)
 * - SAML 2.0 for Denver Agent SSO
 * - JWT/JWE token generation with LivePerson integration
 * - Enhanced request logging and monitoring
 * 
 * Architecture:
 * - config/: Configuration management
 * - utils/: Utility functions (PKCE, JWT)
 * - middleware/: Express middleware modules
 * - routes/: Route handlers (OAuth, SAML)
 * - ui/: HTML template generation
 * - saml/: SAML processing modules
 */

import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Core dependencies that remain in main server
import * as jose from 'jose';
import saml from 'samlify';

// Import configuration
import config, { runtimeConfig } from './config/config.js';

// Import utilities
import { generateJWKS } from './utils/jwt.js';

// Import middleware
import { setupExpressMiddleware } from './middleware/express.js';
import { createRequestLoggingMiddleware, requestLogs } from './middleware/logging.js';

// Import routes
import { oauthRoutes } from './routes/oauth.js';
import { samlRoutes } from './routes/saml.js';

// Import SAML modules
import { loadLivePersonCertificate } from './saml/saml-encryption.js';
import { initializeSAML, getIdentityProvider, getServiceProvider } from './saml/saml-core.js';

// Import UI templates
import { generateDashboardHTML, generateOAuthCallbackHTML, generateTestPageHTML } from './ui/templates.js';

// ES module equivalent of __dirname
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ============================================================================
// SERVER SETUP
// ============================================================================

const app = express();
const PORT = config.server.port;

// ============================================================================
// APPLICATION STATE
// ============================================================================

// Encryption toggle state
let encryptionEnabled = false;

// Selected encryption certificate
let selectedEncryptionCert = 'lpsso2026';

// OAuth flow type state
let flowType = config.oauth.defaultFlowType;

// SAML state management
let samlEncryptionEnabled = false;
let samlEncryptionCertificate = null;

// SAML Identity Provider and Service Provider instances
let identityProvider = null;
let serviceProvider = null;

// Key storage for JWT functionality
let signingPrivateKey, signingPublicKey, lpEncryptionPublicKey;

// ============================================================================
// MIDDLEWARE SETUP
// ============================================================================

// Middleware
setupExpressMiddleware(app);

// Function to get current server state for logging middleware
function getServerState() {
    return {
        encryptionEnabled,
        flowType,
        selectedEncryptionCert
    };
}

// Setup custom request logging middleware
app.use(createRequestLoggingMiddleware(getServerState));

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

function loadSelectedEncryptionCert() {
    try {
        const certPath = path.join(__dirname, 'certs', `${selectedEncryptionCert}.pem`);
        lpEncryptionPublicKey = fs.readFileSync(certPath, 'utf8');
        console.log(`[OK] LivePerson encryption certificate (${selectedEncryptionCert}.pem) loaded`);
    } catch (error) {
        console.log(`[WARN] LivePerson encryption certificate (${selectedEncryptionCert}.pem) not found - place it in ./certs/ for JWE encryption`);
        lpEncryptionPublicKey = null;
    }
}

function loadKeys() {
    try {
        // Load required signing keys
        signingPrivateKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-private.pem'), 'utf8');
        signingPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-public.pem'), 'utf8');
        console.log('[OK] Signing keys loaded successfully');
        
        // Try to load LivePerson encryption certificate
        loadSelectedEncryptionCert();
        
        // Initialize SAML after keys are loaded
        const samlInitialized = initializeSAML();
        if (samlInitialized) {
            console.log('[OK] SAML library initialized successfully');
        } else {
            console.log('[WARN] SAML library initialization failed - using legacy implementation');
        }
        
        console.log('[OK] Key loading completed');
    } catch (error) {
        console.error('Error loading required signing keys:', error.message);
        console.log('Please run: npm run generate-keys');
        process.exit(1);
    }
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

// Setup app.locals for sharing state with route modules
function updateAppLocals() {
    app.locals.encryptionEnabled = encryptionEnabled;
    app.locals.flowType = flowType;
    app.locals.signingPrivateKey = signingPrivateKey;
    app.locals.lpEncryptionPublicKey = lpEncryptionPublicKey;
    app.locals.selectedEncryptionCert = selectedEncryptionCert;
    app.locals.requestLogs = requestLogs;
}

// ============================================================================
// ROUTE MOUNTING
// ============================================================================

// Mount OAuth routes
app.use('/', oauthRoutes);

// Mount SAML routes
app.use('/', samlRoutes);

// ============================================================================
// UI ROUTES
// ============================================================================

// Home page with request logs and encryption toggle
app.get('/', (req, res) => {
    const html = generateDashboardHTML({
        PORT: PORT,
        encryptionEnabled: encryptionEnabled,
        flowType: flowType,
        lpEncryptionPublicKey: lpEncryptionPublicKey,
        requestLogs: requestLogs,
        selectedEncryptionCert: selectedEncryptionCert
    });
    res.send(html);
});

// OAuth callback page for implicit flow
app.get('/oauth-callback.html', (req, res) => {
    const html = generateOAuthCallbackHTML();
    res.send(html);
});

// LivePerson Test Page (without auto-refresh)
app.get('/test', (req, res) => {
    const html = generateTestPageHTML({
        PORT: PORT,
        encryptionEnabled: encryptionEnabled,
        flowType: flowType
    });
    res.send(html);
});

// ============================================================================
// API ROUTES
// ============================================================================

// Toggle encryption endpoint
app.post('/toggle-encryption', (req, res) => {
    const { enabled } = req.body;
    encryptionEnabled = !!enabled;
    updateAppLocals(); // Update state for route modules
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
        updateAppLocals(); // Update state for route modules
        console.log(`OAuth Flow Type changed to: ${flowType.toUpperCase()}`);
        res.json({ 
            success: true, 
            flowType: flowType,
            issuer: `${config.jwt.issuerBase}/${flowType}`
        });
    } else {
        res.status(400).json({ 
            error: 'invalid_flow_type', 
            error_description: 'Supported flow types: implicit, code, codepkce' 
        });
    }
});

// Select encryption certificate endpoint
app.post('/select-encryption-cert', (req, res) => {
    const { certName } = req.body;
    if (certName && certName.match(/^lpsso\d{4}(dev)?$/)) {
        selectedEncryptionCert = certName;
        loadSelectedEncryptionCert(); // Reload certificate
        updateAppLocals();
        console.log(`Encryption certificate changed to: ${selectedEncryptionCert}`);
        res.json({ 
            success: true, 
            selectedEncryptionCert: selectedEncryptionCert,
            certAvailable: !!lpEncryptionPublicKey
        });
    } else {
        res.status(400).json({ 
            error: 'invalid_cert_name', 
            error_description: 'Certificate name must match pattern lpssoYYYY or lpssoYYYYdev' 
        });
    }
});

// ============================================================================
// ACCOUNT MANAGEMENT ENDPOINTS
// ============================================================================

// Get current account configuration
app.get('/api/account', (req, res) => {
    res.json({
        success: true,
        currentAccount: runtimeConfig.currentAccount,
        availableAccounts: config.livePerson.testAccounts,
        defaultAgent: config.livePerson.defaultAgent
    });
});

// Update current account
app.post('/api/account', (req, res) => {
    const { siteId, name, description } = req.body;
    
    if (!siteId) {
        return res.status(400).json({
            error: 'missing_site_id',
            error_description: 'Site ID is required'
        });
    }
    
    // Update runtime configuration
    runtimeConfig.currentAccount = {
        siteId: siteId,
        name: name || `Account ${siteId}`,
        description: description || 'Custom test account'
    };
    
    console.log(`[ACCOUNT] Updated to: ${runtimeConfig.currentAccount.name} (${siteId})`);
    
    res.json({
        success: true,
        currentAccount: runtimeConfig.currentAccount,
        message: `Account switched to ${runtimeConfig.currentAccount.name}`
    });
});

// Get current account (quick endpoint for UI)
app.get('/api/account/current', (req, res) => {
    res.json(runtimeConfig.currentAccount);
});

// ============================================================================
// EXISTING API ROUTES CONTINUE...
// ============================================================================

// OpenID Connect Discovery endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
    // Check for forwarded headers from ngrok/proxy
    const forwardedHost = req.get('x-forwarded-host') || req.get('x-original-host');
    const forwardedProto = req.get('x-forwarded-proto') || req.get('x-forwarded-protocol');
    
    // Use forwarded headers if available, otherwise fall back to direct headers
    const host = forwardedHost || req.get('host');
    const protocol = forwardedProto || req.protocol;
    
    const baseUrl = `${protocol}://${host}`;
    
    // Debug logging
    console.log('🔍 OpenID Connect Discovery endpoint called');
    console.log('🌐 Request headers:');
    console.log('   - host:', req.get('host'));
    console.log('   - x-forwarded-host:', req.get('x-forwarded-host'));
    console.log('   - x-forwarded-proto:', req.get('x-forwarded-proto'));
    console.log('   - protocol:', req.protocol);
    console.log('📍 Resolved Base URL:', baseUrl);
    
    const openidConfig = {
        issuer: `${baseUrl}`,
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        userinfo_endpoint: `${baseUrl}/userinfo`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        response_types_supported: [
            "code",
            "id_token", 
            "code id_token"
        ],
        response_modes_supported: [
            "query",
            "fragment", 
            "form_post"
        ],
        grant_types_supported: [
            "authorization_code",
            "implicit"
        ],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: ["openid", "profile", "email"],
        token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post"
        ],
        claims_supported: [
            "iss", "sub", "aud", "exp", "iat", "nonce",
            "name", "given_name", "family_name", "email", 
            "phone_number", "lp_sdes"
        ]
    };
    
    res.json(openidConfig);
});

// JWKS endpoint for public key distribution
app.get('/.well-known/jwks.json', async (req, res) => {
    try {
        const jwks = await generateJWKS(signingPublicKey);
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

// Health check endpoint
app.get('/health', (req, res) => {
    const identityProvider = getIdentityProvider();
    const serviceProvider = getServiceProvider();
    
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        encryptionEnabled: encryptionEnabled,
        flowType: flowType,
        saml: {
            initialized: !!(identityProvider && serviceProvider),
            encryption: !!loadLivePersonCertificate()
        }
    });
});

// ============================================================================
// SERVER INITIALIZATION
// ============================================================================

// Initialize SAML on server startup
function startServer() {
    // Initialize SAML
    const samlInitialized = initializeSAML();
    if (!samlInitialized) {
        console.error('WARN Failed to initialize SAML - server may not function properly');
    }
    
    // Load keys for JWT functionality
    loadKeys();
    
    // Update app.locals with current state for route modules
    updateAppLocals();
    
    app.listen(PORT, () => {
        console.log(` OK IDP Server running on port ${PORT}`);
        console.log(` OK Available endpoints:`);
        console.log(`   GET  /health - Health check`);
        console.log(`   GET  / - Main page with endpoint list`);
        console.log(`   GET  /agentsso-denver - Denver SAML SSO Testing Page`);
        console.log(`   POST /generate-saml-assertion - Generate SAML assertion`);
        console.log(`   POST /discover-denver-domain - Discover Denver domain`);
        console.log(` OK Available endpoints:`);
        console.log(` OK SAML Status: ${samlInitialized ? 'Initialized' : 'Failed'}`);
        console.log(` OK Encryption: ${!!loadLivePersonCertificate() ? 'Available' : 'Not Available'}`);
    });
}

// Start the server
startServer();

// Denver SSO endpoint (POST) - Create and return SAML assertion for Denver system
app.post('/denver-sso', async (req, res) => {
    try {
        const { loginName, siteId, destinationUrl, encrypt, method } = req.body;
        
        // Use provided values or defaults
        const finalLoginName = loginName || 'test.user@liveperson.com';
        const finalSiteId = siteId || runtimeConfig.currentAccount.siteId;
        const finalDestinationUrl = destinationUrl || 'https://authentication.liveperson.net/api/account/a41244303/saml/redirect?lpservice=liveEngage&authRequest=Auth-Consume';
        const shouldEncrypt = encrypt === 'true' || encrypt === true;
        
        // Get SAML implementation method from config or request
        const samlMethod = method || config.saml.implementation || 'auto';
        
        console.log('🚀 Denver SSO Request received');
        console.log(`📧 Login Name: ${finalLoginName}`);
        console.log(`🏢 Site ID: ${finalSiteId}`);
        console.log(`🎯 Destination URL: ${finalDestinationUrl}`);
        console.log(`🔒 Encrypt: ${shouldEncrypt}`);
        console.log(`🛠️ SAML Method: ${samlMethod}`);
        
        // Create SAML response with specified method
        const { samlResponse, method: usedMethod } = await createSAMLResponse(
            finalSiteId, 
            finalLoginName, 
            finalDestinationUrl, 
            shouldEncrypt,
            samlMethod
        );
        
        console.log(`✅ SAML Response created successfully using ${usedMethod}`);
        
        // Determine the form action URL (use destination URL)
        const formAction = finalDestinationUrl;
        
        // Create the HTML auto-submit form
        const htmlForm = `<!DOCTYPE html>
<html>
<head>
    <title>SAML SSO - Redirecting...</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            text-align: center;
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .debug-info {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1rem;
            text-align: left;
            font-family: monospace;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h2>🚀 SAML SSO Login</h2>
        <p>Redirecting to LivePerson Denver system...</p>
        <p><strong>User:</strong> ${finalLoginName}</p>
        <p><strong>Site ID:</strong> ${finalSiteId}</p>
        <p><strong>Method:</strong> ${usedMethod}</p>
        
        <form id="samlForm" action="${formAction}" method="post">
            <input type="hidden" name="SAMLResponse" value="${Buffer.from(samlResponse).toString('base64')}" />
        </form>
        
        <div class="debug-info">
            <strong>🔧 Debug Information:</strong><br>
            Destination: ${finalDestinationUrl}<br>
            Encryption: ${shouldEncrypt ? 'Enabled' : 'Disabled'}<br>
            SAML Method: ${usedMethod}<br>
            Response Length: ${samlResponse.length} chars<br>
            Timestamp: ${new Date().toISOString()}
        </div>
        
        <p style="margin-top: 1rem;">
            <small>If you are not redirected automatically, <a href="#" onclick="document.getElementById('samlForm').submit();">click here</a>.</small>
        </p>
    </div>
    
    <script>
        // Auto-submit the form after a brief delay
        setTimeout(() => {
            document.getElementById('samlForm').submit();
        }, 2000);
    </script>
</body>
</html>`;
        
        res.send(htmlForm);
        
    } catch (error) {
        console.error('❌ Error in Denver SSO endpoint:', error);
        res.status(500).json({
            error: 'SAML Response generation failed',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});
