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
import config from './config/config.js';

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
        flowType
    };
}

// Setup custom request logging middleware
app.use(createRequestLoggingMiddleware(getServerState));

// ============================================================================
// KEY MANAGEMENT
// ============================================================================

function loadKeys() {
    try {
        // Load required signing keys
        signingPrivateKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-private.pem'), 'utf8');
        signingPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-public.pem'), 'utf8');
        console.log('[OK] Signing keys loaded successfully');
        
        // Try to load LivePerson encryption certificate
        try {
            lpEncryptionPublicKey = fs.readFileSync(path.join(__dirname, 'certs', 'lpsso2026.pem'), 'utf8');
            console.log('[OK] LivePerson encryption certificate (lpsso2026.pem) loaded');
        } catch (error) {
            console.log('[WARN] LivePerson encryption certificate (lpsso2026.pem) not found - place it in ./certs/ for JWE encryption');
            lpEncryptionPublicKey = null;
        }
        
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
        requestLogs: requestLogs
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
