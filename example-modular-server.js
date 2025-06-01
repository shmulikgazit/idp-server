// Example of modular server.js structure
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

// Import modular components
const { loadLivePersonCertificate, encryptSAMLAssertion } = require('./saml/saml-encryption');
const { initializeSAML, createSAMLResponse, signSAMLAssertion } = require('./saml/saml-core');
const { setupOAuthRoutes } = require('./auth/oauth');
const { setupJWTHandling } = require('./auth/jwt-handler');
const { setupDashboardRoutes } = require('./routes/dashboard');
const { setupHealthRoutes } = require('./routes/health');
const { setupDenverSSORoutes } = require('./saml/denver-sso');
const { loadKeys, loadSigningCertificate } = require('./crypto/keys');
const { setupLogging } = require('./middleware/logging');
const { validateCertificate } = require('./crypto/certificates');

const app = express();

// Global configuration
let encryptionEnabled = false;
let flowType = 'consumer';

// Initialize middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Setup custom logging middleware
setupLogging(app);

// Load keys and initialize SAML
loadKeys();
const samlInitialized = initializeSAML();

// Setup route modules
setupHealthRoutes(app);
setupOAuthRoutes(app);
setupJWTHandling(app);
setupDashboardRoutes(app);
setupDenverSSORoutes(app);

// Main encryption toggle endpoint
app.post('/toggle-encryption', (req, res) => {
    encryptionEnabled = !encryptionEnabled;
    console.log(`🔄 Encryption toggled: ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    
    res.json({
        success: true,
        encryptionEnabled: encryptionEnabled,
        message: `Encryption ${encryptionEnabled ? 'enabled' : 'disabled'}`
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 LivePerson IDP Server running on port ${PORT}`);
    console.log(`🔐 Encryption: ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`🔄 Flow Type: ${flowType.toUpperCase()}`);
    console.log(`📋 SAML: ${samlInitialized ? 'INITIALIZED' : 'FAILED'}`);
});

module.exports = app; 