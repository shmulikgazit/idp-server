# LivePerson IDP Server - Architecture Documentation

## Overview

The LivePerson IDP Server is a comprehensive Identity Provider server that has been refactored from a single monolithic file into a well-organized, modular architecture. The server supports OAuth 2.0, SAML 2.0, and provides seamless integration with LivePerson's platform.

## 🏗️ Architecture

### **Modular Structure**

```
idp-server/
├── server.js                 # Main server entry point (270 lines)
├── config/
│   └── config.js             # Centralized configuration
├── utils/
│   ├── pkce.js               # PKCE utilities
│   └── jwt.js                # JWT/JWE utilities
├── middleware/
│   ├── express.js            # Basic Express middleware setup
│   └── logging.js            # Request logging middleware
├── routes/
│   ├── oauth.js              # OAuth 2.0 routes
│   └── saml.js               # SAML 2.0 routes
├── ui/
│   └── templates.js          # HTML template generation
└── saml/
    ├── saml-core.js          # Core SAML functionality
    ├── saml-encryption.js    # SAML encryption handling
    └── saml-response.js      # SAML response generation
```

### **Before vs After Refactoring**

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Main file size | ~2,950 lines | 270 lines | 91% reduction |
| Number of modules | 1 | 11 | Better organization |
| Code maintainability | Low | High | Easier to modify |
| Test coverage potential | Difficult | Easy | Modular testing |

## 📋 Supported Features

### **OAuth 2.0 Flows**
- **Implicit Flow** (`response_type=id_token`)
- **Authorization Code Flow** (`response_type=code`)
- **Authorization Code + PKCE Flow** (with challenge/verifier)

### **SAML 2.0**
- Denver Agent SSO integration
- Encrypted SAML assertions
- Custom SAML response generation

### **Security Features**
- JWT signing with RS256
- JWE encryption support
- PKCE implementation
- Certificate-based encryption

### **Integration Features**
- LivePerson platform integration
- Dynamic issuer support
- Multi-IdP configuration
- Real-time request logging

## 🔧 Module Details

### **config/config.js**
Centralized configuration management for all server components.

**Exports:**
- Server configuration (port, host)
- OAuth configuration (flows, issuers)
- JWT configuration (algorithms, keys)
- PKCE configuration
- LivePerson configuration

### **utils/pkce.js**
PKCE (Proof Key for Code Exchange) utilities for secure OAuth flows.

**Functions:**
- `verifyCodeChallenge(verifier, challenge)` - Verify PKCE challenge
- `validatePKCEParams(params)` - Validate PKCE parameters
- `base64URLEncode(buffer)` - Base64 URL encoding
- `sha256(data)` - SHA256 hashing

### **utils/jwt.js**
JWT/JWE token creation and management utilities.

**Functions:**
- `createToken(payload, options)` - Create JWT/JWE tokens
- `createAccessToken(payload)` - Create access tokens
- `pemToJwk(pemKey)` - Convert PEM to JWK format
- `generateJWKS(publicKey)` - Generate JWKS response

### **middleware/express.js**
Basic Express middleware setup and configuration.

**Functions:**
- `setupExpressMiddleware(app)` - Setup CORS, JSON parsing, Morgan
- `setupExpressMiddlewareWithOptions(app, options)` - Advanced setup

### **middleware/logging.js**
Enhanced request logging with token analysis and state tracking.

**Features:**
- Request/response logging
- Token format analysis
- State-aware logging
- Console and array storage
- 100-request history limit

### **routes/oauth.js**
Complete OAuth 2.0 implementation with all supported flows.

**Endpoints:**
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token exchange endpoint
- `POST /token-direct` - Direct token endpoint (testing)
- `GET /oauth-callback.html` - OAuth callback page

**Features:**
- Client authentication
- Authorization code management
- PKCE support
- LivePerson ssoKey format

### **routes/saml.js**
SAML 2.0 implementation for Denver Agent SSO.

**Endpoints:**
- `GET /agentsso-denver` - Denver SSO testing page
- `POST /generate-saml-assertion` - Generate SAML assertion
- `POST /discover-denver-domain` - Domain discovery

### **ui/templates.js**
HTML template generation for all UI components.

**Templates:**
- `generateDashboardHTML()` - Main dashboard with controls
- `generateOAuthCallbackHTML()` - OAuth callback page
- `generateTestPageHTML()` - LivePerson test page with chat

## 🚀 Usage

### **Starting the Server**
```bash
npm start
# or
node server.js
```

### **Development Mode**
```bash
npm run dev
# Uses nodemon for auto-restart
```

### **Configuration**
All configuration is centralized in `config/config.js`. Key settings:

```javascript
export default {
    server: {
        port: process.env.PORT || 3000
    },
    oauth: {
        defaultFlowType: 'implicit'
    },
    jwt: {
        issuerBase: 'https://your-domain.com'
    }
}
```

### **Key Management**
The server requires RSA key pairs for JWT signing:

```bash
npm run generate-keys
```

For JWE encryption, place the LivePerson certificate:
```
certs/lpsso2026.pem
```

## 🔄 State Management

The server maintains several state variables that are shared across modules:

- `encryptionEnabled` - Toggle for JWE encryption
- `flowType` - Current OAuth flow type
- `signingPrivateKey` / `signingPublicKey` - JWT signing keys
- `lpEncryptionPublicKey` - LivePerson encryption certificate
- `requestLogs` - Array of recent requests

State is synchronized across modules using the `updateAppLocals()` function.

## 🧪 Testing

### **Health Check**
```bash
curl http://localhost:3000/health
```

### **OAuth Flow Testing**
1. Visit `http://localhost:3000/test` for LivePerson integration testing
2. Use `http://localhost:3000/` for request monitoring
3. SAML testing at `http://localhost:3000/agentsso-denver`

### **Flow Type Switching**
The server supports dynamic switching between OAuth flows:
- Implicit Flow
- Authorization Code Flow  
- Authorization Code + PKCE Flow

## 🔐 Security Considerations

1. **JWT Signing**: Uses RS256 with RSA key pairs
2. **JWE Encryption**: Optional encryption with LivePerson certificates
3. **PKCE**: Implemented for enhanced OAuth security
4. **SAML**: Supports encrypted assertions
5. **CORS**: Properly configured for cross-origin requests

## 📊 Monitoring

The server includes comprehensive request logging:
- All requests logged with timestamps
- Token analysis for OAuth responses
- State tracking (encryption, flow type)
- Console output with structured formatting
- Web dashboard with real-time logs

## 🔄 Deployment

### **Environment Variables**
```bash
PORT=3000
NODE_ENV=production
```

### **Required Files**
- `certs/signing-private.pem`
- `certs/signing-public.pem`
- `certs/lpsso2026.pem` (optional, for encryption)

### **LivePerson Configuration**
Configure LivePerson IdP with:
- **Authorization URL**: `https://your-domain.com/authorize`
- **Token URL**: `https://your-domain.com/token`
- **JWKS URL**: `https://your-domain.com/.well-known/jwks.json`
- **Client ID**: `clientid`
- **Client Secret**: `1234567890`

## 🚀 Performance Benefits

The modular architecture provides several performance and maintainability benefits:

1. **Faster Development**: Smaller, focused modules
2. **Better Testing**: Each module can be tested independently
3. **Easier Debugging**: Clear separation of concerns
4. **Scalable Architecture**: Easy to add new features
5. **Code Reusability**: Modules can be reused in other projects

## 🔮 Future Enhancements

Possible future improvements:
1. Database integration for persistent storage
2. Redis for session management
3. Rate limiting middleware
4. Enhanced error handling
5. API versioning
6. Swagger/OpenAPI documentation
7. Docker containerization
8. Unit and integration tests 