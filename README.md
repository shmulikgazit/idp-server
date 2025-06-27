# LivePerson IDP Server

A comprehensive Identity Provider (IDP) server for testing LivePerson authentication integrations with support for:
- **🔄 OIDC Agent SSO** (Front Channel & Back Channel flows)
- **🔐 SAML Agent SSO** (Auth0 & Denver integrations)  
- **👤 OAuth 2.0 Consumer Authentication**

## 🚀 Quick Start

### 1. Install and Generate Keys
```bash
npm install
npm run generate-keys
```

### 2. Optional - Add LivePerson Encryption Certificate
Place `lpsso2026.pem` (or similar) in `./certs/` directory for encryption support.

### 3. Start Server & ngrok
```bash
npm start        # Start server on port 3000
ngrok http 3000  # Create public tunnel
```
Copy the HTTPS ngrok URL: `https://your-domain.ngrok-free.app`

---

## 🎯 Testing Scenarios

### 🔄 OIDC Agent SSO (Recommended)

**Use for:** LivePerson Agent SSO with OpenID Connect

#### Front Channel (Implicit Flow)
1. **Visit:** `https://your-ngrok-url/agentsso-oidc-auth0`
2. **Configure LivePerson connection:** `MyIdPOIDCFC`
3. **Copy configuration values** using the 📋 copy buttons
4. **Test flow:** Click "Start Front Channel Flow"

#### Back Channel (Authorization Code Flow) 
1. **Visit:** `https://your-ngrok-url/agentsso-oidc-auth0`
2. **Configure LivePerson connection:** `MyIdPOIDCBC`
3. **Copy configuration values** using the 📋 copy buttons
4. **Test flow:** Click "Start Back Channel Flow"

**OIDC Configuration:**
- **Issuer:** `https://your-ngrok-url`
- **Authorization Endpoint:** `https://your-ngrok-url/authorize`
- **Token Endpoint:** `https://your-ngrok-url/token`
- **JWKS URL:** `https://your-ngrok-url/.well-known/jwks.json`
- **Client ID:** `MyIdPOIDC`
- **Client Secret:** `client-secret-123`

---

### 🔐 SAML Agent SSO 

#### Auth0 SAML Integration
**Use for:** SP-initiated SAML with LivePerson (Account: 81785735)

1. **Visit:** `https://your-ngrok-url/agentsso-auth0`
2. **Configure environment** (Alpha, NA, EU, APAC)
3. **Enable/disable encryption** with certificate selection
4. **Test flow:** Enter credentials and click "Initiate SAML Authentication"

**Key Features:**
- SP-initiated flow with LivePerson
- Dynamic certificate download (lpsso2026, lpsso2027, lpsso2028)
- Automatic PEM-to-DER conversion
- Environment-aware configuration

#### Denver SAML Integration
**Use for:** Legacy Denver agent authentication

1. **Visit:** `https://your-ngrok-url/agentsso-denver`
2. **Configure agent details** (Login Name, Site ID, Destination URL)
3. **Enable encryption** if needed
4. **Test flow:** Click "Generate SAML Assertion"

**Key Features:**
- Custom SAML response generation
- Agent attribute mapping
- Encryption support with LivePerson certificates
- Auto PEM-to-DER conversion

---

### 👤 OAuth Consumer Authentication

**Use for:** LivePerson Consumer Authentication connector

1. **Visit:** `https://your-ngrok-url/test`
2. **Configure LivePerson** with OAuth endpoints:
   - Authorization: `https://your-ngrok-url/authorize`
   - Token: `https://your-ngrok-url/token`
   - JWKS: `https://your-ngrok-url/.well-known/jwks.json`
3. **Test authentication** from LivePerson chat widget

---

## 🗂️ Project Structure

```
├── server.js                     # Main server with OIDC discovery
├── config/config.js              # Configuration management
├── routes/
│   ├── oauth.js                  # OAuth/OIDC endpoints
│   └── saml.js                   # SAML endpoints & test pages
├── middleware/
│   ├── express.js                # Express middleware setup
│   └── logging.js                # Request logging
├── utils/
│   ├── jwt.js                    # JWT utilities & JWKS
│   └── pkce.js                   # PKCE implementation
├── saml/
│   ├── saml-core.js              # SAML initialization
│   ├── saml-encryption.js        # Certificate handling
│   ├── saml-response.js          # SAML response generation
│   └── denver-sso.js             # Denver-specific SAML
├── ui/
│   └── templates.js              # HTML template generation
├── certs/                        # Certificate storage
│   ├── lpsso2026.pem            # LivePerson certificates
│   ├── samlify-signing-cert.pem # SAML signing certificate
│   ├── signing-private.pem      # JWT signing keys
│   └── CREATE-CERTIFICATE.md    # Certificate instructions
└── generate-keys.js              # Key generation utility
```

---

## 🔧 Available Endpoints

### Web UI
| Page | URL | Description |
|------|-----|-------------|
| **Dashboard** | `/` | Server status & request logs |
| **OIDC Test Page** | `/agentsso-oidc-auth0` | Front/Back Channel OIDC testing |
| **Auth0 SAML** | `/agentsso-auth0` | SP-initiated SAML with LivePerson |
| **Denver SAML** | `/agentsso-denver` | Legacy Denver SAML testing |
| **Consumer Test** | `/test` | OAuth consumer authentication |

### API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/.well-known/jwks.json` | GET | Public keys (JWKS) |
| `/authorize` | GET | OAuth/OIDC authorization |
| `/token` | POST | Token exchange (authorization code flow) |
| `/userinfo` | GET | OIDC user information |
| `/sso/saml` | GET/POST | SAML SSO endpoint |
| `/health` | GET | Server health check |

---

## 🎫 Token Format

### OIDC Agent SSO (Minimal)
```json
{
  "sub": "admin",
  "aud": "MyIdPOIDC",
  "exp": 1751031850,
  "iat": 1751028250,
  "iss": "https://your-ngrok-url",
  "nonce": "...",
  "loginName": "admin"
}
```

### OAuth Consumer Authentication (Full)
```json
{
  "sub": "test-user-123",
  "email": "test.user@example.com",
  "name": "Test User",
  "given_name": "Test",
  "family_name": "User",
  "phone_number": "+1234567890",
  "lp_sdes": {
    "customerInfo": {
      "customerId": "test-customer-123",
      "customerType": "premium",
      "balance": 1500.00
    }
  }
}
```

---

## 🔒 Security Features

### Encryption Support
- **JWT Signing:** RS256 with rotatable keys
- **JWE Encryption:** RSA-OAEP + A256GCM when enabled
- **SAML Encryption:** Dynamic certificate download and conversion
- **ngrok Bypass:** Automatic header injection for seamless flows

### Certificate Management
- **Auto-conversion:** PEM-to-DER conversion for SAML
- **Dynamic download:** Certificate fetching from LivePerson URLs
- **Multi-certificate:** Support for lpsso2026, lpsso2027, lpsso2028
- **Graceful fallback:** Fallback to signing-only when encryption unavailable

### OIDC Compliance
- **Standard flows:** Implicit and Authorization Code flows
- **Response modes:** Fragment, query, and form_post
- **PKCE support:** For enhanced security in authorization code flows
- **Discovery document:** Full OpenID Connect discovery support

---

## 🚨 Troubleshooting

### OIDC Issues
- **"invalid_request":** Check connection name matches (MyIdPOIDCFC/MyIdPOIDCBC)
- **"unexpected iss value":** Verify issuer uses HTTPS not HTTP
- **"tenant not found":** Ensure using `code=` not `ssoKey=` for back channel

### SAML Issues
- **Certificate errors:** Check PEM files exist in `./certs/`
- **Encryption failures:** Verify certificate format and auto-conversion
- **SP-initiated failures:** Check LivePerson environment configuration

### General Issues
- **Port conflicts:** Use `PORT=3001 npm start`
- **Key errors:** Run `npm run generate-keys`
- **ngrok warnings:** Server includes bypass headers automatically

---

## 🎯 Testing Quick Reference

### OIDC Front Channel Test
```bash
# Visit in browser (will redirect to LivePerson)
https://your-ngrok-url/authorize?client_id=MyIdPOIDC&response_type=id_token&response_mode=form_post&scope=openid&redirect_uri=https://auth-z1-a.liveperson.net/login/callback&nonce=test123
```

### OIDC Back Channel Test
```bash
# Step 1: Get authorization code
https://your-ngrok-url/authorize?client_id=MyIdPOIDC&response_type=code&scope=openid&redirect_uri=https://auth-z1-a.liveperson.net/login/callback&state=test123

# Step 2: Exchange code for tokens
curl -X POST https://your-ngrok-url/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=RECEIVED_CODE&client_id=MyIdPOIDC&client_secret=client-secret-123"
```

### OIDC Discovery
```bash
curl https://your-ngrok-url/.well-known/openid-configuration | jq
```

---

## ⚠️ Important Notes

**For Development/Testing Only!**
- Uses fixed test credentials (`admin`/`client-secret-123`)
- No real authentication validation
- Certificates stored in plaintext
- Not suitable for production environments

---

## 📚 Resources

- [LivePerson OIDC Documentation](https://developers.liveperson.com/)
- [LivePerson SAML SSO Guide](https://developers.liveperson.com/)
- [OpenID Connect Specification](https://openid.net/connect/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)

---

## 🏗️ Architecture

This server implements a comprehensive identity provider supporting multiple authentication protocols and flows for LivePerson integration testing. It features modular architecture with separate concerns for OAuth, SAML, certificate management, and UI generation, making it easy to extend and maintain.

The server automatically handles protocol-specific requirements like ngrok bypass headers, certificate format conversion, and response mode handling to ensure seamless integration with LivePerson's various authentication systems. 