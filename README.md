# LivePerson IDP Server

A local Identity Provider (IDP) server for testing LivePerson consumer authentication with JWE encryption support.

## Features

- ✅ OAuth 2.0 Implicit Flow support
- ✅ OpenID Connect ID tokens
- ✅ JWT signing with RS256
- ✅ JWE encryption support (RSA-OAEP) with LivePerson certificate
- ✅ JWKS endpoint for public key distribution
- ✅ Real-time request logging with web dashboard
- ✅ LivePerson-specific claims (lp_sdes)
- ✅ Encryption toggle for easy testing
- ✅ Ready for ngrok exposure
- ✅ SAML SSO support with samlify library (handles signing and encryption)
- ✅ Denver agent SSO integration with AttributeStatement support

## Quick Start

### Prerequisites

Make sure you have Node.js installed. If not, download it from [nodejs.org](https://nodejs.org/).

### 1. Install Dependencies

```bash
npm install
```

### 2. Generate Cryptographic Keys

```bash
npm run generate-keys
```

This creates RSA key pairs in the `./certs/` directory:
- `signing-private.pem` / `signing-public.pem` - For JWT signing/verification

### 3. Add LivePerson Encryption Certificate (Optional)

To test JWE encryption with LivePerson's actual certificate:

1. Place LivePerson's encryption certificate as `./certs/lpsso2026.pem`
2. The server will automatically detect and use it when encryption is enabled
3. The JWE header will use `kid: "lpsso2026"` as required by LivePerson

### 4. Start the Server

```bash
npm start
```

The server will start on `http://localhost:3000`

### 5. Expose via ngrok (for LivePerson integration)

```bash
# Install ngrok if you haven't already
# Download from https://ngrok.com/

# Expose the local server
ngrok http 3000
```

Copy the ngrok HTTPS URL (e.g., `https://abc123.ngrok.io`) for LivePerson configuration.

## Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Request logs dashboard with encryption toggle |
| `/.well-known/jwks.json` | GET | JWKS endpoint for public keys |
| `/token` | POST | OAuth token endpoint |
| `/authorize` | GET | OAuth authorization endpoint (implicit flow) |
| `/encryption-public-key` | GET | Public encryption key for LivePerson |
| `/toggle-encryption` | POST | Toggle JWE encryption on/off |
| `/health` | GET | Health check |

## Encryption Toggle Feature

The server includes a web-based toggle to switch between:

1. **Signing Only Mode** (Default) - Returns standard signed JWTs (easier for initial testing)
2. **JWE Encryption Mode** - Returns JWE-encrypted tokens using LivePerson's certificate

### Using the Toggle

1. Visit `http://localhost:3000` (or your ngrok URL)
2. Use the encryption toggle switch in the dashboard
3. The toggle shows current status and certificate availability
4. All subsequent token requests will use the selected mode

## Testing Workflow

### Phase 1: Start with Signing Only
1. Start server with encryption disabled (default)
2. Configure LivePerson connector
3. Test authentication flow with signed JWTs
4. Verify user data appears correctly in LivePerson

### Phase 2: Enable JWE Encryption
1. Place `lpsso2026.pem` in `./certs/` directory
2. Enable encryption via the web toggle
3. Test authentication flow with JWE tokens
4. Verify LivePerson can decrypt and process tokens

### 1. SAML AttributeStatement Test

To validate that SAML responses include the required attributes for LivePerson:

```bash
node test-saml-attributes.js
```

This test verifies that:
- SAML responses contain `AttributeStatement` section
- `loginName` and `siteId` attributes are properly included
- NameID is populated correctly
- AuthnStatement is present with proper timestamps

### 2. Implicit Flow Test

Visit the authorization endpoint directly:
```
http://localhost:3000/authorize?client_id=test&redirect_uri=http://localhost:3000&response_type=id_token&scope=openid&state=test&nonce=123
```

### 3. Token Endpoint Test

```bash
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=test&client_id=test"
```

### 4. Toggle Encryption Test

```bash
# Enable encryption
curl -X POST http://localhost:3000/toggle-encryption \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# Disable encryption  
curl -X POST http://localhost:3000/toggle-encryption \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

## LivePerson Configuration

### 1. Consumer Authentication Connector Setup

In your LivePerson account, configure the Consumer Authentication connector with:

**Authorization Endpoint:**
```
https://your-ngrok-url.ngrok.io/authorize
```

**Token Endpoint:**
```
https://your-ngrok-url.ngrok.io/token
```

**JWKS Endpoint:**
```
https://your-ngrok-url.ngrok.io/.well-known/jwks.json
```

### 2. Encryption Certificate

Get the encryption public key from:
```
https://your-ngrok-url.ngrok.io/encryption-public-key
```

This endpoint returns the LivePerson certificate (`lpsso2026.pem`) if available in the `./certs/` directory.

### 3. Test User Data

The server returns test user data in ID tokens:

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
      "balance": 1500.00,
      "accountNumber": "ACC-789456123"
    },
    "personalInfo": {
      "name": "Test User",
      "email": "test.user@example.com",
      "phone": "+1234567890"
    }
  }
}
```

## Request Monitoring

Visit `http://localhost:3000` (or your ngrok URL) to see:
- Real-time request logs
- Server status
- Encryption toggle control
- Available endpoints
- Recent authentication requests from LivePerson

The page auto-refreshes every 10 seconds to show new requests.

## File Structure

```
├── server.js                  # Main server application
├── generate-keys.js           # Key generation script
├── generate-certificate.js    # Certificate generation utility
├── test-saml-attributes.js    # SAML AttributeStatement test
├── package.json               # Dependencies and scripts
├── README.md                  # This file
├── test-endpoints.ps1         # PowerShell test script
├── test-endpoints.bat         # Batch test script
└── certs/                     # Certificate files (all actively used)
    ├── lpsso2026.pem          # LivePerson encryption certificate (for JWE)
    ├── samlify-signing-cert.pem # SAML signing certificate
    ├── samlify-private.pem    # SAML signing private key
    ├── signing-private.pem    # JWT signing private key
    └── signing-public.pem     # JWT signing public key
```

## JWE Implementation Notes

When encryption is enabled and `lpsso2026.pem` is available:
- JWE header will include `kid: "lpsso2026"`
- Encryption algorithm: RSA-OAEP
- Content encryption: A256GCM (standard)
- The signed JWT becomes the JWE payload

## Security Notes

⚠️ **This is for testing only!** 

- Uses fixed test user data
- Accepts any authorization code
- No real authentication validation
- Keys are generated locally
- Not suitable for production use

## Troubleshooting

### Keys Not Found Error
```
Error loading keys: ENOENT: no such file or directory
```
**Solution:** Run `npm run generate-keys` first.

### LivePerson Certificate Not Found
```
⚠ LivePerson encryption certificate (lpsso2026.pem) not found
```
**Solution:** Place the LivePerson certificate as `./certs/lpsso2026.pem`

### Port Already in Use
```
Error: listen EADDRINUSE :::3000
```
**Solution:** Change the port by setting the PORT environment variable:
```bash
PORT=3001 npm start
```

### ngrok Connection Issues
- Make sure ngrok is installed and authenticated
- Use the HTTPS URL from ngrok (not HTTP)
- Check that the ngrok tunnel is active

## Development

### Start with Auto-reload
```bash
npm run dev
```

### Customize Test User Data

Edit the payload in `server.js` around line 300 to modify the test user information returned in ID tokens.

### Add Custom Claims

Modify the `lp_sdes` object in the token creation functions to include additional LivePerson-specific data.

## Support

For LivePerson-specific configuration questions, refer to:
- [LivePerson Developer Documentation](https://developers.liveperson.com/)
- [Consumer Authentication Guide](https://developers.liveperson.com/consumer-authentication-authenticate-in-web-and-mobile-messaging-introduction.html)

## License

MIT License - This is a testing tool for development purposes. 