// JWT utilities for token creation and validation
import * as jose from 'jose';
import crypto from 'crypto';
import config from '../config/config.js';

/**
 * Convert PEM to JWK format for JWKS endpoint
 * @param {string} pemKey - PEM formatted key
 * @param {string} use - Key usage ('sig' or 'enc')
 * @param {string} alg - Algorithm
 * @param {string} kid - Key ID
 * @returns {Object} JWK object
 */
export function pemToJwk(pemKey, use, alg, kid) {
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

/**
 * Create JWT or JWE token with optional encryption
 * @param {Object} payload - Token payload
 * @param {string} issuer - Token issuer
 * @param {string} signingPrivateKey - Private key for signing
 * @param {string} lpEncryptionPublicKey - Public key for encryption (optional)
 * @param {boolean} encryptionEnabled - Whether to encrypt the token
 * @returns {Promise<string>} Signed and optionally encrypted token
 */
export async function createToken(payload, issuer, signingPrivateKey, lpEncryptionPublicKey, encryptionEnabled) {
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
        const privateKey = await jose.importPKCS8(pkcs8Key, config.jwt.algorithm);
        
        // Create the signed JWT using modern jose library
        const signedToken = await new jose.SignJWT(tokenPayload)
            .setProtectedHeader({ alg: config.jwt.algorithm, kid: config.jwt.keyId })
            .setIssuedAt()
            .setExpirationTime(config.oauth.tokenExpiryTime)
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

/**
 * Generate JWKS (JSON Web Key Set) from public key
 * @param {string} signingPublicKey - Public key in PEM format
 * @returns {Promise<Object>} JWKS object
 */
export async function generateJWKS(signingPublicKey) {
    try {
        // Import the public key using modern jose library
        const publicKey = await jose.importSPKI(signingPublicKey, config.jwt.algorithm);
        
        // Export as JWK with proper formatting
        const jwk = await jose.exportJWK(publicKey);
        
        // Add the required fields for our key
        jwk.use = 'sig';
        jwk.alg = config.jwt.algorithm;
        jwk.kid = config.jwt.keyId;
        
        const jwks = {
            keys: [jwk]
        };
        
        console.log('JWKS generated successfully with modern jose library');
        return jwks;
    } catch (error) {
        console.error('Error generating JWKS:', error);
        throw error;
    }
}

/**
 * Create access token (simpler JWT for API access)
 * @param {Object} payload - Token payload
 * @param {string} issuer - Token issuer
 * @param {string} signingPrivateKey - Private key for signing
 * @returns {Promise<string>} Signed access token
 */
export async function createAccessToken(payload, issuer, signingPrivateKey) {
    try {
        // Convert PKCS#1 to PKCS#8 format using Node.js crypto
        const keyObject = crypto.createPrivateKey(signingPrivateKey);
        const pkcs8Key = keyObject.export({ type: 'pkcs8', format: 'pem' });
        const privateKey = await jose.importPKCS8(pkcs8Key, config.jwt.algorithm);
        
        const accessToken = await new jose.SignJWT({
            iss: issuer,
            sub: payload.sub,
            aud: payload.aud,
            scope: config.oauth.scopes.join(' ')
        })
            .setProtectedHeader({ alg: config.jwt.algorithm, kid: config.jwt.keyId })
            .setIssuedAt()
            .setExpirationTime(config.oauth.tokenExpiryTime)
            .sign(privateKey);
            
        return accessToken;
    } catch (error) {
        console.error('❌ Error creating access token:', error);
        throw error;
    }
} 