// OAuth routes for LivePerson IDP Server
import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import * as jose from 'jose';
import crypto from 'crypto';
import config from '../config/config.js';
import { verifyCodeChallenge, validatePKCEParams } from '../utils/pkce.js';
import { createToken, createAccessToken } from '../utils/jwt.js';

const router = express.Router();

// In-memory store for authorization codes (in production, use Redis or database)
const authorizationCodes = new Map();

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
}, config.cleanup.authCodeCleanupInterval);

// OAuth callback page for implicit flow
router.get('/oauth-callback.html', (req, res) => {
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

// OAuth Authorization endpoint (both implicit and authorization code flow)
router.get('/authorize', async (req, res) => {
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
    
    // Get current state from main app
    const { encryptionEnabled, flowType, signingPrivateKey, lpEncryptionPublicKey } = req.app.locals;
    
    console.log('Authorization request received:', req.query);
    console.log(`Encryption mode: ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    
    // Enhanced PKCE parameter logging for debugging
    console.log('\n🔍 === DETAILED PARAMETER ANALYSIS ===');
    console.log('📋 All Query Parameters:');
    Object.keys(req.query).forEach(key => {
        console.log(`   ${key}: ${req.query[key]}`);
    });
    console.log('🔐 PKCE Parameters Check:');
    console.log(`   code_challenge: ${code_challenge ? 'PRESENT (' + code_challenge.substring(0, 20) + '...)' : 'MISSING'}`);
    console.log(`   code_challenge_method: ${code_challenge_method || 'MISSING'}`);
    console.log(`   Current flow type: ${flowType}`);
    console.log(`   Should expect PKCE: ${flowType === 'codepkce' ? 'YES' : 'NO'}`);
    console.log('==========================================\n');
    
    // Check if this is an AJAX request (from lpgetToken)
    const isAjaxRequest = req.headers['x-requested-with'] === 'XMLHttpRequest' || 
                         req.headers['accept']?.includes('application/json') ||
                         req.query.format === 'json';
    
    // PKCE validation for codepkce flow
    const isPKCEFlow = flowType === 'codepkce' || (code_challenge && code_challenge_method);
    if (isPKCEFlow) {
        const validation = validatePKCEParams(code_challenge, code_challenge_method);
        if (!validation.success) {
            console.log('❌ PKCE validation failed:', validation.error);
            return res.status(400).json({
                error: 'invalid_request',
                error_description: validation.error
            });
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
        const issuer = `${config.jwt.issuerBase}/${flowType}`;
        
        const payload = {
            // iss will be added by createToken function
            sub: config.livePerson.testUser.id,
            aud: client_id || config.oauth.clientId,
            exp: now + 3600,
            iat: now,
            nonce: nonce,
            
            // Custom claims for LivePerson
            email: config.livePerson.testUser.email,
            name: config.livePerson.testUser.name,
            given_name: 'Test',
            family_name: 'User',
            phone_number: config.livePerson.testUser.phone,
            
            // LivePerson specific claims
            lp_sdes: {
                customerInfo: {
                    customerId: 'test-customer-123',
                    customerType: 'premium',
                    balance: 1500.00,
                    accountNumber: 'ACC-789456123'
                },
                personalInfo: {
                    name: config.livePerson.testUser.name,
                    email: config.livePerson.testUser.email,
                    phone: config.livePerson.testUser.phone
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
                expiresAt: Date.now() + (config.oauth.codeExpiryMinutes * 60 * 1000),
                clientId: client_id || config.oauth.clientId
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
            console.log(`⏰ Expires at: ${new Date(Date.now() + (config.oauth.codeExpiryMinutes * 60 * 1000)).toISOString()}`);
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
            const idToken = await createToken(payload, issuer, signingPrivateKey, lpEncryptionPublicKey, encryptionEnabled);
            
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
router.post('/token', async (req, res) => {
    const { grant_type, code, client_id, client_secret, redirect_uri, code_verifier } = req.body;
    
    // Get current state from main app
    const { encryptionEnabled, flowType, signingPrivateKey, lpEncryptionPublicKey } = req.app.locals;
    
    console.log('\n🔥 === TOKEN ENDPOINT CALLED ===');
    console.log('📅 Timestamp:', new Date().toISOString());
    console.log('🌐 Request Headers:', JSON.stringify(req.headers, null, 2));
    console.log('📝 Request Body:', JSON.stringify(req.body, null, 2));
    console.log('🔐 Encryption mode:', encryptionEnabled ? 'ENABLED' : 'DISABLED');
    console.log('🔄 Current flow type:', flowType);
    console.log('🏷️  Current issuer:', `${config.jwt.issuerBase}/${flowType}`);
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
    
    console.log('   Expected client_id:', config.oauth.clientId);
    console.log('   Received client_id:', receivedClientId);
    console.log('   Expected client_secret:', config.oauth.clientSecret);
    console.log('   Received client_secret:', receivedClientSecret ? '[PRESENT]' : '[MISSING]');
    
    if (receivedClientId !== config.oauth.clientId || receivedClientSecret !== config.oauth.clientSecret) {
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
        const idToken = await createToken(payload, payload.iss, signingPrivateKey, lpEncryptionPublicKey, encryptionEnabled);
        const accessToken = await createAccessToken(payload, payload.iss, signingPrivateKey);
        
        const response = {
            access_token: accessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: config.oauth.scopes.join(' ')
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
router.post('/token-direct', async (req, res) => {
    const { user_id, client_id } = req.body;
    
    // Get current state from main app
    const { encryptionEnabled, flowType, signingPrivateKey, lpEncryptionPublicKey } = req.app.locals;
    
    console.log('Direct token request received:', req.body);
    console.log(`Encryption mode: ${encryptionEnabled ? 'ENABLED' : 'DISABLED'}`);
    console.log('⚠️  Using direct token endpoint - not standard OAuth flow');
    
    // Determine user identifier - either from user_id or default test user
    const userId = user_id || config.livePerson.testUser.id;
    const clientId = client_id || config.oauth.clientId;
    
    console.log(`Creating token for user: ${userId}, client: ${clientId}`);
    
    try {
        const now = Math.floor(Date.now() / 1000);
        const issuer = `${config.jwt.issuerBase}/${flowType}`;
        
        const payload = {
            // iss will be added by createToken function
            sub: userId,
            aud: clientId,
            exp: now + 3600,
            iat: now,
            
            // Test user data (can be customized based on user_id)
            email: `${userId}@example.com`,
            name: userId === config.livePerson.testUser.id ? config.livePerson.testUser.name : `User ${userId}`,
            given_name: userId === config.livePerson.testUser.id ? 'Test' : 'User',
            family_name: userId === config.livePerson.testUser.id ? 'User' : userId,
            phone_number: config.livePerson.testUser.phone,
            
            // LivePerson specific claims
            lp_sdes: {
                customerInfo: {
                    customerId: userId,
                    customerType: 'premium',
                    balance: 1500.00,
                    accountNumber: `ACC-${userId.replace(/[^0-9]/g, '')}123`
                },
                personalInfo: {
                    name: userId === config.livePerson.testUser.id ? config.livePerson.testUser.name : `User ${userId}`,
                    email: `${userId}@example.com`,
                    phone: config.livePerson.testUser.phone
                }
            }
        };
        
        console.log(`🔄 Using ${flowType.toUpperCase()} flow with issuer: ${issuer}`);
        
        // Create signed JWT or JWE based on encryption setting
        const idToken = await createToken(payload, issuer, signingPrivateKey, lpEncryptionPublicKey, encryptionEnabled);
        const accessToken = await createAccessToken(payload, issuer, signingPrivateKey);
        
        const response = {
            access_token: accessToken,
            id_token: idToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: config.oauth.scopes.join(' ')
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

export { router as oauthRoutes, authorizationCodes }; 