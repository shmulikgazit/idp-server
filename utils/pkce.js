// PKCE (Proof Key for Code Exchange) utility functions
import crypto from 'crypto';
import config from '../config/config.js';

/**
 * Base64 URL encode a string
 * @param {string} str - String to encode
 * @returns {string} Base64 URL encoded string
 */
export function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Create SHA256 hash of buffer
 * @param {Buffer} buffer - Buffer to hash
 * @returns {Buffer} SHA256 hash
 */
export function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}

/**
 * Verify PKCE code challenge against code verifier
 * @param {string} codeVerifier - The code verifier
 * @param {string} codeChallenge - The code challenge to verify
 * @param {string} method - Challenge method ('S256' or 'plain')
 * @returns {boolean} True if verification passes
 */
export function verifyCodeChallenge(codeVerifier, codeChallenge, method) {
    if (!config.pkce.supportedMethods.includes(method)) {
        console.error(`❌ Unsupported PKCE method: ${method}`);
        return false;
    }
    
    if (method === 'S256') {
        const hash = sha256(codeVerifier);
        const challenge = base64URLEncode(hash);
        return challenge === codeChallenge;
    } else if (method === 'plain') {
        return codeVerifier === codeChallenge;
    }
    
    return false;
}

/**
 * Generate a secure code verifier for PKCE
 * @returns {string} Random code verifier
 */
export function generateCodeVerifier() {
    return base64URLEncode(crypto.randomBytes(32));
}

/**
 * Generate code challenge from verifier
 * @param {string} codeVerifier - The code verifier
 * @param {string} method - Challenge method ('S256' or 'plain')
 * @returns {string} Code challenge
 */
export function generateCodeChallenge(codeVerifier, method = config.pkce.defaultMethod) {
    if (method === 'S256') {
        const hash = sha256(codeVerifier);
        return base64URLEncode(hash);
    } else if (method === 'plain') {
        return codeVerifier;
    }
    
    throw new Error(`Unsupported PKCE method: ${method}`);
}

/**
 * Validate PKCE parameters
 * @param {string} codeChallenge - Code challenge
 * @param {string} codeChallengeMethod - Challenge method
 * @returns {Object} Validation result with success flag and error message
 */
export function validatePKCEParams(codeChallenge, codeChallengeMethod) {
    if (!codeChallenge || !codeChallengeMethod) {
        return {
            success: false,
            error: 'PKCE flow requires code_challenge and code_challenge_method parameters'
        };
    }
    
    if (!config.pkce.supportedMethods.includes(codeChallengeMethod)) {
        return {
            success: false,
            error: `Unsupported code_challenge_method. Supported: ${config.pkce.supportedMethods.join(', ')}`
        };
    }
    
    return { success: true };
} 