// Request Logging Middleware for LivePerson IDP Server
import config from '../config/config.js';

// Request logging array - shared storage for request logs
export const requestLogs = [];

/**
 * Parse Authorization header to extract client credentials
 * @param {string} authHeader - The Authorization header value
 * @returns {Object} Parsed credentials or null
 */
function parseAuthorizationHeader(authHeader) {
    if (!authHeader) return null;
    
    try {
        if (authHeader.startsWith('Basic ')) {
            // Extract Basic auth credentials
            const base64Credentials = authHeader.substring(6); // Remove 'Basic '
            const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
            const [clientId, clientSecret] = credentials.split(':');
            
            return {
                type: 'Basic',
                clientId: clientId || 'N/A',
                clientSecret: clientSecret ? `${clientSecret.substring(0, 4)}***` : 'N/A', // Mask secret for security
                fullSecret: clientSecret || 'N/A' // Keep full secret for internal use
            };
        } else if (authHeader.startsWith('Bearer ')) {
            // Extract Bearer token
            const token = authHeader.substring(7); // Remove 'Bearer '
            return {
                type: 'Bearer',
                token: `${token.substring(0, 20)}...`,
                fullToken: token
            };
        }
    } catch (error) {
        return {
            type: 'Invalid',
            error: 'Failed to parse authorization header'
        };
    }
    
    return {
        type: 'Unknown',
        value: authHeader
    };
}

/**
 * Create enhanced request logging middleware
 * @param {Function} getServerState - Function to get current server state (encryption, flowType)
 * @returns {Function} Express middleware function
 */
export function createRequestLoggingMiddleware(getServerState) {
    return (req, res, next) => {
        // Skip logging for dashboard requests to reduce clutter
        if (req.url === '/') {
            return next();
        }
        
        // Get current server state
        const { encryptionEnabled, flowType } = getServerState();
        
        // Parse Authorization header if present
        const authInfo = parseAuthorizationHeader(req.headers.authorization);
        
        const logEntry = {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.url,
            headers: req.headers,
            body: req.body,
            query: req.query,
            ip: req.ip,
            encryptionMode: encryptionEnabled ? 'SIGNING + ENCRYPTION (JWE)' : 'SIGNING ONLY (JWT)',
            flowType: flowType.toUpperCase(),
            issuer: `${config.jwt.issuerBase}/${flowType}`,
            clientCredentials: authInfo, // Add parsed client credentials
            response: null
        };
        
        // Capture response data
        const originalSend = res.send;
        const originalJson = res.json;
        
        res.send = function(data) {
            logEntry.response = {
                statusCode: res.statusCode,
                data: data,
                contentType: res.get('Content-Type') || 'text/html'
            };
            return originalSend.call(this, data);
        };
        
        res.json = function(data) {
            logEntry.response = {
                statusCode: res.statusCode,
                data: data,
                contentType: 'application/json'
            };
            
            // Add token analysis for token responses
            if (data && (data.id_token || data.access_token)) {
                logEntry.tokenAnalysis = {
                    id_token_length: data.id_token ? data.id_token.length : 0,
                    id_token_format: data.id_token ? (data.id_token.split('.').length === 3 ? 'JWT (3 parts)' : data.id_token.split('.').length === 5 ? 'JWE (5 parts)' : 'Unknown') : 'N/A',
                    access_token_length: data.access_token ? data.access_token.length : 0,
                    access_token_format: data.access_token ? (data.access_token.split('.').length === 3 ? 'JWT (3 parts)' : 'Unknown') : 'N/A'
                };
            }
            
            return originalJson.call(this, data);
        };
        
        // Add to logs when response is finished
        res.on('finish', () => {
            requestLogs.push(logEntry);
            
            // Keep only last 100 requests
            if (requestLogs.length > 100) {
                requestLogs.shift();
            }
        });
        
        // Enhanced console logging with POST body details
        let logMessage = `[${logEntry.timestamp}] ${req.method} ${req.url}`;
        
        // Add query parameters if present
        if (req.query && Object.keys(req.query).length > 0) {
            logMessage += `\n  Query: ${JSON.stringify(req.query)}`;
        }
        
        // Add POST body if present
        if (req.method === 'POST' && req.body && Object.keys(req.body).length > 0) {
            logMessage += `\n  Body: ${JSON.stringify(req.body, null, 2)}`;
        }
        
        // Add client credentials information
        if (authInfo) {
            if (authInfo.type === 'Basic') {
                logMessage += `\n  Client ID: ${authInfo.clientId}`;
                logMessage += `\n  Client Secret: ${authInfo.clientSecret}`;
                logMessage += `\n  Authorization: Basic [clientid:clientsecret]`;
            } else if (authInfo.type === 'Bearer') {
                logMessage += `\n  Authorization: Bearer ${authInfo.token}`;
            } else {
                logMessage += `\n  Authorization: ${authInfo.type} - ${authInfo.value || authInfo.error}`;
            }
        }
        
        console.log(logMessage);
        next();
    };
}

/**
 * Get the current request logs
 * @returns {Array} Array of request log entries
 */
export function getRequestLogs() {
    return requestLogs;
}

/**
 * Clear all request logs
 */
export function clearRequestLogs() {
    requestLogs.length = 0;
} 