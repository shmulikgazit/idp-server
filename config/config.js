// Configuration module for LivePerson IDP Server
export const config = {
    // Server settings
    server: {
        port: process.env.PORT || 3000,
        baseUrl: 'https://mature-mackerel-golden.ngrok-free.app'
    },
    
    // OAuth settings
    oauth: {
        defaultFlowType: 'implicit', // 'implicit', 'code', or 'codepkce'
        clientId: 'clientid',
        clientSecret: '1234567890',
        scopes: ['openid', 'profile', 'email'],
        tokenExpiryTime: '1h',
        codeExpiryMinutes: 10,
        maxStoredCodes: 1000
    },
    
    // JWT settings
    jwt: {
        algorithm: 'RS256',
        keyId: 'signing-key-1',
        issuerBase: 'https://mature-mackerel-golden.ngrok-free.app'
    },
    
    // PKCE settings
    pkce: {
        supportedMethods: ['S256', 'plain'],
        defaultMethod: 'S256'
    },
    
    // File paths
    paths: {
        certs: './certs',
        signingPrivateKey: 'signing-private.pem',
        signingPublicKey: 'signing-public.pem',
        lpEncryptionCert: 'lpsso2026.pem',
        samlSigningCert: 'samlify-signing-cert.pem',
        samlPrivateKey: 'samlify-private.pem'
    },
    
    // LivePerson settings
    livePerson: {
        siteId: 'a41244303',
        domain: 'lptag-a.liveperson.net',
        testUser: {
            id: 'test-user-123',
            name: 'Test User',
            email: 'test.user@example.com',
            phone: '+1234567890'
        }
    },
    
    // SAML settings
    saml: {
        issuer: 'https://idp.liveperson.com',
        entityId: 'https://idp.liveperson.com',
        spEntityId: 'LEna2',
        nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        sessionIndexLength: 9
    },
    
    // Logging settings
    logging: {
        maxRequestLogs: 100,
        skipDashboardLogs: true,
        logLevel: 'info'
    },
    
    // Cleanup settings
    cleanup: {
        authCodeCleanupInterval: 5 * 60 * 1000, // 5 minutes
        maxRequestAge: 24 * 60 * 60 * 1000 // 24 hours
    }
};

export default config; 