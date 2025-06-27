// Configuration module for LivePerson IDP Server
export const config = {
    // Server settings
    server: {
        port: process.env.PORT || 3000,
        baseUrl: 'https://mature-mackerel-golden.ngrok-free.app',
        host: 'localhost'
    },
    
    // OAuth settings
    oauth: {
        defaultFlowType: 'implicit', // 'implicit', 'code', or 'codepkce'
        clientId: 'MyIdPOIDC', // OIDC Client ID for LivePerson
        clientSecret: 'client-secret-123',
        scopes: ['openid', 'profile', 'email'],
        tokenExpiryTime: '1h',
        codeExpiryMinutes: 10,
        maxStoredCodes: 1000,
        redirectUri: 'https://localhost:3000/callback',
        tokenExpiry: 3600, // 1 hour
        scope: 'openid profile email'
    },
    
    // JWT settings
    jwt: {
        algorithm: 'RS256',
        keyId: 'signing-key-1',
        issuerBase: 'https://mature-mackerel-golden.ngrok-free.app',
        issuer: 'https://localhost:3000',
        issuer: 'https://localhost:3000'
    },
    
    // PKCE settings
    pkce: {
        supportedMethods: ['S256', 'plain'],
        defaultMethod: 'S256',
        enabled: true,
        codeVerifierLength: 128,
        codeChallengeMethod: 'S256'
    },
    
    // File paths
    paths: {
        certs: './certs',
        signingPrivateKey: 'signing-private.pem',
        signingPublicKey: 'signing-public.pem',
        lpEncryptionCert: 'lpsso2026.pem',
        samlSigningCert: 'samlify-signing-cert.pem',
        samlPrivateKey: 'samlify-private.pem',
        privateKey: './keys/private-key.pem',
        publicKey: './keys/public-key.pem'
    },
    
    // LivePerson settings - Enhanced account management
    livePerson: {
        // Default test account
        defaultAccount: {
            siteId: 'a41244303',
            name: 'Primary Test Account',
            description: 'Main testing account for LivePerson integration'
        },
        
        // Legacy compatibility (to be deprecated)
        siteId: 'a41244303',
        
        domain: 'lptag-a.liveperson.net',
        apiBaseUrl: 'https://api.liveperson.net',
        
        // Test accounts for quick switching
        testAccounts: [
            {
                siteId: 'a41244303',
                name: 'Primary Test Account',
                description: 'Main testing account',
                isDefault: true
            },
            {
                siteId: 'a12345678',
                name: 'Secondary Test Account', 
                description: 'Alternative testing account'
            },
            {
                siteId: 'a87654321',
                name: 'Demo Account',
                description: 'Demonstration account for showcasing features'
            }
        ],
        
        // Default test user data
        testUser: {
            id: 'test-user-123',
            name: 'Test User',
            email: 'test.user@example.com',
            phone: '+1234567890'
        },
        
        // Default agent data for Denver SSO
        defaultAgent: {
            loginName: 'test.agent@company.com',
            displayName: 'Test Agent',
            email: 'test.agent@company.com'
        }
    },
    
    // SAML settings
    saml: {
        // SAML implementation method
        // Options: 'auto', 'node-saml', 'samlify'
        // - 'auto': Auto-select best implementation (currently defaults to node-saml)
        // - 'node-saml': Use @node-saml/node-saml (better XML signature support, handles InclusiveNamespaces)
        // - 'samlify': Use samlify library (legacy fallback, limited XML signature support)
        implementation: 'auto',
        
        // Identity Provider settings
        issuer: 'https://idp.liveperson.com',
        entityId: 'https://idp.liveperson.com',
        
        // Certificate paths
        certificates: {
            signing: './certs/samlify-signing-cert.pem',
            signingKey: './certs/samlify-private.pem',
            encryption: './certs/lpsso2026.pem'
        },
        
        // Encryption certificate settings
        encryption: {
            // Default certificate (current year)
            defaultCert: 'lpsso2026',
            
            // Available certificates for testing
            availableCerts: [
                {
                    name: 'lpsso2026',
                    description: 'LivePerson 2026 Certificate',
                    year: 2026,
                    isDefault: true
                },
                {
                    name: 'lpsso2027',
                    description: 'LivePerson 2027 Certificate',
                    year: 2027,
                    isDefault: false
                },
                {
                    name: 'lpsso2028',
                    description: 'LivePerson 2028 Certificate',
                    year: 2028,
                    isDefault: false
                }
            ]
        },
        
        // Signature settings
        signature: {
            algorithm: 'sha256',
            digestAlgorithm: 'sha256',
            canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#'
        },
        
        // Assertion settings
        assertion: {
            nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            audience: 'SAML-81785735-MyIdPSAML',
            encryptionEnabled: false
        }
    },
    
    // Logging settings
    logging: {
        maxRequestLogs: 100,
        skipDashboardLogs: true,
        logLevel: 'info',
        level: 'info',
        enableSamlDebugging: true,
        logFailedRequests: true
    },
    
    // Cleanup settings
    cleanup: {
        authCodeCleanupInterval: 5 * 60 * 1000, // 5 minutes
        maxRequestAge: 24 * 60 * 60 * 1000, // 24 hours
        enablePeriodicCleanup: true,
        cleanupIntervalHours: 24
    }
};

// Runtime configuration that can be modified
export const runtimeConfig = {
    currentAccount: {
        siteId: config.livePerson.defaultAccount.siteId,
        name: config.livePerson.defaultAccount.name,
        description: config.livePerson.defaultAccount.description
    },
    
    // Current encryption certificate selection
    encryptionCert: {
        name: config.saml.encryption.defaultCert,
        description: config.saml.encryption.availableCerts.find(cert => cert.isDefault)?.description || 'Default Certificate'
    }
};

export default config; 