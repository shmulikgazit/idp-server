const fs = require('fs');
const jose = require('node-jose');

async function debugKid() {
    try {
        // Load the LivePerson certificate
        const lpCert = fs.readFileSync('./certs/lpsso2026.pem', 'utf8');
        console.log('Certificate loaded, length:', lpCert.length);
        
        // Import as JWK
        const key = await jose.JWK.asKey(lpCert, 'pem');
        console.log('Key imported successfully');
        console.log('Key thumbprint:', key.thumbprint);
        console.log('Key kid (if any):', key.kid);
        console.log('Key kty:', key.kty);
        
        // Try to create a simple JWE to see what kid gets used
        const testPayload = 'test-payload';
        
        console.log('\n--- Test 1: Without explicit kid ---');
        const jwe1 = await jose.JWE.createEncrypt({
            format: 'compact',
            fields: {
                alg: 'RSA-OAEP-256',
                enc: 'A256GCM'
            }
        }, key)
        .update(testPayload)
        .final();
        
        const parts1 = jwe1.split('.');
        const header1 = JSON.parse(Buffer.from(parts1[0], 'base64url').toString());
        console.log('Header without explicit kid:', JSON.stringify(header1, null, 2));
        
        console.log('\n--- Test 2: With explicit kid ---');
        const jwe2 = await jose.JWE.createEncrypt({
            format: 'compact',
            fields: {
                alg: 'RSA-OAEP-256',
                enc: 'A256GCM',
                kid: 'lpsso2026'
            }
        }, key)
        .update(testPayload)
        .final();
        
        const parts2 = jwe2.split('.');
        const header2 = JSON.parse(Buffer.from(parts2[0], 'base64url').toString());
        console.log('Header with explicit kid:', JSON.stringify(header2, null, 2));
        
        console.log('\n--- Test 3: Setting kid on key ---');
        key.kid = 'lpsso2026';
        const jwe3 = await jose.JWE.createEncrypt({
            format: 'compact',
            fields: {
                alg: 'RSA-OAEP-256',
                enc: 'A256GCM'
            }
        }, key)
        .update(testPayload)
        .final();
        
        const parts3 = jwe3.split('.');
        const header3 = JSON.parse(Buffer.from(parts3[0], 'base64url').toString());
        console.log('Header with kid set on key:', JSON.stringify(header3, null, 2));
        
    } catch (error) {
        console.error('Error:', error.message);
        console.error(error.stack);
    }
}

debugKid(); 