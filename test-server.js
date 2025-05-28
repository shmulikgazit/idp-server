const axios = require('axios');
const { jwtVerify, importSPKI } = require('jose');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'http://localhost:3000';

async function testServer() {
    console.log('🧪 Testing LivePerson IDP Server...\n');
    
    try {
        // Test 1: Health check
        console.log('1. Testing health endpoint...');
        const healthResponse = await axios.get(`${BASE_URL}/health`);
        console.log('✅ Health check passed:', healthResponse.data.status);
        
        // Test 2: JWKS endpoint
        console.log('\n2. Testing JWKS endpoint...');
        const jwksResponse = await axios.get(`${BASE_URL}/.well-known/jwks.json`);
        console.log('✅ JWKS endpoint working, keys found:', jwksResponse.data.keys.length);
        
        // Test 3: Encryption public key
        console.log('\n3. Testing encryption public key endpoint...');
        const encKeyResponse = await axios.get(`${BASE_URL}/encryption-public-key`);
        console.log('✅ Encryption public key retrieved, length:', encKeyResponse.data.length);
        
        // Test 4: Token endpoint
        console.log('\n4. Testing token endpoint...');
        const tokenResponse = await axios.post(`${BASE_URL}/token`, {
            grant_type: 'authorization_code',
            code: 'test-code',
            client_id: 'test-client'
        }, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });
        
        console.log('✅ Token endpoint working');
        console.log('   - Access token received:', !!tokenResponse.data.access_token);
        console.log('   - ID token received:', !!tokenResponse.data.id_token);
        
        // Test 5: Verify JWT signature
        console.log('\n5. Testing JWT signature verification...');
        const idToken = tokenResponse.data.id_token;
        
        // Load public key for verification
        const signingPublicPem = fs.readFileSync(path.join(__dirname, 'certs', 'signing-public.pem'), 'utf8');
        const publicKey = await importSPKI(signingPublicPem, 'RS256');
        
        const { payload } = await jwtVerify(idToken, publicKey);
        console.log('✅ JWT signature verified successfully');
        console.log('   - Subject:', payload.sub);
        console.log('   - Email:', payload.email);
        console.log('   - Customer ID:', payload.lp_sdes?.customerInfo?.customerId);
        
        // Test 6: Authorization endpoint (implicit flow)
        console.log('\n6. Testing authorization endpoint...');
        try {
            const authUrl = `${BASE_URL}/authorize?client_id=test&redirect_uri=http://localhost:3000&response_type=id_token&scope=openid&state=test&nonce=123`;
            const authResponse = await axios.get(authUrl, { 
                maxRedirects: 0,
                validateStatus: (status) => status === 302 
            });
            console.log('✅ Authorization endpoint working (redirect received)');
        } catch (error) {
            if (error.response && error.response.status === 302) {
                console.log('✅ Authorization endpoint working (redirect received)');
            } else {
                throw error;
            }
        }
        
        console.log('\n🎉 All tests passed! Server is ready for LivePerson integration.');
        console.log('\nNext steps:');
        console.log('1. Run: ngrok http 3000');
        console.log('2. Copy the ngrok HTTPS URL');
        console.log('3. Configure LivePerson connector with the ngrok endpoints');
        console.log('4. Get encryption public key from: [ngrok-url]/encryption-public-key');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        process.exit(1);
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    testServer();
}

module.exports = { testServer }; 