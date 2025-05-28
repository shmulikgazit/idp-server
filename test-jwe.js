const axios = require('axios');

async function testJWE() {
    const baseUrl = 'http://localhost:3000';
    
    try {
        console.log('🔧 Testing JWE encryption...\n');
        
        // First, enable encryption
        console.log('1. Enabling encryption...');
        const toggleResponse = await axios.post(`${baseUrl}/toggle-encryption`, {
            enabled: true
        });
        console.log('✓ Encryption enabled:', toggleResponse.data);
        
        // Wait a moment for the toggle to take effect
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Request a token
        console.log('\n2. Requesting token with encryption enabled...');
        const tokenResponse = await axios.post(`${baseUrl}/token`, {
            user_id: 'test-user-jwe',
            client_id: 'liveperson-client'
        });
        
        const idToken = tokenResponse.data.id_token;
        console.log('✓ Token received');
        console.log('Token length:', idToken.length);
        console.log('Token starts with:', idToken.substring(0, 50) + '...');
        
        // Check if it's JWE (should have 5 parts separated by dots)
        const parts = idToken.split('.');
        console.log('Token parts count:', parts.length);
        
        if (parts.length === 5) {
            console.log('✅ SUCCESS: Token appears to be JWE (5 parts)');
            console.log('JWE Header (base64):', parts[0]);
            
            // Try to decode the header to see the algorithm
            try {
                const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
                console.log('JWE Header decoded:', JSON.stringify(header, null, 2));
            } catch (e) {
                console.log('Could not decode header:', e.message);
            }
        } else if (parts.length === 3) {
            console.log('❌ ISSUE: Token appears to be JWT (3 parts), not JWE');
            
            // Try to decode the header to see what we got
            try {
                const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
                console.log('JWT Header decoded:', JSON.stringify(header, null, 2));
            } catch (e) {
                console.log('Could not decode header:', e.message);
            }
        } else {
            console.log('❓ UNKNOWN: Token has unexpected number of parts:', parts.length);
        }
        
        // Now disable encryption and test again
        console.log('\n3. Disabling encryption...');
        await axios.post(`${baseUrl}/toggle-encryption`, {
            enabled: false
        });
        console.log('✓ Encryption disabled');
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        console.log('\n4. Requesting token with encryption disabled...');
        const tokenResponse2 = await axios.post(`${baseUrl}/token`, {
            user_id: 'test-user-jwt',
            client_id: 'liveperson-client'
        });
        
        const idToken2 = tokenResponse2.data.id_token;
        const parts2 = idToken2.split('.');
        console.log('✓ Token received (encryption disabled)');
        console.log('Token parts count:', parts2.length);
        
        if (parts2.length === 3) {
            console.log('✅ SUCCESS: Token is JWT (3 parts) when encryption disabled');
        } else {
            console.log('❌ ISSUE: Expected JWT (3 parts) but got', parts2.length, 'parts');
        }
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
    }
}

testJWE(); 