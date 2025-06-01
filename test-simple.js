const http = require('http');

async function testSAMLEndpoint(shouldEncrypt) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            siteId: '12345',
            loginName: 'testuser@example.com',
            destinationUrl: 'https://test.liveperson.com/acs',
            shouldEncrypt: shouldEncrypt
        });

        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/generate-saml-assertion',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    resolve(result);
                } catch (error) {
                    console.log('Raw response:', data);
                    reject(new Error(`Failed to parse response: ${error.message}`));
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.write(postData);
        req.end();
    });
}

async function runTests() {
    console.log('🧪 Testing SAML Encryption...');
    
    try {
        console.log('\n🔍 Testing WITHOUT encryption...');
        const unencryptedResult = await testSAMLEndpoint(false);
        
        if (unencryptedResult.success) {
            console.log('✅ Unencrypted SAML generated successfully');
            console.log('   Method:', unencryptedResult.method);
            console.log('   XML length:', unencryptedResult.xml.length);
            console.log('   Contains EncryptedAssertion:', unencryptedResult.xml.includes('EncryptedAssertion'));
            console.log('   Contains regular Assertion:', unencryptedResult.xml.includes('Assertion'));
        } else {
            console.log('❌ Unencrypted test failed:', unencryptedResult.error);
        }
        
        console.log('\n🔍 Testing WITH encryption...');
        const encryptedResult = await testSAMLEndpoint(true);
        
        if (encryptedResult.success) {
            console.log('✅ Encrypted SAML generated successfully');
            console.log('   Method:', encryptedResult.method);
            console.log('   XML length:', encryptedResult.xml.length);
            console.log('   Contains EncryptedAssertion:', encryptedResult.xml.includes('EncryptedAssertion'));
            console.log('   Contains EncryptedData:', encryptedResult.xml.includes('EncryptedData'));
            console.log('   Contains CipherValue:', encryptedResult.xml.includes('CipherValue'));
            console.log('   Contains regular Assertion:', encryptedResult.xml.includes('Assertion'));
            console.log('   Encryption used flag:', encryptedResult.encryptionUsed);
            
            if (encryptedResult.xml.includes('EncryptedAssertion') || encryptedResult.xml.includes('EncryptedData')) {
                console.log('\n🎉 SUCCESS! SAML encryption is working!');
            } else {
                console.log('\n❌ FAILED! SAML encryption is not working');
                console.log('   First 500 chars of XML:');
                console.log('   ' + encryptedResult.xml.substring(0, 500));
                
                // Check if the method indicates encryption was attempted
                if (encryptedResult.method.includes('ENCRYPTED')) {
                    console.log('   🔍 Method indicates encryption was attempted but XML doesn\'t contain encrypted elements');
                } else {
                    console.log('   🔍 Method indicates encryption was not attempted');
                }
            }
        } else {
            console.log('❌ Encrypted test failed:', encryptedResult.error);
        }
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
    }
}

runTests(); 