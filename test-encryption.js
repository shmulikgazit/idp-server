const saml = require('samlify');
const fs = require('fs');
const http = require('http');

// Load certificates
function loadSigningCertificate() {
    try {
        return fs.readFileSync('./certs/samlify-signing-cert.pem', 'utf8');
    } catch (error) {
        console.error('Failed to load signing certificate:', error.message);
        return null;
    }
}

function loadSigningPrivateKey() {
    try {
        return fs.readFileSync('./certs/samlify-private.pem', 'utf8');
    } catch (error) {
        console.error('Failed to load signing private key:', error.message);
        return null;
    }
}

function loadLivePersonCertificate() {
    try {
        return fs.readFileSync('./certs/lpsso2026.pem', 'utf8');
    } catch (error) {
        console.error('Failed to load LivePerson certificate:', error.message);
        return null;
    }
}

// Test server's SAML generation endpoint
async function testServerSAMLGeneration(shouldEncrypt) {
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

async function testEncryption() {
    console.log('🧪 === SAML Encryption Test (Server Endpoint) ===');
    
    const signingCert = loadSigningCertificate();
    const signingKey = loadSigningPrivateKey();
    const encryptionCert = loadLivePersonCertificate();
    
    if (!signingCert || !signingKey || !encryptionCert) {
        console.error('❌ Missing required certificates');
        return;
    }
    
    console.log('✅ All certificates loaded');
    
    try {
        console.log('🔍 Testing server WITHOUT encryption...');
        const unencryptedResult = await testServerSAMLGeneration(false);
        
        if (unencryptedResult.success) {
            const unencryptedXml = unencryptedResult.xml;
            console.log('✅ Unencrypted response created');
            console.log('   Method:', unencryptedResult.method);
            console.log('   Contains EncryptedAssertion:', unencryptedXml.includes('EncryptedAssertion'));
            console.log('   Contains regular Assertion:', unencryptedXml.includes('<saml:Assertion') || unencryptedXml.includes('<saml2:Assertion'));
        } else {
            console.log('❌ Unencrypted test failed:', unencryptedResult.error);
        }
        
        console.log('🔍 Testing server WITH encryption...');
        const encryptedResult = await testServerSAMLGeneration(true);
        
        if (encryptedResult.success) {
            const encryptedXml = encryptedResult.xml;
            console.log('✅ Encrypted response created');
            console.log('   Method:', encryptedResult.method);
            console.log('   Response length:', encryptedXml.length);
            console.log('   First 200 chars:', encryptedXml.substring(0, 200));
            console.log('   Contains EncryptedAssertion:', encryptedXml.includes('EncryptedAssertion'));
            console.log('   Contains EncryptedData:', encryptedXml.includes('EncryptedData'));
            console.log('   Contains CipherValue:', encryptedXml.includes('CipherValue'));
            console.log('   Contains regular Assertion:', encryptedXml.includes('<saml:Assertion') || encryptedXml.includes('<saml2:Assertion'));
            
            if (encryptedXml.includes('EncryptedAssertion') || encryptedXml.includes('EncryptedData')) {
                console.log('🎉 SUCCESS! SAML encryption is working!');
            } else {
                console.log('❌ FAILED! SAML encryption is not working - no encrypted elements found');
                console.log('   Full XML preview:', encryptedXml.substring(0, 500));
            }
        } else {
            console.log('❌ Encrypted test failed:', encryptedResult.error);
        }
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        console.error('Stack:', error.stack);
    }
}

testEncryption().catch(console.error); 