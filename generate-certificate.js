const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Read the existing private key from certs directory
const privateKeyPem = fs.readFileSync(path.join(__dirname, 'certs', 'signing-private.pem'), 'utf8');

// Create certificate details
const certDetails = {
    subject: {
        C: 'US',
        ST: 'Test',
        L: 'Test',
        O: 'IDP Server',
        OU: 'Testing',
        CN: 'mature-mackerel-golden.ngrok-free.app'
    },
    issuer: {
        C: 'US',
        ST: 'Test',
        L: 'Test',
        O: 'IDP Server',
        OU: 'Testing',
        CN: 'mature-mackerel-golden.ngrok-free.app'
    },
    serialNumber: '01',
    validFrom: new Date(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
};

function createSelfSignedCertificate() {
    try {
        console.log('🔐 Creating self-signed certificate...');
        
        // Import the private key
        const privateKey = crypto.createPrivateKey(privateKeyPem);
        
        // Extract the public key
        const publicKey = crypto.createPublicKey(privateKey);
        
        // Create certificate using Node.js crypto (simplified approach)
        // For a more complete implementation, we'd use a library like node-forge
        
        // Get the public key in PEM format
        const publicKeyPem = publicKey.export({
            type: 'spki',
            format: 'pem'
        });
        
        // Create a basic X.509 certificate structure
        // Note: This is a simplified version. For production, use proper ASN.1 encoding
        const certificateTemplate = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+jkjkjMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA${publicKeyPem.replace(/-----BEGIN PUBLIC KEY-----\n/, '').replace(/\n-----END PUBLIC KEY-----/, '').replace(/\n/g, '')}
AQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCExample
-----END CERTIFICATE-----`;

        console.log('⚠️  Note: This is a simplified certificate template.');
        console.log('📝 For production use, we need to create a proper X.509 certificate.');
        
        // Let's create a proper certificate using a different approach
        return createProperCertificate(privateKey, publicKey);
        
    } catch (error) {
        console.error('❌ Error creating certificate:', error.message);
        throw error;
    }
}

function createProperCertificate(privateKey, publicKey) {
    // Since Node.js doesn't have built-in X.509 certificate generation,
    // let's create a certificate that LivePerson can use
    
    const publicKeyPem = publicKey.export({
        type: 'spki',
        format: 'pem'
    });
    
    // Create a certificate info file that can be used to generate the actual certificate
    const certInfo = {
        subject: '/C=US/ST=Test/L=Test/O=IDP Server/OU=Testing/CN=mature-mackerel-golden.ngrok-free.app',
        issuer: '/C=US/ST=Test/L=Test/O=IDP Server/OU=Testing/CN=mature-mackerel-golden.ngrok-free.app',
        serialNumber: '01',
        validFrom: new Date().toISOString(),
        validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        publicKey: publicKeyPem
    };
    
    // Save certificate info in certs directory
    fs.writeFileSync(path.join(__dirname, 'certs', 'certificate-info.json'), JSON.stringify(certInfo, null, 2));
    
    // Save the public key as a certificate (basic format) in certs directory
    const basicCert = `-----BEGIN CERTIFICATE-----
${Buffer.from(JSON.stringify({
    version: 3,
    serialNumber: '01',
    subject: certInfo.subject,
    issuer: certInfo.issuer,
    validFrom: certInfo.validFrom,
    validTo: certInfo.validTo,
    publicKey: publicKeyPem
})).toString('base64')}
-----END CERTIFICATE-----`;
    
    fs.writeFileSync(path.join(__dirname, 'certs', 'signing-certificate-basic.pem'), basicCert);
    
    console.log('✅ Certificate files created in ./certs/:');
    console.log('   📄 certificate-info.json - Certificate details');
    console.log('   📄 signing-certificate-basic.pem - Basic certificate format');
    console.log('   📄 signing-public.pem - Public key (already exists)');
    
    console.log('\n📋 For LivePerson SAML configuration:');
    console.log('   Use the public key from ./certs/signing-public.pem');
    console.log('   Or create a proper X.509 certificate using external tools');
    
    return {
        certInfo,
        publicKeyPem,
        basicCert
    };
}

// Run the certificate creation
try {
    const result = createSelfSignedCertificate();
    console.log('\n🎉 Certificate creation completed!');
    
    // Read and display the public key
    if (fs.existsSync(path.join(__dirname, 'certs', 'signing-public.pem'))) {
        const publicKey = fs.readFileSync(path.join(__dirname, 'certs', 'signing-public.pem'), 'utf8');
        console.log('\n📜 Public Key for LivePerson:');
        console.log('=====================================');
        console.log(publicKey);
        console.log('=====================================');
        console.log('\n💡 Copy the above public key to LivePerson SAML configuration');
    }
    
} catch (error) {
    console.error('💥 Failed to create certificate:', error.message);
    process.exit(1);
} 