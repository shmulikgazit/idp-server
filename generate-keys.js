const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Create certs directory if it doesn't exist
const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir);
}

console.log('Generating RSA key pairs using OpenSSL...\n');

// Try to find OpenSSL
let opensslCmd = 'openssl';
const possiblePaths = [
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
    'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
    'openssl'
];

for (const opensslPath of possiblePaths) {
    try {
        execSync(`"${opensslPath}" version`, { stdio: 'pipe' });
        opensslCmd = `"${opensslPath}"`;
        console.log(`Found OpenSSL at: ${opensslPath}`);
        break;
    } catch (e) {
        // Continue to next path
    }
}

try {
    // Generate signing key pair (RS256)
    console.log('1. Generating signing key pair...');
    
    // Generate private key
    execSync(`${opensslCmd} genrsa -out "${path.join(certsDir, 'signing-private.pem')}" 2048`, { stdio: 'inherit' });
    
    // Extract public key
    execSync(`${opensslCmd} rsa -in "${path.join(certsDir, 'signing-private.pem')}" -pubout -out "${path.join(certsDir, 'signing-public.pem')}"`, { stdio: 'inherit' });
    
    console.log('✓ Signing key pair generated successfully');
    
    console.log('\n✅ Key pair generated successfully!');
    console.log('\nKey files created in ./certs/:');
    console.log('- signing-public.pem (for JWKS endpoint)');
    console.log('- signing-private.pem (for JWT signing)');
    console.log('\nNote: For JWE encryption, place the LivePerson certificate (lpsso2026.pem) in ./certs/');
    
} catch (error) {
    console.error('\n❌ Error generating keys:', error.message);
    console.log('\nThis script requires OpenSSL to be installed and available in PATH.');
    console.log('On Windows, you can:');
    console.log('1. Install Git for Windows (includes OpenSSL)');
    console.log('2. Install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html');
    console.log('3. Or use Windows Subsystem for Linux (WSL)');
    console.log('\nAlternatively, you can generate keys manually:');
    console.log('openssl genrsa -out certs/signing-private.pem 2048');
    console.log('openssl rsa -in certs/signing-private.pem -pubout -out certs/signing-public.pem');
    process.exit(1);
} 