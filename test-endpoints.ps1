# Test LivePerson IDP Server Endpoints

Write-Host "Testing LivePerson IDP Server..." -ForegroundColor Green

# Test health endpoint
Write-Host "`n1. Testing health endpoint..." -ForegroundColor Yellow
try {
    $health = Invoke-WebRequest -Uri "http://localhost:3000/health"
    Write-Host "✓ Health check passed" -ForegroundColor Green
    Write-Host $health.Content
} catch {
    Write-Host "✗ Health check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test JWKS endpoint
Write-Host "`n2. Testing JWKS endpoint..." -ForegroundColor Yellow
try {
    $jwks = Invoke-WebRequest -Uri "http://localhost:3000/.well-known/jwks.json"
    Write-Host "✓ JWKS endpoint working" -ForegroundColor Green
    Write-Host $jwks.Content
} catch {
    Write-Host "✗ JWKS endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test encryption public key
Write-Host "`n3. Testing encryption public key endpoint..." -ForegroundColor Yellow
try {
    $encKey = Invoke-WebRequest -Uri "http://localhost:3000/encryption-public-key"
    Write-Host "✓ Encryption public key retrieved" -ForegroundColor Green
    Write-Host "Key length: $($encKey.Content.Length) characters"
} catch {
    Write-Host "✗ Encryption public key failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test token endpoint
Write-Host "`n4. Testing token endpoint..." -ForegroundColor Yellow
try {
    $body = "grant_type=authorization_code&code=test&client_id=test"
    $token = Invoke-WebRequest -Uri "http://localhost:3000/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
    Write-Host "✓ Token endpoint working" -ForegroundColor Green
    $tokenData = $token.Content | ConvertFrom-Json
    Write-Host "Access token received: $($tokenData.access_token -ne $null)"
    Write-Host "ID token received: $($tokenData.id_token -ne $null)"
} catch {
    Write-Host "✗ Token endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🎉 Testing complete!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Install ngrok: https://ngrok.com/"
Write-Host "2. Run: ngrok http 3000"
Write-Host "3. Copy the ngrok HTTPS URL"
Write-Host "4. Configure LivePerson connector with the ngrok endpoints"
Write-Host "5. Get encryption public key from: [ngrok-url]/encryption-public-key" 