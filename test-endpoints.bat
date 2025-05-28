@echo off
echo Testing LivePerson IDP Server...
echo.

echo 1. Testing health endpoint...
curl -s http://localhost:3000/health
echo.
echo.

echo 2. Testing JWKS endpoint...
curl -s http://localhost:3000/.well-known/jwks.json
echo.
echo.

echo 3. Testing encryption public key endpoint...
curl -s http://localhost:3000/encryption-public-key
echo.
echo.

echo 4. Testing token endpoint...
curl -s -X POST http://localhost:3000/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=authorization_code&code=test&client_id=test"
echo.
echo.

echo Testing complete!
echo.
echo Next steps:
echo 1. Install ngrok: https://ngrok.com/
echo 2. Run: ngrok http 3000
echo 3. Copy the ngrok HTTPS URL
echo 4. Configure LivePerson connector with the ngrok endpoints
echo 5. Get encryption public key from: [ngrok-url]/encryption-public-key
pause 