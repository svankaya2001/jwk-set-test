# JWKS Server for Epic FHIR OAuth2

This is a simple JWKS (JSON Web Key Set) server implementation that serves your public keys for Epic FHIR OAuth2 authentication.

## Setup

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Generate SSL certificates (required for HTTPS):
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

3. In production, modify the `jwks_server.py` to load your existing RSA key pair instead of generating a new one.

## Running the Server

```bash
python jwks_server.py
```

The server will start on port 8000 with HTTPS enabled. Your JWKS URL will be:
```
https://your-domain:8000/.well-known/jwks.json
```

## Important Notes

1. In production, ensure you:
   - Use proper SSL certificates
   - Load your existing RSA keys instead of generating new ones
   - Set appropriate security headers
   - Use proper key rotation mechanisms
   - Deploy behind a reverse proxy like nginx

2. The JWKS endpoint follows the standard format required by Epic FHIR:
   - Serves keys at the `.well-known/jwks.json` endpoint
   - Returns a JSON object with a "keys" array
   - Each key includes the required JWK parameters (kty, n, e, kid, use, alg)

3. The current implementation uses a static key ID ("kid": "1"). In a production environment, you might want to implement key rotation and dynamic key IDs. 