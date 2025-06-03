from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from jose import jwk
from jose.utils import base64url_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import os

app = FastAPI(title="JWKS Server", description="Serves JWK Set for Epic FHIR OAuth2")


# Generate or load your RSA key pair
# In production, you should load your existing key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


# Convert RSA public key to JWK format
def create_jwk(public_key):
    numbers = public_key.public_numbers()
    jwk_dict = {
        "kty": "RSA",
        "e": base64url_encode(
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder="big")
        ).decode("utf-8"),
        "n": base64url_encode(
            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder="big")
        ).decode("utf-8"),
        "kid": "1",  # Key ID - you might want to make this dynamic
        "use": "sig",  # The intended use of the public key
        "alg": "RS256",  # The algorithm intended for use with this key
    }
    return jwk_dict


# Generate or load key pair
private_key = generate_key_pair()
public_key = private_key.public_key()

# Create JWK from public key
jwk_dict = create_jwk(public_key)


@app.get("/.well-known/jwks.json")
async def get_jwks():
    return JSONResponse(content={"keys": [jwk_dict]})


@app.get("/")
async def root():
    return {
        "message": "JWKS Server is running. Access JWK Set at /.well-known/jwks.json"
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")

    if os.environ.get("RENDER"):
        # Running on Render.com - use HTTP (Render handles HTTPS)
        uvicorn.run(app, host=host, port=port)
    else:
        # Local development - use HTTPS
        uvicorn.run(
            app, host=host, port=port, ssl_keyfile="key.pem", ssl_certfile="cert.pem"
        )
