from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from jose import jwk
from jose.utils import base64url_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
import json
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

app = FastAPI(title="JWKS Server", description="Serves JWK Set for Epic FHIR OAuth2")

# Configuration
KEY_DIR = os.environ.get("KEY_DIR", "keys")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "publickey509.pem")

print(f"Using key directory: {KEY_DIR}")
print(f"Looking for public key at: {PUBLIC_KEY_FILE}")


def load_public_key():
    """Load RSA public key from X.509 certificate"""
    try:
        # Try to load existing X.509 certificate
        with open(PUBLIC_KEY_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            public_key = cert.public_key()
        print("Loaded RSA public key from X.509 certificate")
        return public_key
    except (FileNotFoundError, ValueError) as e:
        raise RuntimeError(
            f"X.509 certificate not found at {PUBLIC_KEY_FILE} or invalid format. "
            "Please ensure your X.509 certificate is in PEM format and placed in the correct location."
        )


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


# Load public key
public_key = load_public_key()

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
