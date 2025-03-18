from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import base64
import uuid

app = FastAPI()

# Storage for keys
key_store = {}

### ====== Request Models ====== ###
class KeyGenerationRequest(BaseModel):
    key_type: str
    key_size: int = 256  # Default AES size

class EncryptionRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str

class DecryptionRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str

class HashRequest(BaseModel):
    data: str
    algorithm: str

class VerifyHashRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str


### ====== Key Generation ====== ###
@app.post("/generate-key/")
def generate_key(request: KeyGenerationRequest):
    key_id = str(uuid.uuid4())

    if request.key_type.upper() == "AES":
        key = Fernet.generate_key()
        key_store[key_id] = {"type": "AES", "key": key}
    elif request.key_type.upper() == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size
        )
        public_key = private_key.public_key()

        key_store[key_id] = {
            "type": "RSA",
            "private_key": private_key,
            "public_key": public_key
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Use 'AES' or 'RSA'.")

    return {"key_id": key_id, "key_value": base64.b64encode(key).decode() if request.key_type == "AES" else "RSA Key Pair Generated"}


### ====== Encryption ====== ###
@app.post("/encrypt/")
def encrypt(request: EncryptionRequest):
    if request.key_id not in key_store:
        raise HTTPException(status_code=404, detail="Key ID not found")

    key_data = key_store[request.key_id]

    if request.algorithm.upper() == "AES" and key_data["type"] == "AES":
        cipher = Fernet(key_data["key"])
        ciphertext = cipher.encrypt(request.plaintext.encode())
        return {"ciphertext": base64.b64encode(ciphertext).decode()}
    
    elif request.algorithm.upper() == "RSA" and key_data["type"] == "RSA":
        ciphertext = key_data["public_key"].encrypt(
            request.plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": base64.b64encode(ciphertext).decode()}
    
    else:
        raise HTTPException(status_code=400, detail="Invalid encryption algorithm or key type")


### ====== Decryption ====== ###
@app.post("/decrypt/")
def decrypt(request: DecryptionRequest):
    if request.key_id not in key_store:
        raise HTTPException(status_code=404, detail="Key ID not found")

    key_data = key_store[request.key_id]

    if request.algorithm.upper() == "AES" and key_data["type"] == "AES":
        cipher = Fernet(key_data["key"])
        decrypted_text = cipher.decrypt(base64.b64decode(request.ciphertext)).decode()
        return {"plaintext": decrypted_text}

    elif request.algorithm.upper() == "RSA" and key_data["type"] == "RSA":
        decrypted_text = key_data["private_key"].decrypt(
            base64.b64decode(request.ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return {"plaintext": decrypted_text}

    else:
        raise HTTPException(status_code=400, detail="Invalid decryption algorithm or key type")


### ====== Hashing ====== ###
@app.post("/generate-hash/")
def generate_hash(request: HashRequest):
    if request.algorithm.upper() == "SHA-256":
        hash_value = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm.upper() == "SHA-512":
        hash_value = hashlib.sha512(request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Invalid hashing algorithm. Use 'SHA-256' or 'SHA-512'.")

    return {
        "hash_value": base64.b64encode(hash_value).decode(),
        "algorithm": request.algorithm.upper()
    }


### ====== Hash Verification ====== ###
@app.post("/verify-hash/")
def verify_hash(request: VerifyHashRequest):
    computed_hash = None
    if request.algorithm.upper() == "SHA-256":
        computed_hash = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm.upper() == "SHA-512":
        computed_hash = hashlib.sha512(request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Invalid hashing algorithm. Use 'SHA-256' or 'SHA-512'.")

    return {
        "is_valid": base64.b64encode(computed_hash).decode() == request.hash_value,
        "message": "Hash matches the data." if base64.b64encode(computed_hash).decode() == request.hash_value else "Hash does not match."
    }


### ====== Root Endpoint ====== ###
@app.get("/")
def home():
    return {"message": "Cryptographic API is running!"}
