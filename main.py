from fastapi import FastAPI
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
import hashlib
import base64
import uuid
import os

app = FastAPI()

# Dictionary to store generated keys
key_store = {}

# Request models
class KeyGenerationRequest(BaseModel):
    key_type: str
    key_size: int = 256  # Default AES key size (128, 192, 256)

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

# Generate a key (AES or RSA)

# Allowed RSA key sizes
ALLOWED_RSA_SIZES = {1024, 2048, 3072, 4096, 8192}

@app.post("/generate-key/")
def generate_key(request: KeyGenerationRequest):
    key_id = str(uuid.uuid4())

    if request.key_type.upper() == "AES":
        if request.key_size not in [128, 192, 256]:
            return {"message": "Invalid AES key size. Use 128, 192, or 256."}

        key = os.urandom(request.key_size // 8)
        key_store[key_id] = {"type": "AES", "key": key}
        return {"key_id": key_id, "key_value": base64.b64encode(key).decode()}

    if request.key_type.upper() == "RSA":
        if request.key_size not in ALLOWED_RSA_SIZES:
            return {"message": "Invalid RSA key size. Use 1024, 2048, 3072, 4096, or 8192."}

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size
        )
        public_key = private_key.public_key()

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_b64 = base64.b64encode(private_key_bytes).decode()

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode()

        key_store[key_id] = {"type": "RSA", "private_key": private_key, "public_key": public_key}

        return {
            "key_id": key_id,
            "public_key": public_key_b64,
            "private_key": private_key_b64
        }

    return {"message": "Invalid key type. Use 'AES' or 'RSA'."}


# Encrypt data using AES (CBC mode) or RSA
@app.post("/encrypt/")
def encrypt(request: EncryptionRequest):
    key_data = key_store.get(request.key_id)
    if not key_data:
        return {"message": "Key ID not found"}

    if request.algorithm.upper() == "AES" and key_data["type"] == "AES":
        iv = os.urandom(16)  # 128-bit IV for AES-CBC
        cipher = Cipher(algorithms.AES(key_data["key"]), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(request.plaintext.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {"ciphertext": base64.b64encode(iv + ciphertext).decode()}

    if request.algorithm.upper() == "RSA" and key_data["type"] == "RSA":
        ciphertext = key_data["public_key"].encrypt(
            request.plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"ciphertext": base64.b64encode(ciphertext).decode()}

    return {"message": "Invalid encryption algorithm or key type"}

# Decrypt data using AES (CBC mode) or RSA
@app.post("/decrypt/")
def decrypt(request: DecryptionRequest):
    key_data = key_store.get(request.key_id)
    if not key_data:
        return {"message": "Key ID not found"}

    if request.algorithm.upper() == "AES" and key_data["type"] == "AES":
        encrypted_data = base64.b64decode(request.ciphertext)
        iv, encrypted_text = encrypted_data[:16], encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key_data["key"]), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_text = decryptor.update(encrypted_text) + decryptor.finalize()

        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()

        return {"plaintext": decrypted_text.decode()}

    if request.algorithm.upper() == "RSA" and key_data["type"] == "RSA":
        decrypted_text = key_data["private_key"].decrypt(
            base64.b64decode(request.ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
        return {"plaintext": decrypted_text}

    return {"message": "Invalid decryption algorithm or key type"}
# Generate hash
@app.post("/generate-hash/")
def generate_hash(request: HashRequest):
    if request.algorithm.upper() == "SHA-256":
        hash_value = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm.upper() == "SHA-512":
        hash_value = hashlib.sha512(request.data.encode()).digest()
    else:
        return {"message": "Invalid hashing algorithm. Use 'SHA-256' or 'SHA-512'."}

    return {"hash_value": base64.b64encode(hash_value).decode(), "algorithm": request.algorithm.upper()}

# Verify hash
@app.post("/verify-hash/")
def verify_hash(request: VerifyHashRequest):
    if request.algorithm.upper() == "SHA-256":
        computed_hash = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm.upper() == "SHA-512":
        computed_hash = hashlib.sha512(request.data.encode()).digest()
    else:
        return {"message": "Invalid hashing algorithm. Use 'SHA-256' or 'SHA-512'."}

    is_valid = base64.b64encode(computed_hash).decode() == request.hash_value
    return {"is_valid": is_valid, "message": "Hash matches." if is_valid else "Hash does not match."}

# Root endpoint
@app.get("/")
def home():
    return {"message": "Cryptographic API is running!"}
