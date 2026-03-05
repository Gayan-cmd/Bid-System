import os
from crypto.ecc_keys import generate_ecc_keypair, save_private_key, save_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import json

EVALUATOR_FOLDER = "storage/evaluators"

def register_evaluator():
    print("\n=== Register Evaluator ===")

    evaluator_id = input("Enter evaluator name: ")
    password = input("Enter password: ")

    folder = os.path.join(EVALUATOR_FOLDER, evaluator_id)
    os.makedirs(folder, exist_ok=True)

    private_key, public_key = generate_ecc_keypair()

    # 1. Serialize the private key to bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Derive a Key-Wrapping Key (KWK) from the password using PBKDF2
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    kwk = kdf.derive(password.encode())

    # 3. Encrypt the private key bytes using AES-GCM
    aesgcm = AESGCM(kwk)
    nonce = os.urandom(12)
    encrypted_private_key = aesgcm.encrypt(nonce, private_bytes, None)

    # 4. Save the wrapped key components to a JSON file
    wrapped_key_data = {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": encrypted_private_key.hex()
    }

    with open(f"{folder}/encrypted_private.json", "w") as f:
        json.dump(wrapped_key_data, f, indent=4)

    # Save the Public Key normally so bidders can encrypt to it
    save_public_key(public_key, f"{folder}/public.pem")

    print("\n[SUCCESS] Evaluator registered:", evaluator_id)
    print("Your private key has been securely encrypted with your password.")

    