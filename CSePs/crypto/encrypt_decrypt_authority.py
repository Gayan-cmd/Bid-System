from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import os

def encrypt_bid_authority(authority_public_key, plaintext: bytes):
    """
    Encrypt data for a single Authority (used for Identity Envelopes).
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    shared_key = ephemeral_private_key.exchange(
        ec.ECDH(), authority_public_key
    )

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"bid-encryption",
    ).derive(shared_key)

    key_aesgcm = AESGCM(derived_key)
    encrypted_aes_key = key_aesgcm.encrypt(
        nonce,
        aes_key,
        None
    )

    ephemeral_public_key = ephemeral_private_key.public_key()

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "encrypted_aes_key": encrypted_aes_key.hex(),
        "ephemeral_public_key": ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }
