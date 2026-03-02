import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes,serialization
from crypto.ecc_keys import load_private_key


def encrypt_bid(evaluator_public_keys, plaintext: bytes):

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_keys = {}

    for evaluator_id, public_key in evaluator_public_keys.items():

        ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())

        shared_key = ephemeral_private_key.exchange(
            ec.ECDH(), public_key
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

        encrypted_keys[evaluator_id] = {
            "encrypted_key": encrypted_aes_key.hex(),
            "ephemeral_public_key": ephemeral_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "encrypted_keys": encrypted_keys
    }


def decrypt_bid(authority_private_key, encrypted_data):
    nonce = bytes.fromhex(encrypted_data["nonce"])
    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
    encrypted_aes_key = bytes.fromhex(encrypted_data["encrypted_aes_key"])

    ephemeral_public_key = serialization.load_pem_public_key(
        encrypted_data["ephemeral_public_key"].encode()
    )

    # Recreate shared key
    shared_key = authority_private_key.exchange(
        ec.ECDH(), ephemeral_public_key
    )

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"bid-encryption",
    ).derive(shared_key)

    key_aesgcm = AESGCM(derived_key)

    aes_key = key_aesgcm.decrypt(
        nonce,
        encrypted_aes_key,
        None
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext

