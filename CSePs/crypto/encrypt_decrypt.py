import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes,serialization
from crypto.ecc_keys import load_private_key
from sslib import shamir, randomness


def encrypt_bid(evaluator_public_keys, plaintext: bytes):

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    num_evaluators = len(evaluator_public_keys)
    if num_evaluators < 1:
        raise ValueError("At least 1 evaluator must be registered.")

    # Convert AES key to hex string for sslib to split
    aes_hex = aes_key.hex()
    
    # Split the AES key into N shares, requiring N shares to rebuild (Unanimity)
    # We explicitly pass URandomReader to ensure cross-platform compatibility (Windows doesn't have /dev/random)
    shares_dict = shamir.split_secret(
        aes_hex.encode(), 
        required_shares=num_evaluators, 
        distributed_shares=num_evaluators,
        randomness_source=randomness.UrandomReader()
    )
    
    # shares_dict is typically {"required_shares": 2, "prime_mod": abc, "shares": [(1, b"share_data"), ...]}
    shares_list = shares_dict["shares"]

    encrypted_keys = {}
    share_index = 0

    for evaluator_id, public_key in evaluator_public_keys.items():
        
        # Grab a unique mathematical share for this specific evaluator
        current_share_id, current_share_data = shares_list[share_index]
        
        # We need to serialize the tuple so it can be reconstructed easily after decryption
        # Convert bytes share to hex to safely encode as an ascii string
        share_payload = f"{current_share_id}:{current_share_data.hex()}".encode()

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
        
        # Encrypt only this evaluator's specific SHARE, not the full AES key!
        encrypted_share = key_aesgcm.encrypt(
            nonce,
            share_payload,
            None
        )

        encrypted_keys[evaluator_id] = {
            "encrypted_share": encrypted_share.hex(),
            "ephemeral_public_key": ephemeral_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        
        share_index += 1

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "encrypted_keys": encrypted_keys,
        "shamir_meta": {
            "prime_mod": shares_dict["prime_mod"].hex(),
            "required_shares": shares_dict["required_shares"]
        }
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

