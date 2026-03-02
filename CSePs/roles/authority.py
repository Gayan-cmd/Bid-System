import os
import json
from crypto.ecc_keys import generate_ecc_keypair, save_private_key, save_public_key,load_private_key,load_public_key
from config import set_deadline,is_deadline_passed
from crypto.encrypt_decrypt import decrypt_bid
from crypto.sign_verify import verify_signature
from crypto.hash_utils import sha256_hash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

AUTHORITY_FOLDER = "storage/authority"

def configure_procurement():
    print("\n=== Configure Procurement Deadline ===")

    minutes = int(input("Enter deadline (minutes from now): "))
    set_deadline(minutes)



def setup_authority():
    print("\n=== Authority Setup ===")

    os.makedirs(AUTHORITY_FOLDER, exist_ok=True)

    private_key, public_key = generate_ecc_keypair()

    save_private_key(private_key, f"{AUTHORITY_FOLDER}/private.pem")
    save_public_key(public_key, f"{AUTHORITY_FOLDER}/public.pem")

    print("Authority keys generated successfully.")


def decrypt_with_evaluators(encrypted_bid):
    nonce = bytes.fromhex(encrypted_bid["nonce"])
    ciphertext = bytes.fromhex(encrypted_bid["ciphertext"])

    recovered_keys = []

    for evaluator_id, data in encrypted_bid["encrypted_keys"].items():
        private_key = load_private_key(
            f"storage/evaluators/{evaluator_id}/private.pem"
        )

        ephemeral_public_key = serialization.load_pem_public_key(
            data["ephemeral_public_key"].encode()
        )

        shared_key = private_key.exchange(
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
            bytes.fromhex(data["encrypted_key"]),
            None
        )

        recovered_keys.append(aes_key)

    # Ensure all evaluators derived same AES key
    if not all(k == recovered_keys[0] for k in recovered_keys):
        raise Exception("Evaluator keys mismatch!")

    aesgcm = AESGCM(recovered_keys[0])
    return aesgcm.decrypt(nonce, ciphertext, None)


def open_all_bids():
    print("\n=== Opening All Bids ===")

    if not is_deadline_passed():
        print("Deadline not reached. Cannot open bids.")
        return

    authority_private_key = load_private_key("storage/authority/private.pem")

    bids_folder = "storage/bids"

    if not os.path.exists(bids_folder):
        print("No bids submitted.")
        return

    for filename in os.listdir(bids_folder):
        filepath = os.path.join(bids_folder, filename)

        with open(filepath, "r") as f:
            bid_record = json.load(f)

        print("\n--- Processing:", filename, "---")

        try:

            encrypted_bid_data = bid_record["encrypted_bid"]
        
            decrypted_data = decrypt_with_evaluators(encrypted_bid_data)

            bid_json = decrypted_data.decode()
            bid_data = json.loads(bid_json)

            recalculated_hash = sha256_hash(decrypted_data).hex()

            bidder_id = bid_data["bidder_id"]
            public_key_path = f"storage/keys/{bidder_id}/public.pem"
            public_key = load_public_key(public_key_path)

            signature = bytes.fromhex(bid_record["signature"])

            signature_valid = verify_signature(
                public_key,
                signature,
                bytes.fromhex(bid_record["hash"])
            )

            print("Bid Data:", bid_data)
            print("Hash matches?", recalculated_hash == bid_record["hash"])
            print("Signature valid?", signature_valid)

        except Exception as e:
            print("Error processing bid Possibly due to tampering:", e)


def reveal_winner_identity():
    print("\n=== Reveal Bidder Identity ===")

    bidder_id = input("Enter the winning Bidder ID to reveal: ")
    identities_folder = "storage/identities"
    identity_file = os.path.join(identities_folder, f"{bidder_id}_identity.json")

    if not os.path.exists(identity_file):
        print(f"Error: Identity envelope not found for {bidder_id}.")
        return

    authority_private_key = load_private_key("storage/authority/private.pem")

    try:
        with open(identity_file, "r") as f:
            encrypted_identity = json.load(f)

        # Decrypt using the single-authority format
        decrypted_data = decrypt_bid(authority_private_key, encrypted_identity)

        identity_data = json.loads(decrypted_data.decode())
        bidder_name = identity_data.get("bidder_name", "Unknown")

        print("\n ==== WINNER IDENTITY REVEALED ==== ")
        print(f"Bidder ID: {bidder_id}")
        print(f"True Name: {bidder_name}")
        print("==================================\n")

    except Exception as e:
        print("Error revealing identity:", e)