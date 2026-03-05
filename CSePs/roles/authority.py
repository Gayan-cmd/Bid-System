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
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
from sslib import shamir

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


def decrypt_with_evaluators(encrypted_bid, evaluator_private_keys):
    nonce = bytes.fromhex(encrypted_bid["nonce"])
    ciphertext = bytes.fromhex(encrypted_bid["ciphertext"])

    gathered_shares = []

    for evaluator_id, private_key in evaluator_private_keys.items():
        # 4. Grab this evaluator's specific Share payload from the bid
        if evaluator_id not in encrypted_bid["encrypted_keys"]:
             raise Exception(f"Bid does not contain a share for Evaluator {evaluator_id}")
             
        data = encrypted_bid["encrypted_keys"][evaluator_id]

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

        # 5. Decrypt the Share! (It is a serialized tuple: "id:hex_data")
        decrypted_share_payload = key_aesgcm.decrypt(
            nonce,
            bytes.fromhex(data["encrypted_share"]),
            None
        )
        
        # 6. Parse the share back into a tuple for sslib (int: id, bytes: byte_data)
        parts = decrypted_share_payload.decode().split(":")
        share_tuple = (int(parts[0]), bytes.fromhex(parts[1]))
        gathered_shares.append(share_tuple)
        
        print(f" -> Share from {evaluator_id} successfully extracted.")

    # 7. Use Shamir's Secret Sharing to re-forge the Master AES key
    
    try:
        dict_shares = {
            "required_shares": encrypted_bid["shamir_meta"]["required_shares"],
            "prime_mod": bytes.fromhex(encrypted_bid["shamir_meta"]["prime_mod"]),
            "shares": gathered_shares
        }
        recovered_aes_hex = shamir.recover_secret(dict_shares)
        master_aes_key = bytes.fromhex(recovered_aes_hex.decode())
    except Exception as e:
        raise Exception(f"Failed to mathematically recombine shares: {e}")

    # 8. Decrypt the actual bid payload
    aesgcm = AESGCM(master_aes_key)
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

    evaluators_dir = "storage/evaluators"
    if not os.path.exists(evaluators_dir):
         print("No evaluators registered.")
         return

    evaluator_ids = os.listdir(evaluators_dir)
    if not evaluator_ids:
         print("No evaluators registered.")
         return

    print("\n[!] MULTI-PARTY DECRYPTION CEREMONY [!]")
    print(f"To unlock the vault, all {len(evaluator_ids)} Evaluators must provide their passwords.")

    evaluator_private_keys = {}

    for evaluator_id in evaluator_ids:
        # Load the encrypted private key bundle
        key_path = os.path.join(evaluators_dir, evaluator_id, "encrypted_private.json")
        if not os.path.exists(key_path):
             print(f"Encrypted private key for {evaluator_id} not found!")
             return
             
        with open(key_path, "r") as f:
             wrapped_data = json.load(f)

        salt = bytes.fromhex(wrapped_data["salt"])
        key_nonce = bytes.fromhex(wrapped_data["nonce"])
        key_ciphertext = bytes.fromhex(wrapped_data["ciphertext"])

        # 1. Prompt exactly this evaluator for their password
        password = getpass.getpass(f"Evaluator '{evaluator_id}', enter your password: ")

        # 2. Derive the KWK
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        try:
             kwk = kdf.derive(password.encode())
             aesgcm_key = AESGCM(kwk)
             # 3. Decrypt the private key *only in memory*
             private_bytes = aesgcm_key.decrypt(key_nonce, key_ciphertext, None)
        except InvalidTag:
             print(f"Incorrect password for Evaluator '{evaluator_id}'! Ceremony aborted.")
             return

        # Re-load the decrypted bytes into an ECC Private Key object
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
        evaluator_private_keys[evaluator_id] = private_key

    print("\n[SUCCESS] All Evaluator keys unlocked. Proceeding to decrypt bids...\n")

    for filename in os.listdir(bids_folder):
        filepath = os.path.join(bids_folder, filename)

        with open(filepath, "r") as f:
            bid_record = json.load(f)

        print("--- Processing:", filename, "---")

        try:

            encrypted_bid_data = bid_record["encrypted_bid"]
        
            decrypted_data = decrypt_with_evaluators(encrypted_bid_data, evaluator_private_keys)

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
            print("\n")

        except ValueError as e:
            if "unsupported key type" in str(e):
                print("Evaluator keys are wrong, cannot open the bid ")
            elif "Incorrect password" in str(e):
                print(e)
            else:
                print("Bid is tampered! Data corruption detected:", e)
        except InvalidTag:
            print("Bid is tampered! Decryption failed.")
        except Exception as e:
            print("Error processing bid:", e)


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