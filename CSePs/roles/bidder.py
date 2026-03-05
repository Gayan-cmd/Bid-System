import os
import json
import uuid
import getpass
from crypto.ecc_keys import generate_ecc_keypair, save_private_key, save_public_key,load_private_key,load_public_key
from crypto.hash_utils import sha256_hash
from crypto.sign_verify import sign_data,verify_signature
from crypto.encrypt_decrypt import encrypt_bid
from crypto.encrypt_decrypt_authority import encrypt_bid_authority
from ledger.ledger import add_block
from datetime import datetime

KEYS_FOLDER = "storage/keys"


def load_evaluator_public_keys():
    evaluator_folder = "storage/evaluators"
    keys = {}

    for evaluator_id in os.listdir(evaluator_folder):
        path = f"{evaluator_folder}/{evaluator_id}/public.pem"
        keys[evaluator_id] = load_public_key(path)

    return keys



def register_bidder():
    print("\n=== Bidder Registration ===")

    bidder_name = input("Enter your name: ")
    password = getpass.getpass("Create a password to protect your Bidder private key: ")
    if not password:
         print("Password cannot be empty!")
         return

    # Generate pseudonymous ID
    bidder_id = str(uuid.uuid4())

    private_key, public_key = generate_ecc_keypair()

    # Create directory for bidder
    bidder_folder = os.path.join(KEYS_FOLDER, bidder_id)
    os.makedirs(bidder_folder, exist_ok=True)

    private_path = os.path.join(bidder_folder, "private.pem")
    public_path = os.path.join(bidder_folder, "public.pem")

    save_private_key(private_key, private_path, password)
    save_public_key(public_key, public_path)

    # Encrypt the Identity Envelope
    identity_data = {
        "bidder_id": bidder_id,
        "bidder_name": bidder_name
    }
    identity_json = json.dumps(identity_data).encode()

    authority_public_key = load_public_key("storage/authority/public.pem")
    
    # We encrypt identity only for the Authority, so evaluators cannot see names
    encrypted_identity = encrypt_bid_authority(authority_public_key, identity_json)

    identities_folder = "storage/identities"
    os.makedirs(identities_folder, exist_ok=True)
    
    identity_file = os.path.join(identities_folder, f"{bidder_id}_identity.json")
    with open(identity_file, "w") as f:
        json.dump(encrypted_identity, f, indent=4)

    print("\nRegistration Successful!")
    print("Your Bidder ID (KEEP THIS SAFE):", bidder_id)
    print("Keys stored in:", bidder_folder)
    print("Encrypted identity stored in:", identity_file)

    return bidder_id


def create_bid(bidder_id):
    print("\n=== Create Bid ===")

    amount = input("Enter bid amount: ")
    description = input("Enter bid description: ")

    bid_data = {
        "bidder_id": bidder_id,
        "amount": amount,
        "description": description
    }

    bid_json = json.dumps(bid_data).encode()

    bid_hash = sha256_hash(bid_json)

    password = getpass.getpass("Enter your Bidder password to sign the bid: ")

    private_key_path = f"storage/keys/{bidder_id}/private.pem"
    try:
        private_key = load_private_key(private_key_path, password)
    except Exception as e:
        print("Incorrect Bidder Password! Cannot sign the bid.")
        return

    signature = sign_data(private_key, bid_hash)

    evaluator_keys = load_evaluator_public_keys()
    encrypted_data = encrypt_bid(evaluator_keys, bid_json)

    

    signed_bid = {
        "encrypted_bid": encrypted_data,
        "hash": bid_hash.hex(),
        "signature": signature.hex()
    }

    final_json_string = json.dumps(signed_bid, indent=4).encode()
    final_file_hash = sha256_hash(final_json_string).hex()

    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"storage/bids/{bidder_id}_{timestamp}.json"

    os.makedirs("storage/bids", exist_ok=True)

    with open(filename, "wb") as f:
        f.write(final_json_string)

    print("Encrypted bid saved to:", filename)

    # Add the hash of the ENCRYPTED FILE to the ledger for public verification
    add_block(final_file_hash)

    return filename


def verify_bid(bidder_id, signed_bid):
    public_key_path = f"storage/keys/{bidder_id}/public.pem"
    public_key = load_public_key(public_key_path)

    bid_json = json.dumps(signed_bid["encrypted_bid"]).encode()
    recalculated_hash = sha256_hash(bid_json)

    signature = bytes.fromhex(signed_bid["signature"])

    valid = verify_signature(public_key, signature, recalculated_hash)

    return valid