import json
import os
from datetime import datetime
from crypto.hash_utils import sha256_hash

LEDGER_FILE = "storage/ledger.json"


def initialize_ledger():
    if not os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "w") as f:
            json.dump([], f)


def load_ledger():
    with open(LEDGER_FILE, "r") as f:
        return json.load(f)


def save_ledger(ledger):
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=4)


def calculate_block_hash(block_data):
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return sha256_hash(block_string).hex()


def add_block(bid_hash):
    initialize_ledger()
    ledger = load_ledger()

    index = len(ledger)
    timestamp = datetime.utcnow().isoformat()

    previous_hash = ledger[-1]["current_hash"] if ledger else "0"

    block_data = {
        "index": index,
        "timestamp": timestamp,
        "bid_hash": bid_hash,
        "previous_hash": previous_hash
    }

    current_hash = calculate_block_hash(block_data)

    block_data["current_hash"] = current_hash

    ledger.append(block_data)
    save_ledger(ledger)

    print("Ledger updated successfully.")



def verify_ledger():
    initialize_ledger()
    ledger = load_ledger()

    for i in range(len(ledger)):
        block = ledger[i]

        block_data = {
            "index": block["index"],
            "timestamp": block["timestamp"],
            "bid_hash": block["bid_hash"],
            "previous_hash": block["previous_hash"]
        }

        recalculated_hash = calculate_block_hash(block_data)

        if recalculated_hash != block["current_hash"]:
            return False

        if i > 0:
            if block["previous_hash"] != ledger[i - 1]["current_hash"]:
                return False

    return True


def verify_physical_bids_against_ledger():
    print("\n--- Cross-Verifying Physical Bids against Ledger ---")
    initialize_ledger()
    ledger = load_ledger()
    
    # Extract all securely logged file hashes from the ledger
    ledger_hashes = [block["bid_hash"] for block in ledger]
    
    bids_folder = "storage/bids"
    if not os.path.exists(bids_folder):
        print("No bids folder found. Nothing to verify.")
        return True
        
    all_valid = True
    for filename in os.listdir(bids_folder):
        if not filename.endswith(".json"):
            continue
            
        filepath = os.path.join(bids_folder, filename)
        
        # Read the raw physical file exactly as it sits on disk
        with open(filepath, "rb") as f:
            raw_bytes = f.read()
            
        physical_file_hash = sha256_hash(raw_bytes).hex()
        
        if physical_file_hash not in ledger_hashes:
            all_valid = False
            
    if all_valid:
        print("[OK] All physical bids are securely logged and untampered.")
    else:
        print("[ERROR] INTEGRITY COMPROMISED! One or more bid files have been modified or injected!")
        
    return all_valid