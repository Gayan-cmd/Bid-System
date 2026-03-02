import os
from crypto.ecc_keys import generate_ecc_keypair, save_private_key, save_public_key

EVALUATOR_FOLDER = "storage/evaluators"

def register_evaluator():
    print("\n=== Register Evaluator ===")

    evaluator_id = input("Enter evaluator name: ")

    folder = os.path.join(EVALUATOR_FOLDER, evaluator_id)
    os.makedirs(folder, exist_ok=True)

    private_key, public_key = generate_ecc_keypair()

    save_private_key(private_key, f"{folder}/private.pem")
    save_public_key(public_key, f"{folder}/public.pem")

    print("Evaluator registered:", evaluator_id)

    