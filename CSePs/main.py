from roles.bidder import register_bidder, create_bid
from roles.authority import setup_authority, configure_procurement, open_all_bids, reveal_winner_identity
from ledger.ledger import verify_ledger, verify_physical_bids_against_ledger
from roles.evaluator import register_evaluator


def authority_menu():
    while True:
        print("\n=== [ AUTHORITY MENU ] ===")
        print("1. Setup Authority Keys")
        print("2. Register New Evaluator")
        print("3. Configure Procurement Deadline")
        print("4. Open All Bids")
        print("5. Reveal Winner's True Identity")
        print("0. Back to Main Menu")
        
        choice = input("Select option: ")
        
        if choice == "1":
            setup_authority()
        elif choice == "2":
            register_evaluator()
        elif choice == "3":
            configure_procurement()
        elif choice == "4":
            open_all_bids()
        elif choice == "5":
            reveal_winner_identity()
        elif choice == "0":
            break
        else:
            print("Invalid option.")


def bidder_menu():
    
    current_bidder_id = None
    
    while True:
        print("\n=== [ BIDDER MENU ] ===")
        print("1. Register Bidder Profile")
        print("2. Submit Encrypted Bid")
        print("0. Back to Main Menu")
        
        choice = input("Select option: ")
        
        if choice == "1":
            current_bidder_id = register_bidder()
        elif choice == "2":
    
            b_id = current_bidder_id if current_bidder_id else input("Enter your Bidder ID (UUID): ")
            if not b_id:
                print("Please register or provide a valid Bidder ID.")
            else:
                create_bid(b_id)
                current_bidder_id = b_id 
        elif choice == "0":
            break
        else:
            print("Invalid option.")


def public_menu():
    while True:
        print("\n=== [ PUBLIC AUDIT MENU ] ===")
        print("1. Cross-Verify Physical Bids Against Ledger")
        print("0. Back to Main Menu")
        
        choice = input("Select option: ")
        
        
        if choice == "1":
            verify_physical_bids_against_ledger()
            valid = verify_ledger()
            print("Ledger Chain Intact?", valid)

        elif choice == "0":
            break
        else:
            print("Invalid option.")


def main_menu():
    while True:
        print("\n========================================")
        print("   Crypto-Secure e-Procurement System   ")
        print("========================================")
        print("Select Your Role:")
        print("1. Authority")
        print("2. Bidder")
        print("3. Public Auditor")
        print("0. Exit Application")
        
        choice = input("Select role: ")

        if choice == "1":
            authority_menu()
        elif choice == "2":
            bidder_menu()
        elif choice == "3":
            public_menu()
        elif choice == "0":
            print("Exiting CSePS...")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main_menu()
