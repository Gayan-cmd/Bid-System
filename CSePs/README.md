# Cryptographically Secure Government e-Procurement System (CSePS)

CSePS is a cryptographic prototype designed to solve long-standing real-world issues in government and corporate bidding processes: early bid leaks, physical bid tampering, corruption, and denial disputes.

## Core Features
1. **Bid Encryption (Confidentiality):** Bids are encrypted locally so evaluators mathematically cannot read them before the official deadline.
2. **Digital Signatures (Non-repudiation & Authenticity):** Every bid is digitally signed. A bidder cannot later claim they did not submit the bid, nor can an attacker forge a bid.
3. **Immutable Ledger (Integrity & Transparency):** A hash-based chronological ledger stores all submissions. If any bid file is modified on the server, the ledger verification instantly catches it.
4. **Anonymity:** Bids are evaluated purely via pseudonymous UUIDs. True names are locked in encrypted envelopes only decipherable by the Authority *after* a winner is chosen.

---

## Live Demonstration Guide

Follow this script to demonstrate the system to your reviewers or examiners during the final defense.

### Step 1: Preparation
1. Ensure your terminal is open in the `CSePs/` directory.
2. Delete the `storage/` folder if it exists from previous tests to start with a totally clean slate for the presentation.

### Step 2: System Setup
1. Run `python main.py`
2. Select **Role 1: Authority**. Choose **Option 1: Setup Authority Keys**.  
   *Narrative to Reviewer:* "First, we initialize the central Authority. This generates the master ECC keypair that will act as the root of trust for the procurement process."
3. Still in Authority Menu, select **Option 2: Register as New Evaluator**. Register a couple of evaluators (e.g., `Eval_A`, `Eval_B`).  
   *Narrative to Reviewer:* "Evaluators generate their own ECC keypairs. Bidders will encrypt their submissions against these public keys using a multi-party scheme."
4. Select **Option 3: Configure Procurement Deadline**. Set it to `1` or `2` minutes. Enter `0` to return to the Main Menu.   
   *Narrative to Reviewer:* "We set a strict cryptographic deadline. Opening any bids before this timer expires is mathematically blocked by the protocol."

### Step 3: The Bidding Process
1. Select **Role 2: Bidder**. Choose **Option 1: Register Bidder Profile**. Enter a name like `Stark Industries`. 
   *Narrative to Reviewer:* "The bidder registers. Their true identity is encrypted into a special envelope only the Authority can read, while they are issued a random UUID for anonymous evaluation."
2. **Copy the Bidder UUID** printed on the screen.
3. Select **Option 2: Submit Encrypted Bid**. Enter a bid amount (`5000000`), and a description. Return to Main Menu.
   *Narrative to Reviewer:* "The bid is hashed (SHA-256), signed with the Bidder's private key (ECDSA), and encrypted with a wrapped AES-256-GCM key. Finally, the hash is burned into the immutable ledger."

### Step 4: System Safeguards Verification
1. Select **Role 1: Authority**. Choose **Option 4: Open All Bids (After Deadline)**. 
   *Narrative to Reviewer:* "Notice how the system rejects opening the bids. The deadline has not passed. Early bid-leaking—a common corruption vector—is impossible." Return to Main Menu.
2. Select **Role 3: Public/Auditor**. Choose **Option 1: Verify Ledger Hash Integrity**.
   *Narrative to Reviewer:* "The ledger tracks the cryptographic hashes of all files. It validates perfectly."
3. *(Optional)* Let the examiner manually modify a `storage/bids/...json` file maliciously (e.g., change the ciphertext). Run **Option 1** again to watch the verification fail spectacularly!

### Step 5: The Unveiling
1. Wait for the 1-2 minute procurement deadline to expire.
2. Select **Role 1: Authority**. Choose **Option 4: Open All Bids (After Deadline)**.
   *Narrative to Reviewer:* "Now that the deadline has passed, the system uses the Evaluators' keys to successfully decrypt the JSON payloads. It automatically verifies all digital signatures, ensuring no tampering occurred in transit."
3. Select **Option 5: Reveal Winner's True Identity**. Paste the UUID from Step 3.
   *Narrative to Reviewer:* "The evaluators have chosen the winning UUID completely blind. Now, the Authority uses its private key to tear open the identity envelope and reveal the true winner."

---

## Threat Model & Security Posture
*   **Spoofing:** Prevented by `SECP256R1` ECC digital signatures.
*   **Tampering:** Prevented by `AES-256-GCM` authenticated encryption and the `SHA-256` chronological ledger.
*   **Information Disclosure:** Prevented by multi-recipient HKDF enveloped AES keys.
*   **Repudiation:** Denying a bid is mathematically impossible without compromising the bidder's local private key.

*(For detailed breakdowns, see the `docs/` folder).*
