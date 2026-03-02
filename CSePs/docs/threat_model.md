# CSePS Threat Model

This document outlines the threat model for the Cryptographically Secure Government e-Procurement System (CSePS) using the **STRIDE** methodology. It details potential attacks against the procurement process and how the system's cryptographic architecture mitigates them.

## 1. Spoofing Identity
**Threat:** An attacker, or a malicious insider, attempts to submit a bid impersonating a legitimate, registered bidder. Or, the Authority attempts to forge a bid on behalf of a bidder to rig the procurement.
**Mitigation:** 
- Every bid is digitally signed using the bidder's elliptic curve (ECC SECP256R1) private key.
- Without the bidder's private key, forging a valid signature is computationally infeasible. The `verify_signature` mechanism guarantees the identity of the submitter.

## 2. Tampering with Data
**Threat:** An attacker intercepts a submitted bid and modifies its contents (e.g., changing the bid amount) before it reaches the evaluators. Alternatively, a corrupt database administrator alters bids stored on the server.
**Mitigation:** 
- **In-transit & At-rest:** Bids are encrypted using AES-256-GCM. GCM (Galois/Counter Mode) provides authenticated encryption, meaning any modification to the ciphertext will cause the decryption to fail (integrity check failure).
- **Historical Tampering:** The hash of every bid is recorded in an immutable, chain-linked `ledger.json` (similar to a blockchain). The `verify_bids_against_ledger` function hashes the actual decrypted plaintext of stored bids and strictly verifies those hashes against the ledger. Tampering with a bid file breaks the hash chain and is immediately detected.

## 3. Repudiation
**Threat:** A winning bidder regrets their bid and claims they never submitted it, alleging the system generated it.
**Mitigation:** 
- The digital signature attached to every bid provides **Non-repudiation**. Because only the bidder holds their private key, they cannot mathematically deny having created the signature over that specific bid payload. 

## 4. Information Disclosure
**Threat:** Evaluators or the Authority attempt to read the bid amounts before the official procurement deadline closes, allowing them to leak the lowest bid to a favored contractor. Similarly, evaluators might show bias if they know who submitted which bid.
**Mitigation:**
- **Early Decryption:** Bids are encrypted using a multi-party encryption scheme. The symmetric AES key that encrypts the bid data is itself encrypted using the public keys of the Evaluators (and/or Authority). Decryption before the deadline is procedurally blocked by the `is_deadline_passed()` check. 
- **Anonymity (Bias Prevention):** During the evaluation phase, evaluators only see a UUID (`bidder_id`). The mapping to the real `bidder_name` is stored in a separate "Identity Envelope", which is encrypted exclusively for the Authority. Evaluators mathematically cannot decrypt the true identity. The Authority only decrypts the identity envelope *after* the winning UUID is selected.

## 5. Denial of Service (DoS)
**Status:** Out of Scope for this prototype. In a production environment, standard network-level mitigations (rate limiting, WAFs) would protect the API endpoints.

## 6. Elevation of Privilege
**Threat:** A bidder somehow gains Evaluator or Authority privileges to influence the outcome.
**Mitigation:**
- Roles are strictly segregated by cryptographic keypairs. A bidder's signature cannot be used to perform Evaluator decryption actions, because the AES keys are wrapped specifically for the public keys of registered Evaluators.
