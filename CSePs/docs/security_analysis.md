# CSePS Security & Cryptographic Analysis

The Cryptographically Secure Government e-Procurement System (CSePS) relies on a modern, robust cryptographic stack to enforce its security guarantees. This document breaks down the specific algorithms used and the role each plays in securing the procurement lifecycle.

## 1. Asymmetric Cryptography: Elliptic Curve Cryptography (ECC)
**Algorithm:** `SECP256R1` (NIST P-256)
**Library:** `cryptography.hazmat.primitives.asymmetric.ec`

ECC is at the heart of CSePS, favored over traditional RSA due to its smaller key sizes and superior performance at equivalent security levels (256-bit ECC provides roughly the same security as 3072-bit RSA).

**Roles in CSePS:**
- **Digital Signatures (ECDSA):** Every bidder is issued an ECC keypair upon registration. When a bid is submitted, the hashed payload is signed using the bidder's private key. This guarantees **Authenticity** and **Non-repudiation**.
- **Key Exchange (ECDH):** Because symmetric encryption keys (AES) must be safely transmitted to Evaluators, CSePS utilizes Elliptic-Curve Diffie-Hellman (ECDH) key agreement. An ephemeral private key is generated for every bid and combined with the recipient's public key to safely negotiate a shared secret over an insecure channel.

## 2. Symmetric Encryption: AES-GCM
**Algorithm:** `AES-256-GCM` (Advanced Encryption Standard in Galois/Counter Mode)
**Key Size:** 256-bit

**Role in CSePS:**
- **Bulk Data Encryption:** The actual bid payload (containing the bid amount and sensitive descriptions) is encrypted using a randomly generated 256-bit AES key. 
- **Authenticated Encryption:** GCM mode was chosen specifically because it provides both Confidentiality and Integrity. Generating a ciphertext in GCM mode simultaneously produces an authentication tag. If an attacker modifies even a single bit of the encrypted bid file in transit or at rest, the decryption will mathematically fail, guaranteeing **Tamper-Evidence**.

## 3. Key Derivation: HKDF
**Algorithm:** `HKDF` (HMAC-based Extract-and-Expand Key Derivation Function)
**Underlying Hash:** `SHA-256`

**Role in CSePS:**
- After an ECDH key exchange calculates a "shared secret", that raw secret is not uniformly random enough to be used directly as an AES key. 
- HKDF is used to cryptographically derive a strong, uniform 32-byte (256-bit) symmetric wrapping key from the ECDH shared secret. This wrapping key is then used to encrypt the AES-GCM bid key for each specific Evaluator.

## 4. Hashing & Integrity Validation: SHA-256
**Algorithm:** `SHA-256` (Secure Hash Algorithm 2)

**Role in CSePS:**
- **Payload Hashing for Signatures:** Before an ECC signature is generated, the payload is deterministically hashed using SHA-256. The signature is then applied to the hash.
- **The Immutable Ledger:** The system maintains a `ledger.json` that acts as a localized blockchain. When a bid is accepted, the SHA-256 hash of its encrypted payload is recorded. Each ledger block also records the hash of the *previous* block (`previous_hash`), creating an immutable chronological chain. 

## Summary of Guarantees
| Cryptographic Primitive | Implementation | Primary Security Goal |
|---|---|---|
| **Digital Signatures** | ECDSA (SECP256R1) | Authenticity, Non-repudiation |
| **Symmetric Encryption** | AES-256-GCM | Confidentiality, Tamper-evidence (Integrity) |
| **Key Exchange** | ECDH (SECP256R1) | Secure sharing of AES keys |
| **Key Derivation** | HKDF (SHA-256) | Entropy maximization for wrapped keys |
| **Hash Chaining** | SHA-256 | Immutable chronological audit trail |
