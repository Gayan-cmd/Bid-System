from __future__ import annotations

import hashlib
import json
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sslib import shamir
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bid import Bid, BidResult, EvaluatorShare
from app.models.user import User


async def open_bid(db: AsyncSession, bid_id: UUID) -> BidResult:
    """
    Called when enough Shamir shares have been collected for a bid.
    Recovers the AES master key, decrypts the bid, and verifies integrity.
    """
    # ── 1. Load bid ──────────────────────────────────────────────────────────
    bid_result_q = await db.execute(select(Bid).where(Bid.id == bid_id))
    bid = bid_result_q.scalar_one_or_none()
    if not bid:
        raise ValueError(f"Bid {bid_id} not found")

    # ── 2. Load submitted shares ─────────────────────────────────────────────
    shares_q = await db.execute(
        select(EvaluatorShare).where(EvaluatorShare.bid_id == bid_id)
    )
    db_shares = shares_q.scalars().all()

    required = bid.shamir_meta.get("required_shares", len(db_shares))
    if len(db_shares) < required:
        raise ValueError(f"Need {required} shares, only {len(db_shares)} collected")

    # ── 3. Rebuild Shamir shares list ────────────────────────────────────────
    shares_list = [
        (s.share_index, bytes.fromhex(s.share_hex))
        for s in db_shares[:required]
    ]

    shares_dict = {
        "required_shares": required,
        "prime_mod": bytes.fromhex(bid.shamir_meta["prime_mod"]),
        "shares": shares_list,
    }

    # ── 4. Recover AES master key via Shamir's ────────────────────────────────
    recovered_hex_bytes: bytes = shamir.recover_secret(shares_dict)
    master_aes_key = bytes.fromhex(recovered_hex_bytes.decode())

    # ── 5. Decrypt the bid ───────────────────────────────────────────────────
    aesgcm = AESGCM(master_aes_key)
    nonce = bytes.fromhex(bid.bid_nonce)
    ciphertext = bytes.fromhex(bid.ciphertext)
    bid_json_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    # ── 6. Verify SHA-256 integrity ──────────────────────────────────────────
    recalculated_hash = hashlib.sha256(bid_json_bytes).hexdigest()
    hash_verified = recalculated_hash == bid.bid_hash

    # ── 7. Verify ECDSA signature ────────────────────────────────────────────
    bidder_q = await db.execute(select(User).where(User.id == bid.bidder_id))
    bidder = bidder_q.scalar_one_or_none()
    signature_valid = False
    if bidder and bidder.ecdsa_pubkey:
        try:
            pubkey_bytes = bytes.fromhex(bidder.ecdsa_pubkey) if not bidder.ecdsa_pubkey.startswith("-----") \
                else bidder.ecdsa_pubkey.encode()
            if bidder.ecdsa_pubkey.startswith("-----"):
                public_key = serialization.load_pem_public_key(pubkey_bytes)
            else:
                public_key = serialization.load_der_public_key(pubkey_bytes)
            public_key.verify(
                bytes.fromhex(bid.signature),
                bytes.fromhex(bid.bid_hash),
                ec.ECDSA(hashes.SHA256()),
            )
            signature_valid = True
        except (InvalidSignature, Exception):
            signature_valid = False

    # ── 8. Parse bid JSON ────────────────────────────────────────────────────
    bid_data = json.loads(bid_json_bytes.decode())
    amount = str(bid_data.get("amount", ""))
    description = bid_data.get("description", "")

    # ── 9. Store result ──────────────────────────────────────────────────────
    result = BidResult(
        bid_id=bid_id,
        procurement_id=bid.procurement_id,
        amount=amount,
        description=description,
        hash_verified=hash_verified,
        signature_valid=signature_valid,
    )
    db.add(result)
    await db.flush()
    return result
