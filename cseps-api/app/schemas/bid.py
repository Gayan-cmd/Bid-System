from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel


class BidSubmitRequest(BaseModel):
    procurement_id: UUID
    ciphertext: str
    bid_nonce: str
    bid_hash: str
    signature: str
    shamir_meta: dict[str, Any]
    encrypted_keys: dict[str, Any]


class BidOut(BaseModel):
    id: UUID
    procurement_id: UUID
    bidder_id: UUID
    bid_hash: str
    submitted_at: datetime

    model_config = {"from_attributes": True}


class BidDetail(BaseModel):
    id: UUID
    procurement_id: UUID
    bidder_id: UUID
    ciphertext: str
    bid_nonce: str
    bid_hash: str
    signature: str
    shamir_meta: dict[str, Any]
    encrypted_keys: dict[str, Any]
    submitted_at: datetime

    model_config = {"from_attributes": True}


class SubmitShareRequest(BaseModel):
    bid_id: UUID
    share_index: int
    share_hex: str


class BidResultOut(BaseModel):
    bid_id: UUID
    procurement_id: UUID
    amount: str
    description: Optional[str]
    hash_verified: bool
    signature_valid: bool
    opened_at: datetime

    model_config = {"from_attributes": True}


class CeremonyBidItem(BaseModel):
    """Bid item returned to an evaluator during the ceremony — only their own encrypted share."""
    bid_id: UUID
    bid_hash: str
    shamir_meta: dict[str, Any]
    my_encrypted_key: dict[str, Any]
    share_submitted: bool = False
