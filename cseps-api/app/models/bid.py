from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.procurement import Procurement
    from app.models.user import User


class Bid(Base):
    __tablename__ = "bids"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    procurement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("procurements.id", ondelete="CASCADE"), nullable=False, index=True
    )
    bidder_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    # Encrypted bid payload (AES-256-GCM) — server never decrypts until ceremony
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    bid_nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    # Non-repudiation
    bid_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    # Shamir's Secret Sharing metadata
    shamir_meta: Mapped[dict] = mapped_column(JSON, nullable=False)
    # Per-evaluator ECDH-wrapped shares  {evaluator_id: {enc_share, share_nonce, ephemeral_pubkey}}
    encrypted_keys: Mapped[dict] = mapped_column(JSON, nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    bidder: Mapped[User] = relationship("User", back_populates="bids", lazy="select")
    procurement: Mapped[Procurement] = relationship("Procurement", back_populates="bids", lazy="select")
    shares: Mapped[list[EvaluatorShare]] = relationship("EvaluatorShare", back_populates="bid", lazy="select")
    result: Mapped[Optional[BidResult]] = relationship("BidResult", back_populates="bid", uselist=False, lazy="select")


class EvaluatorShare(Base):
    __tablename__ = "evaluator_shares"
    __table_args__ = (UniqueConstraint("bid_id", "evaluator_id", name="uq_bid_evaluator_share"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bid_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("bids.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evaluator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    share_index: Mapped[int] = mapped_column(Integer, nullable=False)
    share_hex: Mapped[str] = mapped_column(Text, nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    bid: Mapped[Bid] = relationship("Bid", back_populates="shares")
    evaluator: Mapped[User] = relationship("User", lazy="select")


class BidResult(Base):
    __tablename__ = "bid_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bid_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("bids.id"), unique=True, nullable=False
    )
    procurement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("procurements.id"), nullable=False, index=True
    )
    amount: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hash_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    bid: Mapped[Bid] = relationship("Bid", back_populates="result")
