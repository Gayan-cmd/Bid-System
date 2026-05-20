from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import JSON, Boolean, DateTime, Enum, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.bid import Bid
    from app.models.procurement import ProcurementEvaluator


class UserRole(str, enum.Enum):
    AUTHORITY = "AUTHORITY"
    EVALUATOR = "EVALUATOR"
    BIDDER = "BIDDER"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    ecdsa_pubkey: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ecdh_pubkey: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    identity_cipher: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    bids: Mapped[list[Bid]] = relationship("Bid", back_populates="bidder", lazy="select")
    evaluator_assignments: Mapped[list[ProcurementEvaluator]] = relationship(
        "ProcurementEvaluator", back_populates="evaluator", lazy="select"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"
