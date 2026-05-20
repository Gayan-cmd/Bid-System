from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.bid import Bid
    from app.models.user import User


class ProcurementStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    AWARDED = "AWARDED"


class InvitationStatus(str, enum.Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    EXPIRED = "EXPIRED"


class Procurement(Base):
    __tablename__ = "procurements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[ProcurementStatus] = mapped_column(
        Enum(ProcurementStatus), default=ProcurementStatus.DRAFT, nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    bids: Mapped[list[Bid]] = relationship("Bid", back_populates="procurement", lazy="select")
    evaluator_assignments: Mapped[list[ProcurementEvaluator]] = relationship(
        "ProcurementEvaluator", back_populates="procurement", lazy="select"
    )
    invitations: Mapped[list[EvaluatorInvitation]] = relationship(
        "EvaluatorInvitation", back_populates="procurement", lazy="select"
    )
    creator: Mapped[User] = relationship("User", foreign_keys=[created_by], lazy="select")


class ProcurementEvaluator(Base):
    __tablename__ = "procurement_evaluators"

    procurement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("procurements.id", ondelete="CASCADE"), primary_key=True
    )
    evaluator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    procurement: Mapped[Procurement] = relationship("Procurement", back_populates="evaluator_assignments")
    evaluator: Mapped[User] = relationship("User", back_populates="evaluator_assignments")


class EvaluatorInvitation(Base):
    __tablename__ = "evaluator_invitations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    procurement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("procurements.id", ondelete="CASCADE"), nullable=False
    )
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    status: Mapped[InvitationStatus] = mapped_column(
        Enum(InvitationStatus), default=InvitationStatus.PENDING, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    procurement: Mapped[Procurement] = relationship("Procurement", back_populates="invitations")
