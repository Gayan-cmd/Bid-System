from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr

from app.models.procurement import ProcurementStatus


class ProcurementCreate(BaseModel):
    title: str
    description: Optional[str] = None
    deadline: datetime


class ProcurementUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    deadline: Optional[datetime] = None


class ProcurementOut(BaseModel):
    id: UUID
    title: str
    description: Optional[str]
    deadline: datetime
    status: ProcurementStatus
    created_by: UUID
    created_at: datetime
    evaluator_count: int = 0
    bid_count: int = 0

    model_config = {"from_attributes": True}


class InviteEvaluatorRequest(BaseModel):
    email: EmailStr


class AcceptInviteRequest(BaseModel):
    token: str
    name: str
    password: str
    ecdsa_pubkey: str
    ecdh_pubkey: str


class EvaluatorOut(BaseModel):
    id: UUID
    email: str
    name: str
    ecdh_pubkey: Optional[str]

    model_config = {"from_attributes": True}
