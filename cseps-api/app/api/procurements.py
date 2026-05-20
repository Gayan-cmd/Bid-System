from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_current_user, require_role
from app.core.email import send_evaluator_invitation
from app.db.engine import get_db
from app.models.procurement import (
    EvaluatorInvitation,
    InvitationStatus,
    Procurement,
    ProcurementEvaluator,
    ProcurementStatus,
)
from app.models.bid import Bid, BidResult
from app.models.user import User, UserRole
from app.schemas.procurement import (
    EvaluatorOut,
    InviteEvaluatorRequest,
    ProcurementCreate,
    ProcurementOut,
    ProcurementUpdate,
)
from app.schemas.bid import BidResultOut

router = APIRouter(prefix="/procurements", tags=["Procurements"])


@router.post("/", response_model=ProcurementOut, status_code=status.HTTP_201_CREATED)
async def create_procurement(
    payload: ProcurementCreate,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    procurement = Procurement(
        title=payload.title,
        description=payload.description,
        deadline=payload.deadline,
        status=ProcurementStatus.OPEN,
        created_by=current_user.id,
    )
    db.add(procurement)
    await db.flush()
    return _to_out(procurement, 0, 0)


@router.get("/", response_model=list[ProcurementOut])
async def list_procurements(db: Annotated[AsyncSession, Depends(get_db)]):
    result = await db.execute(
        select(Procurement).where(Procurement.status == ProcurementStatus.OPEN).order_by(Procurement.created_at.desc())
    )
    procurements = result.scalars().all()
    out = []
    for p in procurements:
        ev_count = await db.scalar(
            select(func.count()).select_from(ProcurementEvaluator).where(ProcurementEvaluator.procurement_id == p.id)
        )
        bid_count = await db.scalar(
            select(func.count()).select_from(Bid).where(Bid.procurement_id == p.id)
        )
        out.append(_to_out(p, ev_count or 0, bid_count or 0))
    return out


@router.get("/{procurement_id}", response_model=ProcurementOut)
async def get_procurement(procurement_id: UUID, db: Annotated[AsyncSession, Depends(get_db)]):
    procurement = await _get_or_404(db, procurement_id)
    ev_count = await db.scalar(
        select(func.count()).select_from(ProcurementEvaluator).where(ProcurementEvaluator.procurement_id == procurement_id)
    )
    bid_count = await db.scalar(
        select(func.count()).select_from(Bid).where(Bid.procurement_id == procurement_id)
    )
    return _to_out(procurement, ev_count or 0, bid_count or 0)


@router.patch("/{procurement_id}", response_model=ProcurementOut)
async def update_procurement(
    procurement_id: UUID,
    payload: ProcurementUpdate,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    procurement = await _get_or_404(db, procurement_id)
    if payload.title is not None:
        procurement.title = payload.title
    if payload.description is not None:
        procurement.description = payload.description
    if payload.deadline is not None:
        procurement.deadline = payload.deadline
    db.add(procurement)
    await db.flush()
    return _to_out(procurement, 0, 0)


@router.post("/{procurement_id}/invite-evaluator", status_code=status.HTTP_201_CREATED)
async def invite_evaluator(
    procurement_id: UUID,
    payload: InviteEvaluatorRequest,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    procurement = await _get_or_404(db, procurement_id)

    # Check if this email already has a pending/accepted invitation for this procurement
    existing_inv = await db.execute(
        select(EvaluatorInvitation).where(
            EvaluatorInvitation.email == payload.email,
            EvaluatorInvitation.procurement_id == procurement_id,
            EvaluatorInvitation.status == InvitationStatus.PENDING,
        )
    )
    if existing_inv.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="An invitation is already pending for this email")

    token = secrets.token_urlsafe(48)
    invitation = EvaluatorInvitation(
        email=payload.email,
        procurement_id=procurement_id,
        token=token,
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=72),
    )
    db.add(invitation)
    await db.flush()

    invite_url = f"{settings.FRONTEND_URL}/invite/{token}"
    send_evaluator_invitation(
        to_email=payload.email,
        evaluator_name=payload.email,
        procurement_title=procurement.title,
        invite_url=invite_url,
    )
    return {"message": f"Invitation sent to {payload.email}", "invite_url": invite_url}


@router.get("/{procurement_id}/evaluators", response_model=list[EvaluatorOut])
async def list_evaluators(
    procurement_id: UUID,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    await _get_or_404(db, procurement_id)
    result = await db.execute(
        select(User)
        .join(ProcurementEvaluator, ProcurementEvaluator.evaluator_id == User.id)
        .where(ProcurementEvaluator.procurement_id == procurement_id)
    )
    evaluators = result.scalars().all()
    return [EvaluatorOut.model_validate(e) for e in evaluators]


@router.get("/keys/evaluators/{procurement_id}", response_model=list[EvaluatorOut])
async def get_evaluator_keys(
    procurement_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Returns evaluator IDs and their ECDH public keys — needed by bidders to encrypt shares."""
    result = await db.execute(
        select(User)
        .join(ProcurementEvaluator, ProcurementEvaluator.evaluator_id == User.id)
        .where(ProcurementEvaluator.procurement_id == procurement_id)
    )
    evaluators = result.scalars().all()
    return [EvaluatorOut.model_validate(e) for e in evaluators]


@router.post("/{procurement_id}/open", response_model=ProcurementOut)
async def open_procurement(
    procurement_id: UUID,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Close the procurement to new bids (after deadline). Triggers opening ceremony."""
    procurement = await _get_or_404(db, procurement_id)
    now = datetime.now(timezone.utc)

    if procurement.deadline.replace(tzinfo=timezone.utc) > now:
        raise HTTPException(status_code=400, detail="Deadline has not passed yet")
    if procurement.status == ProcurementStatus.CLOSED:
        raise HTTPException(status_code=400, detail="Procurement is already closed")

    procurement.status = ProcurementStatus.CLOSED
    db.add(procurement)
    await db.flush()
    return _to_out(procurement, 0, 0)


@router.get("/{procurement_id}/results", response_model=list[BidResultOut])
async def get_results(
    procurement_id: UUID,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(BidResult).where(BidResult.procurement_id == procurement_id).order_by(BidResult.opened_at.asc())
    )
    results = result.scalars().all()
    return [BidResultOut.model_validate(r) for r in results]


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_or_404(db: AsyncSession, procurement_id: UUID) -> Procurement:
    result = await db.execute(select(Procurement).where(Procurement.id == procurement_id))
    procurement = result.scalar_one_or_none()
    if not procurement:
        raise HTTPException(status_code=404, detail="Procurement not found")
    return procurement


def _to_out(p: Procurement, ev_count: int, bid_count: int) -> ProcurementOut:
    return ProcurementOut(
        id=p.id,
        title=p.title,
        description=p.description,
        deadline=p.deadline,
        status=p.status,
        created_by=p.created_by,
        created_at=p.created_at,
        evaluator_count=ev_count,
        bid_count=bid_count,
    )
