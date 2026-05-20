from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_role
from app.core.security import hash_password
from app.db.engine import get_db
from app.models.bid import Bid, EvaluatorShare
from app.models.procurement import (
    EvaluatorInvitation,
    InvitationStatus,
    Procurement,
    ProcurementEvaluator,
)
from app.models.user import User, UserRole
from app.schemas.bid import CeremonyBidItem, SubmitShareRequest
from app.schemas.procurement import AcceptInviteRequest, EvaluatorOut, ProcurementOut
from app.services import ceremony as ceremony_service

router = APIRouter(prefix="/evaluator", tags=["Evaluator"])


@router.post("/accept-invite", response_model=EvaluatorOut, status_code=status.HTTP_201_CREATED)
async def accept_invite(payload: AcceptInviteRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    """One-time endpoint: accept invitation token and register as evaluator."""
    inv_result = await db.execute(
        select(EvaluatorInvitation).where(
            EvaluatorInvitation.token == payload.token,
            EvaluatorInvitation.status == InvitationStatus.PENDING,
        )
    )
    invitation = inv_result.scalar_one_or_none()
    if not invitation:
        raise HTTPException(status_code=404, detail="Invalid or already used invitation token")

    if invitation.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        invitation.status = InvitationStatus.EXPIRED
        db.add(invitation)
        raise HTTPException(status_code=400, detail="Invitation has expired")

    # Check if this email already has an account
    existing_user = await db.execute(select(User).where(User.email == invitation.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    # Create evaluator account
    evaluator = User(
        email=invitation.email,
        name=payload.name,
        role=UserRole.EVALUATOR,
        hashed_password=hash_password(payload.password),
        ecdsa_pubkey=payload.ecdsa_pubkey,
        ecdh_pubkey=payload.ecdh_pubkey,
    )
    db.add(evaluator)
    await db.flush()

    # Link evaluator to procurement
    link = ProcurementEvaluator(
        procurement_id=invitation.procurement_id,
        evaluator_id=evaluator.id,
    )
    db.add(link)

    # Mark invitation accepted
    invitation.status = InvitationStatus.ACCEPTED
    db.add(invitation)
    await db.flush()

    return EvaluatorOut.model_validate(evaluator)


@router.get("/procurements", response_model=list[ProcurementOut])
async def my_procurements(
    current_user: Annotated[User, Depends(require_role(UserRole.EVALUATOR))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Return procurements this evaluator is assigned to."""
    result = await db.execute(
        select(Procurement)
        .join(ProcurementEvaluator, ProcurementEvaluator.procurement_id == Procurement.id)
        .where(ProcurementEvaluator.evaluator_id == current_user.id)
        .order_by(Procurement.deadline.desc())
    )
    procurements = result.scalars().all()
    return [
        ProcurementOut(
            id=p.id, title=p.title, description=p.description,
            deadline=p.deadline, status=p.status,
            created_by=p.created_by, created_at=p.created_at,
        )
        for p in procurements
    ]


@router.get("/ceremony/{procurement_id}", response_model=list[CeremonyBidItem])
async def get_ceremony_bids(
    procurement_id: UUID,
    current_user: Annotated[User, Depends(require_role(UserRole.EVALUATOR))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Return bids for ceremony — each bid filtered to only THIS evaluator's encrypted share."""
    # Verify evaluator is assigned to this procurement
    assignment = await db.execute(
        select(ProcurementEvaluator).where(
            ProcurementEvaluator.procurement_id == procurement_id,
            ProcurementEvaluator.evaluator_id == current_user.id,
        )
    )
    if not assignment.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="You are not assigned to this procurement")

    bids_result = await db.execute(
        select(Bid).where(Bid.procurement_id == procurement_id)
    )
    bids = bids_result.scalars().all()

    evaluator_id_str = str(current_user.id)
    items = []
    for bid in bids:
        my_key = bid.encrypted_keys.get(evaluator_id_str)
        if not my_key:
            continue  # This bid has no share for this evaluator (shouldn't happen)

        # Check if this evaluator already submitted their share
        share_check = await db.execute(
            select(EvaluatorShare).where(
                EvaluatorShare.bid_id == bid.id,
                EvaluatorShare.evaluator_id == current_user.id,
            )
        )
        share_submitted = share_check.scalar_one_or_none() is not None

        items.append(CeremonyBidItem(
            bid_id=bid.id,
            bid_hash=bid.bid_hash,
            shamir_meta=bid.shamir_meta,
            my_encrypted_key=my_key,
            share_submitted=share_submitted,
        ))
    return items


@router.post("/submit-share", status_code=status.HTTP_201_CREATED)
async def submit_share(
    payload: SubmitShareRequest,
    current_user: Annotated[User, Depends(require_role(UserRole.EVALUATOR))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Submit a decrypted Shamir share. Triggers ceremony if threshold is reached."""
    # Load the bid
    bid_result = await db.execute(select(Bid).where(Bid.id == payload.bid_id))
    bid = bid_result.scalar_one_or_none()
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")

    # Check for duplicate submission
    existing = await db.execute(
        select(EvaluatorShare).where(
            EvaluatorShare.bid_id == payload.bid_id,
            EvaluatorShare.evaluator_id == current_user.id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="You have already submitted a share for this bid")

    share = EvaluatorShare(
        bid_id=payload.bid_id,
        evaluator_id=current_user.id,
        share_index=payload.share_index,
        share_hex=payload.share_hex,
    )
    db.add(share)
    await db.flush()

    # Count total submitted shares for this bid
    count_result = await db.execute(
        select(EvaluatorShare).where(EvaluatorShare.bid_id == payload.bid_id)
    )
    all_shares = count_result.scalars().all()
    required = bid.shamir_meta.get("required_shares", 1)

    ceremony_triggered = False
    if len(all_shares) >= required:
        # Enough shares collected — open the bid
        try:
            await ceremony_service.open_bid(db, payload.bid_id)
            ceremony_triggered = True
        except Exception as e:
            # Log but don't fail — the share was saved successfully
            print(f"[CEREMONY] Failed to open bid {payload.bid_id}: {e}")

    return {
        "message": "Share submitted successfully",
        "shares_collected": len(all_shares),
        "required_shares": required,
        "ceremony_triggered": ceremony_triggered,
    }
