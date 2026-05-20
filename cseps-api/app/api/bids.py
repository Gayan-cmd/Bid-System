from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_role
from app.db.engine import get_db
from app.models.bid import Bid, EvaluatorShare
from app.models.procurement import Procurement, ProcurementStatus
from app.models.user import User, UserRole
from app.schemas.bid import BidDetail, BidOut, BidSubmitRequest
from app.services import ledger as ledger_service

router = APIRouter(prefix="/bids", tags=["Bids"])


@router.post("/", response_model=BidOut, status_code=status.HTTP_201_CREATED)
async def submit_bid(
    payload: BidSubmitRequest,
    current_user: Annotated[User, Depends(require_role(UserRole.BIDDER))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Submit an encrypted bid. Server stores only ciphertext — never plaintext."""
    # Validate procurement exists and is open
    proc_result = await db.execute(select(Procurement).where(Procurement.id == payload.procurement_id))
    procurement = proc_result.scalar_one_or_none()
    if not procurement:
        raise HTTPException(status_code=404, detail="Procurement not found")
    if procurement.status != ProcurementStatus.OPEN:
        raise HTTPException(status_code=400, detail="Procurement is not open for bidding")

    # Prevent duplicate bids from the same bidder
    existing = await db.execute(
        select(Bid).where(
            Bid.procurement_id == payload.procurement_id,
            Bid.bidder_id == current_user.id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="You have already submitted a bid for this procurement")

    bid = Bid(
        procurement_id=payload.procurement_id,
        bidder_id=current_user.id,
        ciphertext=payload.ciphertext,
        bid_nonce=payload.bid_nonce,
        bid_hash=payload.bid_hash,
        signature=payload.signature,
        shamir_meta=payload.shamir_meta,
        encrypted_keys=payload.encrypted_keys,
    )
    db.add(bid)
    await db.flush()

    # Add to blockchain ledger
    await ledger_service.add_block(db, bid.id, bid.bid_hash)

    return BidOut.model_validate(bid)


@router.get("/my", response_model=list[BidOut])
async def my_bids(
    current_user: Annotated[User, Depends(require_role(UserRole.BIDDER))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(
        select(Bid).where(Bid.bidder_id == current_user.id).order_by(Bid.submitted_at.desc())
    )
    return [BidOut.model_validate(b) for b in result.scalars().all()]


@router.get("/procurement/{procurement_id}", response_model=list[BidDetail])
async def get_bids_for_procurement(
    procurement_id: UUID,
    current_user: Annotated[User, Depends(require_role(UserRole.AUTHORITY))],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Authority only: retrieve all bid packages (still encrypted) for a procurement."""
    result = await db.execute(
        select(Bid).where(Bid.procurement_id == procurement_id).order_by(Bid.submitted_at.asc())
    )
    return [BidDetail.model_validate(b) for b in result.scalars().all()]
