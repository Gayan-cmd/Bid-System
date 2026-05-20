from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.models.ledger import LedgerBlock
from app.services import ledger as ledger_service

router = APIRouter(prefix="/audit", tags=["Public Audit"])


@router.get("/ledger")
async def get_ledger(db: AsyncSession = Depends(get_db)):
    """Public endpoint: full blockchain ledger for independent verification."""
    result = await db.execute(
        select(LedgerBlock).order_by(LedgerBlock.block_index.asc())
    )
    blocks = result.scalars().all()
    return [
        {
            "block_index": b.block_index,
            "bid_id": str(b.bid_id) if b.bid_id else None,
            "bid_hash": b.bid_hash,
            "previous_hash": b.previous_hash,
            "current_hash": b.current_hash,
            "created_at": b.created_at.isoformat(),
        }
        for b in blocks
    ]


@router.get("/ledger/verify")
async def verify_ledger(db: AsyncSession = Depends(get_db)):
    """Public endpoint: server-side chain integrity check."""
    is_valid, block_count = await ledger_service.verify_chain(db)
    return {
        "valid": is_valid,
        "block_count": block_count,
        "message": "Ledger chain is intact ✓" if is_valid else "⚠ Chain integrity compromised!",
    }
