from __future__ import annotations

import hashlib
import json
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ledger import LedgerBlock


async def add_block(db: AsyncSession, bid_id: UUID, bid_hash: str) -> LedgerBlock:
    """Append a new block to the blockchain ledger."""
    # Get the last block's index and hash
    result = await db.execute(
        select(LedgerBlock).order_by(LedgerBlock.block_index.desc()).limit(1)
    )
    last_block = result.scalar_one_or_none()

    if last_block is None:
        block_index = 0
        previous_hash = "0" * 64  # Genesis block
    else:
        block_index = last_block.block_index + 1
        previous_hash = last_block.current_hash

    # Build the canonical block data (deterministic key order)
    block_data = {
        "block_index": block_index,
        "bid_id": str(bid_id),
        "bid_hash": bid_hash,
        "previous_hash": previous_hash,
    }
    block_string = json.dumps(block_data, sort_keys=True).encode()
    current_hash = hashlib.sha256(block_string).hexdigest()

    new_block = LedgerBlock(
        block_index=block_index,
        bid_id=bid_id,
        bid_hash=bid_hash,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )
    db.add(new_block)
    await db.flush()  # Get the ID without committing
    return new_block


async def verify_chain(db: AsyncSession) -> tuple[bool, int]:
    """Verify the entire ledger chain. Returns (is_valid, block_count)."""
    result = await db.execute(select(LedgerBlock).order_by(LedgerBlock.block_index.asc()))
    blocks = result.scalars().all()

    if not blocks:
        return True, 0

    for i, block in enumerate(blocks):
        # Recompute this block's hash
        block_data = {
            "block_index": block.block_index,
            "bid_id": str(block.bid_id) if block.bid_id else None,
            "bid_hash": block.bid_hash,
            "previous_hash": block.previous_hash,
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        expected_hash = hashlib.sha256(block_string).hexdigest()

        if expected_hash != block.current_hash:
            return False, len(blocks)

        # Check chain linkage (previous_hash matches previous block's current_hash)
        if i > 0:
            if block.previous_hash != blocks[i - 1].current_hash:
                return False, len(blocks)

    return True, len(blocks)
