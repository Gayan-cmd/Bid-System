from __future__ import annotations

# Import all models here so Alembic autogenerate can find them
from app.models.user import User, UserRole  # noqa: F401
from app.models.procurement import Procurement, ProcurementEvaluator, EvaluatorInvitation  # noqa: F401
from app.models.bid import Bid, EvaluatorShare, BidResult  # noqa: F401
from app.models.ledger import LedgerBlock  # noqa: F401
