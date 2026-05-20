from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, audit, bids, evaluator, procurements
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"🔐 CSePS API starting — environment: {settings.ENVIRONMENT}")
    yield
    # Shutdown
    print("CSePS API shutting down")


app = FastAPI(
    title="CSePS API",
    description=(
        "**Crypto-Secure e-Procurement System** — REST API\n\n"
        "A cryptographic sealed-bid procurement platform where bids are encrypted entirely "
        "in the client browser using **ECDSA**, **AES-256-GCM**, **ECDH**, **HKDF**, and "
        "**Shamir's Secret Sharing**. The server stores only ciphertext and public keys.\n\n"
        "**Roles:** `AUTHORITY` | `EVALUATOR` | `BIDDER` | `PUBLIC`"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ─────────────────────────────────────────────────────────────────────
allowed_origins = [
    settings.FRONTEND_URL,
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api")
app.include_router(procurements.router, prefix="/api")
app.include_router(bids.router, prefix="/api")
app.include_router(evaluator.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "service": "cseps-api", "version": "1.0.0"}
