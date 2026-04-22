"""
FastAPI application entry point for Verity.
Sets up CORS, rate limiting, exception handlers, and mounts all routers.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import load_overrides, settings
from app.core.parser import ParseError
from app.db.session import init_db


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["10/second"])


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup."""
    load_overrides()
    await init_db()
    yield


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Verity API",
    version="1.0.0",
    description=(
        "SBOM Validator and Risk Assessment Platform for TPRM. "
        "Supports CycloneDX and SPDX formats with NTIA compliance checking "
        "and OSV.dev vulnerability lookups."
    ),
    lifespan=lifespan,
)

# Attach rate limiter state and error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(ParseError)
async def parse_error_handler(request: Request, exc: ParseError) -> JSONResponse:
    """Return HTTP 422 for SBOM parse errors."""
    return JSONResponse(
        status_code=422,
        content={
            "detail": str(exc),
            "error": "SBOM_PARSE_ERROR",
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler that returns 500 without leaking internal details."""
    # Re-raise validation and HTTP exceptions so FastAPI handles them normally
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    if isinstance(exc, (StarletteHTTPException, RequestValidationError)):
        raise exc

    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "error": "INTERNAL_SERVER_ERROR",
        },
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from app.api.routes import auth, ci, components, scans, site_settings, workspaces  # noqa: E402

app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(workspaces.router, prefix="/api/v1")
app.include_router(site_settings.router, prefix="/api/v1")
app.include_router(components.router, prefix="/api/v1")
app.include_router(ci.router, prefix="/api/v1")

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
async def health_check() -> dict:
    """Simple liveness probe endpoint."""
    return {"status": "ok", "version": "1.0.0", "auth_enabled": settings.AUTH_ENABLED}


@app.get("/api/v1/health", tags=["meta"])
async def health_check_v1() -> dict:
    """Health endpoint accessible through the nginx /api proxy."""
    return {"status": "ok", "version": "1.0.0", "auth_enabled": settings.AUTH_ENABLED}
