from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import get_settings
from app.database import close_client, ensure_indexes
from app.routers.auth import bootstrap_admin, router as auth_router
from app.routers.scans import limiter, router as scans_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    await ensure_indexes()
    await bootstrap_admin()
    yield
    await close_client()


settings = get_settings()
app = FastAPI(
    title="PhishGuard API",
    description="AI-powered phishing detection for URLs and email content.",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth_router)
app.include_router(scans_router)


from fastapi.exceptions import RequestValidationError


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Try again shortly."})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    for err in errors:
        loc = err.get("loc", [])
        if "email" in loc:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid email format. Please provide a valid email address (e.g. name@example.com)."},
            )
        if "password" in loc:
            return JSONResponse(
                status_code=400,
                content={"detail": "Password must be at least 8 characters long."},
            )
    first_msg = errors[0].get("msg", "Invalid request parameters.") if errors else "Invalid request parameters."
    return JSONResponse(status_code=400, content={"detail": first_msg})


@app.get("/")
async def root():
    return RedirectResponse(url="/docs")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "phishguard"}
