from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status

from app.config import get_settings
from app.database import get_db
from app.schemas import TokenResponse, UserCreate, UserLogin, UserPublic
from app.security import create_access_token, get_current_user, hash_password, verify_password
from fastapi import Depends
from app.services.email_validator_service import validate_legitimate_email

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
async def register(payload: UserCreate):
    email_clean = payload.email.lower().strip()

    # 1. Enforce legitimate email (blocks dummy, disposable, and non-resolving domains)
    is_legit, reason = validate_legitimate_email(email_clean)
    if not is_legit:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    # 2. Check password length
    if len(payload.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )

    # 3. Check confirm password if provided
    if payload.confirm_password is not None and payload.confirm_password != payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password and Confirm Password do not match.",
        )

    db = get_db()
    # 4. Strictly prevent duplicate registrations with clear error
    existing = await db.users.find_one({"email": email_clean})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists. Please sign in instead.",
        )

    user_id = str(uuid4())
    try:
        await db.users.insert_one(
            {
                "_id": user_id,
                "email": email_clean,
                "full_name": payload.full_name.strip(),
                "password_hash": hash_password(payload.password),
                "created_at": datetime.now(timezone.utc),
            }
        )
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "11000" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email already exists. Please sign in instead.",
            )
        raise

    return TokenResponse(access_token=create_access_token(user_id))


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin):
    email_clean = payload.email.lower().strip()

    # 1. Verify that email exists in the system
    user = await get_db().users.find_one({"email": email_clean})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email. Please register first.",
        )

    # 2. Verify that password matches the stored bcrypt hash
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password. Please verify your password and try again.",
        )

    return TokenResponse(access_token=create_access_token(user["_id"]))


@router.get("/me", response_model=UserPublic)
async def me(user=Depends(get_current_user)):
    return UserPublic(
        id=user["_id"],
        email=user["email"],
        full_name=user["full_name"],
        created_at=user["created_at"],
    )


async def bootstrap_admin() -> None:
    settings = get_settings()
    db = get_db()
    if await db.users.count_documents({}) > 0:
        return
    await db.users.insert_one(
        {
            "_id": str(uuid4()),
            "email": settings.admin_email.lower(),
            "full_name": "Admin",
            "password_hash": hash_password(settings.admin_password),
            "created_at": datetime.now(timezone.utc),
        }
    )
