"""Tests for legitimate email validation and password matching during user registration."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from app.routers.auth import register
from app.schemas import UserCreate
from app.security import hash_password
from app.services.email_validator_service import (
    is_dummy_or_disposable_email,
    validate_legitimate_email,
)
from fastapi import HTTPException


# ============================================================================
# 1. Email Legitimacy & Disposable Provider Tests
# ============================================================================

def test_rejects_dummy_and_placeholder_emails():
    """Ensure placeholder, repetitive, and dummy test emails are rejected."""
    is_dummy, reason = is_dummy_or_disposable_email("test@test.com")
    assert is_dummy is True
    assert "dummy" in reason.lower() or "placeholder" in reason.lower()

    is_dummy, _ = is_dummy_or_disposable_email("dummy@gmail.com")
    assert is_dummy is True

    is_dummy, _ = is_dummy_or_disposable_email("fake@yahoo.com")
    assert is_dummy is True

    is_dummy, _ = is_dummy_or_disposable_email("asdf@example.com")
    assert is_dummy is True


def test_rejects_disposable_and_burner_domains():
    """Ensure temporary disposable email domains are blocked."""
    disposable_samples = [
        "victim@mailinator.com",
        "victim@tempmail.com",
        "victim@10minutemail.com",
        "victim@guerrillamail.com",
        "victim@yopmail.com",
        "victim@sharklasers.com",
        "victim@trashmail.com",
    ]
    for email in disposable_samples:
        is_disp, reason = is_dummy_or_disposable_email(email)
        assert is_disp is True, f"Expected {email} to be flagged as disposable"
        assert "temporary" in reason.lower() or "disposable" in reason.lower()


def test_rejects_nonexistent_email_domains_without_mx():
    """Ensure fake domains that cannot receive email are rejected."""
    with patch("app.services.email_validator_service.check_domain_has_mail_server", return_value=False):
        is_legit, reason = validate_legitimate_email("realuser@nonexistentdomain9999.xyz")
        assert is_legit is False
        assert "does not exist or has no valid mail exchange" in reason


def test_accepts_valid_deliverable_email():
    """Ensure genuine email domains with MX pass validation."""
    with patch("app.services.email_validator_service.check_domain_has_mail_server", return_value=True):
        is_legit, _ = validate_legitimate_email("alex.miller@gmail.com")
        assert is_legit is True


# ============================================================================
# 2. Registration Logic: Confirm Password & Existing Email Password Match
# ============================================================================

@pytest.mark.asyncio
async def test_register_rejects_password_mismatch():
    """Registration fails if password and confirm_password do not match."""
    payload = UserCreate(
        email="alex.miller@gmail.com",
        password="ValidPassword123!",
        confirm_password="DifferentPassword456!",
        full_name="Alex Miller",
    )
    with patch("app.routers.auth.validate_legitimate_email", return_value=(True, "ok")):
        with pytest.raises(HTTPException) as exc_info:
            await register(payload)
        assert exc_info.value.status_code == 400
        assert "do not match" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_register_prevents_duplicate_registrations():
    """Duplicate registration must be rejected with a clear error."""
    existing_user = {
        "_id": "user-uuid-1234",
        "email": "alex.miller@gmail.com",
        "full_name": "Alex Miller",
        "password_hash": hash_password("ValidPassword123!"),
    }

    mock_db = AsyncMock()
    mock_db.users.find_one = AsyncMock(return_value=existing_user)

    payload = UserCreate(
        email="alex.miller@gmail.com",
        password="ValidPassword123!",
        confirm_password="ValidPassword123!",
        full_name="Alex Miller",
    )

    with patch("app.routers.auth.validate_legitimate_email", return_value=(True, "ok")), \
         patch("app.routers.auth.get_db", return_value=mock_db):
        with pytest.raises(HTTPException) as exc_info:
            await register(payload)
        assert exc_info.value.status_code == 400
        assert "already exists" in exc_info.value.detail.lower()


# ============================================================================
# 3. Login Logic: Unregistered Emails & Incorrect Passwords
# ============================================================================

from app.routers.auth import login
from app.schemas import UserLogin


@pytest.mark.asyncio
async def test_login_rejects_unregistered_email():
    """Login with nonexistent email returns 404 with clear message."""
    mock_db = AsyncMock()
    mock_db.users.find_one = AsyncMock(return_value=None)

    payload = UserLogin(email="notfound@gmail.com", password="SomePassword123!")
    with patch("app.routers.auth.get_db", return_value=mock_db):
        with pytest.raises(HTTPException) as exc_info:
            await login(payload)
        assert exc_info.value.status_code == 404
        assert "no account found with this email" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_login_rejects_incorrect_password():
    """Login with registered email but incorrect password returns 401 with clear message."""
    existing_user = {
        "_id": "user-uuid-1234",
        "email": "alex.miller@gmail.com",
        "password_hash": hash_password("CorrectPassword123!"),
    }
    mock_db = AsyncMock()
    mock_db.users.find_one = AsyncMock(return_value=existing_user)

    payload = UserLogin(email="alex.miller@gmail.com", password="WrongPassword999!")
    with patch("app.routers.auth.get_db", return_value=mock_db):
        with pytest.raises(HTTPException) as exc_info:
            await login(payload)
        assert exc_info.value.status_code == 401
        assert "incorrect password" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_login_succeeds_with_correct_credentials():
    """Login succeeds with access token when credentials match."""
    existing_user = {
        "_id": "user-uuid-1234",
        "email": "alex.miller@gmail.com",
        "password_hash": hash_password("CorrectPassword123!"),
    }
    mock_db = AsyncMock()
    mock_db.users.find_one = AsyncMock(return_value=existing_user)

    payload = UserLogin(email="alex.miller@gmail.com", password="CorrectPassword123!")
    with patch("app.routers.auth.get_db", return_value=mock_db):
        res = await login(payload)
        assert res.access_token is not None
        assert res.token_type == "bearer"

