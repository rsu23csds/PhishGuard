from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    full_name: str = Field(min_length=2, max_length=80)
    confirm_password: str | None = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    created_at: datetime


class ScanRequest(BaseModel):
    input_type: Literal["url", "email"]
    content: str = Field(min_length=4, max_length=20000)


class ScanResponse(BaseModel):
    id: str
    input_type: str
    content_preview: str
    verdict: str
    risk_score: int = Field(default=0, ge=0, le=100)
    ml_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0)
    features: dict[str, Any] = Field(default_factory=dict)
    signals: dict[str, Any] = Field(default_factory=dict)
    explanations: list[str] = Field(default_factory=list)
    limitations: str = Field(default="")
    created_at: datetime


class StatsResponse(BaseModel):
    total_scans: int
    phishing_count: int
    suspicious_count: int = 0
    legitimate_count: int
    phishing_rate: float
    recent_threats: list[ScanResponse]
