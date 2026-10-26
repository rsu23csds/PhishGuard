from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings
from app.database import get_db
from app.schemas import ScanRequest, ScanResponse, StatsResponse
from app.security import get_current_user
from app.services.predictor import ModelNotReadyError, predict_comprehensive

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/api", tags=["scans"])


def _preview(content: str) -> str:
    compact = " ".join(content.split())
    return compact[:180] + ("…" if len(compact) > 180 else "")


def _doc_to_scan(doc: dict) -> ScanResponse:
    confidence = float(doc.get("confidence", 0.0))
    risk_score = doc.get("risk_score")
    if risk_score is None:
        risk_score = int(round(confidence * 100)) if doc.get("verdict", "").lower() == "phishing" else int(round((1.0 - confidence) * 100))

    ml_score = doc.get("ml_score")
    if ml_score is None:
        ml_score = round(confidence, 4) if doc.get("verdict", "").lower() == "phishing" else round(1.0 - confidence, 4)

    return ScanResponse(
        id=doc["_id"],
        input_type=doc["input_type"],
        content_preview=doc["content_preview"],
        verdict=doc["verdict"],
        risk_score=risk_score,
        ml_score=ml_score,
        confidence=confidence,
        features=doc.get("features", {}),
        signals=doc.get("signals", {}),
        explanations=doc.get("explanations", []),
        limitations=doc.get("limitations", ""),
        created_at=doc["created_at"],
    )


@router.post("/scan", response_model=ScanResponse)
@limiter.limit(f"{get_settings().rate_limit_per_minute}/minute")
async def create_scan(request: Request, payload: ScanRequest, user=Depends(get_current_user)):
    try:
        result = await predict_comprehensive(payload.input_type, payload.content)
    except ModelNotReadyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    doc = {
        "_id": str(uuid4()),
        "user_id": user["_id"],
        "input_type": payload.input_type,
        "content_preview": _preview(payload.content),
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "ml_score": result["ml_score"],
        "confidence": result["confidence"],
        "features": result["features"],
        "signals": result["signals"],
        "explanations": result["explanations"],
        "limitations": result.get("limitations", ""),
        "created_at": datetime.now(timezone.utc),
    }
    await get_db().scans.insert_one(doc)
    return _doc_to_scan(doc)


@router.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    user=Depends(get_current_user),
    limit: int = Query(default=20, ge=1, le=100),
):
    cursor = get_db().scans.find({"user_id": user["_id"]}).sort("created_at", -1).limit(limit)
    return [_doc_to_scan(doc) async for doc in cursor]


@router.get("/stats", response_model=StatsResponse)
async def stats(user=Depends(get_current_user)):
    db = get_db()
    query = {"user_id": user["_id"]}
    total = await db.scans.count_documents(query)
    phishing = await db.scans.count_documents({**query, "verdict": {"$in": ["Phishing", "phishing"]}})
    suspicious = await db.scans.count_documents({**query, "verdict": {"$in": ["Suspicious", "suspicious"]}})
    legitimate = total - (phishing + suspicious)
    threats = (
        db.scans.find({**query, "verdict": {"$in": ["Phishing", "phishing", "Suspicious", "suspicious"]}})
        .sort("created_at", -1)
        .limit(8)
    )
    return StatsResponse(
        total_scans=total,
        phishing_count=phishing,
        suspicious_count=suspicious,
        legitimate_count=max(0, legitimate),
        phishing_rate=round(phishing / total, 4) if total else 0.0,
        recent_threats=[_doc_to_scan(doc) async for doc in threats],
    )
