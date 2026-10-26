"""Prediction and dual-engine phishing analysis.

Preserves the Random Forest machine-learning model and Reputation Feeds:
- Machine Learning: 33 lexical, structural, and character-entropy features (Random Forest)
- Threat Reputation Feeds: VirusTotal API v3 and Google Safe Browsing API v4
"""

from __future__ import annotations

import asyncio
from functools import lru_cache
from pathlib import Path
from typing import Any
import joblib

from app.config import get_settings
from app.services.explainer import explain
from app.services.feature_extractor import URL_IN_TEXT_RE, extract_features, features_to_vector
from app.services.reputation import check_url_reputation
from app.services.scoring import compute_risk_assessment


class ModelNotReadyError(RuntimeError):
    pass


@lru_cache
def load_model():
    settings = get_settings()
    path = Path(settings.ml_model_path)
    if not path.is_file():
        # Fall back to path relative to backend root
        alt = Path(__file__).resolve().parents[2] / "ml" / "models" / "phishing_model.joblib"
        path = alt
    if not path.is_file():
        raise ModelNotReadyError(
            "Trained model not found. Run `python ml/train.py` from the backend directory."
        )
    return joblib.load(path)


def predict_ml(input_type: str, content: str) -> tuple[float, dict[str, Any]]:
    """Execute the Random Forest model and return (probability, features)."""
    bundle = load_model()
    model = bundle["model"]
    features = extract_features(input_type, content)
    vector = [features_to_vector(features)]
    proba = model.predict_proba(vector)[0]
    classes = list(model.classes_)
    phishing_index = classes.index(1) if 1 in classes else 1
    phishing_prob = float(proba[phishing_index])
    return phishing_prob, features


def predict(input_type: str, content: str) -> dict:
    """Synchronous baseline prediction using the Random Forest model.

    Preserved for backward compatibility with existing tests and scripts.
    """
    phishing_prob, features = predict_ml(input_type, content)
    verdict = "phishing" if phishing_prob >= 0.5 else "legitimate"
    confidence = phishing_prob if verdict == "phishing" else 1.0 - phishing_prob
    return {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "features": features,
        "explanations": explain(input_type, content, verdict, features),
    }


async def predict_comprehensive(input_type: str, content: str) -> dict[str, Any]:
    """Execute dual-engine security analysis combining Random Forest ML and Reputation Feeds."""
    # 1. Run Random Forest ML prediction
    phishing_prob, ml_features = predict_ml(input_type, content)

    # 2. Run Threat Reputation Feeds (VirusTotal & Google Safe Browsing)
    target_url: str | None = None
    if input_type == "url":
        target_url = content.strip()
    else:
        # Check if email contains embedded URLs to evaluate reputation
        urls_found = URL_IN_TEXT_RE.findall(content)
        if urls_found:
            target_url = urls_found[0]

    reputation_res: dict[str, Any] = {}
    if target_url:
        try:
            reputation_res = await check_url_reputation(target_url)
        except Exception:
            reputation_res = {
                "is_flagged": False,
                "reputation_score": 0,
                "has_checked_feed": False,
                "virustotal": {"status": "error", "details": "Reputation lookup failed safely"},
                "google_safebrowsing": {"status": "error", "details": "Reputation lookup failed safely"},
                "reasons": [],
            }
    else:
        reputation_res = {
            "is_flagged": False,
            "reputation_score": 0,
            "has_checked_feed": False,
            "virustotal": {"status": "unknown", "details": "No URL found for reputation feed lookup"},
            "google_safebrowsing": {"status": "unknown", "details": "No URL found for reputation feed lookup"},
            "reasons": [],
        }

    # Synthesize signals into transparent risk score and verdict
    assessment = compute_risk_assessment(
        input_type=input_type,
        content=content,
        ml_probability=phishing_prob,
        ml_features=ml_features,
        reputation=reputation_res,
    )

    return {
        "verdict": assessment["verdict"],
        "risk_score": assessment["risk_score"],
        "ml_score": assessment["ml_score"],
        "confidence": round(assessment["risk_score"] / 100.0, 4),
        "features": ml_features,
        "signals": assessment["signals"],
        "explanations": assessment["explanations"],
        "limitations": assessment["limitations"],
    }
