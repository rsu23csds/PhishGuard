"""Transparent composite scoring engine for PhishGuard.

Synthesizes Random Forest ML probabilities (60 pts) and external reputation intelligence (40 pts)
into a transparent, explainable risk score (0-100) and three-tier verdict:
- Phishing (>= 65)
- Suspicious (35 - 64)
- Likely Legitimate (0 - 34) (Never claims guaranteed safe!)
"""

from __future__ import annotations

from typing import Any

SAFETY_DISCLAIMER = (
    "Security Disclaimer: No automated scanner can guarantee a URL or message is 100% safe. "
    "Attackers frequently exploit compromised legitimate servers, utilize zero-day phishing kits, "
    "or deliver delayed redirects. Always verify the domain in your browser's address bar and never "
    "submit passwords or sensitive credentials without verified necessity."
)


def compute_risk_assessment(
    input_type: str,
    content: str,
    ml_probability: float,
    ml_features: dict[str, Any],
    reputation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Calculate the transparent risk score across the two active engines: ML & Reputation Feeds."""
    reputation = reputation or {}

    # 1. Base ML Component (0 - 60 points)
    ml_score = round(float(ml_probability), 4)
    ml_points = round(min(60.0, max(0.0, ml_score * 60.0)), 1)

    # 2. Reputation Component (0 - 40 points)
    rep_points = round(min(40.0, max(0.0, float(reputation.get("reputation_score", 0)))), 1)

    # Initial composite score
    composite = ml_points + rep_points

    # High-confidence security overrides
    override_reason: str | None = None

    # Trigger A: External Threat Intelligence confirmed malicious
    if reputation.get("is_flagged"):
        composite = max(composite, 85.0)
        override_reason = "Flagged as known threat by external threat intelligence databases."

    # Trigger B: High-confidence ML Phishing classification
    # If the Random Forest model sees overwhelming structural indicators (e.g. >= 0.70 prob),
    # ensure it reaches Phishing threshold (>= 65) even for zero-day links not yet in reputation feeds.
    if ml_score >= 0.70:
        composite = max(composite, round(ml_score * 100.0, 1))

    # Trigger C: Moderate ML classification reaches Suspicious tier
    elif ml_score >= 0.50 and composite < 35.0:
        composite = 35.0

    final_risk_score = int(min(100, max(0, round(composite))))

    # Determine Verdict
    if final_risk_score >= 65:
        verdict = "Phishing"
    elif final_risk_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Likely Legitimate"

    # Compile comprehensive, transparent explanations
    explanations: list[str] = []

    if override_reason:
        explanations.append(f"CRITICAL: {override_reason}")

    # Add Reputation explanations
    for reason in reputation.get("reasons", []):
        if reason not in explanations:
            explanations.append(reason)

    # Add ML / Structural feature notes
    if ml_score >= 0.70:
        explanations.append(
            f"Random Forest ML model predicted high phishing probability ({int(ml_score * 100)}%) based on lexical/structural patterns."
        )
    elif ml_score >= 0.50:
        explanations.append(
            f"Random Forest ML model identified suspicious structural attributes ({int(ml_score * 100)}% probability)."
        )

    if ml_features.get("has_ip"):
        explanations.append("Destination uses a raw IP address rather than a legitimate branded domain name.")
    if ml_features.get("uses_shortener"):
        explanations.append("URL shortener obscures destination endpoint.")
    if ml_features.get("risky_tld"):
        explanations.append("Top-level domain (TLD) has a high historical correlation with disposable attack domains.")
    if ml_features.get("keyword_hits", 0) >= 2:
        explanations.append(
            f"Contains {ml_features.get('keyword_hits')} security/account keywords typical of phishing lures."
        )
    if ml_features.get("email_urgency_hits", 0) >= 1:
        explanations.append("Urgency phrasing detected intended to pressure recipient action.")
    if ml_features.get("email_credential_ask"):
        explanations.append("Message solicits account credentials or sensitive information.")
    if ml_features.get("url_length", 0) > 75 and input_type == "url":
        explanations.append("URL length is unusually long, frequently used to obscure deceptive parameters.")

    # Note if external reputation APIs were unconfigured or unavailable (UNKNOWN status)
    if not reputation.get("has_checked_feed"):
        explanations.append(
            "External reputation APIs were unconfigured/unavailable (reputation status UNKNOWN; not assumed safe)."
        )

    # If verdict is Likely Legitimate, explain why without guaranteeing safety
    if verdict == "Likely Legitimate":
        if not any("No threat" in e for e in explanations):
            explanations.append("No active threat blacklist records or critical structural anomalies detected.")
        explanations.append("Note: Always exercise caution before providing credentials or personal data.")

    # Deduplicate and limit explanations to top 8 most impactful points
    deduped_explanations: list[str] = []
    for item in explanations:
        if item not in deduped_explanations:
            deduped_explanations.append(item)
    explanations = deduped_explanations[:8]

    # Consolidated signals package for API response
    signals = {
        "ml": {
            "score": ml_score,
            "points": ml_points,
            "structural_features": {
                k: v for k, v in ml_features.items()
                if k in (
                    "url_length", "hostname_length", "has_https", "has_ip", "uses_shortener",
                    "risky_tld", "subdomain_count", "keyword_hits", "digit_ratio",
                    "entropy", "email_urgency_hits", "email_credential_ask"
                )
            },
        },
        "reputation": {
            "points": rep_points,
            "is_flagged": reputation.get("is_flagged", False),
            "status": "checked" if reputation.get("has_checked_feed") else "unknown",
            "virustotal": reputation.get("virustotal", {}),
            "google_safebrowsing": reputation.get("google_safebrowsing", {}),
        },
        "components": {
            "ml": round(ml_points, 1),
            "reputation": round(rep_points, 1),
        },
    }

    return {
        "verdict": verdict,
        "risk_score": final_risk_score,
        "ml_score": ml_score,
        "signals": signals,
        "explanations": explanations,
        "limitations": SAFETY_DISCLAIMER,
    }
