"""Reputation intelligence service for VirusTotal and Google Safe Browsing.

Interrogates external threat intelligence APIs safely, with strict timeouts,
proper URL normalization, response parsing, and explicit handling of unavailable
or unconfigured APIs as UNKNOWN (never automatically claiming safe).
"""

from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlparse
import httpx

from app.config import get_settings


def normalize_url(url: str) -> str:
    """Canonicalize a URL for reputation hashing and matching."""
    clean = url.strip()
    if not clean:
        return clean
    if clean.lower().startswith("www."):
        clean = "https://" + clean
    elif "://" not in clean:
        clean = "https://" + clean

    parsed = urlparse(clean)
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    normalized = f"{scheme}://{netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


async def check_virustotal(url: str, api_key: str | None = None) -> dict[str, Any]:
    """Check a URL against VirusTotal API v3.
    
    Treats unconfigured or unavailable states as UNKNOWN, never automatically SAFE.
    """
    key = api_key if api_key is not None else get_settings().virustotal_api_key
    if not key or not key.strip():
        return {
            "provider": "VirusTotal",
            "status": "unknown",
            "is_malicious": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "details": "VirusTotal API key not configured; reputation status is UNKNOWN (not verified safe).",
        }

    try:
        norm_url = normalize_url(url)
        # VirusTotal API v3 expects the URL-safe base64 encoded URL without '=' padding
        url_id = base64.urlsafe_b64encode(norm_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": key.strip(), "User-Agent": "PhishGuard/2.0"}

        async with httpx.AsyncClient(timeout=3.5) as client:
            resp = await client.get(endpoint, headers=headers)

        if resp.status_code == 404:
            # URL not yet analyzed or submitted
            return {
                "provider": "VirusTotal",
                "status": "unknown",
                "is_malicious": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "details": "URL not recorded in VirusTotal dataset; reputation status is UNKNOWN.",
            }

        if resp.status_code in (401, 403):
            return {
                "provider": "VirusTotal",
                "status": "unknown",
                "is_malicious": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "details": "VirusTotal authentication error (invalid API key); reputation status is UNKNOWN.",
            }

        if resp.status_code != 200:
            return {
                "provider": "VirusTotal",
                "status": "unknown",
                "is_malicious": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "details": f"VirusTotal returned HTTP {resp.status_code}; reputation status is UNKNOWN.",
            }

        data = resp.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        is_flagged = malicious > 0 or suspicious >= 2

        return {
            "provider": "VirusTotal",
            "status": "checked",
            "is_malicious": is_flagged,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "details": f"{malicious} security vendor(s) flagged this URL as malicious out of {total} engines."
            if is_flagged
            else f"Clean: 0/{total} security vendors flagged this URL.",
        }

    except httpx.TimeoutException:
        return {
            "provider": "VirusTotal",
            "status": "unknown",
            "is_malicious": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "details": "VirusTotal lookup timed out; reputation status is UNKNOWN.",
        }
    except Exception:
        return {
            "provider": "VirusTotal",
            "status": "unknown",
            "is_malicious": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "details": "VirusTotal query failed safely; reputation status is UNKNOWN.",
        }


async def check_google_safebrowsing(url: str, api_key: str | None = None) -> dict[str, Any]:
    """Check a URL against Google Safe Browsing API v4.
    
    Treats unconfigured or unavailable states as UNKNOWN, never automatically SAFE.
    """
    key = api_key if api_key is not None else get_settings().google_safebrowsing_api_key
    if not key or not key.strip():
        return {
            "provider": "Google Safe Browsing",
            "status": "unknown",
            "is_malicious": False,
            "threat_types": [],
            "details": "Google Safe Browsing API key not configured; reputation status is UNKNOWN (not verified safe).",
        }

    try:
        norm_url = normalize_url(url)
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key.strip()}"
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "2.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": norm_url}],
            },
        }

        async with httpx.AsyncClient(timeout=3.5) as client:
            resp = await client.post(endpoint, json=payload)

        if resp.status_code in (400, 401, 403):
            return {
                "provider": "Google Safe Browsing",
                "status": "unknown",
                "is_malicious": False,
                "threat_types": [],
                "details": f"Google Safe Browsing API authentication/query error (HTTP {resp.status_code}); reputation status is UNKNOWN.",
            }

        if resp.status_code != 200:
            return {
                "provider": "Google Safe Browsing",
                "status": "unknown",
                "is_malicious": False,
                "threat_types": [],
                "details": f"Google Safe Browsing returned HTTP {resp.status_code}; reputation status is UNKNOWN.",
            }

        matches = resp.json().get("matches", [])
        if matches:
            threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
            return {
                "provider": "Google Safe Browsing",
                "status": "checked",
                "is_malicious": True,
                "threat_types": threat_types,
                "details": f"Flagged by Google Safe Browsing as: {', '.join(threat_types)}.",
            }

        return {
            "provider": "Google Safe Browsing",
            "status": "checked",
            "is_malicious": False,
            "threat_types": [],
            "details": "No threat matches found in Google Safe Browsing index.",
        }

    except httpx.TimeoutException:
        return {
            "provider": "Google Safe Browsing",
            "status": "unknown",
            "is_malicious": False,
            "threat_types": [],
            "details": "Google Safe Browsing lookup timed out; reputation status is UNKNOWN.",
        }
    except Exception:
        return {
            "provider": "Google Safe Browsing",
            "status": "unknown",
            "is_malicious": False,
            "threat_types": [],
            "details": "Google Safe Browsing query failed safely; reputation status is UNKNOWN.",
        }


async def check_url_reputation(url: str) -> dict[str, Any]:
    """Query all configured reputation providers and compile reputation score (0 - 35 points)."""
    vt_result = await check_virustotal(url)
    gsb_result = await check_google_safebrowsing(url)

    is_flagged = vt_result.get("is_malicious", False) or gsb_result.get("is_malicious", False)
    malicious_reasons: list[str] = []

    if vt_result.get("is_malicious"):
        malicious_reasons.append(
            f"VirusTotal: {vt_result['malicious_count']} vendor(s) detected malicious activity."
        )
    if gsb_result.get("is_malicious"):
        malicious_reasons.append(
            f"Google Safe Browsing: flagged as {', '.join(gsb_result['threat_types'])}."
        )

    # Reputation layer score (strictly 0 - 40 points)
    reputation_score = 0.0
    if vt_result.get("is_malicious"):
        reputation_score = max(reputation_score, min(40.0, 25.0 + vt_result["malicious_count"] * 5.0))
    elif vt_result.get("suspicious_count", 0) > 0:
        reputation_score = max(reputation_score, 18.0)

    if gsb_result.get("is_malicious"):
        reputation_score = max(reputation_score, 40.0)

    # Note if external reputation is unconfigured or unavailable
    has_checked_feed = (vt_result.get("status") == "checked") or (gsb_result.get("status") == "checked")

    return {
        "is_flagged": is_flagged,
        "reputation_score": min(40.0, reputation_score),
        "has_checked_feed": has_checked_feed,
        "virustotal": vt_result,
        "google_safebrowsing": gsb_result,
        "reasons": malicious_reasons,
    }
