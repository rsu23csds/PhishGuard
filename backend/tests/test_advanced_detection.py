"""Comprehensive test suite for PhishGuard dual-engine architecture:
- Machine Learning Detection (Random Forest with 33 lexical/structural features)
- Threat Reputation Feeds (VirusTotal API v3 & Google Safe Browsing API v4)
- Composite Risk Scoring & Explainability
"""

from __future__ import annotations

import httpx
import pytest
from unittest.mock import AsyncMock, patch

from app.services.predictor import predict, predict_comprehensive, predict_ml
from app.services.reputation import (
    check_google_safebrowsing,
    check_url_reputation,
    check_virustotal,
    normalize_url,
)
from app.services.scoring import compute_risk_assessment


# ============================================================================
# 1. Threat Reputation Feeds (VirusTotal & Google Safe Browsing)
# ============================================================================

def test_url_normalization_for_reputation():
    """Ensure URLs are normalized with scheme and proper casing."""
    assert normalize_url("www.example.com").startswith("https://")
    assert normalize_url("EXAMPLE.COM/Path").startswith("https://example.com/Path")
    assert normalize_url("http://test.org/login?foo=1").startswith("http://test.org/login?foo=1")


@pytest.mark.asyncio
async def test_virustotal_malicious_detection():
    """Simulate VirusTotal returning vendor detections for a malicious URL."""
    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 10,
                }
            }
        }
    }

    class MockHttpxResponse:
        status_code = 200
        def json(self):
            return mock_resp

    with patch("httpx.AsyncClient.get", return_value=MockHttpxResponse()):
        res = await check_virustotal("https://malicious-test-link.com", api_key="test-key")
        assert res["status"] == "checked"
        assert res["is_malicious"] is True
        assert res["malicious_count"] == 8
        assert res["total_engines"] == 80
        assert "8 security vendor(s)" in res["details"]


@pytest.mark.asyncio
async def test_virustotal_clean_url():
    """Simulate VirusTotal returning 0 vendor detections."""
    mock_resp = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 75,
                    "undetected": 5,
                }
            }
        }
    }

    class MockHttpxResponse:
        status_code = 200
        def json(self):
            return mock_resp

    with patch("httpx.AsyncClient.get", return_value=MockHttpxResponse()):
        res = await check_virustotal("https://clean-site.org", api_key="test-key")
        assert res["status"] == "checked"
        assert res["is_malicious"] is False
        assert res["malicious_count"] == 0
        assert "Clean" in res["details"]


@pytest.mark.asyncio
async def test_google_safebrowsing_threat_match():
    """Simulate Google Safe Browsing detecting social engineering threat."""
    mock_resp = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
            }
        ]
    }

    class MockHttpxResponse:
        status_code = 200
        def json(self):
            return mock_resp

    with patch("httpx.AsyncClient.post", return_value=MockHttpxResponse()):
        res = await check_google_safebrowsing("https://fake-login-portal.icu", api_key="test-key")
        assert res["status"] == "checked"
        assert res["is_malicious"] is True
        assert "SOCIAL_ENGINEERING" in res["threat_types"]


@pytest.mark.asyncio
async def test_reputation_timeout_handles_gracefully():
    """Ensure timeout does not crash scan and reports UNKNOWN status."""
    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timed out")):
        res = await check_virustotal("https://example.com", api_key="test-key")
        assert res["status"] == "unknown"
        assert res["is_malicious"] is False
        assert "timed out" in res["details"]


@pytest.mark.asyncio
async def test_reputation_unconfigured_api_keys():
    """Ensure missing API keys report 'unknown' without claiming safe."""
    res_vt = await check_virustotal("https://example.com", api_key="")
    assert res_vt["status"] == "unknown"
    assert res_vt["is_malicious"] is False
    assert "not configured" in res_vt["details"]

    res_gsb = await check_google_safebrowsing("https://example.com", api_key="")
    assert res_gsb["status"] == "unknown"
    assert res_gsb["is_malicious"] is False
    assert "not configured" in res_gsb["details"]


@pytest.mark.asyncio
async def test_api_keys_never_leaked_in_output():
    """Verify that external API keys never appear in output dictionaries."""
    secret_key = "super-secret-production-token-99999"
    with patch("httpx.AsyncClient.get", side_effect=Exception("Failed")):
        res = await check_virustotal("https://example.com", api_key=secret_key)
        assert secret_key not in str(res)


# ============================================================================
# 2. Machine Learning Detection (Random Forest Classifier)
# ============================================================================

def test_ml_predict_phishing_url():
    """Verify Random Forest identifies known phishing patterns with high confidence."""
    prob, features = predict_ml("url", "http://paypal-secure-login.tk/webscr?cmd=_login")
    assert prob >= 0.70
    assert features["risky_tld"] == 1
    assert features["keyword_hits"] >= 2


def test_ml_predict_legitimate_url():
    """Verify Random Forest classifies clean legitimate domains with low phishing probability."""
    prob, features = predict_ml("url", "https://www.wikipedia.org/wiki/Phishing")
    assert prob < 0.35
    assert features["has_https"] == 1
    assert features["has_ip"] == 0
    assert features["risky_tld"] == 0


def test_ml_predict_email_payload():
    """Verify Random Forest identifies urgent phishing email prompts."""
    email_text = (
        "URGENT: Your account will be closed in 24 hours. "
        "Verify your credentials immediately at http://192.168.1.100/login"
    )
    prob, features = predict_ml("email", email_text)
    assert features["is_email_input"] == 1
    assert features["email_urgency_hits"] >= 1
    assert features["has_ip"] == 1
    assert prob >= 0.50


# ============================================================================
# 3. Dual-Engine Composite Risk Scoring
# ============================================================================

def test_scoring_reputation_confirmed_malicious_override():
    """Confirmed malicious reputation trigger overrides score to >= 85 (Phishing)."""
    reputation_mock = {
        "is_flagged": True,
        "reputation_score": 35.0,
        "has_checked_feed": True,
        "virustotal": {"status": "checked", "is_malicious": True, "malicious_count": 5},
        "google_safebrowsing": {"status": "checked", "is_malicious": True, "threat_types": ["MALWARE"]},
        "reasons": ["VirusTotal: 5 vendor(s) detected malicious activity."],
    }
    # Even if ML probability was low (0.10)
    res = compute_risk_assessment(
        input_type="url",
        content="https://compromised-site.com",
        ml_probability=0.10,
        ml_features={"has_ip": 0, "uses_shortener": 0, "risky_tld": 0},
        reputation=reputation_mock,
    )
    assert res["verdict"] == "Phishing"
    assert res["risk_score"] >= 85
    assert any("CRITICAL" in exp for exp in res["explanations"])


def test_scoring_high_ml_phishing_triggers_phishing_verdict():
    """Zero-day phishing link with 0 reputation detections should be marked Phishing by ML."""
    reputation_mock = {
        "is_flagged": False,
        "reputation_score": 0.0,
        "has_checked_feed": False,
        "reasons": [],
    }
    res = compute_risk_assessment(
        input_type="url",
        content="http://192.168.1.55/login/verify-account.php",
        ml_probability=0.88,
        ml_features={"has_ip": 1, "uses_shortener": 0, "risky_tld": 0, "keyword_hits": 2},
        reputation=reputation_mock,
    )
    assert res["verdict"] == "Phishing"
    assert res["risk_score"] >= 65
    assert any("Random Forest ML model predicted high phishing probability" in exp for exp in res["explanations"])


def test_scoring_clean_url_produces_likely_legitimate():
    """Clean legitimate URL with low ML probability is marked Likely Legitimate."""
    reputation_mock = {
        "is_flagged": False,
        "reputation_score": 0.0,
        "has_checked_feed": True,
        "reasons": [],
    }
    res = compute_risk_assessment(
        input_type="url",
        content="https://www.wikipedia.org/wiki/Phishing",
        ml_probability=0.08,
        ml_features={"has_ip": 0, "uses_shortener": 0, "risky_tld": 0, "keyword_hits": 0},
        reputation=reputation_mock,
    )
    assert res["verdict"] == "Likely Legitimate"
    assert res["risk_score"] < 35
    assert "Security Disclaimer" in res["limitations"]


# ============================================================================
# 4. Comprehensive End-to-End Predictor Tests
# ============================================================================

@pytest.mark.asyncio
async def test_predict_comprehensive_known_phishing():
    """End-to-end scan of known phishing URL."""
    with patch("app.services.predictor.check_url_reputation", new=AsyncMock(return_value={
        "is_flagged": False,
        "reputation_score": 0,
        "has_checked_feed": True,
        "virustotal": {"status": "checked", "is_malicious": False},
        "google_safebrowsing": {"status": "checked", "is_malicious": False},
        "reasons": [],
    })):
        res = await predict_comprehensive("url", "http://paypal-secure-login.tk/webscr?cmd=_login")
        assert res["verdict"] == "Phishing"
        assert res["risk_score"] >= 65
        assert "ml" in res["signals"]
        assert "reputation" in res["signals"]
        assert "components" in res["signals"]
        assert res["signals"]["components"]["ml"] > 0


@pytest.mark.asyncio
async def test_predict_comprehensive_known_safe():
    """End-to-end scan of known legitimate URL."""
    with patch("app.services.predictor.check_url_reputation", new=AsyncMock(return_value={
        "is_flagged": False,
        "reputation_score": 0,
        "has_checked_feed": True,
        "virustotal": {"status": "checked", "is_malicious": False},
        "google_safebrowsing": {"status": "checked", "is_malicious": False},
        "reasons": [],
    })):
        res = await predict_comprehensive("url", "https://www.wikipedia.org/wiki/Phishing")
        assert res["verdict"] == "Likely Legitimate"
        assert res["risk_score"] < 35


@pytest.mark.asyncio
async def test_predict_comprehensive_email_with_embedded_link():
    """End-to-end scan of an email checks both ML features and reputation for the embedded URL."""
    email_body = "Urgent action required! Please log in at http://192.168.1.1/login"
    mock_rep = {
        "is_flagged": True,
        "reputation_score": 35.0,
        "has_checked_feed": True,
        "virustotal": {"status": "checked", "is_malicious": True, "malicious_count": 3},
        "google_safebrowsing": {"status": "checked", "is_malicious": False},
        "reasons": ["VirusTotal: 3 vendor(s) detected malicious activity."],
    }
    with patch("app.services.predictor.check_url_reputation", new=AsyncMock(return_value=mock_rep)) as mock_check:
        res = await predict_comprehensive("email", email_body)
        mock_check.assert_called_once_with("http://192.168.1.1/login")
        assert res["verdict"] == "Phishing"
        assert res["risk_score"] >= 85
