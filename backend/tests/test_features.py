from app.services.explainer import explain
from app.services.feature_extractor import extract_features


def test_ip_url_flags_ip():
    feats = extract_features("url", "http://192.168.1.10/login")
    assert feats["has_ip"] == 1
    assert feats["has_https"] == 0


def test_https_legit_domain():
    feats = extract_features("url", "https://www.wikipedia.org/wiki/Phishing")
    assert feats["has_https"] == 1
    assert feats["has_ip"] == 0


def test_email_urgency():
    feats = extract_features(
        "email",
        "URGENT: verify your account immediately at http://evil.tk/login",
    )
    assert feats["is_email_input"] == 1
    assert feats["email_urgency_hits"] >= 1
    notes = explain("email", "URGENT verify", "phishing", feats)
    assert notes
