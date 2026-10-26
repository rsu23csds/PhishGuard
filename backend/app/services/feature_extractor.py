"""Security feature extraction for URLs and email content.

All features are derived from the submitted text. The service never follows
unknown links or downloads remote pages, which keeps analysis safe for demos.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "verified",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "confirm",
    "password",
    "banking",
    "invoice",
    "urgent",
    "suspend",
    "limited",
    "unlock",
    "wallet",
    "paypal",
    "appleid",
    "microsoft",
    "office365",
    "outlook",
    "meta",
    "facebook",
    "signin",
    "portal",
    "auth",
    "recover",
    "helpdesk",
    "webscr",
    "ebayisapi",
)

EMAIL_URGENCY = (
    "urgent",
    "immediately",
    "act now",
    "24 hours",
    "suspended",
    "verify your account",
    "confirm your identity",
    "unauthorized",
    "click here",
    "reset your password",
    "limited time",
    "account will be closed",
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
}

RISKY_TLDS = {".xyz", ".top", ".club", ".icu", ".click", ".country", ".gq", ".ml", ".cf", ".tk", ".ga"}
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.I)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _safe_parse(url: str):
    candidate = url.strip()
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    if "://" not in candidate:
        candidate = "http://" + candidate
    return urlparse(candidate)


def extract_url_features(url: str) -> dict:
    parsed = _safe_parse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.strip()

    dots = host.count(".")
    subdomain_count = max(dots - 1, 0)
    digits = sum(ch.isdigit() for ch in full)

    return {
        "url_length": len(full),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": full.count("/"),
        "num_at": full.count("@"),
        "num_question": full.count("?"),
        "num_equals": full.count("="),
        "num_ampersand": full.count("&"),
        "num_percent": full.count("%"),
        "num_digits": digits,
        "digit_ratio": round(digits / max(len(full), 1), 4),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_ip": 1 if host and IP_RE.match(host) else 0,
        "has_port": 1 if parsed.port not in (None, 80, 443) else 0,
        "subdomain_count": subdomain_count,
        "uses_shortener": 1 if host in SHORTENERS else 0,
        "risky_tld": 1 if any(host.endswith(tld) for tld in RISKY_TLDS) else 0,
        "has_at_symbol": 1 if "@" in full else 0,
        "double_slash_redirect": 1 if "//" in (path + query) else 0,
        "has_embedded_url": 1 if "http" in (path + query).lower() else 0,
        "keyword_hits": sum(1 for word in SUSPICIOUS_KEYWORDS if word in full.lower()),
        "entropy": round(_shannon_entropy(full.lower()), 4),
        "is_email_input": 0,
        "email_urgency_hits": 0,
        "email_link_count": 0,
        "email_credential_ask": 0,
        "email_html_form": 0,
        "email_mismatch_hint": 0,
        "email_length": 0,
    }


def extract_email_features(body: str) -> dict:
    text = body.strip()
    lower = text.lower()
    links = URL_IN_TEXT_RE.findall(text)
    primary = extract_url_features(links[0]) if links else extract_url_features("http://placeholder.invalid")
    if not links:
        primary.update(
            {
                "url_length": 0,
                "hostname_length": 0,
                "path_length": 0,
                "query_length": 0,
                "has_https": 0,
                "has_ip": 0,
                "entropy": round(_shannon_entropy(lower), 4),
            }
        )

    primary.update(
        {
            "is_email_input": 1,
            "email_urgency_hits": sum(1 for phrase in EMAIL_URGENCY if phrase in lower),
            "email_link_count": len(links),
            "email_credential_ask": 1
            if any(k in lower for k in ("password", "otp", "one-time", "ssn", "credit card", "cvv"))
            else 0,
            "email_html_form": 1 if "<form" in lower or "input type" in lower else 0,
            "email_mismatch_hint": 1 if ("href=" in lower and any(brand in lower for brand in ("paypal", "apple", "microsoft", "amazon", "bank"))) else 0,
            "email_length": len(text),
            "keyword_hits": sum(1 for word in SUSPICIOUS_KEYWORDS if word in lower),
        }
    )
    return primary


def extract_features(input_type: str, content: str) -> dict:
    if input_type == "email":
        return extract_email_features(content)
    return extract_url_features(content)


FEATURE_ORDER = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_at",
    "num_question",
    "num_equals",
    "num_ampersand",
    "num_percent",
    "num_digits",
    "digit_ratio",
    "has_https",
    "has_ip",
    "has_port",
    "subdomain_count",
    "uses_shortener",
    "risky_tld",
    "has_at_symbol",
    "double_slash_redirect",
    "has_embedded_url",
    "keyword_hits",
    "entropy",
    "is_email_input",
    "email_urgency_hits",
    "email_link_count",
    "email_credential_ask",
    "email_html_form",
    "email_mismatch_hint",
    "email_length",
]


def features_to_vector(features: dict) -> list[float]:
    return [float(features.get(name, 0)) for name in FEATURE_ORDER]
