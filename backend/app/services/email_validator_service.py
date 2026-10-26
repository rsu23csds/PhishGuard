"""Legitimate email validation service.

Guards against:
- Malformed syntax (RFC 5322 compliance via email-validator)
- Disposable / temporary / burner email domains
- Dummy / placeholder test email patterns (e.g. test@test.com, dummy@dummy.com)
- Non-existent domains without valid DNS MX / A records
"""

from __future__ import annotations

import re
import socket
from email_validator import EmailNotValidError, validate_email

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# Known disposable, temporary, and burner email provider domains
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "tempmail.com",
    "temp-mail.org",
    "10minutemail.com",
    "guerrillamail.com",
    "guerrillamail.net",
    "guerrillamail.org",
    "sharklasers.com",
    "grr.la",
    "yopmail.com",
    "yopmail.fr",
    "yopmail.net",
    "throwawaymail.com",
    "getairmail.com",
    "dispostable.com",
    "trashmail.com",
    "trashmail.net",
    "trashmail.org",
    "fakemailgenerator.com",
    "generator.email",
    "maildrop.cc",
    "inboxkitten.com",
    "mohmal.com",
    "crazymailing.com",
    "mytemp.email",
    "burnermail.io",
    "dropmail.me",
    "tempmailo.com",
    "emailondeck.com",
    "getnada.com",
    "nada.ltd",
    "binkmail.com",
    "bobmail.info",
    "chammy.info",
    "devnullmail.com",
    "meltmail.com",
    "spambox.us",
    "mailcatch.com",
    "mintemail.com",
    "fakemail.net",
    "mytrashmail.com",
}

# Dummy and placeholder domains/names
DUMMY_DOMAINS = {
    "test.com",
    "testing.com",
    "dummy.com",
    "fake.com",
    "invalid.com",
    "placeholder.com",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "temp.com",
    "foo.com",
    "bar.com",
    "asdf.com",
    "none.com",
    "null.com",
}

DUMMY_LOCAL_PARTS = {
    "test",
    "testing",
    "dummy",
    "fake",
    "asdf",
    "qwerty",
    "sample",
    "temp",
    "null",
    "undefined",
    "none",
    "user",
    "noone",
    "nobody",
    "testuser",
    "dummyuser",
    "placeholder",
    "random",
}


def is_dummy_or_disposable_email(email: str) -> tuple[bool, str]:
    """Check if the email matches disposable or dummy patterns."""
    clean = email.strip().lower()
    if "@" not in clean:
        return True, "Invalid email format: missing '@' separator."

    local_part, domain = clean.rsplit("@", 1)

    # 1. Check dummy local part
    if local_part in DUMMY_LOCAL_PARTS:
        return True, f"Dummy email address '{local_part}' is not permitted. Please provide a real email."

    # Repetitive character pattern in local part e.g. "aaaaaa", "111111"
    if len(local_part) >= 4 and len(set(local_part)) <= 1:
        return True, "Dummy or placeholder email patterns are not allowed."

    # 2. Check dummy domain
    if domain in DUMMY_DOMAINS:
        return True, f"Placeholder domain '@{domain}' is not allowed. Please use your genuine email domain."

    # 3. Check disposable / burner domain
    if domain in DISPOSABLE_DOMAINS or any(domain.endswith("." + d) for d in DISPOSABLE_DOMAINS):
        return True, "Temporary or disposable email addresses are blocked. Please provide a permanent email address."

    return False, ""


def check_domain_has_mail_server(domain: str, timeout: float = 2.5) -> bool:
    """Verify that the domain has valid DNS records capable of receiving mail (MX or A)."""
    clean_domain = domain.strip().lower()
    if not clean_domain or clean_domain == "localhost":
        return False

    if HAS_DNS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout

        # 1. Check MX records (primary for mail)
        try:
            mx_answers = resolver.resolve(clean_domain, "MX")
            if len(mx_answers) > 0:
                return True
        except Exception:
            pass

        # 2. Check A / AAAA fallback
        try:
            a_answers = resolver.resolve(clean_domain, "A")
            if len(a_answers) > 0:
                return True
        except Exception:
            pass

        try:
            aaaa_answers = resolver.resolve(clean_domain, "AAAA")
            if len(aaaa_answers) > 0:
                return True
        except Exception:
            pass

        return False

    else:
        # Fallback to socket getaddrinfo
        try:
            addrinfo = socket.getaddrinfo(clean_domain, 25, proto=socket.IPPROTO_TCP)
            return len(addrinfo) > 0
        except Exception:
            return False


def validate_legitimate_email(email_str: str) -> tuple[bool, str]:
    """Validate full legitimacy of a user email.

    Ensures:
    1. Valid RFC syntax
    2. Not a disposable/burner inbox
    3. Not a dummy/placeholder address
    4. Active domain with resolvable mail server
    """
    clean = email_str.strip().lower()
    if not clean:
        return False, "Email address cannot be empty."

    # 1. Syntax check
    try:
        validated = validate_email(clean, check_deliverability=False)
        normalized_email = validated.normalized
        domain = normalized_email.rsplit("@", 1)[-1]
    except EmailNotValidError as exc:
        return False, f"Invalid email format: {exc}"

    # 2. Dummy and disposable patterns check
    is_dummy, reason = is_dummy_or_disposable_email(normalized_email)
    if is_dummy:
        return False, reason

    # 3. DNS deliverability check
    if not check_domain_has_mail_server(domain):
        return False, f"Domain '@{domain}' does not exist or has no valid mail exchange (MX) DNS records."

    return True, "Email is legitimate and verified."
