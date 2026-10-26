from app.services.feature_extractor import extract_features


def explain(input_type: str, content: str, verdict: str, features: dict | None = None) -> list[str]:
    feats = features or extract_features(input_type, content)
    notes: list[str] = []

    if feats.get("has_https") == 0 and input_type == "url":
        notes.append("Connection is not HTTPS, which is uncommon for legitimate login or payment pages.")
    if feats.get("has_ip"):
        notes.append("The host is a raw IP address instead of a branded domain name.")
    if feats.get("uses_shortener"):
        notes.append("A URL shortener hides the real destination, a common phishing tactic.")
    if feats.get("risky_tld"):
        notes.append("The domain uses a TLD frequently abused in throwaway phishing campaigns.")
    if feats.get("has_at_symbol"):
        notes.append("An '@' in the URL can trick browsers into treating the left side as a fake user.")
    if feats.get("double_slash_redirect") or feats.get("has_embedded_url"):
        notes.append("The path or query embeds another URL, which is often used for redirects.")
    if feats.get("subdomain_count", 0) >= 3:
        notes.append("Excessive subdomains can impersonate a trusted brand (for example login.bank.example.evil.tld).")
    if feats.get("url_length", 0) > 75 and input_type == "url":
        notes.append("The URL is unusually long, which can hide malicious parameters.")
    if feats.get("keyword_hits", 0) >= 2:
        notes.append("The text contains multiple account-security keywords (login, verify, password, etc.).")
    if feats.get("email_urgency_hits", 0) >= 2:
        notes.append("The email uses urgency language to pressure the recipient into clicking.")
    if feats.get("email_credential_ask"):
        notes.append("The message asks for credentials or financial details.")
    if feats.get("email_html_form"):
        notes.append("An HTML form was detected inside the email body.")
    if feats.get("has_port"):
        notes.append("A non-standard port is present, which is rare for consumer websites.")
    if feats.get("digit_ratio", 0) > 0.25 and input_type == "url":
        notes.append("A high ratio of digits in the URL is typical of generated phishing hosts.")

    if verdict == "legitimate" and not notes:
        notes.append("No high-risk structural indicators were found. Still verify the domain before entering credentials.")
    elif verdict == "legitimate":
        notes.append("Overall risk is low, but review the notes above before trusting the source.")
    elif not notes:
        notes.append("The model classified this as phishing from a combination of lexical and structural signals.")

    return notes[:6]
