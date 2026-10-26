"""Build a labeled training set from public-style phishing patterns.

The generator uses the same feature extractor as production so the model
stays aligned with live inference. Mix of legitimate brands and phishing
lookalikes is typical of academic phishing-URL datasets (UCI / PhiUSIIL style).
"""

from __future__ import annotations

import random

LEGIT_URLS = [
    "https://www.google.com/search?q=news",
    "https://github.com/microsoft/vscode",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://www.amazon.com/gp/bestsellers",
    "https://www.nytimes.com/section/technology",
    "https://login.microsoftonline.com/",
    "https://accounts.google.com/signin",
    "https://www.paypal.com/us/home",
    "https://www.apple.com/icloud/",
    "https://www.bankofamerica.com/",
    "https://stackoverflow.com/questions",
    "https://www.linkedin.com/feed/",
    "https://www.netflix.com/browse",
    "https://outlook.live.com/mail/",
    "https://www.cloudflare.com/",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.mozilla.org/en-US/firefox/",
    "https://www.irs.gov/",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.reddit.com/r/cybersecurity/",
    "https://www.microsoft.com/en-us/",
    "https://www.meta.com/",
    "https://www.facebook.com/",
]

PHISH_URLS = [
    "http://192.168.4.22/login/verify-account",
    "http://paypal-secure-login.tk/webscr?cmd=_login",
    "https://appleid.apple.com.confirm-account.xyz/unlock",
    "http://bit.ly/reset-bank-password",
    "http://secure-update.microsoft-verify.gq/signin",
    "https://login.bankofamerica.com.secure-auth.icu/account",
    "http://confirm-paypal-identity.click/webscr",
    "http://user:pass@evil.example/paypal.com/login",
    "http://tinyurl.com/urgent-wallet-unlock",
    "https://accounts.google.com.security-check.ml/signin",
    "http://185.22.11.9:8080/update/password",
    "https://www.paypa1.com/cgi-bin/webscr?cmd=_login-submit",
    "http://verify-your-account.top/login?redirect=http://evil.test",
    "https://secure.amazon.account-hold.xyz/ap/signin",
    "http://ebayisapi.login-update.cf/ws/eBayISAPI.dll",
    "https://icloud.com-unlock-id.club/appleid/verify",
    "http://www.paypal.com.session-expired.ga/login",
    "https://office365-login-secure.country/owa",
    "http://confirm.your.bank.login.now.icu/urgent",
    "https://netflix-billing-update.xyz/account?next=http://phish.test",
    "https://login-outlook365.yzz.me/account",
    "https://fb-meta-verified-14259.vercel.app/login",
    "https://auth-google-security.pages.dev/signin",
    "https://microsoft-support-portal.firebaseapp.com/update",
]

LEGIT_EMAILS = [
    "Your package from Amazon is out for delivery. Track it at https://www.amazon.com/progress-tracker/package.",
    "GitHub: a new SSH key was added to your account. Review at https://github.com/settings/keys if this was not you.",
    "Coursera weekly digest: continue Machine Learning. Visit https://www.coursera.org.",
    "Your Netflix bill of $15.49 will be charged to the card on file. Manage billing at https://www.netflix.com/account.",
    "Microsoft 365: here is your monthly usage summary. No action required.",
    "Wikipedia donation reminder: if you can, support independent knowledge at https://donate.wikimedia.org.",
    "LinkedIn: Ali viewed your profile. See more at https://www.linkedin.com.",
    "Your IRS online account statement is available at https://www.irs.gov. We will never ask for your password by email.",
]

PHISH_EMAILS = [
    "URGENT: Your PayPal account will be suspended in 24 hours. Verify your password now at http://paypal-secure-login.tk/webscr.",
    "We detected unauthorized access. Confirm your identity and enter your OTP at http://192.168.4.22/login/verify-account.",
    "Apple ID locked. Unlock immediately: https://appleid.apple.com.confirm-account.xyz/unlock",
    "Your bank account is limited. Click here to reset your password: http://bit.ly/reset-bank-password",
    "Invoice attached. Update billing details and credit card CVV at http://secure-update.microsoft-verify.gq/signin",
    "<form action='http://evil.test'><input type='password'> Submit to keep your Microsoft account.</form>",
    "Act now! Your mailbox quota is full. Sign in at https://login.microsoftonline.com.secure-auth.icu/account",
    "Amazon: unusual sign-in. Confirm your password and SSN at https://secure.amazon.account-hold.xyz/ap/signin",
]


def _mutate_url(url: str, phishing: bool, rng: random.Random) -> str:
    if not phishing:
        extras = ["", "?ref=home", "/about", "/help", "/pricing"]
        return url.rstrip("/") + rng.choice(extras)
    tokens = ["login", "verify", "secure", "update", "account", str(rng.randint(10, 99))]
    glue = rng.choice(["-", ".", ""])
    extra = glue.join(rng.sample(tokens, k=2))
    if "?" in url:
        return url + "&session=" + extra
    return url + "/" + extra


def build_raw_samples(n: int = 1600, seed: int = 42) -> list[tuple[str, str, int]]:
    rng = random.Random(seed)
    rows: list[tuple[str, str, int]] = []
    while len(rows) < n:
        if rng.random() < 0.55:
            if rng.random() < 0.8:
                url = _mutate_url(rng.choice(PHISH_URLS), True, rng)
                # A few phishing pages use HTTPS and shorter paths (harder cases).
                if rng.random() < 0.12:
                    url = url.replace("http://", "https://", 1)
                rows.append(("url", url, 1))
            else:
                rows.append(("email", rng.choice(PHISH_EMAILS), 1))
        else:
            if rng.random() < 0.8:
                url = _mutate_url(rng.choice(LEGIT_URLS), False, rng)
                if rng.random() < 0.1:
                    url += "/account/login"
                rows.append(("url", url, 0))
            else:
                rows.append(("email", rng.choice(LEGIT_EMAILS), 0))
    return rows
