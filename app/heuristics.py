import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-z0-9-]+\.(?:com|net|org|info|xyz|top|click|link|icu|et)\b[^\s]*",
    re.I,
)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
RISKY_TLDS = {"xyz", "top", "click", "link", "icu", "info", "zip", "work", "support"}

# Brands scammers like to imitate. Add local banks and telecoms you care about.
BRANDS = ["telebirr", "ethiotelecom", "safaricom", "mpesa", "cbe", "dashenbank", "awashbank",
          "paypal", "amazon", "apple", "google", "microsoft", "netflix", "dhl", "fedex",
          "whatsapp", "facebook"]

URGENCY = ["urgent", "immediately", "within 24 hours", "act now", "last warning",
           "suspended", "blocked", "expire", "verify now", "final notice", "locked"]

MONEY = ["send money", "transfer", "processing fee", "claim your prize", "you have won",
         "winner", "gift card", "bitcoin", "refund", "pay a fee", "deposit"]

CREDENTIALS = ["password", "pin", "otp", "one-time code", "verification code",
               "cvv", "login", "account number"]


def extract_urls(text: str) -> list[str]:
    """Return unique links found in the text, in order."""
    found = (m.group(0).rstrip(".,);") for m in URL_RE.finditer(text))
    return list(dict.fromkeys(found))


def get_host(url: str) -> str:
    """'http://Telebirr-Verify.top/login' -> 'telebirr-verify.top'"""
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def find_words(words: list[str], text: str) -> list[str]:
    """Whole-word match, so 'pin' no longer matches inside 'shopping'."""
    t = text.lower()
    return [w for w in words if re.search(r"\b" + re.escape(w) + r"\b", t)]


def find_lookalike(host: str) -> str | None:
    """Return the brand a domain seems to imitate, or None."""
    labels = host.split(".")
    if len(labels) < 2:
        return None
    # 'te1ebirr-verify' -> 'telebirrverify' (undo common character swaps)
    core = labels[-2].replace("-", "").replace("0", "o").replace("1", "l")
    if core in BRANDS:
        return None  # the main domain is the brand itself
    for b in BRANDS:
        if len(b) >= 5 and b in core:
            return b  # e.g. telebirrverify
        if SequenceMatcher(None, core, b).ratio() >= 0.82:
            return b  # e.g. telebirr -> telebrr
    # Brand hidden in a subdomain: paypal.verify-account.com
    for label in labels[:-2]:
        for b in BRANDS:
            if len(b) >= 5 and b in label:
                return b
    return None


def analyze(text: str) -> dict:
    signals = []
    urls = extract_urls(text)

    for url in urls:
        host = get_host(url)
        if not host:
            continue

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            signals.append({"code": "ip_url", "label": f"Link uses a raw IP address: {host}", "weight": 30})

        if host in SHORTENERS:
            signals.append({"code": "shortener", "label": f"Shortened link hides the real destination: {host}", "weight": 20})

        if "xn--" in host:
            signals.append({"code": "punycode", "label": f"Domain uses look-alike characters: {host}", "weight": 35})

        tld = host.split(".")[-1]
        if tld in RISKY_TLDS:
            signals.append({"code": "risky_tld", "label": f"Domain ending .{tld} is common in scams: {host}", "weight": 15})

        if host.count("-") >= 2:
            signals.append({"code": "hyphens", "label": f"Domain has many hyphens: {host}", "weight": 10})

        brand = find_lookalike(host)
        if brand:
            signals.append({"code": "lookalike", "label": f"Domain imitates '{brand}' but is not the official site: {host}", "weight": 40})

        if url.lower().startswith("http://"):
            signals.append({"code": "no_https", "label": f"Link is not encrypted (http): {host}", "weight": 8})

    hits = find_words(URGENCY, text)
    if hits:
        signals.append({"code": "urgency", "label": f"Pressure or fake urgency: {', '.join(hits[:3])}", "weight": 18})

    hits = find_words(MONEY, text)
    if hits:
        signals.append({"code": "money", "label": f"Asks for money or promises a reward: {', '.join(hits[:3])}", "weight": 22})

    hits = find_words(CREDENTIALS, text)
    if hits:
        signals.append({"code": "credentials", "label": f"Asks for a password, PIN or code: {', '.join(hits[:3])}", "weight": 30})

    risky = {"urgency", "money", "credentials"}
    if urls and any(s["code"] in risky for s in signals):
        signals.append({"code": "combo", "label": "Link combined with pressure or a request for money or codes", "weight": 15})

    score = min(100, sum(s["weight"] for s in signals))
    verdict = "likely_scam" if score >= 55 else "suspicious" if score >= 25 else "looks_ok"
    return {"score": score, "verdict": verdict, "urls": urls, "signals": signals}