from app.heuristics import analyze, extract_urls


def codes(text):
    return {s["code"] for s in analyze(text)["signals"]}


def test_phishing_message_is_flagged():
    r = analyze("URGENT: your telebirr account is suspended. Verify now at http://telebirr-verify.top/login")
    assert r["verdict"] == "likely_scam"
    assert {"urgency", "risky_tld", "lookalike"} <= {s["code"] for s in r["signals"]}


def test_normal_message_scores_zero():
    r = analyze("Hey, are we still meeting for lunch tomorrow at 1?")
    assert r["score"] == 0 and r["verdict"] == "looks_ok"


def test_pin_does_not_match_inside_other_words():
    assert "credentials" not in codes("I love shopping and spinning classes")


def test_pin_as_a_word_is_flagged():
    assert "credentials" in codes("Please send me your PIN")


def test_shortener_ip_and_prize():
    assert {"ip_url", "shortener", "money"} <= codes("claim your prize http://192.168.4.4/x or https://bit.ly/abc")


def test_brand_in_subdomain_is_flagged():
    assert "lookalike" in codes("Log in at https://paypal.verify-account.com")


def test_real_brand_domain_is_not_flagged():
    assert "lookalike" not in codes("Open https://www.paypal.com")


def test_extract_urls():
    assert "https://example.com/a" in extract_urls("see https://example.com/a now")