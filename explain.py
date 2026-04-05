"""
explain.py
───────────
Improved rule-based explanation engine for phishing detection.
"""

from features import extract_features


def explain_url(url: str) -> dict:
    feats = extract_features(url)

    reasons = []   # suspicious signals
    safe    = []   # safe signals
    score   = 0

    # ── HTTPS ─────────────────────────────
    if feats["is_https"]:
        safe.append("Uses HTTPS (secure connection)")
    else:
        reasons.append("Uses HTTP (not secure)")
        score += 15

    # ── IP address ────────────────────────
    if feats["has_ip_address"]:
        reasons.append("Uses IP address instead of domain")
        score += 30

    # ── URL length ────────────────────────
    if feats["url_length"] > 80:
        reasons.append(f"Long URL ({feats['url_length']} chars)")
        score += 10
    elif feats["url_length"] < 30:
        safe.append("Short and clean URL")

    # ── subdomains ────────────────────────
    if feats["num_subdomains"] >= 3:
        reasons.append(f"Multiple subdomains ({feats['num_subdomains']})")
        score += 10
    elif feats["num_subdomains"] <= 1:
        safe.append("Simple domain structure")

    # ── suspicious TLD ────────────────────
    if feats["has_suspicious_tld"]:
        reasons.append("Suspicious top-level domain (.xyz, .tk, etc.)")
        score += 20

    # ── brand impersonation ───────────────
    if feats["has_brand_in_subdomain"]:
        reasons.append("Brand name used in subdomain (possible impersonation)")
        score += 20

    # ── hyphens ───────────────────────────
    if feats["num_hyphens"] >= 2:
        reasons.append(f"Multiple hyphens in URL ({feats['num_hyphens']})")
        score += 10

    # ── login keywords ────────────────────
    if feats["has_login_keyword"]:
        reasons.append("Contains login/verify keywords")
        score += 15

    # ── @ symbol ──────────────────────────
    if feats["num_at_signs"] > 0:
        reasons.append("Contains '@' symbol (URL masking trick)")
        score += 25

    # ── redirect parameter ────────────────
    if feats["has_redirect_param"]:
        reasons.append("Contains redirect parameter")
        score += 10

    # ── encoding ──────────────────────────
    if feats["has_hex_encoding"]:
        reasons.append("Encoded characters in URL")
        score += 5

    # ── suspicious file types ─────────────
    if feats["has_exe_or_php"]:
        reasons.append("Suspicious file extension (.php/.exe)")
        score += 15

    # ── dots complexity ───────────────────
    if feats["num_dots"] > 3:
        reasons.append(f"Too many dots ({feats['num_dots']})")
        score += 10

    # ── entropy (randomness) ──────────────
    if feats["url_entropy"] > 4.0:
        reasons.append(f"High randomness (entropy {feats['url_entropy']:.2f})")
        score += 10

    # ── fallback safe signal ──────────────
    if not reasons:
        safe.append("No suspicious patterns detected")

    # ── final score & verdict ─────────────
    score = min(score, 100)

    if score >= 50:
        verdict = "Phishing"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons or ["No suspicious signals found"],
        "safe_signs": safe or ["Standard URL structure"],
    }


# ── testing ─────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://secure-paypal-login.xyz/account",
        "http://192.168.1.1/login",
        "https://phishing-detection-system-a6qe.onrender.com"
    ]

    for url in test_urls:
        result = explain_url(url)
        print(f"\nURL: {url}")
        print(f"Verdict: {result['verdict']} | Score: {result['risk_score']}")
        print("Reasons:", result["reasons"])
        print("Safe:", result["safe_signs"])