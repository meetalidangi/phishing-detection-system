"""
explain.py
───────────
Rule-based explanation engine.
Given extracted features for a URL, returns a human-readable list of
reasons why the URL looks phishing or legitimate.
"""

from features import extract_features


def explain_url(url: str) -> dict:
    """
    Returns:
        {
          "verdict"    : "Phishing" | "Legitimate",
          "risk_score" : 0-100,
          "reasons"    : [list of plain-English reason strings],
          "safe_signs" : [list of reassuring signs],
        }
    """
    feats = extract_features(url)
    reasons   = []   # suspicious signals
    safe      = []   # reassuring signals

    # ── HTTPS ────────────────────────────────────────────────────────────────
    if feats["is_https"]:
        safe.append("Uses HTTPS (encrypted connection)")
    else:
        reasons.append("Uses plain HTTP – no encryption")

    # ── IP address ───────────────────────────────────────────────────────────
    if feats["has_ip_address"]:
        reasons.append("Domain is a raw IP address – legitimate sites use domain names")

    # ── URL length ───────────────────────────────────────────────────────────
    if feats["url_length"] > 100:
        reasons.append(f"Very long URL ({feats['url_length']} chars) – phishing URLs are often excessively long")
    elif feats["url_length"] < 30:
        safe.append("Short, clean URL")

    # ── subdomains ───────────────────────────────────────────────────────────
    if feats["num_subdomains"] >= 4:
        reasons.append(f"Many subdomain levels ({feats['num_subdomains']}) – used to mimic legitimate sites")
    elif feats["num_subdomains"] <= 1:
        safe.append("Clean subdomain structure")

    # ── suspicious TLD ───────────────────────────────────────────────────────
    if feats["has_suspicious_tld"]:
        reasons.append("Uses a free / suspicious top-level domain (.tk, .ml, .xyz, etc.)")

    # ── brand in subdomain ───────────────────────────────────────────────────
    if feats["has_brand_in_subdomain"]:
        reasons.append("Brand name (PayPal, Amazon, etc.) appears in the subdomain – classic impersonation tactic")

    # ── hyphens ──────────────────────────────────────────────────────────────
    if feats["num_hyphens"] >= 4:
        reasons.append(f"Many hyphens ({feats['num_hyphens']}) in URL – often used to mimic real domains")

    # ── login keywords ───────────────────────────────────────────────────────
    if feats["has_login_keyword"]:
        reasons.append("Contains keywords like 'login', 'verify', 'secure', 'account' – common in phishing lures")

    # ── @ sign ───────────────────────────────────────────────────────────────
    if feats["num_at_signs"] > 0:
        reasons.append("'@' in URL – browser ignores everything before it, used to disguise true destination")

    # ── redirect param ───────────────────────────────────────────────────────
    if feats["has_redirect_param"]:
        reasons.append("Contains a redirect parameter – may send you to a malicious site after fake login")

    # ── hex encoding ─────────────────────────────────────────────────────────
    if feats["has_hex_encoding"]:
        reasons.append("URL contains percent-encoded characters – sometimes used to obfuscate malicious paths")

    # ── entropy ──────────────────────────────────────────────────────────────
    if feats["url_entropy"] > 4.5:
        reasons.append(f"High URL randomness (entropy {feats['url_entropy']:.2f}) – looks algorithmically generated")

    # ── PHP / EXE ────────────────────────────────────────────────────────────
    if feats["has_exe_or_php"]:
        reasons.append("URL ends in .php, .exe, .zip etc. – may deliver malware or fake login form")

    # ── dots ─────────────────────────────────────────────────────────────────
    if feats["num_dots"] > 5:
        reasons.append(f"Many dots ({feats['num_dots']}) – overly complex domain structure")

    # ── fallback safe signs ───────────────────────────────────────────────────
    if not reasons:
        safe.append("No suspicious patterns detected in URL structure")

    # ── simple rule-based risk score (0–100) ─────────────────────────────────
    # Each reason adds weight; capped at 100
    weights = {
        "has_ip_address"        : 30,
        "has_suspicious_tld"    : 20,
        "has_brand_in_subdomain": 20,
        "has_login_keyword"     : 10,
        "has_redirect_param"    : 10,
        "has_hex_encoding"      : 5,
        "has_exe_or_php"        : 15,
        "num_at_signs"          : 25,
    }
    score = 0
    for feat, w in weights.items():
        score += feats.get(feat, 0) * w
    if not feats["is_https"]:
        score += 15
    if feats["url_length"] > 100:
        score += 10
    if feats["num_subdomains"] >= 4:
        score += 10
    if feats["url_entropy"] > 4.5:
        score += 10
    score = min(score, 100)

    verdict = "Phishing" if score >= 40 or len(reasons) >= 2 else "Legitimate"

    return {
        "verdict"   : verdict,
        "risk_score": score,
        "reasons"   : reasons  or ["No suspicious signals found"],
        "safe_signs": safe     or ["Standard URL structure"],
    }


if __name__ == "__main__":
    tests = [
        "https://www.google.com/search?q=hello",
        "http://192.168.1.1/phishing/steal",
        "http://secure-paypal-login.xyz/account-verify?redirect=true",
    ]
    for url in tests:
        r = explain_url(url)
        print(f"\nURL : {url}")
        print(f"Verdict   : {r['verdict']}  |  Risk score: {r['risk_score']}")
        print("⚠  Reasons :", r["reasons"])
        print("✓  Safe    :", r["safe_signs"])
