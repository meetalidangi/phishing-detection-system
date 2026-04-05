"""
features.py
────────────
Extracts numerical features from a raw URL string.
These features are used by the ML model to classify URLs.
"""

import re
import math
from urllib.parse import urlparse


# ── character-level helpers ───────────────────────────────────────────────────

def entropy(s: str) -> float:
    """Shannon entropy – high entropy → random-looking string (bad sign)."""
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


# ── main feature extractor ────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Returns a dict of numeric features for one URL.
    All features are self-explanatory via their keys.
    """
    features = {}

    # ── raw URL stats ────────────────────────────────────────────────────────
    features["url_length"]          = len(url)
    features["num_dots"]            = url.count(".")
    features["num_hyphens"]         = url.count("-")
    features["num_underscores"]     = url.count("_")
    features["num_slashes"]         = url.count("/")
    features["num_question_marks"]  = url.count("?")
    features["num_equals"]          = url.count("=")
    features["num_at_signs"]        = url.count("@")     # @ in URL → suspicious
    features["num_ampersands"]      = url.count("&")
    features["num_hash"]            = url.count("#")
    features["num_digits"]          = sum(c.isdigit() for c in url)
    features["num_uppercase"]       = sum(c.isupper() for c in url)
    features["url_entropy"]         = round(entropy(url), 4)

    # ── scheme ───────────────────────────────────────────────────────────────
    features["is_https"]            = int(url.lower().startswith("https"))

    # ── parsed components ────────────────────────────────────────────────────
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://invalid")

    hostname  = parsed.hostname or ""
    path      = parsed.path     or ""
    query     = parsed.query    or ""
    netloc    = parsed.netloc   or ""

    # ── hostname features ────────────────────────────────────────────────────
    features["hostname_length"]     = len(hostname)
    features["hostname_entropy"]    = round(entropy(hostname), 4)
    features["num_subdomains"]      = hostname.count(".") if hostname else 0
    features["has_ip_address"]      = int(bool(
        re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname)
    ))  # bare IP → almost always phishing

    # common suspicious TLDs
    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"}
    features["has_suspicious_tld"]  = int(any(hostname.endswith(t) for t in suspicious_tlds))

    # brand keywords appearing in a suspicious domain
    brand_keywords = ["paypal","amazon","google","apple","microsoft","facebook",
                      "netflix","ebay","instagram","twitter","linkedin"]
    features["has_brand_in_subdomain"] = int(
        any(b in hostname.split(".")[0] for b in brand_keywords)
        if "." in hostname else 0
    )

    # ── path features ────────────────────────────────────────────────────────
    features["path_length"]         = len(path)
    features["path_depth"]          = path.count("/")
    features["has_login_keyword"]   = int(bool(
        re.search(r"(login|signin|verify|account|update|secure|banking|confirm)", url, re.I)
    ))
    features["has_exe_or_php"]      = int(bool(
        re.search(r"\.(exe|php|zip|rar|js)(\?|$)", path, re.I)
    ))

    # ── query features ───────────────────────────────────────────────────────
    features["query_length"]        = len(query)
    features["num_query_params"]    = query.count("&") + 1 if query else 0
    features["has_redirect_param"]  = int(bool(
        re.search(r"(redirect|url|next|return|goto)=", query, re.I)
    ))

    # ── lexical patterns ─────────────────────────────────────────────────────
    features["has_double_slash"]    = int("//" in path)
    features["has_hex_encoding"]    = int("%" in url)
    features["consecutive_digits"]  = len(re.findall(r"\d{4,}", url))  # e.g. IPs hidden in path

    return features


def features_to_list(url: str) -> list:
    """Returns ordered list of feature values (used for model prediction)."""
    return list(extract_features(url).values())


FEATURE_NAMES = list(extract_features("https://example.com").keys())


# ── quick sanity check ────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=hello",
        "http://192.168.1.1/phishing/steal-data",
        "http://secure-paypal-login.xyz/update-account?redirect=true",
    ]
    for u in test_urls:
        feats = extract_features(u)
        print(f"\nURL: {u}")
        for k, v in feats.items():
            print(f"  {k:30s} = {v}")
