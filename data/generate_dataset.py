"""
generate_dataset.py
────────────────────
Generates a synthetic phishing / legitimate URL dataset.
In production swap this with a real source (PhishTank, ISCX, UCI).
"""

import pandas as pd
import numpy as np
import random, string

random.seed(42)
np.random.seed(42)

# ── helpers ──────────────────────────────────────────────────────────────────
def rstr(n):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def rip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

# ── legitimate URL builder ────────────────────────────────────────────────────
LEGIT_DOMAINS = [
    "google.com","youtube.com","facebook.com","amazon.com","wikipedia.org",
    "twitter.com","instagram.com","linkedin.com","github.com","reddit.com",
    "microsoft.com","apple.com","netflix.com","spotify.com","stackoverflow.com",
    "bbc.co.uk","cnn.com","nytimes.com","medium.com","wordpress.com",
]
LEGIT_PATHS = [
    "/","/about","/contact","/login","/signup","/products","/services",
    "/blog/article","/news/today","/help/faq","/docs/api","/pricing",
]

def legit_url():
    sub = random.choice(["www","www","","mail","docs","support"])
    dom = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    prefix = f"{sub}." if sub else ""
    return f"https://{prefix}{dom}{path}"

# ── phishing URL builder ──────────────────────────────────────────────────────
PHISH_TACTICS = [
    lambda: f"http://{''.join(random.choice(['g00gle','paypa1','amaz0n','faceb00k','micros0ft']))}.{rstr(4)}.com/login",
    lambda: f"http://{rip()}/phishing/steal-data",
    lambda: f"http://{rstr(20)}.{random.choice(['secure','login','verify','account'])}.{rstr(5)}.com/login.php",
    lambda: f"http://{rstr(8)}.com/{random.choice(['paypal','amazon'])}-{rstr(3)}/verify",
    lambda: f"http://secure-{rstr(6)}-login.{rstr(5)}.tk/update-account",
    lambda: f"http://{random.choice(['paypal','amazon','ebay'])}.{rstr(6)}.xyz/login?redirect=true",
    lambda: f"http://{rstr(5)}.{random.choice(['cc','tk','ml','ga'])}/{rstr(8)}",
    lambda: f"https://login-{random.choice(['paypal','amazon','google'])}-verify.{rstr(6)}.com/secure",
]

def phish_url():
    return random.choice(PHISH_TACTICS)()

# ── build & save ──────────────────────────────────────────────────────────────
def generate_dataset(n=1500):
    rows = [(legit_url(), 0) for _ in range(n)] + [(phish_url(), 1) for _ in range(n)]
    df = pd.DataFrame(rows, columns=["url","label"]).sample(frac=1, random_state=42).reset_index(drop=True)
    return df

if __name__ == "__main__":
    df = generate_dataset()
    df.to_csv("phishing_dataset.csv", index=False)
    print(f"Saved {len(df)} rows.\n", df["label"].value_counts(), "\n", df.head())
