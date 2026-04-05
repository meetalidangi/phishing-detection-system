"""
app.py  –  Flask backend for the Phishing Detection System
──────────────────────────────────────────────────────────
Routes:
  GET  /          → serves index.html
  POST /predict   → accepts { "url": "..." } → returns prediction + explanation
  GET  /health    → model status (debugging)
"""

import os, sys, pickle
import numpy as np
from flask import Flask, request, jsonify, render_template

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from features import extract_features
from explain  import explain_url

app = Flask(__name__, template_folder="templates", static_folder="static")

MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
model, feature_names = None, None

def load_model():
    global model, feature_names
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Run `python train_model.py` first.")
        return False
    with open(MODEL_PATH, "rb") as f:
        payload = pickle.load(f)
    model         = payload["model"]
    feature_names = payload["feature_names"]
    print(f"Model loaded from {MODEL_PATH}")
    return True

model_ready = load_model()

# ─── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field."}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if not model_ready or model is None:
        return jsonify({"error": "Model not loaded. Run train_model.py first."}), 503

    try:
        feat_dict  = extract_features(url)
        X          = np.array([list(feat_dict.values())], dtype=float)
        pred       = model.predict(X)[0]
        proba      = model.predict_proba(X)[0]
        legit_prob = round(float(proba[0]), 4)
        phish_prob = round(float(proba[1]), 4)
        confidence = round(float(max(proba)), 4)
        label      = "Phishing" if pred == 1 else "Legitimate"
        explanation = explain_url(url)

        return jsonify({
            "url"        : url,
            "label"      : label,
            "confidence" : confidence,
            "phish_prob" : phish_prob,
            "legit_prob" : legit_prob,
            "explanation": explanation,
            "error"      : None,
        })
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model_loaded": model_ready})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
