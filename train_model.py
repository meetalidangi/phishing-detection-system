"""
train_model.py
───────────────
1. Loads (or generates) the phishing dataset
2. Extracts URL features
3. Trains a Random Forest classifier
4. Evaluates accuracy / precision / recall / F1
5. Saves the model + feature names to model/phishing_model.pkl
"""

import os, sys, pickle
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

# ── ensure we can import our own modules ─────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from features import extract_features, FEATURE_NAMES

# ── paths ─────────────────────────────────────────────────────────────────────
DATA_PATH  = os.path.join(os.path.dirname(__file__), "data", "phishing_dataset.csv")
MODEL_DIR  = os.path.join(os.path.dirname(__file__), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Load dataset (auto-generate if missing)
# ─────────────────────────────────────────────────────────────────────────────
def load_data():
    if not os.path.exists(DATA_PATH):
        print("Dataset not found – generating synthetic data …")
        # import the generator from the data folder
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "generate_dataset",
            os.path.join(os.path.dirname(__file__), "data", "generate_dataset.py")
        )
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        df = gen.generate_dataset()
        df.to_csv(DATA_PATH, index=False)
    else:
        df = pd.read_csv(DATA_PATH)

    print(f"Loaded {len(df)} rows | label counts:\n{df['label'].value_counts().to_string()}\n")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# 2. Feature extraction
# ─────────────────────────────────────────────────────────────────────────────
def build_feature_matrix(df: pd.DataFrame):
    print("Extracting features …")
    rows = []
    for url in df["url"]:
        rows.append(list(extract_features(str(url)).values()))
    X = np.array(rows, dtype=float)
    y = df["label"].values
    print(f"Feature matrix: {X.shape}  (samples × features)\n")
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# 3. Train / evaluate
# ─────────────────────────────────────────────────────────────────────────────
def train_and_evaluate(X, y):
    # 80 / 20 split, stratified so both classes are balanced in train + test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} samples | Test: {len(X_test)} samples\n")

    # ── Random Forest ────────────────────────────────────────────────────────
    model = RandomForestClassifier(
        n_estimators=200,       # 200 trees
        max_depth=None,         # grow full trees
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,              # use all CPU cores
    )
    model.fit(X_train, y_train)

    # ── evaluation ───────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)

    print("=" * 50)
    print(f"  Accuracy  : {acc  * 100:.2f}%")
    print(f"  Precision : {prec * 100:.2f}%")
    print(f"  Recall    : {rec  * 100:.2f}%")
    print(f"  F1 Score  : {f1   * 100:.2f}%")
    print("=" * 50)
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}\n")

    # ── feature importance ───────────────────────────────────────────────────
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("Top 10 most important features:")
    for name, imp in importances[:10]:
        bar = "█" * int(imp * 200)
        print(f"  {name:35s} {imp:.4f}  {bar}")

    return model


# ─────────────────────────────────────────────────────────────────────────────
# 4. Save model
# ─────────────────────────────────────────────────────────────────────────────
def save_model(model):
    payload = {
        "model": model,
        "feature_names": FEATURE_NAMES,
    }
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(payload, f)
    print(f"\nModel saved → {MODEL_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    df            = load_data()
    X, y          = build_feature_matrix(df)
    model         = train_and_evaluate(X, y)
    save_model(model)
    print("\nTraining complete. Run `python app.py` to start the web server.")
