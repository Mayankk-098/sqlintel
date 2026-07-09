"""Train the SQLintel false-positive triage classifier and export it.

Reads datasets/train.csv, trains XGBoost (falls back to RandomForest), reports metrics,
and writes models/sqli_clf.joblib — which sqlintel/ml/triage.py auto-loads at scan time.

Runs free and local (or on Colab/Kaggle). No GPU needed for this baseline.

Usage:
    python scripts/generate_dataset.py    # produce datasets/train.csv first
    python scripts/train_model.py
"""

from __future__ import annotations

import os
import sys

import joblib
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_predict

HERE = os.path.dirname(__file__)
DATA = os.path.join(HERE, "..", "datasets", "train.csv")
MODEL_DIR = os.path.join(HERE, "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "sqli_clf.joblib")


def build_model():
    """XGBoost if installed, else RandomForest. Both expose predict_proba."""
    try:
        from xgboost import XGBClassifier

        return XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.1, eval_metric="logloss"
        )
    except Exception:
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(n_estimators=300, random_state=0)


def main() -> None:
    if not os.path.exists(DATA):
        sys.exit(f"Missing {DATA}. Run: python scripts/generate_dataset.py")

    df = pd.read_csv(DATA).fillna(0.0)
    X = df.drop(columns=["label"])
    y = df["label"]

    model = build_model()

    # Honest estimate on a tiny seed set: cross-validated predictions.
    try:
        preds = cross_val_predict(model, X, y, cv=min(5, y.value_counts().min()))
        print("Cross-validated performance:\n")
        print(classification_report(y, preds, digits=3))
    except Exception as exc:  # tiny/imbalanced data may not support CV
        print(f"(Skipped cross-val: {exc})")

    # Fit on all data for the shipped model.
    model.fit(X, y)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nSaved model -> {os.path.normpath(MODEL_PATH)}")
    print("triage.py will now blend model probability into finding confidence.")


if __name__ == "__main__":
    main()
