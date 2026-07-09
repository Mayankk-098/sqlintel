"""Feature extraction for the ML false-positive triage model.

This is the bridge between the deterministic engine and the trained classifier.
The SAME function is used in two places, which is what keeps training and inference
consistent:
  * offline (notebooks/train_classifier.ipynb) to build the training matrix, and
  * online (sqlintel.ml.triage) to score a live Finding.

For the v1 baseline we emit a flat dict of interpretable features; a TF-IDF/XGBoost
model consumes these plus the raw payload string. Later phases can swap in
transformer embeddings without changing callers.
"""

from __future__ import annotations

from typing import Dict

# Tokens that, when reflected in a response, correlate with genuine SQLi.
_SQL_TOKENS = ["select", "union", "sleep", "and", "or", "'", '"', "--", "=", ")"]


def payload_features(payload: str) -> Dict[str, float]:
    """Cheap, interpretable features derived from a payload string."""
    p = payload.lower()
    feats: Dict[str, float] = {
        "len": float(len(payload)),
        "n_quotes": float(payload.count("'") + payload.count('"')),
        "n_spaces": float(payload.count(" ")),
        "has_comment": 1.0 if "--" in payload or "#" in payload else 0.0,
    }
    for tok in _SQL_TOKENS:
        feats[f"tok_{tok}"] = float(p.count(tok))
    return feats


def finding_features(technique: str, confidence: float, payload: str) -> Dict[str, float]:
    """Full feature vector for a Finding, used by the triage classifier."""
    feats = payload_features(payload)
    feats["det_confidence"] = float(confidence)
    # One-hot the technique that fired.
    for t in ("error-based", "boolean-based", "time-based"):
        feats[f"tech_{t}"] = 1.0 if technique == t else 0.0
    return feats
