"""ML false-positive triage.

Loads a trained classifier (models/sqli_clf.joblib) if present and uses it to refine
a Finding's confidence. If no model is trained yet, this is a no-op — so the tool is
fully functional before the ML phase, and gets smarter once you train the model in
notebooks/train_classifier.ipynb.

Design rule: the model only *adjusts confidence*. It never flips a detected finding to
"not vulnerable" or invents one. Deterministic detection stays the source of truth.
"""

from __future__ import annotations

import os
from typing import Optional

from ..core.target import Finding
from .features import finding_features

_MODEL_PATH = os.environ.get("SQLINTEL_MODEL", os.path.join("models", "sqli_clf.joblib"))
_model = None
_load_attempted = False


def _load_model():
    global _model, _load_attempted
    if _load_attempted:
        return _model
    _load_attempted = True
    if not os.path.exists(_MODEL_PATH):
        return None
    try:
        import joblib  # optional dependency (sqlintel[ml])

        _model = joblib.load(_MODEL_PATH)
    except Exception:
        _model = None
    return _model


def triage_finding(finding: Finding) -> Finding:
    """Adjust `finding.confidence` in place using the trained model, if available."""
    model = _load_model()
    if model is None:
        return finding  # graceful no-op until a model exists

    feats = finding_features(finding.technique, finding.confidence, finding.payload)
    try:
        # Expect a scikit-learn-style classifier exposing predict_proba.
        import pandas as pd

        proba = model.predict_proba(pd.DataFrame([feats]))[0][1]
        # Blend model probability with deterministic confidence (average).
        finding.confidence = round((finding.confidence + float(proba)) / 2, 3)
    except Exception:
        pass
    return finding
