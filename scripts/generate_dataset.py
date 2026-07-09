"""Generate a labeled training dataset for the ML false-positive triage model.

Writes datasets/train.csv with one row per (technique, confidence, payload) sample,
featurized with the SAME `finding_features()` the live scanner uses — so training and
inference never drift.

Two label classes:
  1 = genuine SQL-injection signal   (real payloads that indicate injectability)
  0 = benign / likely false positive (normal user input that a naive scanner may over-flag)

This is a seed generator so the pipeline runs at $0 today. To make it stronger, append
rows you collect by running the engine against DVWA/Juice Shop (real proven/unproven
outcomes) and re-train — that self-generated data is the project's differentiator.

Usage:  python scripts/generate_dataset.py
"""

from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlintel.ml.features import finding_features  # noqa: E402

TECHNIQUES = ["error-based", "boolean-based", "time-based"]

# --- Malicious payloads (label 1) --------------------------------------------
MALICIOUS = [
    "'", "''''", "' OR '1'='1", "' OR 1=1-- -", "') OR ('1'='1",
    "\" OR \"\"=\"", "' OR 'x'='x", "admin'-- -", "' UNION SELECT NULL-- -",
    "' UNION SELECT username,password FROM users-- -",
    "1' AND 1=1-- -", "1' AND 1=2-- -", "' AND SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'-- -", "' AND pg_sleep(5)-- -",
    "1 AND 1=1", "1 AND 1=2", "' AND '1'='1", "' AND '1'='2",
    "') AND 1=1-- -", "%27%20OR%201=1", "' OR SLEEP(5)#",
    "1)) OR SLEEP(5)#", "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -",
    "' OR EXISTS(SELECT * FROM users)-- -", "'||'", "' AND ORD(MID(version(),1,1))>51-- -",
    "1' ORDER BY 3-- -", "-1' UNION SELECT 1,2,3-- -", "' OR 1=1 LIMIT 1-- -",
]

# --- Benign inputs (label 0) --------------------------------------------------
BENIGN = [
    "1", "42", "book", "blue widget", "search term", "O'Brien", "d'Angelo",
    "user@example.com", "John Smith", "2024-01-01", "hello world", "product-123",
    "New York", "café", "it's fine", "size: large", "price under 100",
    "normal input", "category=shoes", "true", "false", "null", "N/A",
    "3.14159", "customer#5", "order_id_9981", "red", "green", "a quick brown fox",
    "don't panic", "l'hôtel", "50% off",
]


def rows():
    # Malicious: rotate through techniques; give a plausible detector confidence.
    for i, payload in enumerate(MALICIOUS):
        tech = TECHNIQUES[i % len(TECHNIQUES)]
        conf = 0.85 if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() else 0.8
        yield {**finding_features(tech, conf, payload), "label": 1}
    # Benign: lower confidence, spread across techniques.
    for i, payload in enumerate(BENIGN):
        tech = TECHNIQUES[i % len(TECHNIQUES)]
        yield {**finding_features(tech, 0.55, payload), "label": 0}


def main() -> None:
    out_dir = os.path.join(os.path.dirname(__file__), "..", "datasets")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "train.csv")

    data = list(rows())
    # Column order comes from finding_features (stable) + label last.
    fieldnames = list(data[0].keys())

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    pos = sum(r["label"] for r in data)
    print(f"Wrote {len(data)} rows ({pos} malicious / {len(data) - pos} benign) -> {out_path}")


if __name__ == "__main__":
    main()
