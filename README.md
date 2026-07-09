# SQLintel

**AI-augmented SQL injection vulnerability scanner.** A deterministic detection engine
(boolean / error / time-based) that reliably finds and *proves* SQLi, with a trained ML
layer to cut false positives — plus a roadmap for browser-based SPA/API crawling that
traditional scanners miss.

> ⚠️ **Legal use only.** Scan only systems you own or have **written authorization** to test.
> The bundled `docker-compose.yml` spins up intentionally vulnerable practice apps (DVWA,
> OWASP Juice Shop) so you can develop and benchmark legally. Unauthorized scanning is a crime.

---

## Why another scanner?

Every existing tool has the same gaps (see the design notes in `docs/`):

- **sqlmap / Ghauri** — powerful but noisy, give up early on edge cases, and are blind to
  modern JS/SPA/API targets.
- **Commercial scanners** — low false positives via *proof-based* scanning, but closed and expensive.
- **AI research tools** — great reasoning, but a "capability gap": they identify a bug then fail to execute it.

SQLintel's thesis: **a reliable deterministic engine does the execution and proof; a trained ML
model advises (false-positive triage, injectability ranking). The model never decides alone.**

## Architecture

```
Crawler (Playwright, planned) ─▶ Detection Engine ─▶ Proof Verifier ─▶ Report (console/JSON/SARIF)
                                      │  ▲
                                      ▼  │
                                  ML layer (advises: FP triage, ranking)
```

## Status

| Phase | What | State |
|-------|------|-------|
| 1 | Deterministic engine (boolean + error + time-based), CLI, `-r`/URL input, JSON report | ✅ done |
| 2 | Proof-based verification (independent re-confirmation) + SARIF output | ✅ done |
| 3 | Playwright SPA/API crawler | 🔜 |
| 4 | Trained ML classifier (XGBoost baseline → DistilBERT) wired into triage | ✅ baseline done |
| 5 | Benchmark vs sqlmap & Ghauri on DVWA/Juice Shop | 🔜 |

## Quick start

```bash
# 1. Install (core is dependency-light)
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

# 2. Start a legal test target
docker compose up -d          # DVWA on :8080, Juice Shop on :3000

# 3. Scan a single parameter
sqlintel -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" -p id --batch

# ...or replay a saved request (like sqlmap's -r)
sqlintel -r request.txt --batch

# JSON + SARIF report for CI/CD (SARIF uploads to GitHub code scanning)
sqlintel -u "http://target/item?id=1" -p id --json reports/scan.json --sarif reports/scan.sarif

# Skip proof-based re-confirmation (faster, noisier)
sqlintel -u "http://target/item?id=1" -p id --no-verify
```

## Proof-based verification

Every finding is re-confirmed a second, independent way before it's marked `proven`
(severity → `critical`) — the open-source take on commercial "proof-based scanning":

- **error-based**: an unbalanced quote must raise a DB error *and* a balanced (`''`) one must not.
- **boolean-based**: an *orthogonal* TRUE/FALSE payload pair must reproduce the same divergence.
- **time-based**: the detector already double-confirms against a 0-second control.

## Train the ML triage model (free, local)

```bash
pip install -e ".[ml]"
python scripts/generate_dataset.py   # -> datasets/train.csv (seed data; extend with your own)
python scripts/train_model.py        # -> models/sqli_clf.joblib
```

Once `models/sqli_clf.joblib` exists, `sqlintel/ml/triage.py` auto-loads it and blends the
model's probability into each finding's confidence. Until then, triage is a graceful no-op.

> ⚠️ The bundled seed dataset is tiny (~60 rows) and scores ~1.0 — that's **overfitting**, not a
> real metric. The honest numbers come from Phase 5: collect labeled traffic by running the engine
> against DVWA/Juice Shop, retrain, and report precision/recall/FP-rate vs sqlmap & Ghauri.

## Roadmap for the ML component

`notebooks/train_classifier.ipynb` is a free (Colab/Kaggle) starter that:
1. loads labeled request/response samples (public sets + traffic you generate with this engine),
2. trains a TF-IDF + XGBoost baseline classifier, then
3. exports `models/sqli_clf.joblib`, which `sqlintel/ml/` loads to triage findings.

Everything in this project runs at **$0**: local Python, free Colab GPU, Dockerized targets.

## License

MIT — see `LICENSE`.
