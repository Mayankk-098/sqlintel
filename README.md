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
| 1 | Deterministic engine (boolean + error + time-based), CLI, `-r`/URL input, JSON report | ✅ this scaffold |
| 2 | Proof-based verification + SARIF output | 🔜 |
| 3 | Playwright SPA/API crawler | 🔜 |
| 4 | Trained ML classifier (TF-IDF/XGBoost → DistilBERT) | 🔜 (`notebooks/`) |
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

# JSON report for CI/CD
sqlintel -u "http://target/item?id=1" -p id --json reports/scan.json
```

## Roadmap for the ML component

`notebooks/train_classifier.ipynb` is a free (Colab/Kaggle) starter that:
1. loads labeled request/response samples (public sets + traffic you generate with this engine),
2. trains a TF-IDF + XGBoost baseline classifier, then
3. exports `models/sqli_clf.joblib`, which `sqlintel/ml/` loads to triage findings.

Everything in this project runs at **$0**: local Python, free Colab GPU, Dockerized targets.

## License

MIT — see `LICENSE`.
