# SQLintel benchmark

Honest, reproducible comparison of **SQLintel** against **[sqlmap]** and **[Ghauri]** on
targets with known ground-truth labels.

The headline design choice: we score the **full confusion matrix** — precision, recall,
F1, **false-positive rate**, and accuracy — not just recall. A scanner that reports
everything as vulnerable gets perfect recall and is worthless; only measuring against
SAFE (non-vulnerable) endpoints as *true negatives* exposes that. So the target manifest
deliberately includes safe endpoints.

## Target sets

| set    | reproducible? | targets | true negatives? |
|--------|---------------|---------|-----------------|
| `mock` | yes (primary) | 2 vulnerable + 2 safe, served by `tests/mock_vuln_server.py` | yes |
| `dvwa` | needs Docker  | DVWA SQLi + blind SQLi modules (security=low)                | add your own |

The **mock** suite is the primary metric because it is fully deterministic and needs no
external services. It covers SQLintel's differentiator directly: a JSON API body sink
(`POST /api/item`, tested with `--json-body`) alongside the classic query sink.

## Running the mock suite (no external tools required)

```bash
python -m benchmark.run_benchmark                 # compares whatever is installed
python -m benchmark.run_benchmark --tools sqlintel
```

The runner starts the mock server, scores each **available** tool (sqlmap/Ghauri are
auto-detected via `PATH` and skipped gracefully if missing), tears the server down, and
writes `results.md` + `results.json`. SQLintel is always available (it runs as
`python -m sqlintel`).

## Installing the baselines (both free)

```bash
pip install sqlmap        # https://github.com/sqlmapproject/sqlmap
pip install ghauri        # https://github.com/r0oth3x49/ghauri
```

Once either is on `PATH`, re-run the command above and it joins the comparison.

## Running against DVWA

Bring up the bundled DVWA (`docker-compose.yml` at the repo root), log in
(`admin` / `password`), create/reset the database, and set **DVWA Security = low**. Then
grab your session cookie and run:

```bash
python -m benchmark.run_benchmark --target-set dvwa --base-url http://127.0.0.1:8080
```

DVWA gates its SQLi modules behind auth, so the tools need the session cookie
(`PHPSESSID=<id>; security=low`). SQLintel accepts it via `-H "Cookie: PHPSESSID=...; security=low"`;
sqlmap/Ghauri take `--cookie`. (Cookie wiring for the DVWA adapters is a documented
next step — the mock suite is the number that matters for the write-up.)

## How tools are scored

- **SQLintel** — invoked as `python -m sqlintel ... --batch -q`; a finding is signalled by
  **exit code 1** (0 = clean). JSON targets add `--json-body`.
- **sqlmap / Ghauri** — invoked with `--batch`; a finding is detected by parsing stdout
  for an injection marker (see `parse_sqlmap_output` / `parse_ghauri_output` in
  `harness.py`, unit-tested in `tests/test_benchmark.py`).

Each tool's `found` verdict is compared to the target's `vulnerable` label to fill the
confusion matrix, then aggregated into the metrics table.

## Honest caveats

- **The mock suite is small** (4 targets). The numbers demonstrate methodology, not a
  statistically robust ranking. Real percentages need many more labeled targets.
- The mock server models error/boolean/time behavior faithfully but is not a real DBMS;
  edge cases (WAFs, second-order injection, weird encodings) aren't represented.
- DVWA FP-rate is only meaningful once you add labeled safe pages to `DVWA_TARGETS` — the
  module endpoints shipped here are all vulnerable, so that set measures recall only.
- Wall-clock times depend heavily on machine, network, and each tool's default
  technique/level; treat `mean(s)` as a rough guide, not a precise figure.

[sqlmap]: https://github.com/sqlmapproject/sqlmap
[Ghauri]: https://github.com/r0oth3x49/ghauri
