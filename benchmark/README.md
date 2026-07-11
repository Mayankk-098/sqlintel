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

## Interpreting the sqlmap result on the mock suite

On the mock suite sqlmap reports **0 confirmed** findings, and that number is honest but
needs context — it is *not* evidence that sqlmap is a weak scanner. Against the mock,
sqlmap's verbose log shows it **heuristically detects** the injection and flags the
parameter as `appears to be injectable` for the boolean-based, stacked-query, and
time-based techniques. It then runs its own false-positive / exploitability check and
**declines to confirm**:

```
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] checking if the injection point on GET parameter 'id' is a false positive
[WARNING] false positive or unexploitable injection point detected
```

The mock oracle is deliberately fair: it evaluates sqlmap's own verification payloads
(`AND <rand>=<rand>` true vs false, inequalities, and the `1) AND ... AND (1=1`
parenthesis boundary) and returns the logically correct page for each. The reason sqlmap
still declines is that the mock is a **blind** target that returns no extractable query
data, so sqlmap's conservative gate — which prefers a corroborating error/UNION vector
before committing — treats a boolean-only signal as unexploitable. Ghauri, which is less
conservative, confirms the same target. SQLintel confirms it because its independent
proof-verifier re-derives the boolean toggle.

**Takeaway:** on the mock, treat this as "SQLintel and Ghauri confirm; sqlmap detects but
won't commit without exploitable output." For a fair read of sqlmap's real recall, use the
DVWA target set, where the app returns query data sqlmap can corroborate.

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
