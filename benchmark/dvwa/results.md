# SQLintel benchmark results

- Target set: `dvwa`  (http://localhost:8080)
- Tools compared: sqlintel, sqlmap, ghauri

Metrics include the false-positive rate, measured against SAFE (non-vulnerable)
endpoints as true negatives. Recall alone is not enough: a scanner that flags
everything has perfect recall and a useless FP-rate.

See benchmark/README.md for methodology and per-tool interpretation (e.g. why
sqlmap declines to confirm on the blind mock oracle despite detecting it).

## Aggregate metrics

| tool | TP | FP | TN | FN | prec | recall | F1 | FP-rate | acc | mean(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| sqlintel | 2 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 18.80 |
| sqlmap | 2 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 15.35 |
| ghauri | 2 | 0 | 0 | 0 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 11.07 |

## Per-target detail

### sqlintel

| target | vulnerable | found | correct | seconds |
|---|---|---|---|---|
| dvwa-sqli | True | True | True | 29.555 |
| dvwa-sqli-blind | True | True | True | 8.041 |

### sqlmap

| target | vulnerable | found | correct | seconds |
|---|---|---|---|---|
| dvwa-sqli | True | True | True | 16.362 |
| dvwa-sqli-blind | True | True | True | 14.331 |

### ghauri

| target | vulnerable | found | correct | seconds |
|---|---|---|---|---|
| dvwa-sqli | True | True | True | 10.462 |
| dvwa-sqli-blind | True | True | True | 11.671 |
