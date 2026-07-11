# SQLintel benchmark results

- Target set: `mock`  (http://127.0.0.1:8099)
- Tools compared: sqlintel, sqlmap, ghauri

Metrics include the false-positive rate, measured against SAFE (non-vulnerable)
endpoints as true negatives. Recall alone is not enough: a scanner that flags
everything has perfect recall and a useless FP-rate.

See benchmark/README.md for methodology and per-tool interpretation (e.g. why
sqlmap declines to confirm on the blind mock oracle despite detecting it).

## Aggregate metrics

| tool | TP | FP | TN | FN | prec | recall | F1 | FP-rate | acc | mean(s) |
|---|---|---|---|---|---|---|---|---|---|---|
| sqlintel | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 1.79 |
| sqlmap | 0 | 0 | 2 | 2 | 0.00 | 0.00 | 0.00 | 0.00 | 0.50 | 14.27 |
| ghauri | 2 | 0 | 2 | 0 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 7.83 |

## Per-target detail

### sqlintel

| target | vulnerable | found | correct | seconds |
|---|---|---|---|---|
| mock-item-query | True | True | True | 2.772 |
| mock-api-json | True | True | True | 2.507 |
| mock-safe-query | False | False | True | 0.934 |
| mock-safe-json | False | False | True | 0.947 |

### sqlmap

| target | vulnerable | found | correct | seconds |
|---|---|---|---|---|
| mock-item-query | True | False | False | 26.053 |
| mock-api-json | True | False | False | 25.963 |
| mock-safe-query | False | False | True | 2.562 |
| mock-safe-json | False | False | True | 2.502 |

### ghauri

| target | vulnerable | found | correct | seconds |
|---|---|---|---|---|
| mock-item-query | True | True | True | 0.427 |
| mock-api-json | True | True | True | 0.377 |
| mock-safe-query | False | False | True | 15.375 |
| mock-safe-json | False | False | True | 15.136 |
