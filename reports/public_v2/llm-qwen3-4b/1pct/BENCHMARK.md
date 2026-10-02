# Public benchmark v2 run

- System: `Apple M5`; OS `macOS-27.0-arm64-arm-64bit` (arm64); Python 3.12.13.
- Provider/model: `local_jev` / `llm-qwen3-4b` (Qwen3-4B-Instruct-2507; HF snapshot cdbee75f17c01a7cc42f958dc650907174af0554); local-jev endpoint `0.2.0`.
- Test windows: 4,000; validation windows: 4,000; test malicious prevalence: 1.00%.
- Synthetic events: 240,000; elapsed 22.7s; full-window throughput 352.3/s.
- Uncached model calls: 15; cache/provider stats `{"cache_hit_rate": 0.998125, "cache_hits": 7985, "cached_decisions": 15, "context_bytes": 33623, "inference_count": 15}`.
- Model inference latency for uncached calls: p50 898.6 ms, p95 1359.2 ms. Context payload bytes: 33623; tokens: unavailable from endpoint.

All 1-minute source-IP windows in the split are evaluated. Thresholds are fitted only on the disjoint validation split, separately by predicted behavior category, with a 5% maximum validation FPR objective; test labels are used only for final metric calculation.

## Systems

| System | Precision | Recall / retention | F1 | FPR | FNR | Review rate | Reviews | Alert reduction vs Rules |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 1.000 | 0.475 | 0.644 | 0.000 | 0.525 | 0.47% | 19 | +0.0% |
| Jev every window | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% |
| Calibrated Jev | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% |
| Hybrid | 0.087 | 0.625 | 0.152 | 0.067 | 0.375 | 7.22% | 289 | -1421.1% |
| Calibrated Hybrid (≤5% val FPR) | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% |
| Prefilter → Jev Hybrid | 0.087 | 0.625 | 0.152 | 0.067 | 0.375 | 7.22% | 289 | -1421.1% |
| Calibrated Jev (≥95% val recall) | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% |
| Calibrated Hybrid (≥95% val recall) | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% |

## Validation-fitted threshold table

The detailed category thresholds and validation counts are in `thresholds.json`; no test split was consulted when choosing them.

| Category | Jev threshold, max 5% FPR | Hybrid threshold, max 5% FPR | Jev threshold, 95% recall target | Hybrid threshold, 95% recall target |
|---|---:|---:|---:|---:|
| reconnaissance | 70.75 (FPR 0.00%) | 76.76 (FPR 0.00%) | 70.75 (recall 100.00%) | 76.76 (recall 100.00%) |
| credential_abuse | 89.37 (FPR 0.00%) | 67.03 (FPR 0.00%) | 89.37 (recall 100.00%) | 67.03 (recall 100.00%) |
| automation | 100.00 (FPR 0.00%) | 100.00 (FPR 0.00%) | 7.92 (recall 100.00%) | 3.97 (recall 100.00%) |
| post_authentication_anomaly | 45.51 (FPR 0.00%) | 53.63 (FPR 0.00%) | 45.51 (recall 100.00%) | 53.63 (recall 100.00%) |
| web_exploitation | 60.60 (FPR 0.00%) | 35.51 (FPR 0.00%) | 60.60 (recall 100.00%) | 35.51 (recall 100.00%) |
| unknown_suspicious | 100.00 (FPR 0.00%) | 19.25 (FPR 0.00%) | 14.15 (recall 100.00%) | 19.25 (recall 100.00%) |
| benign | 101.00 (FPR 0.00%) | 101.00 (FPR 0.00%) | 101.00 (recall 0.00%) | 101.00 (recall 0.00%) |

## Recommended operating points

- **FPR-constrained:** per-category threshold maximizes validation recall subject to no more than 5% validation FPR.
- **Review-budget oriented:** highest per-category threshold preserving at least 95% validation recall minimizes validation review volume at that retention target.
- **Rules shadow baseline:** static configured threshold; no model call. Compare against the same held-out rows.

## Reproduction

Run `scripts/run_public_benchmark.sh`. Fixed seed, generator, model identifiers, split boundaries and all result files are retained under `reports/public_v2/`.

This is a synthetic benchmark, not a production prevalence estimate. False positive rates and review rates depend on the included scenario mix.
