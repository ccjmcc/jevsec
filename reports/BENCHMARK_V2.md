# Public benchmark v2

Reproducible synthetic benchmark for the single supported local model, Qwen3-4B. Every held-out test behavior window is scored. Threshold fitting sees validation rows only and uses per-category operating points constrained to at most 5% validation FPR.

## Reproduce

Run `scripts/run_public_benchmark.sh` with local-jev available. Defaults: 20,000 behavior windows per prevalence and seed 20261001. `SDE_PUBLIC_WINDOWS` can lower the count for a smoke run; test counts are recorded in each report.

## Results

Model calls, cache hits, and prefilter skips count validation plus test work; scores below use held-out test windows only. Project Rules has no model call. Latency shows measured uncached local-model requests; the prefilter changes the number of requests, not their measured latency.

| Model | Test prevalence | System | n | Precision | Recall / attack retention | F1 | FPR | FNR | Review rate | Reviews | Alert reduction vs rules | p50/p95 model ms | Model calls/cache hits | Prefilter skips |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| llm-qwen3-4b | 10pct (10.00%) | Rules | 4,000 | 1.000 | 0.497 | 0.664 | 0.000 | 0.502 | 4.98% | 199 | +0.0% | n/a | 0/0 | 0 |
| llm-qwen3-4b | 10pct (10.00%) | Jev every window | 4,000 | 1.000 | 0.688 | 0.815 | 0.000 | 0.312 | 6.88% | 275 | -38.2% | 956/1199 | 15/7,985 | 0 |
| llm-qwen3-4b | 10pct (10.00%) | Calibrated Jev | 4,000 | 1.000 | 0.688 | 0.815 | 0.000 | 0.312 | 6.88% | 275 | -38.2% | 956/1199 | 15/7,985 | 0 |
| llm-qwen3-4b | 10pct (10.00%) | Hybrid | 4,000 | 0.527 | 0.688 | 0.597 | 0.069 | 0.312 | 13.05% | 522 | -162.3% | 956/1199 | 15/7,985 | 0 |
| llm-qwen3-4b | 10pct (10.00%) | Calibrated Hybrid (≤5% val FPR) | 4,000 | 1.000 | 0.688 | 0.815 | 0.000 | 0.312 | 6.88% | 275 | -38.2% | 956/1199 | 15/7,985 | 0 |
| llm-qwen3-4b | 10pct (10.00%) | Prefilter → Jev Hybrid | 4,000 | 0.527 | 0.688 | 0.597 | 0.069 | 0.312 | 13.05% | 522 | -162.3% | 956/1199 | 9/4,051 | 3,940 |
| llm-qwen3-4b | 10pct (10.00%) | Calibrated Jev (≥95% val recall) | 4,000 | 1.000 | 0.688 | 0.815 | 0.000 | 0.312 | 6.88% | 275 | -38.2% | 956/1199 | 15/7,985 | 0 |
| llm-qwen3-4b | 10pct (10.00%) | Calibrated Hybrid (≥95% val recall) | 4,000 | 1.000 | 0.688 | 0.815 | 0.000 | 0.312 | 6.88% | 275 | -38.2% | 956/1199 | 15/7,985 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Rules | 4,000 | 1.000 | 0.475 | 0.644 | 0.000 | 0.525 | 0.47% | 19 | +0.0% | n/a | 0/0 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Jev every window | 4,000 | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% | 899/1359 | 15/7,985 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Calibrated Jev | 4,000 | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% | 899/1359 | 15/7,985 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Hybrid | 4,000 | 0.087 | 0.625 | 0.152 | 0.067 | 0.375 | 7.22% | 289 | -1421.1% | 899/1359 | 15/7,985 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Calibrated Hybrid (≤5% val FPR) | 4,000 | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% | 899/1359 | 15/7,985 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Prefilter → Jev Hybrid | 4,000 | 0.087 | 0.625 | 0.152 | 0.067 | 0.375 | 7.22% | 289 | -1421.1% | 899/1359 | 9/3,752 | 4,239 |
| llm-qwen3-4b | 1pct (1.00%) | Calibrated Jev (≥95% val recall) | 4,000 | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% | 899/1359 | 15/7,985 | 0 |
| llm-qwen3-4b | 1pct (1.00%) | Calibrated Hybrid (≥95% val recall) | 4,000 | 1.000 | 0.625 | 0.769 | 0.000 | 0.375 | 0.62% | 25 | -31.6% | 899/1359 | 15/7,985 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Rules | 4,000 | 1.000 | 0.555 | 0.714 | 0.000 | 0.445 | 2.77% | 111 | +0.0% | n/a | 0/0 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Jev every window | 4,000 | 1.000 | 0.695 | 0.820 | 0.000 | 0.305 | 3.48% | 139 | -25.2% | 900/1553 | 15/7,985 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Calibrated Jev | 4,000 | 1.000 | 0.695 | 0.820 | 0.000 | 0.305 | 3.48% | 139 | -25.2% | 900/1553 | 15/7,985 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Hybrid | 4,000 | 0.358 | 0.695 | 0.473 | 0.066 | 0.305 | 9.70% | 388 | -249.5% | 900/1553 | 15/7,985 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Calibrated Hybrid (≤5% val FPR) | 4,000 | 1.000 | 0.695 | 0.820 | 0.000 | 0.305 | 3.48% | 139 | -25.2% | 900/1553 | 15/7,985 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Prefilter → Jev Hybrid | 4,000 | 0.358 | 0.695 | 0.473 | 0.066 | 0.305 | 9.70% | 388 | -249.5% | 900/1553 | 9/3,863 | 4,128 |
| llm-qwen3-4b | 5pct (5.00%) | Calibrated Jev (≥95% val recall) | 4,000 | 1.000 | 0.695 | 0.820 | 0.000 | 0.305 | 3.48% | 139 | -25.2% | 900/1553 | 15/7,985 | 0 |
| llm-qwen3-4b | 5pct (5.00%) | Calibrated Hybrid (≥95% val recall) | 4,000 | 1.000 | 0.695 | 0.820 | 0.000 | 0.305 | 3.48% | 139 | -25.2% | 900/1553 | 15/7,985 | 0 |

## Dataset composition

Each behavior window contains 12 synthetic requests using the RFC 2544 benchmarking range. The entity-disjoint splits are fixed at 60% calibration reserve, 20% validation, and 20% test. Threshold fitting reads validation rows only; test labels are used only for final metrics and PR curves.

| Model | Requested rate | Split | Windows | Class distribution | Scenario distribution |
|---|---|---|---:|---|---|
| llm-qwen3-4b | 10pct | test | 4,000 | `{"automated_bot": 55, "benign": 3600, "credential_abuse": 66, "possible_web_exploitation": 76, "reconnaissance": 64, "suspicious_post_authentication": 69, "unknown_suspicious": 70}` | `{"admin_batch_operation": 248, "api_polling": 240, "automated_bot": 55, "cdn": 228, "ci_cd": 232, "credential_abuse": 66, "development_scan": 237, "enterprise_proxy": 242, "health_check": 242, "high_volume_api": 230, "mobile_retry": 240, "monitoring_system": 243, "normal_crawler": 238, "ordinary_browse": 244, "possible_web_exploitation": 76, "reconnaissance": 64, "search_bot": 247, "slow_login_failures": 247, "spa_404": 242, "suspicious_post_authentication": 69, "unknown_suspicious": 70}` |
| llm-qwen3-4b | 10pct | train_calibration | 12,000 | `{"automated_bot": 211, "benign": 10800, "credential_abuse": 212, "possible_web_exploitation": 197, "reconnaissance": 189, "suspicious_post_authentication": 189, "unknown_suspicious": 202}` | `{"admin_batch_operation": 731, "api_polling": 726, "automated_bot": 211, "cdn": 701, "ci_cd": 711, "credential_abuse": 212, "development_scan": 716, "enterprise_proxy": 708, "health_check": 731, "high_volume_api": 712, "mobile_retry": 716, "monitoring_system": 729, "normal_crawler": 737, "ordinary_browse": 722, "possible_web_exploitation": 197, "reconnaissance": 189, "search_bot": 726, "slow_login_failures": 726, "spa_404": 708, "suspicious_post_authentication": 189, "unknown_suspicious": 202}` |
| llm-qwen3-4b | 10pct | validation | 4,000 | `{"automated_bot": 67, "benign": 3600, "credential_abuse": 56, "possible_web_exploitation": 60, "reconnaissance": 81, "suspicious_post_authentication": 75, "unknown_suspicious": 61}` | `{"admin_batch_operation": 239, "api_polling": 247, "automated_bot": 67, "cdn": 236, "ci_cd": 244, "credential_abuse": 56, "development_scan": 238, "enterprise_proxy": 243, "health_check": 239, "high_volume_api": 238, "mobile_retry": 246, "monitoring_system": 236, "normal_crawler": 235, "ordinary_browse": 242, "possible_web_exploitation": 60, "reconnaissance": 81, "search_bot": 233, "slow_login_failures": 243, "spa_404": 241, "suspicious_post_authentication": 75, "unknown_suspicious": 61}` |
| llm-qwen3-4b | 1pct | test | 4,000 | `{"automated_bot": 9, "benign": 3960, "credential_abuse": 5, "possible_web_exploitation": 6, "reconnaissance": 7, "suspicious_post_authentication": 7, "unknown_suspicious": 6}` | `{"admin_batch_operation": 264, "api_polling": 263, "automated_bot": 9, "cdn": 263, "ci_cd": 264, "credential_abuse": 5, "development_scan": 263, "enterprise_proxy": 265, "health_check": 266, "high_volume_api": 261, "mobile_retry": 262, "monitoring_system": 265, "normal_crawler": 266, "ordinary_browse": 266, "possible_web_exploitation": 6, "reconnaissance": 7, "search_bot": 265, "slow_login_failures": 264, "spa_404": 263, "suspicious_post_authentication": 7, "unknown_suspicious": 6}` |
| llm-qwen3-4b | 1pct | train_calibration | 12,000 | `{"automated_bot": 18, "benign": 11880, "credential_abuse": 21, "possible_web_exploitation": 19, "reconnaissance": 21, "suspicious_post_authentication": 24, "unknown_suspicious": 17}` | `{"admin_batch_operation": 795, "api_polling": 793, "automated_bot": 18, "cdn": 790, "ci_cd": 789, "credential_abuse": 21, "development_scan": 791, "enterprise_proxy": 786, "health_check": 798, "high_volume_api": 785, "mobile_retry": 785, "monitoring_system": 794, "normal_crawler": 800, "ordinary_browse": 793, "possible_web_exploitation": 19, "reconnaissance": 21, "search_bot": 799, "slow_login_failures": 788, "spa_404": 794, "suspicious_post_authentication": 24, "unknown_suspicious": 17}` |
| llm-qwen3-4b | 1pct | validation | 4,000 | `{"automated_bot": 6, "benign": 3960, "credential_abuse": 8, "possible_web_exploitation": 8, "reconnaissance": 6, "suspicious_post_authentication": 2, "unknown_suspicious": 10}` | `{"admin_batch_operation": 262, "api_polling": 264, "automated_bot": 6, "cdn": 262, "ci_cd": 265, "credential_abuse": 8, "development_scan": 264, "enterprise_proxy": 264, "health_check": 265, "high_volume_api": 263, "mobile_retry": 264, "monitoring_system": 264, "normal_crawler": 265, "ordinary_browse": 263, "possible_web_exploitation": 8, "reconnaissance": 6, "search_bot": 266, "slow_login_failures": 266, "spa_404": 263, "suspicious_post_authentication": 2, "unknown_suspicious": 10}` |
| llm-qwen3-4b | 5pct | test | 4,000 | `{"automated_bot": 31, "benign": 3800, "credential_abuse": 40, "possible_web_exploitation": 28, "reconnaissance": 39, "suspicious_post_authentication": 32, "unknown_suspicious": 30}` | `{"admin_batch_operation": 250, "api_polling": 254, "automated_bot": 31, "cdn": 256, "ci_cd": 246, "credential_abuse": 40, "development_scan": 253, "enterprise_proxy": 250, "health_check": 253, "high_volume_api": 259, "mobile_retry": 257, "monitoring_system": 256, "normal_crawler": 254, "ordinary_browse": 257, "possible_web_exploitation": 28, "reconnaissance": 39, "search_bot": 255, "slow_login_failures": 249, "spa_404": 251, "suspicious_post_authentication": 32, "unknown_suspicious": 30}` |
| llm-qwen3-4b | 5pct | train_calibration | 12,000 | `{"automated_bot": 108, "benign": 11400, "credential_abuse": 103, "possible_web_exploitation": 104, "reconnaissance": 95, "suspicious_post_authentication": 94, "unknown_suspicious": 96}` | `{"admin_batch_operation": 766, "api_polling": 763, "automated_bot": 108, "cdn": 746, "ci_cd": 756, "credential_abuse": 103, "development_scan": 755, "enterprise_proxy": 759, "health_check": 771, "high_volume_api": 749, "mobile_retry": 755, "monitoring_system": 771, "normal_crawler": 771, "ordinary_browse": 760, "possible_web_exploitation": 104, "reconnaissance": 95, "search_bot": 764, "slow_login_failures": 762, "spa_404": 752, "suspicious_post_authentication": 94, "unknown_suspicious": 96}` |
| llm-qwen3-4b | 5pct | validation | 4,000 | `{"automated_bot": 28, "benign": 3800, "credential_abuse": 24, "possible_web_exploitation": 34, "reconnaissance": 33, "suspicious_post_authentication": 41, "unknown_suspicious": 40}` | `{"admin_batch_operation": 255, "api_polling": 253, "automated_bot": 28, "cdn": 254, "ci_cd": 255, "credential_abuse": 24, "development_scan": 250, "enterprise_proxy": 250, "health_check": 254, "high_volume_api": 250, "mobile_retry": 255, "monitoring_system": 252, "normal_crawler": 258, "ordinary_browse": 256, "possible_web_exploitation": 34, "reconnaissance": 33, "search_bot": 249, "slow_login_failures": 252, "spa_404": 257, "suspicious_post_authentication": 41, "unknown_suspicious": 40}` |

Attack classes include reconnaissance, credential abuse, automation, post-authentication anomaly, safe web errors, and unknown suspicious. Benign cases include crawlers/search bots, API polling, health checks, CDN, SPA 404, administrator batch work, development scans, monitoring, slow login failures, enterprise proxy, high-volume API, mobile retries and CI/CD.

All three measured prevalences are retained. Per-category operating points are in `reports/public_v2/threshold_table.csv`; precision-recall curves are in `reports/public_v2/precision_recall_curve.csv`.

## Model cost proxy

The System-One endpoint does not expose token counts. Reports retain exact context payload bytes, uncached calls, cache hits, uncached inference p50/p95, full-window throughput and wall time. Prefilter results measure calls avoided against Jev every window.

Synthetic results are not production estimates, WAF replacement claims, or evidence that unknown vulnerabilities will be detected.
