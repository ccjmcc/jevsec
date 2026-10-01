# Benchmark report

- Machine: macOS-27.0-arm64-arm-64bit (arm64)
- Python: 3.12.13
- Provider/model: local_jev / llm-qwen3-4b
- Synthetic events: 13634
- Held-out test behavior windows available: 240
- Model inferences completed: 70

- First request latency in this evaluation: 82094.94674999996 ms (the model may already have been warm)

## Held-out test results

| System | n | Alerts/reviews | Workload change vs rules | Precision | Recall / attack retention | F1 | FPR | FNR | Accuracy | AUROC | p50 ms | p95 ms | req/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules Only | 70 | 20 | +0.0% | 0.750 | 0.429 | 0.545 | 0.143 | 0.571 | 0.643 | 0.7538775510204082 | 0.01 | 0.02 | 9032.46 |
| Local Jev Only | 70 | 29 | +45.0% | 0.793 | 0.657 | 0.719 | 0.171 | 0.343 | 0.743 | 0.8155102040816327 | 839.41 | 873.85 | 0.50 |
| Hybrid | 70 | 38 | +90.0% | 0.711 | 0.771 | 0.740 | 0.314 | 0.229 | 0.729 | 0.833469387755102 | 839.41 | 873.85 | 0.50 |

Only the reported test partition is scored; thresholds are config defaults, not fitted on test labels. Model inference is stratified and capped to the requested sample limit. Uncertain outcomes count as review alerts for workload/recall calculations. These synthetic results do not estimate production performance.

Jev behavior-category accuracy: 0.4714285714285714

## Category recall

| Category | n | Rules alert recall | Jev review recall | Hybrid review recall | Jev category accuracy |
|---|---:|---:|---:|---:|---:|
| automated_bot | 6 | 0.167 | 0.0 | 0.3333333333333333 | 0.0 |
| benign | 35 | 0.143 | 0.17142857142857143 | 0.3142857142857143 | 0.7428571428571429 |
| credential_abuse | 6 | 1.000 | 1.0 | 1.0 | 1.0 |
| possible_web_exploitation | 6 | 0.000 | 1.0 | 1.0 | 0.0 |
| reconnaissance | 6 | 0.667 | 1.0 | 1.0 | 0.16666666666666666 |
| suspicious_post_authentication | 6 | 0.667 | 0.8333333333333334 | 1.0 | 0.0 |
| unknown_suspicious | 5 | 0.000 | 0.0 | 0.2 | 0.0 |

## Benign hard negatives

| Scenario | n | Rules review rate | Jev review rate | Hybrid review rate |
|---|---:|---:|---:|---:|
| admin_sensitive_access | 1 | 0.000 | 0.0 | 0.0 |
| api_polling | 4 | 0.000 | 0.0 | 0.0 |
| forgot_password | 4 | 0.000 | 0.0 | 0.75 |
| health_check | 6 | 0.000 | 0.0 | 0.0 |
| high_volume_api | 4 | 1.000 | 0.25 | 0.75 |
| internal_monitor | 3 | 0.000 | 0.0 | 0.0 |
| mobile_client | 3 | 0.000 | 0.0 | 0.0 |
| normal_crawler | 1 | 0.000 | 0.0 | 0.0 |
| ordinary_browse | 4 | 0.000 | 0.0 | 0.0 |
| spa_404 | 5 | 0.200 | 1.0 | 1.0 |
