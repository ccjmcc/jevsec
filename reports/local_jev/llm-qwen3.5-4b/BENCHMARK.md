# Benchmark report

- Machine: macOS-27.0-arm64-arm-64bit (arm64)
- Python: 3.12.13
- Provider/model: local_jev / llm-qwen3.5-4b
- Synthetic events: 13634
- Held-out test behavior windows available: 240
- Model inferences completed: 70

- First request latency in this evaluation: 115660.27016700082 ms (the model may already have been warm)

## Held-out test results

| System | n | Alerts/reviews | Workload change vs rules | Precision | Recall / attack retention | F1 | FPR | FNR | Accuracy | AUROC | p50 ms | p95 ms | req/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules Only | 70 | 20 | +0.0% | 0.750 | 0.429 | 0.545 | 0.143 | 0.571 | 0.643 | 0.7538775510204082 | 0.02 | 0.33 | 7895.29 |
| Local Jev Only | 70 | 40 | +100.0% | 0.650 | 0.743 | 0.693 | 0.400 | 0.257 | 0.671 | 0.8648979591836735 | 2868.11 | 3451.75 | 0.22 |
| Hybrid | 70 | 47 | +135.0% | 0.702 | 0.943 | 0.805 | 0.400 | 0.057 | 0.771 | 0.833469387755102 | 2868.11 | 3451.75 | 0.22 |

Only the reported test partition is scored; thresholds are config defaults, not fitted on test labels. Model inference is stratified and capped to the requested sample limit. Uncertain outcomes count as review alerts for workload/recall calculations. These synthetic results do not estimate production performance.

Jev behavior-category accuracy: 0.6285714285714286

## Category recall

| Category | n | Rules alert recall | Jev review recall | Hybrid review recall | Jev category accuracy |
|---|---:|---:|---:|---:|---:|
| automated_bot | 6 | 0.167 | 0.0 | 0.6666666666666666 | 0.0 |
| benign | 35 | 0.143 | 0.4 | 0.4 | 0.8571428571428571 |
| credential_abuse | 6 | 1.000 | 1.0 | 1.0 | 1.0 |
| possible_web_exploitation | 6 | 0.000 | 1.0 | 1.0 | 0.0 |
| reconnaissance | 6 | 0.667 | 1.0 | 1.0 | 0.3333333333333333 |
| suspicious_post_authentication | 6 | 0.667 | 1.0 | 1.0 | 1.0 |
| unknown_suspicious | 5 | 0.000 | 0.4 | 1.0 | 0.0 |

## Benign hard negatives

| Scenario | n | Rules review rate | Jev review rate | Hybrid review rate |
|---|---:|---:|---:|---:|
| admin_sensitive_access | 1 | 0.000 | 1.0 | 1.0 |
| api_polling | 4 | 0.000 | 0.0 | 0.0 |
| forgot_password | 4 | 0.000 | 1.0 | 1.0 |
| health_check | 6 | 0.000 | 0.0 | 0.0 |
| high_volume_api | 4 | 1.000 | 1.0 | 1.0 |
| internal_monitor | 3 | 0.000 | 0.0 | 0.0 |
| mobile_client | 3 | 0.000 | 0.0 | 0.0 |
| normal_crawler | 1 | 0.000 | 0.0 | 0.0 |
| ordinary_browse | 4 | 0.000 | 0.0 | 0.0 |
| spa_404 | 5 | 0.200 | 1.0 | 1.0 |
