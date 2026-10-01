# Benchmark report

- Machine: macOS-27.0-arm64-arm-64bit (arm64)
- Python: 3.12.13
- Provider/model: local_jev / nli-deberta-large
- Synthetic events: 13634
- Held-out test behavior windows available: 240
- Model inferences completed: 70

- First request latency in this evaluation: 8544.011083000441 ms (the model may already have been warm)

## Held-out test results

| System | n | Alerts/reviews | Workload change vs rules | Precision | Recall / attack retention | F1 | FPR | FNR | Accuracy | AUROC | p50 ms | p95 ms | req/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules Only | 70 | 20 | +0.0% | 0.750 | 0.429 | 0.545 | 0.143 | 0.571 | 0.643 | 0.7538775510204082 | 0.02 | 0.27 | 6963.59 |
| Local Jev Only | 70 | 70 | +250.0% | 0.500 | 1.000 | 0.667 | 1.000 | 0.000 | 0.500 | 0.3669387755102041 | 3606.15 | 5229.37 | 0.26 |
| Hybrid | 70 | 70 | +250.0% | 0.500 | 1.000 | 0.667 | 1.000 | 0.000 | 0.500 | 0.7383673469387755 | 3606.15 | 5229.37 | 0.26 |

Only the reported test partition is scored; thresholds are config defaults, not fitted on test labels. Model inference is stratified and capped to the requested sample limit. Uncertain outcomes count as review alerts for workload/recall calculations. These synthetic results do not estimate production performance.

Jev behavior-category accuracy: 0.08571428571428572

## Category recall

| Category | n | Rules alert recall | Jev review recall | Hybrid review recall | Jev category accuracy |
|---|---:|---:|---:|---:|---:|
| automated_bot | 6 | 0.167 | 1.0 | 1.0 | 0.0 |
| benign | 35 | 0.143 | 1.0 | 1.0 | 0.0 |
| credential_abuse | 6 | 1.000 | 1.0 | 1.0 | 0.0 |
| possible_web_exploitation | 6 | 0.000 | 1.0 | 1.0 | 1.0 |
| reconnaissance | 6 | 0.667 | 1.0 | 1.0 | 0.0 |
| suspicious_post_authentication | 6 | 0.667 | 1.0 | 1.0 | 0.0 |
| unknown_suspicious | 5 | 0.000 | 1.0 | 1.0 | 0.0 |

## Benign hard negatives

| Scenario | n | Rules review rate | Jev review rate | Hybrid review rate |
|---|---:|---:|---:|---:|
| admin_sensitive_access | 1 | 0.000 | 1.0 | 1.0 |
| api_polling | 4 | 0.000 | 1.0 | 1.0 |
| forgot_password | 4 | 0.000 | 1.0 | 1.0 |
| health_check | 6 | 0.000 | 1.0 | 1.0 |
| high_volume_api | 4 | 1.000 | 1.0 | 1.0 |
| internal_monitor | 3 | 0.000 | 1.0 | 1.0 |
| mobile_client | 3 | 0.000 | 1.0 | 1.0 |
| normal_crawler | 1 | 0.000 | 1.0 | 1.0 |
| ordinary_browse | 4 | 0.000 | 1.0 | 1.0 |
| spa_404 | 5 | 0.200 | 1.0 | 1.0 |
