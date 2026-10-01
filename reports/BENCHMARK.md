# Benchmark report

## Environment

- Hardware: Apple M5, 16 GB unified memory, arm64.
- OS: macOS 27.0.
- Python: 3.12.13.
- PyTorch: 2.14.1; Transformers: 5.18.0; MPS available.
- local-jev: upstream v0.2.0, commit `64a0b31ff343dca32142496cf9edca5a0174a18d` (independent MIT project).
- local-jev and security engine ran natively on macOS; model was not run inside Docker.
- Model weights are cached outside this repository and are not part of the release archive.

## Dataset and method

Fixed seed `20261001`, 1,200 labeled entities and 13,634 event records. The dataset includes 50% benign behavior and hard negatives for crawler, internal monitor, high-volume API, forgotten password, SPA 404, normal admin access, mobile and polling. Suspicious categories are recon, credential abuse, automated bot, suspicious post-auth, possible web exploitation and unknown suspicious. All records are synthetic; source addresses come from RFC 5737 documentation-only ranges.

Entity-disjoint split counts: {'train_calibration': 720, 'validation': 240, 'test': 240}. This yields 240 source-IP one-minute windows in test. The provider was evaluated on 70 test windows per model, stratified approximately by category while preserving the balanced benign share (35 benign and 5–6 examples per suspicious category). Model scoring is one state request with four typed questions. Threshold defaults were held fixed (alert=55, high=78, low confidence=0.52); none was fit on test labels.

An `UNCERTAIN` assessment counts as requiring human review for workload, precision/recall and confusion matrices. AUROC uses the continuous risk score. Results are from this deterministic but authored dataset and are not production estimates.

## Rules Only vs Local Jev Only vs Hybrid

| Model | System | n | Precision | Recall | F1 | FPR | FNR | Accuracy | AUROC | Alerts/reviews | Workload change vs rules | p50 ms | p95 ms | states/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| llm-qwen3-4b | Rules Only | 70 | 0.750 | 0.429 | 0.545 | 0.143 | 0.571 | 0.643 | 0.7538775510204082 | 20 | +0.0% | 0.01 | 0.02 | 9032.46 |
| llm-qwen3-4b | Local Jev Only | 70 | 0.793 | 0.657 | 0.719 | 0.171 | 0.343 | 0.743 | 0.8155102040816327 | 29 | +45.0% | 839.41 | 873.85 | 0.50 |
| llm-qwen3-4b | Hybrid | 70 | 0.711 | 0.771 | 0.740 | 0.314 | 0.229 | 0.729 | 0.833469387755102 | 38 | +90.0% | 839.41 | 873.85 | 0.50 |
| llm-qwen3.5-4b | Rules Only | 70 | 0.750 | 0.429 | 0.545 | 0.143 | 0.571 | 0.643 | 0.7538775510204082 | 20 | +0.0% | 0.02 | 0.33 | 7895.29 |
| llm-qwen3.5-4b | Local Jev Only | 70 | 0.650 | 0.743 | 0.693 | 0.400 | 0.257 | 0.671 | 0.8648979591836735 | 40 | +100.0% | 2868.11 | 3451.75 | 0.22 |
| llm-qwen3.5-4b | Hybrid | 70 | 0.702 | 0.943 | 0.805 | 0.400 | 0.057 | 0.771 | 0.833469387755102 | 47 | +135.0% | 2868.11 | 3451.75 | 0.22 |
| nli-deberta-large | Rules Only | 70 | 0.750 | 0.429 | 0.545 | 0.143 | 0.571 | 0.643 | 0.7538775510204082 | 20 | +0.0% | 0.02 | 0.27 | 6963.59 |
| nli-deberta-large | Local Jev Only | 70 | 0.500 | 1.000 | 0.667 | 1.000 | 0.000 | 0.500 | 0.3669387755102041 | 70 | +250.0% | 3606.15 | 5229.37 | 0.26 |
| nli-deberta-large | Hybrid | 70 | 0.500 | 1.000 | 0.667 | 1.000 | 0.000 | 0.500 | 0.7383673469387755 | 70 | +250.0% | 3606.15 | 5229.37 | 0.26 |

Rules Only is measured once in each identical stratified sample; its baseline repeats so Hybrid remains directly comparable to its paired Jev result. Positive workload change means more analyst reviews than Rules Only.

### Per-category recall and category accuracy

**llm-qwen3-4b**

| Category | n | Rules recall | Jev review recall | Hybrid review recall | Jev category accuracy |
|---|---:|---:|---:|---:|---:|
| automated_bot | 6 | 0.167 | 0.0 | 0.3333333333333333 | 0.0 |
| benign | 35 | 0.143 | 0.17142857142857143 | 0.3142857142857143 | 0.7428571428571429 |
| credential_abuse | 6 | 1.000 | 1.0 | 1.0 | 1.0 |
| possible_web_exploitation | 6 | 0.000 | 1.0 | 1.0 | 0.0 |
| reconnaissance | 6 | 0.667 | 1.0 | 1.0 | 0.16666666666666666 |
| suspicious_post_authentication | 6 | 0.667 | 0.8333333333333334 | 1.0 | 0.0 |
| unknown_suspicious | 5 | 0.000 | 0.0 | 0.2 | 0.0 |

**llm-qwen3.5-4b**

| Category | n | Rules recall | Jev review recall | Hybrid review recall | Jev category accuracy |
|---|---:|---:|---:|---:|---:|
| automated_bot | 6 | 0.167 | 0.0 | 0.6666666666666666 | 0.0 |
| benign | 35 | 0.143 | 0.4 | 0.4 | 0.8571428571428571 |
| credential_abuse | 6 | 1.000 | 1.0 | 1.0 | 1.0 |
| possible_web_exploitation | 6 | 0.000 | 1.0 | 1.0 | 0.0 |
| reconnaissance | 6 | 0.667 | 1.0 | 1.0 | 0.3333333333333333 |
| suspicious_post_authentication | 6 | 0.667 | 1.0 | 1.0 | 1.0 |
| unknown_suspicious | 5 | 0.000 | 0.4 | 1.0 | 0.0 |

**nli-deberta-large**

| Category | n | Rules recall | Jev review recall | Hybrid review recall | Jev category accuracy |
|---|---:|---:|---:|---:|---:|
| automated_bot | 6 | 0.167 | 1.0 | 1.0 | 0.0 |
| benign | 35 | 0.143 | 1.0 | 1.0 | 0.0 |
| credential_abuse | 6 | 1.000 | 1.0 | 1.0 | 0.0 |
| possible_web_exploitation | 6 | 0.000 | 1.0 | 1.0 | 1.0 |
| reconnaissance | 6 | 0.667 | 1.0 | 1.0 | 0.0 |
| suspicious_post_authentication | 6 | 0.667 | 1.0 | 1.0 | 0.0 |
| unknown_suspicious | 5 | 0.000 | 1.0 | 1.0 | 0.0 |

## Confusion matrices

Counts use the held-out sample; TP/FP/TN/FN order is conventional. The exact matrices are retained in each model's `benchmark_results.json`.

**llm-qwen3-4b**
- Rules Only: TP 15, FP 5, TN 30, FN 20
- Local Jev Only: TP 23, FP 6, TN 29, FN 12
- Hybrid: TP 27, FP 11, TN 24, FN 8
**llm-qwen3.5-4b**
- Rules Only: TP 15, FP 5, TN 30, FN 20
- Local Jev Only: TP 26, FP 14, TN 21, FN 9
- Hybrid: TP 33, FP 14, TN 21, FN 2
**nli-deberta-large**
- Rules Only: TP 15, FP 5, TN 30, FN 20
- Local Jev Only: TP 35, FP 35, TN 0, FN 0
- Hybrid: TP 35, FP 35, TN 0, FN 0

## False-positive, false-negative and hard-negative analysis

**llm-qwen3-4b**
- Rules Only: 20 reviews; FPR 14.3%; FNR 57.1%; recall/attack retention 42.9%.
- Local Jev Only: 29 reviews; FPR 17.1%; FNR 34.3%; recall/attack retention 65.7%.
- Hybrid: 38 reviews; FPR 31.4%; FNR 22.9%; recall/attack retention 77.1%.
- Benign hard-negative review rates:
  - admin_sensitive_access (n=1): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - api_polling (n=4): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - forgot_password (n=4): rules 0.0%; Jev 0.0%; Hybrid 75.0%.
  - health_check (n=6): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - high_volume_api (n=4): rules 100.0%; Jev 25.0%; Hybrid 75.0%.
  - internal_monitor (n=3): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - mobile_client (n=3): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - normal_crawler (n=1): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - ordinary_browse (n=4): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - spa_404 (n=5): rules 20.0%; Jev 100.0%; Hybrid 100.0%.

**llm-qwen3.5-4b**
- Rules Only: 20 reviews; FPR 14.3%; FNR 57.1%; recall/attack retention 42.9%.
- Local Jev Only: 40 reviews; FPR 40.0%; FNR 25.7%; recall/attack retention 74.3%.
- Hybrid: 47 reviews; FPR 40.0%; FNR 5.7%; recall/attack retention 94.3%.
- Benign hard-negative review rates:
  - admin_sensitive_access (n=1): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - api_polling (n=4): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - forgot_password (n=4): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - health_check (n=6): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - high_volume_api (n=4): rules 100.0%; Jev 100.0%; Hybrid 100.0%.
  - internal_monitor (n=3): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - mobile_client (n=3): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - normal_crawler (n=1): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - ordinary_browse (n=4): rules 0.0%; Jev 0.0%; Hybrid 0.0%.
  - spa_404 (n=5): rules 20.0%; Jev 100.0%; Hybrid 100.0%.

**nli-deberta-large**
- Rules Only: 20 reviews; FPR 14.3%; FNR 57.1%; recall/attack retention 42.9%.
- Local Jev Only: 70 reviews; FPR 100.0%; FNR 0.0%; recall/attack retention 100.0%.
- Hybrid: 70 reviews; FPR 100.0%; FNR 0.0%; recall/attack retention 100.0%.
- Benign hard-negative review rates:
  - admin_sensitive_access (n=1): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - api_polling (n=4): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - forgot_password (n=4): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - health_check (n=6): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - high_volume_api (n=4): rules 100.0%; Jev 100.0%; Hybrid 100.0%.
  - internal_monitor (n=3): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - mobile_client (n=3): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - normal_crawler (n=1): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - ordinary_browse (n=4): rules 0.0%; Jev 100.0%; Hybrid 100.0%.
  - spa_404 (n=5): rules 20.0%; Jev 100.0%; Hybrid 100.0%.

A 1,000-traditional-alert production workload estimate is omitted. The evaluation split is deliberately 50% malicious, and the sample is only 70 windows, so converting its rate to a production queue size would overstate certainty.

## Model load, latency and memory

| Model | First request observation | p50 ms | p95 ms | throughput |
|---|---|---:|---:|---:|
| llm-qwen3-4b | First uncached provider request, including Hugging Face download, backend load, warm-up and inference: 299.3 seconds.; first evaluation request 82094.94674999996 ms | 839.41 | 873.85 | 0.50 states/s |
| llm-qwen3.5-4b | Initial uncached request exceeded the 90-second HTTP timeout while downloading/loading. After cache population a benchmark request succeeded; the completed end-to-end cold duration was not captured.; first evaluation request 115660.27016700082 ms | 2868.11 | 3451.75 | 0.22 states/s |
| nli-deberta-large | Initial startup included the approximately 0.87 GB weight download, but the exact startup duration was not isolated. A first direct request after the API became healthy took 1910.5 ms.; first evaluation request 8544.011083000441 ms | 3606.15 | 5229.37 | 0.26 states/s |

Observed process physical footprint (macOS `sample`, process-wide with cached model backends): NLI-only peak 2.7 GB; Qwen3-4B with NLI still cached peaked at 11.1 GB; Qwen3.5-4B process footprint reached 10.2 GB current and 18.7 GB peak. The Qwen3.5 peak exceeded installed unified RAM and can imply memory compression/swap; it is a material latency risk. These values reflect cache state and do not isolate per-model tensor allocation.

Throughput is the reciprocal of sequential single-request latency, not a load test. First request may include model loading/warmup; cold-download observations are reported separately in the CSV and notes.

## Robustness

A localhost-only synthetic input check used 3 user-agent variants. All variants mapped to identical aggregate feature objects and produced identical Jev answers; the provider payload omitted the raw strings. The unit test also injects unknown prompt-like feature keys and confirms the allowlist discards them.

This verifies that attacker-controlled strings are not transported to Jev; it does not establish resistance to every model error or prompt attack.

## Known limitations

- The dataset is synthetic and authored, and per-model test sample size is 70.
- High-volume API and SPA 404 hard negatives can trigger rules or model reviews; false positives are visible in the scenario tables.
- The NLI model's uncertainty and category accuracy require human review and were weak on this security task.
- Thresholds are fixed defaults; further calibration requires a separate labeled operational dataset.
- Source IPs remain identifying data in local SQLite; session and request identifiers are pseudonymized.
- API/dashboard have no built-in authentication, rate limiting, retention scheduler or production isolation.
- File tailing handles append and malformed lines but does not robustly handle rotation/truncation.
- Models require a one-time weight download; local inference itself does not send event data off-host.
- Results do not justify automatic blocking; the product is detection and triage in shadow mode.
