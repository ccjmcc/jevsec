# Failure analysis

Error counts come from each held-out test split and are grouped by model, prevalence, system, true class, and synthetic scenario. Examples contain only synthetic labels/features.

## Top false positives

| Model | Prevalence | System | Class | Scenario | Count |
|---|---|---|---|---|---:|
| llm-qwen3-4b | 1pct | hybrid | benign | slow_login_failures | 264 |
| llm-qwen3-4b | 1pct | prefilter_hybrid | benign | slow_login_failures | 264 |
| llm-qwen3-4b | 5pct | hybrid | benign | slow_login_failures | 249 |
| llm-qwen3-4b | 5pct | prefilter_hybrid | benign | slow_login_failures | 249 |
| llm-qwen3-4b | 10pct | hybrid | benign | slow_login_failures | 247 |
| llm-qwen3-4b | 10pct | prefilter_hybrid | benign | slow_login_failures | 247 |

## Top false negatives

| Model | Prevalence | System | Class | Scenario | Count |
|---|---|---|---|---|---:|
| llm-qwen3-4b | 10pct | rules | possible_web_exploitation | possible_web_exploitation | 76 |
| llm-qwen3-4b | 10pct | rules | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | jev | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | calibrated_jev | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | hybrid | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | calibrated_hybrid | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | prefilter_hybrid | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | jev_95 | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | hybrid_95 | unknown_suspicious | unknown_suspicious | 70 |
| llm-qwen3-4b | 10pct | rules | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | jev | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | calibrated_jev | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | hybrid | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | calibrated_hybrid | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | prefilter_hybrid | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | jev_95 | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 10pct | hybrid_95 | automated_bot | automated_bot | 55 |
| llm-qwen3-4b | 5pct | rules | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | jev | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | calibrated_jev | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | hybrid | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | calibrated_hybrid | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | prefilter_hybrid | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | jev_95 | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | hybrid_95 | automated_bot | automated_bot | 31 |
| llm-qwen3-4b | 5pct | rules | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | jev | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | calibrated_jev | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | hybrid | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | calibrated_hybrid | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | prefilter_hybrid | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | jev_95 | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | hybrid_95 | unknown_suspicious | unknown_suspicious | 30 |
| llm-qwen3-4b | 5pct | rules | possible_web_exploitation | possible_web_exploitation | 28 |
| llm-qwen3-4b | 1pct | rules | automated_bot | automated_bot | 9 |
| llm-qwen3-4b | 1pct | jev | automated_bot | automated_bot | 9 |
| llm-qwen3-4b | 1pct | calibrated_jev | automated_bot | automated_bot | 9 |
| llm-qwen3-4b | 1pct | hybrid | automated_bot | automated_bot | 9 |
| llm-qwen3-4b | 1pct | calibrated_hybrid | automated_bot | automated_bot | 9 |
| llm-qwen3-4b | 1pct | prefilter_hybrid | automated_bot | automated_bot | 9 |

## Examples

### False positives

```json
[
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FP",
    "category": "benign",
    "scenario": "slow_login_failures",
    "score": "18.2",
    "predicted_category": "credential_abuse",
    "rule_ids": ""
  }
]
```

### False negatives

```json
[
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "rules",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "0.0",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "7.92",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_jev",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "7.92",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "3.97",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_hybrid",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "3.97",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "1.63",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev_95",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "7.92",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid_95",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "3.97",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "rules",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "0.0",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "7.92",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_jev",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "7.92",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "3.97",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_hybrid",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "3.97",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "1.63",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev_95",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "7.92",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid_95",
    "error": "FN",
    "category": "automated_bot",
    "scenario": "automated_bot",
    "score": "3.97",
    "predicted_category": "benign",
    "rule_ids": ""
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "rules",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "22.0",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_jev",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev_95",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid_95",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "rules",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "22.0",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_jev",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev_95",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid_95",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "rules",
    "error": "FN",
    "category": "possible_web_exploitation",
    "scenario": "possible_web_exploitation",
    "score": "22.0",
    "predicted_category": "automated_bot",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "rules",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "22.0",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_jev",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "calibrated_hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "prefilter_hybrid",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "19.25",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  },
  {
    "model": "llm-qwen3-4b",
    "prevalence": "10pct",
    "system": "jev_95",
    "error": "FN",
    "category": "unknown_suspicious",
    "scenario": "unknown_suspicious",
    "score": "14.15",
    "predicted_category": "benign",
    "rule_ids": "many_403"
  }
]
```
