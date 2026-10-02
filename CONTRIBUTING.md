# Contributing

Use synthetic data or a scrubbed copy of logs. Do not commit credentials, raw cookies/Authorization, customer data, or model weights.

```sh
uv sync --all-extras --python 3.12
uv run pytest
```

Keep behavior windows entity-disjoint across train/validation/test. Only validation labels may tune thresholds. Never choose operating points from the test split. Preserve all benchmark runs and report false positives and false negatives by scenario.

For model evaluation, start local-jev natively and run `scripts/run_public_benchmark.sh`. Use `SDE_PUBLIC_WINDOWS=1000` only for a smoke test; mark the resulting counts and do not present it as the full public benchmark.

Before a release, run the test suite, shadow-mode ingestion, authenticated Docker Compose health checks, the complete Qwen3-4B benchmark and OWASP CRS comparison, then inspect `reports/FAILURE_ANALYSIS.md` and `reports/WAF_COMPARISON.md`.
