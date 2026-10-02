# Changelog

## 0.2.0

- Added validation-only per-category calibration and BENIGN/REVIEW/HIGH_RISK/UNCERTAIN outcomes.
- Added 20,000-window deterministic benign-heavy datasets at 1%, 5% and 10% malicious prevalence and full-split public benchmark tooling.
- Locked the product benchmark/runtime model to Qwen3-4B, added dataset manifests/fingerprints, and verified corrected full-split reports.
- Added an isolated, reproducible OWASP CRS 4.29.0 behavior-window comparison and local request-signature positive controls.
- Added structured attack stories, IP/session/pseudonymous-user aggregation, historical baseline features and feedback storage.
- Reused Jev HTTP connections, cached repeated feature decisions, added a conservative rule prefilter and provider-cost metrics.
- Added resilient Nginx shadow tailing, loopback default and required Basic authentication for non-loopback binds.
- Productized the dashboard and Docker Compose authentication/health checks; no traffic prevention is performed.

## 0.1.0

- Initial self-hosted shadow-mode release: Nginx/JSONL ingestion, behavior aggregation, explainable rules, pluggable Jev provider, hybrid triage, SQLite API/dashboard, synthetic dataset and benchmark tooling.
