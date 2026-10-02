# Architecture

```text
Nginx Combined / JSONL (shadow tail or import)
        │ secret-safe whitelist parser
        ▼
Normalized event + pseudonymous user ──► SQLite
        │
        ├──► IP / session / user behavior windows + historical deviation features
        │       ├──► explainable rules → conservative prefilter
        │       └──► allowlisted context → persistent DecisionProvider connection/cache
        │              ├── LocalJevProvider (HTTP /v1/systemone)
        │              └── MockProvider (offline UI smoke only)
        ▼
Rules / Jev / Hybrid → validation-fitted per-category calibration
        ▼
BENIGN / REVIEW / HIGH_RISK / UNCERTAIN
        ├──► structured Attack Stories + evidence
        └──► FastAPI (loopback or authenticated) → local dashboard/feedback
```

`SecurityEvent` is the normalized schema. Input keys are whitelisted and secret-bearing fields are discarded. Aggregation produces numeric/boolean features and, where history exists, simple interpretable rate/path/hour/auth/UA deviations. The provider sends only the fixed feature allowlist. Threshold fitting uses a disjoint validation split; test rows are not read by the calibrator. Stories are built from chronological event evidence, never as free-form model narratives.

SQLite is the only persistence dependency. No queue, cloud service, or enforcement integration is present. local-jev is an independent process and is not vendored or modified. On Apple Silicon it should be run natively to access MPS.

## Data flow boundaries

- Collector parses but does not execute values found in logs.
- Aggregator strips arbitrary content before model evaluation.
- Decision provider uses an HTTP timeout and receives no model credentials.
- Dashboard is a local read/ingest UI and has no remediation actions.
- Public benchmark evaluates every held-out window at three benign-heavy prevalences, reports cache/call cost proxies, and retains per-run JSON/CSV/threshold/PR artifacts.
- Basic authentication is mandatory on non-loopback server binds. TLS belongs at a trusted reverse proxy.
