# Architecture

```text
Nginx Combined / JSONL
        │ whitelist parser
        ▼
Normalized event ──► SQLite
        │
        ├──► source_ip and session behavior windows (1m / 5m)
        │       ├──► explainable baseline rules
        │       └──► DecisionProvider
        │              ├── LocalJevProvider (HTTP /v1/systemone)
        │              └── MockProvider (offline demo only)
        ▼
Rules Only / Jev Only / Hybrid risk assessment
        ▼
FastAPI read/ingest endpoints ──► local dashboard
```

`SecurityEvent` is the normalized schema. Input keys are whitelisted and secrets are not modeled. Aggregation produces numeric and boolean features. The provider sends those features and explicit trusted/untrusted context metadata; raw request-controlled text is omitted. Typed Jev questions ask malicious likelihood, category, severity, and human review. The risk layer exposes separate component values and uses low-confidence uncertainty handling.

SQLite is the only persistence dependency. No queue, cloud service, or enforcement integration is present. local-jev is an independent process and is not vendored or modified. On Apple Silicon it should be run natively to access MPS.

## Data flow boundaries

- Collector parses but does not execute values found in logs.
- Aggregator strips arbitrary content before model evaluation.
- Decision provider uses an HTTP timeout and receives no model credentials.
- Dashboard is a local read/ingest UI and has no remediation actions.
- Benchmark uses a fixed synthetic generator, entity-level split and test-only scoring.
