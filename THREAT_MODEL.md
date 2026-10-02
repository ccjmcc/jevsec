# Threat model

## Purpose and boundaries

JevSec supports local detection and human triage for Nginx/web logs. It is not a WAF, exploit executor, prevention system, or guarantee for unknown vulnerabilities. It is designed for shadow mode.

## Assets

- Local normalized request events and source IPs in SQLite.
- Pseudonymous user/session/request identifiers.
- Model endpoint credentials/configuration and downloaded local model weights.
- Operator feedback and review decisions.

## Adversaries and untrusted input

Remote clients can choose request paths, query strings, methods, status-triggering behavior, user-agent/referer headers, and potentially remote-user values. These log fields are untrusted. A crafted user-agent may resemble instructions or ask a model to ignore policy; raw attacker text is not included in Jev context. Prompt-injection-like variants are tested by checking identical feature objects and model payload allowlisting.

Operators can misconfigure the provider URL or expose the dashboard. A compromised host, SQLite file, dependency, or model endpoint is outside the protection provided by application-level normalization.

## Controls

- JSON field whitelist and typed schema; secret-bearing and unknown keys are dropped.
- Query/fragment removal, method allowlisting, valid IP parsing, and pseudonymized session/request/user IDs.
- Local feature allowlist before model calls; bounded local response cache.
- Explainable rule evidence, category calibration, uncertainty state, and human feedback.
- Loopback default; non-loopback binds require Basic-auth credentials. Use TLS termination for any external network.
- No automatic action against production traffic.

## Residual risks

The model can be wrong, overconfident, or coerced by structured-feature combinations; calibration only reflects the versioned synthetic/operational validation sample. False positives and false negatives remain possible. Local data can expose personal information through paths, IPs and user-agent values. File rotation and retention depend on the operator. Model/provider endpoint compromise can affect decision integrity.
