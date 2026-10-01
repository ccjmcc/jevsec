# Threat model

## Assets

Access logs, pseudonymous session identifiers, local model availability, assessment integrity, and operator credentials on the host.

## Adversaries and threats

- Remote clients can control request paths, user-agent and referer strings, status patterns, and request timing represented in logs.
- Prompt-like text can appear in attacker-controlled fields. Raw strings are excluded from provider context; feature names and data types are fixed.
- Malformed log lines can exhaust parser time or corrupt ingestion; parse failures are counted and skipped.
- Local users/processes may access the unauthenticated dashboard or SQLite file. Loopback binding and host access controls are required.
- Model/API failures can delay scoring; a configured timeout and rule-only mode are available.

## Boundaries and residual risk

Aggregation can lose relevant sequence detail, heuristics can flag legitimate crawlers or API clients, and local models can be wrong or overconfident. The dashboard is not an enforcement point. The v0.1 API has no authentication, retention scheduler, signed audit trail, rate limiting, or production isolation. Treat all results as advisory.
