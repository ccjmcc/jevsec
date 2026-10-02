# Privacy

JevSec stores normalized events, derived assessments, structured stories and operator feedback in local SQLite. The software does not include telemetry or a cloud inference client. Local model weights are downloaded separately; System-One requests go to the configured Jev-compatible endpoint, which should be local or operator-controlled.

## Collection and minimization

- JSONL input is field-whitelisted. Cookie, Authorization, password, API key, and unknown JSON properties are discarded.
- Session, request, and pseudonymous user identifiers are hashed at ingestion. Nginx `$remote_user` is hashed before storage.
- Path query strings/fragments are removed. Referers are reduced to scheme and host.
- Source IP, normalized path, status, timestamp, and user-agent text may remain in the local event database to support timelines; these can identify or describe users and require operator-controlled access/retention.
- Jev receives only fixed aggregate numeric/boolean features and hashed identity context is not included. Raw path, user-agent, referer and credentials are never sent to the model.
- Feedback stores entity/window and one of true-positive, false-positive, or unsure. It does not automatically retrain a model or alter thresholds.

The log fields are untrusted attacker-controlled input unless independently verified. Synthetic benchmarks use reserved example/benchmark address space and safe route names, not executable exploit payloads.
