# JevSec Roadmap

JevSec is a research-alpha, shadow-mode behavioral security triage project. The roadmap is intentionally focused on evidence quality before enforcement.

## v0.3 — Sequence context

- Preserve meaningful request ordering in privacy-safe behavior windows.
- Improve low-intensity and unknown-suspicious behavior recall.
- Separate review-worthiness from behavior-category classification.
- Add sequence-aware failure analysis.
- Target substantially better risk ranking than the current semi-real baseline.

## v0.4 — WAF signal fusion

- Ingest WAF anomaly scores and matched-rule identifiers as optional signals.
- Keep request-level WAF enforcement separate from JevSec review decisions.
- Evaluate whether WAF + behavior context improves recall without materially increasing false review rate.
- Add explicit disagreement states for WAF/rules/model conflict.

## v0.5 — Real shadow validation

- Run on scrubbed or privacy-reviewed real Nginx logs.
- Build realistic benign baselines.
- Measure alert/review volume, latency, and operator usefulness.
- Report confidence intervals and failure modes instead of headline metrics alone.

## Before any enforcement mode

JevSec should not automatically block traffic until there is strong evidence across multiple environments, clear rollback semantics, conservative policy controls, and human-review experience showing acceptable false-positive behavior.

## Research questions

1. Does sequence context materially improve AUROC over aggregate counts?
2. Which behavior classes are genuinely complementary to OWASP CRS?
3. Can a 4B local model remain useful at practical review volumes?
4. How much context can be removed for privacy without destroying useful signal?
