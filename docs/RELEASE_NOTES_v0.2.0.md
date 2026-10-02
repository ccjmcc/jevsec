# JevSec v0.2.0 — Public Research Alpha

JevSec is now packaged for public evaluation as a **self-hosted behavioral security triage layer powered by local Qwen3-4B**.

> **Your WAF sees requests. JevSec sees behavior.**

## Highlights

- Local Qwen3-4B decision provider through local-jev.
- Behavior-window aggregation for Nginx / JSONL traffic.
- Deterministic rules + local-model Hybrid review path.
- Shadow mode: no automatic blocking, firewall changes, or IP bans.
- Privacy-aware model context with whitelisted aggregate features.
- Docker support for Linux and native Apple Silicon local-model execution.
- Authenticated non-loopback dashboard/API mode.
- Reproducible benchmark and OWASP CRS comparison.
- Failure analysis, threat model, privacy policy, roadmap, and CI.

## Semi-real held-out result

Current deterministic CSIC replay sample:

| System | Recall | Precision | Observed FPR | Detected |
|---|---:|---:|---:|---:|
| Static rules | 20.69% | 100.00% | 0.00% | 30 / 145 |
| Qwen3-4B | 23.45% | 97.14% | 0.95% | 34 / 145 |
| **JevSec Hybrid** | **26.90%** | **97.50%** | **0.95%** | **39 / 145** |

On this held-out replay sample, Hybrid detected **39 anomalous windows vs 30** for the static-rule baseline, while adding **1 false review among 105 normal windows**.

## Important limitation

Current risk-score AUROC is still weak:

- Static rules: 0.522
- Qwen3-4B: 0.473
- Hybrid: 0.454

This release is **not** a production-effectiveness claim and does not claim unknown-vulnerability or zero-day detection.

JevSec remains a **Research Alpha / shadow-mode engineering prototype** intended to complement mature WAF enforcement.

## Quick start

```bash
git clone https://github.com/ccjmcc/jevsec.git
cd jevsec
./scripts/demo.sh
```

Then open:

```text
http://127.0.0.1:8000
```

## Documentation

- README: https://github.com/ccjmcc/jevsec
- Project page: https://www.easytool.me/jevsec/
- Technical write-up: https://www.ccjmcc.xyz/posts/jevsec-local-ai-security-triage/
- Roadmap: https://github.com/ccjmcc/jevsec/blob/main/docs/ROADMAP.md
- WAF comparison: https://github.com/ccjmcc/jevsec/blob/main/reports/WAF_COMPARISON.md
- Failure analysis: https://github.com/ccjmcc/jevsec/blob/main/reports/FAILURE_ANALYSIS.md

## Next milestone

v0.3 focuses on **Sequence Context**: preserving privacy-safe request order so the local model can reason about behavior chains rather than mostly aggregate statistics.
