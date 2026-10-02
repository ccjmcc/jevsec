# JevSec — Security Decision Engine

**Self-hosted behavioral security triage powered by local Qwen3-4B.**

> Traditional WAFs inspect requests. **JevSec analyzes behavior across requests.**

![JevSec benchmark](docs/media/benchmark.svg)

## Latest semi-real benchmark

Deterministic held-out CSIC replay sample:

- **250 test windows**
- **145 anomalous / 105 normal**
- Local **Qwen3-4B**
- Validation-only calibration
- Shadow-mode review, not automated blocking

| System | Recall | Precision | Observed FPR | Anomalies detected |
|---|---:|---:|---:|---:|
| Static rules | 20.69% | 100.00% | 0.00% | 30 / 145 |
| Qwen3-4B | 23.45% | 97.14% | 0.95% | 34 / 145 |
| **JevSec Hybrid** | **26.90%** | **97.50%** | **0.95%** | **39 / 145** |

### Headline result

**JevSec Hybrid detected 39 anomalous windows vs 30 for the static-rule baseline — 30% more detections — while adding one false review among 105 normal windows.**

On the low-intensity subgroup with only one anomalous request mixed into a window, recall improved from **16.67% to 25.00%** (**+50% relative**).

### Important limitation

Current risk-score ranking is still weak:

- Static rules AUROC: **0.522**
- Qwen3-4B AUROC: **0.473**
- Hybrid AUROC: **0.454**

This benchmark shows incremental review coverage, **not** production effectiveness, unknown-vulnerability detection, or superiority over a mature WAF.

## Why JevSec

A request-level WAF and a behavioral review engine solve different problems.

JevSec groups activity into short behavior windows, combines deterministic evidence with local-model decisions, and produces structured outcomes for human review.

Typical flow:

```
Nginx / JSONL
    ↓
privacy-aware normalization
    ↓
behavior windows
    ↓
rules + local Qwen3-4B
    ↓
BENIGN / REVIEW / HIGH_RISK / UNCERTAIN
    ↓
local SQLite + dashboard
```

JevSec is designed to **complement** an existing WAF, not replace it.

## Quick start

Requirements: Python 3.12, `uv`, Git.

```bash
git clone https://github.com/ccjmcc/jevsec.git
cd jevsec
./scripts/demo.sh
```

Open:

```
http://127.0.0.1:8000
```

The first local-model launch downloads Qwen3-4B weights.

For a deterministic UI-only smoke test:

```bash
SDE_DECISION_PROVIDER=mock ./scripts/demo.sh
```

## Shadow mode

```bash
security-engine shadow --nginx /var/log/nginx/access.log
```

Shadow mode tails logs and emits structured findings. It does not block requests, change network configuration, or ban addresses.

## Benchmark and WAF comparison

- [Public benchmark v2](reports/BENCHMARK_V2.md)
- [OWASP CRS comparison](reports/WAF_COMPARISON.md)
- [Failure analysis](reports/FAILURE_ANALYSIS.md)

The OWASP CRS comparison uses a different controlled dataset and should not be directly ranked against the CSIC replay results.

## Privacy

Cookies, Authorization values, passwords, API keys and unknown JSON keys are not retained. User/session identifiers are pseudonymized before aggregation. The local decision layer receives whitelisted aggregate features rather than raw request paths or user-agent strings.

See:

- [Architecture](ARCHITECTURE.md)
- [Privacy](PRIVACY.md)
- [Security](SECURITY.md)
- [Threat model](THREAT_MODEL.md)

## Docker

On Linux:

```bash
cp .env.example .env
docker compose up --build
```

On Apple Silicon, run local-jev natively for Apple GPU acceleration.

## Project state

JevSec is an **engineering prototype / research alpha**.

Current strengths:

- self-hosted;
- local Qwen3-4B;
- reproducible benchmarks;
- behavior-window aggregation;
- shadow-mode operation;
- explainable rule/model evidence.

Current limitations:

- semi-real and synthetic benchmarks are not production estimates;
- current model risk ranking remains weak;
- real-world shadow-mode validation is still required;
- JevSec does not replace WAF enforcement.

## License and contribution

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), and repository license information.
