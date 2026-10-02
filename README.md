# JevSec

**Self-hosted behavioral security triage powered by local Qwen3-4B.**

[![Status](https://img.shields.io/badge/status-research%20alpha-f59e0b)](docs/ROADMAP.md)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)](pyproject.toml)
[![Model](https://img.shields.io/badge/local%20model-Qwen3--4B-8b5cf6)](https://github.com/QwenLM/Qwen3)
[![Mode](https://img.shields.io/badge/deployment-shadow%20mode-2563eb)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT-16a34a)](LICENSE)

> **Your WAF sees requests. JevSec sees behavior.**

[Project page](https://www.easytool.me/jevsec/) · [Technical write-up](https://www.ccjmcc.xyz/posts/jevsec-local-ai-security-triage/) · [Benchmark](#benchmark) · [Architecture](ARCHITECTURE.md) · [Roadmap](docs/ROADMAP.md)

![JevSec benchmark](docs/media/benchmark.svg)

## Why JevSec exists

Request-level WAFs are strong at matching exploit syntax and known request patterns. JevSec is aimed at the layer above that: **short sequences of activity that become suspicious only when viewed together**.

JevSec groups web activity into behavior windows, combines deterministic evidence with local-model decisions, and produces structured findings for human review.

```text
Nginx / JSONL
      │
      ▼
privacy-aware normalization
      │
      ▼
behavior windows
      │
      ├── deterministic rules
      │
      └── local Qwen3-4B
               │
               ▼
BENIGN / REVIEW / HIGH_RISK / UNCERTAIN
               │
               ▼
       local SQLite + dashboard
```

**JevSec complements a WAF. It does not replace WAF enforcement.**

## Benchmark

### Semi-real CSIC replay

Deterministic held-out sample:

- **250 test windows**
- **145 anomalous / 105 normal**
- local **Qwen3-4B**
- thresholds selected from validation only
- shadow-mode review, not automated blocking

| System | Recall | Precision | Observed FPR | Anomalies detected |
|---|---:|---:|---:|---:|
| Static rules | 20.69% | 100.00% | 0.00% | 30 / 145 |
| Qwen3-4B | 23.45% | 97.14% | 0.95% | 34 / 145 |
| **JevSec Hybrid** | **26.90%** | **97.50%** | **0.95%** | **39 / 145** |

**Headline:** Hybrid detected **39 vs 30 anomalous windows** compared with the static-rule baseline — **30% more detections** — while adding **1 false review among 105 normal windows**.

For windows containing only one anomalous request mixed with normal requests, recall moved from **16.67% to 25.00%** (**+50% relative** on that small subgroup).

### What the benchmark does not prove

Current risk-score AUROC remains weak:

- Static rules: **0.522**
- Qwen3-4B: **0.473**
- Hybrid: **0.454**

So the result is evidence of **incremental review coverage**, not evidence that the model globally ranks risk well, detects unknown vulnerabilities in production, or outperforms a mature WAF at request-level exploit signatures.

See [public benchmark v2](reports/BENCHMARK_V2.md), [OWASP CRS comparison](reports/WAF_COMPARISON.md), and [failure analysis](reports/FAILURE_ANALYSIS.md).

## JevSec vs a traditional WAF

| | Traditional request-level WAF | JevSec |
|---|---|---|
| Primary view | Individual HTTP request | Activity across a behavior window |
| Best fit | Request syntax / signatures / exploit indicators | Sequence, frequency, context, rule-model disagreement |
| Output | Allow / block / anomaly score | Review-oriented risk finding |
| Model | Usually not required | Local Qwen3-4B |
| Deployment | Enforcement layer | **Shadow / triage layer** |
| Relationship | Keep it | Add JevSec beside it |

The OWASP CRS report in this repository intentionally treats the two systems as complementary rather than as interchangeable products.

## Key properties

- **Self-hosted** — core application and decision workflow stay local.
- **Local AI** — current supported model is Qwen3-4B through local-jev.
- **Privacy-aware context** — the model receives whitelisted aggregate features rather than raw request paths, cookies, Authorization values, or user-agent strings.
- **Behavior windows** — aggregate by source IP and optional pseudonymous session identity.
- **Explainable evidence** — rule/model evidence is kept with each finding.
- **Shadow mode first** — no automatic firewall changes, bans, or request blocking.
- **Reproducible evaluation** — fixed seeds, validation-only threshold fitting, held-out test reporting.

## Quick start

Requirements: Python 3.12, `uv`, Git.

```bash
git clone https://github.com/ccjmcc/jevsec.git
cd jevsec
./scripts/demo.sh
```

Open:

```text
http://127.0.0.1:8000
```

The first local-model launch downloads Qwen3-4B weights.

UI-only smoke test:

```bash
SDE_DECISION_PROVIDER=mock ./scripts/demo.sh
```

## Shadow mode

```bash
security-engine shadow --nginx /var/log/nginx/access.log
```

Shadow mode tails logs and emits structured findings. It does **not** block requests, change network configuration, or ban addresses.

## Docker

On Linux:

```bash
cp .env.example .env
docker compose up --build
```

On Apple Silicon, run local-jev natively if you want Apple GPU acceleration.

## Privacy and security

JevSec is intentionally conservative about what reaches the model:

- cookies are not retained;
- Authorization values are not retained;
- passwords and API keys are discarded;
- unknown JSON fields are discarded;
- user/session identifiers are pseudonymized before aggregation;
- model outputs are advisory.

Read [PRIVACY.md](PRIVACY.md), [SECURITY.md](SECURITY.md), and [THREAT_MODEL.md](THREAT_MODEL.md).

## Project status

**Research Alpha / shadow-mode engineering prototype.**

The next milestones are real-world shadow validation, better sequence context, stronger risk ranking, and tighter WAF-signal fusion. See the [roadmap](docs/ROADMAP.md).

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Usage](docs/USAGE.md)
- [Benchmark index](BENCHMARK.md)
- [OWASP CRS comparison](reports/WAF_COMPARISON.md)
- [Failure analysis](reports/FAILURE_ANALYSIS.md)
- [Privacy](PRIVACY.md)
- [Security policy](SECURITY.md)
- [Threat model](THREAT_MODEL.md)
- [Press kit](docs/PRESS_KIT.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
