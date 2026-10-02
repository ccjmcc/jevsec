# JevSec Press Kit

## One-line description

**JevSec is a self-hosted, local-AI behavioral security triage layer that analyzes activity across web requests and complements existing WAF enforcement.**

## Short description

JevSec groups Nginx or JSONL events into behavior windows, combines deterministic evidence with local Qwen3-4B decisions, and produces structured review findings. It is designed for shadow-mode evaluation and does not automatically block requests.

## Positioning

**Your WAF sees requests. JevSec sees behavior.**

JevSec is not marketed as a WAF replacement. Request-level exploit syntax remains the domain of mature WAFs such as OWASP CRS. JevSec focuses on cross-request context, sequence, frequency, and rule/model disagreement.

## Current semi-real benchmark

Deterministic held-out CSIC replay sample:

- 250 test windows
- 145 anomalous / 105 normal
- Static rules: 30 / 145 detected
- Qwen3-4B: 34 / 145 detected
- JevSec Hybrid: 39 / 145 detected
- Hybrid precision: 97.50%
- Hybrid observed FPR: 0.95% (1 / 105 normal windows)

A concise description of the result:

> On this held-out replay sample, JevSec Hybrid detected 39 anomalous windows versus 30 for the static-rule baseline, while adding one false review among 105 normal windows.

The benchmark is not a production-effectiveness claim. Current risk-score AUROC remains weak and is disclosed in the README.

## Links

- Project: https://github.com/ccjmcc/jevsec
- Product page: https://www.easytool.me/jevsec/
- Technical article: https://www.ccjmcc.xyz/posts/jevsec-local-ai-security-triage/
- Benchmark: https://github.com/ccjmcc/jevsec/blob/main/reports/BENCHMARK_V2.md
- WAF comparison: https://github.com/ccjmcc/jevsec/blob/main/reports/WAF_COMPARISON.md

## Suggested descriptions

### 20 words

Local Qwen3-4B behavioral security triage for web traffic, designed to complement WAFs with cross-request context.

### 50 words

JevSec is a self-hosted behavioral security triage engine for web traffic. It aggregates short activity windows, combines deterministic evidence with a local Qwen3-4B decision layer, and produces structured findings for human review. It runs in shadow mode and is designed to complement, not replace, mature WAF enforcement.

## Claims we intentionally avoid

Do not describe JevSec as:

- a zero-day prevention system;
- a replacement for OWASP CRS or other WAFs;
- production-proven;
- guaranteed unknown-attack detection;
- zero-false-positive security.

## Logo / visual

For public posts, use the benchmark visual at `docs/media/benchmark.svg`.
