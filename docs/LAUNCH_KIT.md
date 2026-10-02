# JevSec Launch Kit

## Core message

**Your WAF sees requests. JevSec sees behavior.**

JevSec is a self-hosted behavioral security triage layer powered by local Qwen3-4B. It is designed to complement request-level WAF enforcement with cross-request context and shadow-mode review.

## Headline metric

On the current semi-real held-out CSIC replay sample:

- Static rules: 30 / 145 anomalous windows detected
- JevSec Hybrid: 39 / 145 detected
- Hybrid precision: 97.50%
- Observed Hybrid FPR: 0.95% (1 / 105 normal windows)

Safe shorthand:

> **39 vs 30 anomalous windows detected on the current held-out replay sample.**

Do not describe this as production effectiveness.

## Show HN draft title

Show HN: JevSec – local Qwen3-4B behavioral security triage for web traffic

## Product Hunt tagline

Local AI behavioral security triage that complements your WAF.

## Short social post

I built JevSec, a self-hosted behavioral security triage layer powered by local Qwen3-4B.

The idea: traditional WAFs inspect requests; JevSec looks across short behavior windows.

Current semi-real held-out replay result:
- static rules: 30 / 145 anomalous windows detected
- Hybrid: 39 / 145
- precision: 97.50%
- 1 false review among 105 normal windows

Still Research Alpha: AUROC is weak and the data is not production traffic. The repo includes the benchmark, WAF comparison, failure analysis, privacy design and roadmap.

https://github.com/ccjmcc/jevsec

## Submission notes

Prefer technical, reproducible framing over security-marketing claims. Keep these limitations visible:

- semi-real / synthetic benchmarks are not production estimates;
- current risk-score AUROC is weak;
- JevSec is not a WAF replacement;
- no zero-day or unknown-vulnerability claim;
- no automated blocking.
