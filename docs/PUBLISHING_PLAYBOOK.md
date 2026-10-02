# JevSec Publishing Playbook

This document turns one project into several different stories instead of reposting the same announcement everywhere.

## Core rule

Do not publish the same article with a different title five times.

Use a different angle for each audience:

| Audience | Best angle |
|---|---|
| GitHub | runnable project, architecture, benchmark, limitations |
| Personal blog | engineering story and research process |
| Zhihu | why this problem matters and what the numbers mean |
| V2EX | what I built, why, how to run it, ask for technical feedback |
| Juejin | implementation details and architecture |
| Bilibili | visual demo and before/after comparison |
| Show HN | something people can actually run and critique |
| Product Hunt | concise product positioning and polished demo |
| X / LinkedIn | one graph, one result, one limitation |
| Reddit / security communities | methodology, failure cases, reproducibility |

## The five long-form articles

1. Why JevSec is not an AI WAF
2. Benchmark theater: why the first pretty numbers were not enough
3. Can a local 4B model help with web security triage?
4. Sequence Context: the v0.3 research direction
5. Why JevSec stays in Shadow Mode

All five are published in the Fuwari source repository.

## Suggested publishing cadence

Do not dump everything in one hour.

### Day 1 — GitHub + personal blog

Publish the main technical introduction.

Suggested title:

JevSec：我为什么想做一个“看行为而不是只看单次请求”的本地 AI 安全引擎

Goal: establish the project and link to GitHub.

### Day 2 — V2EX

Title:

我做了个本地 Qwen3-4B Web 行为安全引擎，想听听大家怎么喷这个 benchmark

Body:

最近在做一个叫 JevSec 的开源实验项目。

核心想法不是用 AI 替代 WAF，而是把多条 Web 请求聚合成短行为窗口，让本地 Qwen3-4B 和规则一起做 shadow-mode triage。

目前半真实 held-out replay：
- Static rules：30 / 145 异常窗口
- Qwen3-4B：34 / 145
- Hybrid：39 / 145
- Hybrid Precision：97.5%
- 正常窗口误复核：1 / 105

但不漂亮的地方也很明显：Hybrid AUROC 只有 0.454，所以现在只能说多捞到了一些异常，不能说模型已经会稳定排序风险。

项目：
https://github.com/ccjmcc/jevsec

展示页：
https://www.easytool.me/jevsec/

现在最想听的是 benchmark 设计、行为特征和 false positive 方面的批评。

Do not ask for stars. Ask for technical criticism.

### Day 3 — Zhihu

Use article:

安全 AI Benchmark 最容易骗人：我把 JevSec 的漂亮数字重新打回现实

Recommended opening:

很多 AI 安全 Demo 最容易做的不是模型，而是做出一张漂亮 benchmark。真正麻烦的是，当你开始把 validation、test leakage、false positive 和 AUROC 都算进去之后，那些数字还剩多少。

At the end, link to the repository and the full benchmark.

### Day 4 — Juejin

Use article:

4B 本地模型能做 Web 安全判断吗？我用 Qwen3-4B 做了 JevSec

Add a short architecture section near the top:

Nginx / JSONL
→ privacy-aware normalization
→ behavior windows
→ rules + local Qwen3-4B
→ review findings

Juejin readers generally benefit from implementation detail, so focus less on product marketing and more on architecture.

### Day 5 — Bilibili

Video title:

我用本地 Qwen3-4B 做了个 Web 安全引擎，它真的比规则强吗？

Thumbnail text:

39 vs 30
但 AUROC 只有 0.454

Suggested 4-minute structure:

0:00 — What JevSec is
0:20 — WAF sees one request; JevSec sees a behavior window
0:55 — Demo: start local service and dashboard
1:35 — Replay a suspicious behavior chain
2:15 — Show the 39 vs 30 benchmark
2:50 — Reveal the weak AUROC
3:20 — Explain Sequence Context v0.3
3:50 — GitHub and request for feedback

Do not turn the video into an exploit tutorial. Keep the demo synthetic and focused on detection / triage.

### Day 6 — Show HN

Title:

Show HN: JevSec – local Qwen3-4B behavioral security triage for web traffic

Suggested first comment:

I built JevSec to explore a narrow question: can a small local model add useful cross-request context beside an existing WAF?

It runs in shadow mode, groups Nginx/JSONL events into behavior windows, and combines deterministic rules with a local Qwen3-4B decision layer.

Current semi-real held-out replay result:
- static rules: 30 / 145 anomalous windows detected
- Qwen3-4B: 34 / 145
- Hybrid: 39 / 145
- Hybrid precision: 97.5%
- 1 false review among 105 normal windows

The uncomfortable result is also public: Hybrid risk-score AUROC is only 0.454, so I do not consider this production-ready or evidence of unknown-attack detection.

The next experiment is sequence-preserving context rather than mostly aggregate statistics.

Repo:
https://github.com/ccjmcc/jevsec

I would especially appreciate criticism of the benchmark and architecture.

Important: use the GitHub repository as the submission URL, not the marketing landing page.

### Day 7 or later — Product Hunt

Do Product Hunt only after the demo page and screenshots are polished.

Product name:

JevSec

Tagline:

Local AI behavioral security triage that complements your WAF

Description:

JevSec is a self-hosted security triage layer powered by local Qwen3-4B. It groups activity across web requests, combines deterministic evidence with local-model decisions, and surfaces structured findings for human review. It runs in shadow mode and is designed to complement, not replace, WAF enforcement.

Primary URL:

https://www.easytool.me/jevsec/

Maker comment:

I built JevSec because request-level WAF rules and cross-request behavior analysis are different problems.

The current release is intentionally conservative: local inference, privacy-aware context, shadow mode, reproducible benchmarks, and explicit failure metrics.

The project is still Research Alpha. The current semi-real benchmark shows incremental review coverage, while AUROC remains weak. I am launching it early because I want feedback on the architecture and evaluation before adding any enforcement mode.

## Short posts

### X / LinkedIn

Your WAF sees requests. JevSec sees behavior.

I built a self-hosted behavioral security triage layer using local Qwen3-4B.

Current held-out semi-real replay:
Rules: 30 / 145 detected
Qwen: 34 / 145
Hybrid: 39 / 145
Precision: 97.5%
False reviews: 1 / 105 normal windows

Important caveat: Hybrid AUROC is still only 0.454.

Research Alpha, shadow mode, fully open:
https://github.com/ccjmcc/jevsec

### Short Chinese post

最近做了个开源实验项目 JevSec。

不是 AI WAF，而是放在 WAF 旁边看“跨请求行为”的本地安全复核层。

当前半真实 held-out：
规则抓 30 / 145
Qwen 抓 34 / 145
Hybrid 抓 39 / 145
Precision 97.5%
正常误复核 1 / 105

但 AUROC 只有 0.454，所以我不会说它已经比 WAF 强。

代码、benchmark、失败分析全公开：
https://github.com/ccjmcc/jevsec

## What not to do

Avoid these claims:

- replaces your WAF
- zero-day protection
- detects unknown attacks
- zero false positives
- production-proven
- 30% better security

Use narrower claims:

- 39 vs 30 anomalous windows detected on the current held-out replay sample
- 30% more detections relative to the static-rule baseline on this sample
- one additional false review among 105 normal windows
- Research Alpha
- shadow mode
- complements WAF enforcement

## Every post should contain

1. One sentence explaining JevSec.
2. One concrete benchmark result.
3. One limitation.
4. One link to GitHub.
5. One clear question asking for technical feedback.

That combination is much more credible than a pure launch advertisement.
