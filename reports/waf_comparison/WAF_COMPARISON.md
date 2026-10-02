# JevSec vs OWASP CRS: local benchmark

- WAF: `owasp/modsecurity-crs:4.29.0-nginx-202609301109`; pinned reference `owasp/modsecurity-crs@sha256:ac057618e2c42e8192c000cb918ae1dff11446cf12beb6b23d4fa0065b0fe5be`; local image digest `owasp/modsecurity-crs@sha256:ac057618e2c42e8192c000cb918ae1dff11446cf12beb6b23d4fa0065b0fe5be`.
- CRS policy: paranoia level 1, blocking paranoia level 1, inbound anomaly threshold 5.
- Requests were sent only through a loopback-published WAF container to an in-process localhost origin. No external hosts were contacted.
- The behavior corpus contains 12 synthetic, non-exploit requests per source-IP window. Attack labels describe behavior such as repeated login failure, enumeration, or suspicious status patterns; the request payloads are intentionally safe.
- Data provenance is recorded per run in `reports/waf_comparison/waf_comparison.json`: generator version inputs, seed, full-window count, and SHA-256 fingerprint.
- A WAF window is positive when any of its 12 requests receives HTTP 403. Qwen3 is measured on the same held-out entities using validation-calibrated Hybrid review decisions.
- Exact repeated method/path/User-Agent signatures are sent once through the request-stateless CRS policy and the result is projected to every matching window. No rate-limit plugin is configured; this is a detection comparison, not a 144,000-request throughput test.
- This is a complementarity comparison, not a head-to-head replacement claim: CRS inspects HTTP request content; JevSec sees aggregate behavior features and does not receive raw paths or user-agent text.

## Behavior-window test split

| Requested test prevalence | Windows | Actual prevalence | System | Precision | Recall | F1 | FPR | FNR | Review/block rate | TP / FP / FN / TN |
|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---|
| 1pct | 4,000 | 1.00% | OWASP CRS (any 403 in 12 requests) | n/a | 0.000 | 0.000 | 0.000% | 100.000% | 0.000% | 0 / 0 / 40 / 3,960 |
| 1pct | 4,000 | 1.00% | Qwen3-4B calibrated Hybrid | 1.000 | 0.625 | 0.769 | 0.000% | 37.500% | 0.625% | 25 / 0 / 15 / 3,960 |
  - 1pct CRS unique-signature HTTP latency: p50 25.62 ms / p95 51.41 ms (not a load-test throughput result).
| 5pct | 4,000 | 5.00% | OWASP CRS (any 403 in 12 requests) | n/a | 0.000 | 0.000 | 0.000% | 100.000% | 0.000% | 0 / 0 / 200 / 3,800 |
| 5pct | 4,000 | 5.00% | Qwen3-4B calibrated Hybrid | 1.000 | 0.695 | 0.820 | 0.000% | 30.500% | 3.475% | 139 / 0 / 61 / 3,800 |
  - 5pct CRS unique-signature HTTP latency: p50 20.94 ms / p95 43.59 ms (not a load-test throughput result).
| 10pct | 4,000 | 10.00% | OWASP CRS (any 403 in 12 requests) | n/a | 0.000 | 0.000 | 0.000% | 100.000% | 0.000% | 0 / 0 / 400 / 3,600 |
| 10pct | 4,000 | 10.00% | Qwen3-4B calibrated Hybrid | 1.000 | 0.688 | 0.815 | 0.000% | 31.250% | 6.875% | 275 / 0 / 125 / 3,600 |
  - 10pct CRS unique-signature HTTP latency: p50 22.01 ms / p95 47.55 ms (not a load-test throughput result).

## CRS request-signature positive controls

These well-known detection strings were sent to the localhost WAF and never to an external application. They test that the CRS engine is active; they are not used to claim JevSec payload detection.

| Fixture | Attack-like control | HTTP status | Blocked |
|---|---:|---:|---:|
| benign_search | no | 200 | no |
| sqli_boolean_probe | yes | 403 | yes |
| xss_probe | yes | 403 | yes |
| path_traversal_probe | yes | 403 | yes |
| command_injection_probe | yes | 403 | yes |

Blocked 4/4 attack-signature controls; blocked 0/1 benign controls. Positive-control sample is intentionally small and not a CRS effectiveness certification.

## Interpretation and limitations

The behavior labels do not imply malicious request syntax. A request-signature WAF can correctly pass a low-rate client that repeatedly fails login, enumerates harmless routes, or behaves unusually after authentication; JevSec can aggregate these patterns. Conversely, request payloads that match CRS signatures are squarely in the WAF's domain. Run both in shadow/monitoring mode during evaluation and keep the WAF as the enforcement layer.
Synthetic prevalence is controlled and differs from production traffic. Results depend on scenario mix, request fields, CRS version, paranoia/blocking settings, WAF exclusions, and application behavior. The model latency is reported in `reports/BENCHMARK_V2.md`; WAF request latency is the round-trip for the deduplicated signature set and is not a throughput measurement or directly comparable to a per-window model inference.

Full JSON, per-window CSVs, per-scenario breakdowns and status counts are alongside this report under `reports/waf_comparison/`.
