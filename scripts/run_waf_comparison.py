#!/usr/bin/env python3
"""Run an isolated localhost OWASP CRS vs Qwen3 behavior-window comparison."""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import statistics
import subprocess
import threading
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
CRS_TAG = "owasp/modsecurity-crs:4.29.0-nginx-202609301109"
CRS_IMAGE = "owasp/modsecurity-crs@sha256:ac057618e2c42e8192c000cb918ae1dff11446cf12beb6b23d4fa0065b0fe5be"
ORIGIN_PORT = 18080
WAF_PORT = 18081
CONCURRENCY = 24


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size:
            self.rfile.read(min(size, 1_000_000))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, *_args):
        pass


class ThreadingOrigin(ThreadingHTTPServer):
    request_queue_size = 256
    daemon_threads = True


def _metric(rows: list[dict], key: str) -> dict:
    tp = sum(bool(r["label"]) and bool(r[key]) for r in rows)
    fp = sum(not bool(r["label"]) and bool(r[key]) for r in rows)
    fn = sum(bool(r["label"]) and not bool(r[key]) for r in rows)
    tn = len(rows) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision is not None and precision + recall else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "fnr": fn / (fn + tp) if fn + tp else 0.0,
            "review_rate": (tp + fp) / len(rows) if rows else 0.0}


def _labels(path: Path) -> dict[str, tuple[str, str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return {r["entity"]: (r["category"], r["scenario"], r["split"]) for r in csv.DictReader(f)}


def _test_requests(data_dir: Path, labels: dict[str, tuple[str, str, str]]) -> dict[str, list[dict]]:
    windows: dict[str, list[dict]] = defaultdict(list)
    with (data_dir / "events.jsonl").open(encoding="utf-8") as f:
        for line in f:
            event = json.loads(line)
            ip = event["source_ip"]
            if ip in labels and labels[ip][2] == "test":
                windows[ip].append(event)
    return windows


def _signature(event: dict) -> tuple[str, str, str]:
    """CRS default rules inspect each request independently; no rate-limit rules are enabled."""
    return (event.get("method", "GET"), event.get("path") or "/", event.get("user_agent") or "JevSecSynthetic/1.0")


async def _scan_windows(base_url: str, windows: dict[str, list[dict]]):
    limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
    timeout = httpx.Timeout(20, connect=5)
    semaphore = asyncio.Semaphore(CONCURRENCY)
    durations: list[float] = []
    statuses: Counter = Counter()

    async with httpx.AsyncClient(base_url=base_url, limits=limits, timeout=timeout, follow_redirects=False) as client:
        async def send(event: dict) -> tuple[tuple[str, str, str], int, float]:
            headers = {"User-Agent": event.get("user_agent") or "JevSecSynthetic/1.0",
                       "Host": "benchmark.local", "X-Forwarded-For": event["source_ip"],
                       "X-JevSec-Synthetic": "behavior-benchmark"}
            path = event.get("path") or "/"
            method = event.get("method", "GET")
            async with semaphore:
                started = time.perf_counter()
                response = await client.request(method, path, headers=headers)
                return _signature(event), response.status_code, (time.perf_counter() - started) * 1000

        signatures: dict[tuple[str, str, str], dict] = {}
        for events in windows.values():
            for event in events:
                signatures.setdefault(_signature(event), event)
        tasks = [send(event) for event in signatures.values()]
        scanned = 0
        blocked_signatures: dict[tuple[str, str, str], bool] = defaultdict(bool)
        infra_errors = []
        for coro in asyncio.as_completed(tasks):
            try:
                signature, status, elapsed = await coro
            except Exception as exc:
                infra_errors.append(f"{type(exc).__name__}: {exc}")
                continue
            scanned += 1
            statuses[str(status)] += 1
            durations.append(elapsed)
            if status == 403:
                blocked_signatures[signature] = True
            elif status >= 500:
                infra_errors.append(f"HTTP {status} from WAF/origin")
            if scanned % 5000 == 0:
                print(f"WAF requests completed: {scanned:,}/{len(tasks):,}", flush=True)
    if infra_errors:
        raise RuntimeError(f"WAF benchmark infrastructure errors ({len(infra_errors)}); examples: {infra_errors[:5]}")
    return blocked_signatures, durations, statuses, len(signatures)


async def _controls(base_url: str) -> tuple[list[dict], list[float]]:
    controls = [
        ("benign_search", "/search?q=security+headers", False),
        ("sqli_boolean_probe", "/search?id=1%20OR%201%3D1", True),
        ("xss_probe", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", True),
        ("path_traversal_probe", "/download?file=..%2F..%2Fetc%2Fpasswd", True),
        ("command_injection_probe", "/tools?cmd=%3Bcat%20%2Fetc%2Fpasswd", True),
    ]
    results, latencies = [], []
    async with httpx.AsyncClient(base_url=base_url, timeout=20) as client:
        for name, path, is_attack in controls:
            started = time.perf_counter()
            response = await client.get(path, headers={"User-Agent": "JevSecLocalWafFixture/1.0", "Host": "benchmark.local"})
            elapsed = (time.perf_counter() - started) * 1000
            latencies.append(elapsed)
            results.append({"fixture": name, "expected_attack_signature": is_attack,
                            "status": response.status_code, "blocked": response.status_code == 403,
                            "latency_ms": round(elapsed, 3)})
    return results, latencies


def _fmt(m: dict) -> str:
    precision = "n/a (no positives predicted)" if m["precision"] is None else f"{m['precision']:.3f}"
    return (f"n={m['n']:,}, TP={m['tp']:,}, FP={m['fp']:,}, FN={m['fn']:,}, TN={m['tn']:,}; "
            f"precision={precision}, recall={m['recall']:.3f}, F1={m['f1']:.3f}, "
            f"FPR={m['fpr']:.3%}, FNR={m['fnr']:.3%}, review/block rate={m['review_rate']:.3%}")


async def run(data_root: Path, output: Path) -> None:
    origin = ThreadingOrigin(("0.0.0.0", ORIGIN_PORT), OriginHandler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    name = f"jevsec-crs-bench-{int(time.time())}"
    container_started = False
    try:
        subprocess.run(["docker", "run", "--detach", "--rm", "--name", name,
                        "--publish", f"127.0.0.1:{WAF_PORT}:8080",
                        "--env", f"BACKEND=http://host.docker.internal:{ORIGIN_PORT}",
                        "--env", "SERVER_NAME=benchmark.local",
                        "--env", "PARANOIA=1", "--env", "BLOCKING_PARANOIA=1",
                        "--env", "ANOMALY_INBOUND=5", CRS_IMAGE], check=True, capture_output=True, text=True)
        container_started = True
        base_url = f"http://127.0.0.1:{WAF_PORT}"
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                response = httpx.get(base_url + "/healthz", timeout=2)
                if response.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(1)
        else:
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout[-4000:]
            raise RuntimeError(f"OWASP CRS did not become ready. Container logs:\n{logs}")

        repo_digest = subprocess.run(["docker", "image", "inspect", CRS_IMAGE, "--format", "{{join .RepoDigests \";\"}}"],
                                     check=True, capture_output=True, text=True).stdout.strip()
        result = {"waf_image": CRS_TAG, "image_ref": CRS_IMAGE, "image_digest": repo_digest,
                  "paranoia_level": 1, "blocking_paranoia_level": 1, "inbound_anomaly_threshold": 5,
                  "runs": [], "payload_controls": [], "methodology": {
                      "request_level_waf_window_rule": "flag behavior window when any of its 12 requests receives HTTP 403",
                      "request_signature_deduplication": "send each exact method/path/user-agent signature once, then project its result to every matching window; default CRS config is request-stateless and no rate-limit plugin is enabled",
                      "behavior_requests_are_safe": True,
                      "qwen_policy": "calibrated_hybrid_review from the same held-out entity windows",
                      "warning": "Behavior corpus labels represent rate/auth/path patterns; benign-looking requests intentionally contain no exploit payloads. WAF signature positives are a separate local-only control set."}}
        for prevalence in ("1pct", "5pct", "10pct"):
            data_dir = data_root / prevalence
            manifest = json.loads((data_dir / "dataset_manifest.json").read_text())
            if manifest.get("generator_version") != 2:
                raise ValueError(f"{data_dir} is not generated by current scenario-stratified dataset code")
            labels = _labels(data_dir / "labels.csv")
            windows = _test_requests(data_dir, labels)
            if len(windows) != int(manifest["behavior_windows"] * .2):
                raise ValueError(f"expected a complete test split in {data_dir}; found {len(windows)} test windows")
            model_report = ROOT / "reports/public_v2/llm-qwen3-4b" / prevalence / "benchmark_results.csv"
            model_meta = json.loads(model_report.with_name("benchmark_results.json").read_text())
            fingerprint = hashlib.sha256((manifest["events_sha256"] + manifest["labels_sha256"]).encode("ascii")).hexdigest()
            if model_meta.get("dataset_fingerprint") != fingerprint:
                raise ValueError(f"Qwen3 report does not match current dataset for {prevalence}; run the public benchmark first")
            model_rows = {r["entity"]: r for r in csv.DictReader(model_report.open(encoding="utf-8")) if r["split"] == "test"}
            blocked_signatures, latencies, statuses, unique_signatures = await _scan_windows(base_url, windows)
            rows = []
            for entity, events in windows.items():
                category, scenario, split = labels[entity]
                qwen = model_rows[entity]
                rows.append({"entity": entity, "category": category, "scenario": scenario,
                             "label": category != "benign", "waf_blocked": any(
                                 blocked_signatures.get(_signature(event), False) for event in events),
                             "qwen3_calibrated_hybrid_review": qwen["calibrated_hybrid_review"].lower() == "true",
                             "request_count": len(events)})
            qwen_metrics = _metric(rows, "qwen3_calibrated_hybrid_review")
            waf_metrics = _metric(rows, "waf_blocked")
            scenarios = defaultdict(list)
            for row in rows:
                scenarios[row["scenario"]].append(row)
            per_scenario = {scenario: {"windows": len(part), "positive": sum(r["label"] for r in part),
                             "waf_blocked": sum(r["waf_blocked"] for r in part),
                             "qwen3_reviewed": sum(r["qwen3_calibrated_hybrid_review"] for r in part)}
                            for scenario, part in sorted(scenarios.items())}
            ordered_latencies = sorted(latencies)
            result["runs"].append({"prevalence": prevalence, "test_windows": len(rows),
                "test_attack_prevalence": sum(r["label"] for r in rows) / len(rows),
                "dataset_fingerprint": fingerprint, "dataset_seed": manifest["seed"],
                "dataset_behavior_windows": manifest["behavior_windows"],
                "waf": waf_metrics, "qwen3_calibrated_hybrid": qwen_metrics,
                "behavior_http_requests": sum(len(events) for events in windows.values()),
                "waf_http_requests_sent": sum(statuses.values()), "waf_unique_signatures": unique_signatures,
                "waf_http_statuses": dict(statuses),
                "waf_request_latency_ms": {"p50": statistics.median(latencies),
                    "p95": ordered_latencies[max(0, int(len(ordered_latencies) * .95) - 1)]},
                "per_scenario": per_scenario})
            output.mkdir(parents=True, exist_ok=True)
            with (output / f"{prevalence}_window_results.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
                writer.writeheader(); writer.writerows(rows)
            print(f"{prevalence}: WAF {_fmt(waf_metrics)} | Qwen3 calibrated hybrid {_fmt(qwen_metrics)}", flush=True)

        controls, control_latencies = await _controls(base_url)
        result["payload_controls"] = controls
        result["payload_control_summary"] = {
            "attack_signature_fixtures": sum(x["expected_attack_signature"] for x in controls),
            "attack_signature_fixtures_blocked": sum(x["expected_attack_signature"] and x["blocked"] for x in controls),
            "benign_controls": sum(not x["expected_attack_signature"] for x in controls),
            "benign_controls_blocked": sum(not x["expected_attack_signature"] and x["blocked"] for x in controls),
            "latency_p50_ms": statistics.median(control_latencies)}
        (output / "waf_comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        _render_report(result, output / "WAF_COMPARISON.md")
        (ROOT / "reports/WAF_COMPARISON.md").write_text((output / "WAF_COMPARISON.md").read_text())
    finally:
        origin.shutdown(); origin.server_close()
        if container_started:
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, text=True)


def _render_report(result: dict, path: Path) -> None:
    lines = ["# JevSec vs OWASP CRS: local benchmark", "",
        f"- WAF: `{result['waf_image']}`; pinned reference `{result['image_ref']}`; local image digest `{result['image_digest'] or 'not exposed by Docker'}`.",
        f"- CRS policy: paranoia level {result['paranoia_level']}, blocking paranoia level {result['blocking_paranoia_level']}, inbound anomaly threshold {result['inbound_anomaly_threshold']}.",
        "- Requests were sent only through a loopback-published WAF container to an in-process localhost origin. No external hosts were contacted.",
        "- The behavior corpus contains 12 synthetic, non-exploit requests per source-IP window. Attack labels describe behavior such as repeated login failure, enumeration, or suspicious status patterns; the request payloads are intentionally safe.",
        "- Data provenance is recorded per run in `reports/waf_comparison/waf_comparison.json`: generator version inputs, seed, full-window count, and SHA-256 fingerprint.",
        "- A WAF window is positive when any of its 12 requests receives HTTP 403. Qwen3 is measured on the same held-out entities using validation-calibrated Hybrid review decisions.",
        "- Exact repeated method/path/User-Agent signatures are sent once through the request-stateless CRS policy and the result is projected to every matching window. No rate-limit plugin is configured; this is a detection comparison, not a 144,000-request throughput test.",
        "- This is a complementarity comparison, not a head-to-head replacement claim: CRS inspects HTTP request content; JevSec sees aggregate behavior features and does not receive raw paths or user-agent text.", "",
        "## Behavior-window test split", "",
        "| Requested test prevalence | Windows | Actual prevalence | System | Precision | Recall | F1 | FPR | FNR | Review/block rate | TP / FP / FN / TN |",
        "|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---|"]
    for run in result["runs"]:
        for name, key in (("OWASP CRS (any 403 in 12 requests)", "waf"),
                          ("Qwen3-4B calibrated Hybrid", "qwen3_calibrated_hybrid")):
            m = run[key]
            precision = "n/a" if m["precision"] is None else f"{m['precision']:.3f}"
            lines.append(f"| {run['prevalence']} | {run['test_windows']:,} | {run['test_attack_prevalence']:.2%} | {name} | {precision} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3%} | {m['fnr']:.3%} | {m['review_rate']:.3%} | {m['tp']:,} / {m['fp']:,} / {m['fn']:,} / {m['tn']:,} |")
        latency = run["waf_request_latency_ms"]
        lines.append(f"  - {run['prevalence']} CRS unique-signature HTTP latency: p50 {latency['p50']:.2f} ms / p95 {latency['p95']:.2f} ms (not a load-test throughput result).")
    lines += ["", "## CRS request-signature positive controls", "",
        "These well-known detection strings were sent to the localhost WAF and never to an external application. They test that the CRS engine is active; they are not used to claim JevSec payload detection.", "",
        "| Fixture | Attack-like control | HTTP status | Blocked |", "|---|---:|---:|---:|"]
    for item in result["payload_controls"]:
        lines.append(f"| {item['fixture']} | {'yes' if item['expected_attack_signature'] else 'no'} | {item['status']} | {'yes' if item['blocked'] else 'no'} |")
    summary = result["payload_control_summary"]
    lines += ["", f"Blocked {summary['attack_signature_fixtures_blocked']}/{summary['attack_signature_fixtures']} attack-signature controls; blocked {summary['benign_controls_blocked']}/{summary['benign_controls']} benign controls. Positive-control sample is intentionally small and not a CRS effectiveness certification.", "",
        "## Interpretation and limitations", "",
        "The behavior labels do not imply malicious request syntax. A request-signature WAF can correctly pass a low-rate client that repeatedly fails login, enumerates harmless routes, or behaves unusually after authentication; JevSec can aggregate these patterns. Conversely, request payloads that match CRS signatures are squarely in the WAF's domain. Run both in shadow/monitoring mode during evaluation and keep the WAF as the enforcement layer.",
        "Synthetic prevalence is controlled and differs from production traffic. Results depend on scenario mix, request fields, CRS version, paranoia/blocking settings, WAF exclusions, and application behavior. The model latency is reported in `reports/BENCHMARK_V2.md`; WAF request latency is the round-trip for the deduplicated signature set and is not a throughput measurement or directly comparable to a per-window model inference.", "",
        "Full JSON, per-window CSVs, per-scenario breakdowns and status counts are alongside this report under `reports/waf_comparison/`.", ""]
    path.write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=ROOT / "datasets/public_v2")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/waf_comparison")
    args = parser.parse_args()
    asyncio.run(run(args.data_root, args.output))


if __name__ == "__main__":
    main()
