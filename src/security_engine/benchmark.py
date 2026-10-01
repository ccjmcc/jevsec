from __future__ import annotations

import asyncio
import csv
import json
import math
import platform
import statistics
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .aggregation import aggregate
from .decision import DecisionProvider, LocalJevProvider, MockProvider
from .models import SecurityEvent
from .risk import assess
from .rules import evaluate_rules


def _auc(labels: list[int], scores: list[float]) -> float | None:
    pos, neg = sum(labels), len(labels) - sum(labels)
    if not pos or not neg: return None
    ranks = [r for r, _ in sorted(enumerate(scores), key=lambda x: x[1])]
    # Average tied ranks.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    rank_values = [0.0] * len(scores)
    k = 0
    while k < len(order):
        end = k + 1
        while end < len(order) and scores[order[end]] == scores[order[k]]: end += 1
        rank = (k + 1 + end) / 2
        for ix in order[k:end]: rank_values[ix] = rank
        k = end
    return (sum(rank_values[i] for i, v in enumerate(labels) if v) - pos * (pos + 1) / 2) / (pos * neg)


def _metrics(rows: list[dict], risk_key: str = "risk", alert_key: str = "alert") -> dict:
    tp = sum(x["label"] and x[alert_key] for x in rows); fp = sum(not x["label"] and x[alert_key] for x in rows)
    fn = sum(x["label"] and not x[alert_key] for x in rows); tn = len(rows) - tp - fp - fn
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    return {"n": len(rows), "precision": prec, "recall": rec, "f1": 2*prec*rec/(prec+rec) if prec+rec else 0,
            "false_positive_rate": fp/(fp+tn) if fp+tn else 0, "false_negative_rate": fn/(fn+tp) if fn+tp else 0,
            "accuracy": (tp+tn)/len(rows) if rows else 0, "auroc": _auc([int(x["label"]) for x in rows],[float(x[risk_key]) for x in rows]),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _splits(labels_file: Path) -> dict[str, dict[str, tuple[str, str]]]:
    res = defaultdict(dict)
    with labels_file.open() as f:
        for row in csv.DictReader(f): res[row["split"]][row["entity"]] = (row["category"], row["scenario"])
    return res


async def run_benchmark(data_dir: Path, report_dir: Path, provider_name="mock", model="llm-qwen3-4b", base_url="http://127.0.0.1:8765", sample_limit=120):
    events_path, labels_path = data_dir / "events.jsonl", data_dir / "labels.csv"
    events = [SecurityEvent.model_validate_json(line) for line in events_path.open() if line.strip()]
    labels = _splits(labels_path)
    groups = aggregate(events, 1)
    # Fixed test partition; model runs are stratified and capped because local generation is slow.
    test_entities = labels["test"]
    groups = [g for g in groups if g["entity_type"] == "source_ip" and g["entity"] in test_entities]
    by_cat = defaultdict(list)
    for g in groups: by_cat[test_entities[g["entity"]][0]].append(g)
    if provider_name == "local_jev": provider: DecisionProvider = LocalJevProvider(base_url, model, timeout=1200)
    elif provider_name == "mock": provider = MockProvider()
    else: provider = None
    selected = []
    # Stratified prefix from the held-out set to retain representation across classes.
    quotas = {cat: max(1, int(sample_limit * len(items) / len(groups))) for cat, items in by_cat.items()}
    while sum(quotas.values()) > sample_limit:
        cat = max((c for c in quotas if quotas[c] > 1), key=lambda c: quotas[c] - sample_limit * len(by_cat[c]) / len(groups))
        quotas[cat] -= 1
    while sum(quotas.values()) < min(sample_limit, len(groups)):
        cat = max(by_cat, key=lambda c: sample_limit * len(by_cat[c]) / len(groups) - quotas[c])
        quotas[cat] += 1
    for category in sorted(by_cat): selected.extend(by_cat[category][:quotas[category]])
    outputs = []
    latencies = []
    rule_latencies = []
    for idx, group in enumerate(selected):
        features = group["features"]
        rule_started = time.perf_counter()
        rule_matches, rule_score = evaluate_rules(features)
        rule_latencies.append((time.perf_counter() - rule_started) * 1000)
        truth_category = test_entities[group["entity"]][0]
        truth = truth_category != "benign"
        jev = None
        if provider:
            jev = await provider.decide(features)
            latencies.append(jev.latency_ms)
        rules = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
                       ended_at=group["ended_at"], request_count=len(group["events"]), features=features,
                       rules=rule_matches, rule_risk=rule_score, jev=None, mode="rules_only")
        hybrid = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
                        ended_at=group["ended_at"], request_count=len(group["events"]), features=features,
                        rules=rule_matches, rule_risk=rule_score, jev=jev, mode="hybrid") if jev else None
        jev_only = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
                          ended_at=group["ended_at"], request_count=len(group["events"]), features=features,
                          rules=rule_matches, rule_risk=rule_score, jev=jev, mode="jev_only") if jev else None
        outputs.append({"entity": group["entity"], "category": truth_category, "scenario": test_entities[group["entity"]][1],
                        "label": truth, "rule_risk": rules.hybrid_risk, "rule_alert": rules.disposition in {"SUSPICIOUS", "HIGH_RISK"},
                        "jev_risk": jev_only.hybrid_risk if jev_only else 0, "jev_disposition": jev_only.disposition if jev_only else "",
                        "jev_alert": bool(jev_only and jev_only.disposition in {"SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"}),
                        "hybrid_risk": hybrid.hybrid_risk if hybrid else 0,
                        "hybrid_disposition": hybrid.disposition if hybrid else "",
                        "hybrid_alert": bool(hybrid and hybrid.disposition in {"SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"}),
                        "jev_category": jev.category if jev else "", "jev_category_correct": bool(jev and jev.category == truth_category),
                        "jev_confidence": jev.confidence if jev else 0, "latency_ms": jev.latency_ms if jev else 0})
    report_dir.mkdir(parents=True, exist_ok=True)
    with (report_dir / "benchmark_results.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=outputs[0].keys(), lineterminator="\n"); writer.writeheader(); writer.writerows(outputs)
    systems = {}
    for name, risk_key, alert_key in [("Rules Only", "rule_risk", "rule_alert"), ("Local Jev Only", "jev_risk", "jev_alert"), ("Hybrid", "hybrid_risk", "hybrid_alert")]:
        if name != "Rules Only" and not provider: continue
        stats = _metrics([{**o, "risk": o[risk_key], "alert": o[alert_key]} for o in outputs], "risk", "alert")
        traditional_alerts = sum(1 for o in outputs if o["rule_alert"])
        system_alerts = sum(1 for o in outputs if o[alert_key])
        stats["alert_reduction_rate"] = 1 - system_alerts / max(1, traditional_alerts)
        rule_tp = sum(1 for o in outputs if o["rule_alert"] and o["label"])
        stats["attack_retention_rate"] = stats["recall"]
        stats["traditional_alerts"] = traditional_alerts
        stats["system_alerts"] = system_alerts
        measure = rule_latencies if name == "Rules Only" else latencies
        stats["latency_p50_ms"] = statistics.median(measure) if measure else 0
        stats["latency_p95_ms"] = sorted(measure)[math.ceil(.95*len(measure))-1] if measure else 0
        stats["throughput_rps"] = 1000/statistics.mean(measure) if measure and statistics.mean(measure) else 0
        systems[name] = stats
    per_category = {}
    for cat in sorted(set(o["category"] for o in outputs)):
        subset = [o for o in outputs if o["category"] == cat]
        per_category[cat] = {"n":len(subset), "rules_recall":sum(o["rule_alert"] for o in subset)/len(subset),
                             "jev_recall":sum(o["jev_alert"] for o in subset)/len(subset) if provider else None,
                             "hybrid_recall":sum(o["hybrid_alert"] for o in subset)/len(subset) if provider else None,
                             "jev_category_accuracy":sum(o["jev_category_correct"] for o in subset)/len(subset) if provider else None}
    meta = {"hardware": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
            "provider": provider_name, "model": model if provider_name == "local_jev" else ("mock-heuristic-v1" if provider_name == "mock" else "not run"),
            "total_events": len(events), "test_windows_available": len(groups), "model_inferences": len(latencies),
            "first_model_request_ms": latencies[0] if latencies else None,
            "systems": systems, "per_category": per_category,
            "category_accuracy":sum(o["jev_category_correct"] for o in outputs)/len(outputs) if provider else None,
            "benign_scenarios": {scenario: {"n":sum(o["scenario"]==scenario for o in outputs),
                "rules_review_rate":sum(o["rule_alert"] for o in outputs if o["scenario"]==scenario)/max(1,sum(o["scenario"]==scenario for o in outputs)),
                "jev_review_rate":sum(o["jev_alert"] for o in outputs if o["scenario"]==scenario)/max(1,sum(o["scenario"]==scenario for o in outputs)) if provider else None,
                "hybrid_review_rate":sum(o["hybrid_alert"] for o in outputs if o["scenario"]==scenario)/max(1,sum(o["scenario"]==scenario for o in outputs)) if provider else None}
                for scenario in sorted({o["scenario"] for o in outputs if o["category"]=="benign"})},
            "confusion_matrices": {name:{k:systems[name][k] for k in ["tp","fp","tn","fn"]} for name in systems},
            "completed_at": datetime.now().isoformat()}
    (report_dir / "benchmark_results.json").write_text(json.dumps(meta, indent=2))
    return meta


def render_report(meta: dict, path: Path):
    lines=["# Benchmark report", "", f"- Machine: {meta['hardware']} ({meta['machine']})", f"- Python: {meta['python']}",
           f"- Provider/model: {meta['provider']} / {meta['model']}", f"- Synthetic events: {meta['total_events']}",
           f"- Held-out test behavior windows available: {meta['test_windows_available']}", f"- Model inferences completed: {meta['model_inferences']}", "",
           f"- First request latency in this evaluation: {meta.get('first_model_request_ms') if meta.get('first_model_request_ms') is not None else 'n/a'} ms (the model may already have been warm)", "",
           "## Held-out test results", "", "| System | n | Alerts/reviews | Workload change vs rules | Precision | Recall / attack retention | F1 | FPR | FNR | Accuracy | AUROC | p50 ms | p95 ms | req/s |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name,s in meta["systems"].items(): lines.append(f"| {name} | {s['n']} | {s['system_alerts']} | {(s['system_alerts']/max(1,s['traditional_alerts'])-1)*100:+.1f}% | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | {s['false_positive_rate']:.3f} | {s['false_negative_rate']:.3f} | {s['accuracy']:.3f} | {s['auroc'] if s['auroc'] is not None else 'n/a'} | {s['latency_p50_ms']:.2f} | {s['latency_p95_ms']:.2f} | {s['throughput_rps']:.2f} |")
    lines += ["", "Only the reported test partition is scored; thresholds are config defaults, not fitted on test labels. Model inference is stratified and capped to the requested sample limit. Uncertain outcomes count as review alerts for workload/recall calculations. These synthetic results do not estimate production performance.", "", f"Jev behavior-category accuracy: {meta['category_accuracy'] if meta['category_accuracy'] is not None else 'n/a'}", "", "## Category recall", "", "| Category | n | Rules alert recall | Jev review recall | Hybrid review recall | Jev category accuracy |", "|---|---:|---:|---:|---:|---:|"]
    for cat,s in meta["per_category"].items(): lines.append(f"| {cat} | {s['n']} | {s['rules_recall']:.3f} | {s['jev_recall'] if s['jev_recall'] is not None else 'n/a'} | {s['hybrid_recall'] if s['hybrid_recall'] is not None else 'n/a'} | {s['jev_category_accuracy'] if s['jev_category_accuracy'] is not None else 'n/a'} |")
    if meta.get("benign_scenarios"):
        lines += ["", "## Benign hard negatives", "", "| Scenario | n | Rules review rate | Jev review rate | Hybrid review rate |", "|---|---:|---:|---:|---:|"]
        for scenario,s in meta["benign_scenarios"].items(): lines.append(f"| {scenario} | {s['n']} | {s['rules_review_rate']:.3f} | {s['jev_review_rate'] if s['jev_review_rate'] is not None else 'n/a'} | {s['hybrid_review_rate'] if s['hybrid_review_rate'] is not None else 'n/a'} |")
    path.write_text("\n".join(lines)+"\n")
