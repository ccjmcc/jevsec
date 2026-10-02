from __future__ import annotations

import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import SecurityEvent

CATEGORIES = ["benign", "reconnaissance", "credential_abuse", "automated_bot", "suspicious_post_authentication", "possible_web_exploitation", "unknown_suspicious"]
BENIGN = ["ordinary_browse", "normal_crawler", "search_bot", "api_polling", "health_check", "cdn", "spa_404", "admin_batch_operation", "development_scan", "monitoring_system", "slow_login_failures", "enterprise_proxy", "high_volume_api", "mobile_retry", "ci_cd"]
ATTACK = CATEGORIES[1:]
GENERATOR_VERSION = 2


def generate_dataset(out: Path, entities: int = 1200, seed: int = 20261001, malicious_rate: float = .2) -> tuple[Path, Path]:
    """Generate deterministic labeled behavior windows from safe synthetic events.

    Entity count equals one 1-minute source-IP window per row. Attack prevalence is
    explicit so 1%, 5%, and 10% populations can be evaluated without resampling test.
    """
    if entities < 100:
        raise ValueError("entities must be at least 100 to provide all data splits")
    if not 0 <= malicious_rate <= 1:
        raise ValueError("malicious_rate must be between 0 and 1")
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    events_path, labels_path = out / "events.jsonl", out / "labels.csv"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    split_for_index = lambda i: "train_calibration" if i % 10 < 6 else "validation" if i % 10 < 8 else "test"
    indexes_by_split = {split: [i for i in range(entities) if split_for_index(i) == split]
                        for split in ("train_calibration", "validation", "test")}
    malicious_indexes = set()
    for indexes in indexes_by_split.values():
        malicious_indexes.update(rng.sample(indexes, round(len(indexes) * malicious_rate)))
    attack_seen = 0
    with events_path.open("w", encoding="utf-8") as ef, labels_path.open("w", newline="", encoding="utf-8") as lf:
        labels = csv.writer(lf, lineterminator="\n")
        labels.writerow(["entity", "category", "scenario", "split"])
        for i in range(entities):
            ip = f"198.18.{(i // 254) % 256}.{i % 254 + 1}"
            if i in malicious_indexes:
                category = ATTACK[attack_seen % len(ATTACK)]
                scenario = category
                attack_seen += 1
            else:
                category = "benign"
                # Keep each benign scenario represented in every disjoint split.
                # Splits are arranged in 10-index blocks (6/2/2); advancing the
                # scenario once per block avoids train/validation/test mix bias.
                scenario = BENIGN[(i // 10) % len(BENIGN)]
            # Patterns are fixed by scenario, making repeated feature contexts
            # cacheable while rotating safe path templates across entities.
            n = 12
            ua = "ExampleBrowser/1.0"
            if category == "benign":
                if scenario in {"ordinary_browse", "enterprise_proxy"}:
                    paths = ["/", "/home", "/products", "/search", "/assets/app.js"]
                    statuses = [200] * n; methods = ["GET"] * n; auth = ["unknown"] * n
                elif scenario in {"normal_crawler", "search_bot"}:
                    paths = ["/robots.txt", "/sitemap.xml", "/about", "/news"]
                    statuses = [200] * n; methods = ["GET"] * n; auth = ["unknown"] * n; ua = "ExampleSearchBot/1.0"
                elif scenario in {"health_check", "monitoring_system"}:
                    paths = ["/health", "/healthz"]
                    statuses = [200] * n; methods = ["GET"] * n; auth = ["unknown"] * n; ua = "InternalMonitor/1.0"
                elif scenario == "cdn":
                    paths = ["/assets/app.js", "/assets/site.css", "/assets/logo.svg"]
                    statuses = [200] * n; methods = ["GET"] * n; auth = ["unknown"] * n; ua = "ExampleCDN/1.0"
                elif scenario == "spa_404":
                    paths = [f"/app/route/{j % 3}" for j in range(n)]
                    statuses = [200 if j % 3 else 404 for j in range(n)]; methods = ["GET"] * n; auth = ["unknown"] * n
                elif scenario in {"admin_batch_operation", "ci_cd", "development_scan"}:
                    paths = ["/admin/reports", "/admin/jobs", "/api/status"]
                    statuses = [200] * n; methods = ["GET", "POST"] * 6; auth = ["success"] * n; ua = "InternalAutomation/1.0"
                elif scenario == "slow_login_failures":
                    paths = ["/login"] * n; statuses = [401 if j in {1, 5, 9} else 200 for j in range(n)]
                    methods = ["POST"] * n; auth = ["failure" if j in {1, 5, 9} else "unknown" for j in range(n)]
                elif scenario == "high_volume_api":
                    paths = ["/api/items", "/api/status", "/api/profile"]
                    statuses = [200] * n; methods = ["GET", "GET", "POST"] * 4; auth = ["unknown"] * n; ua = "PartnerAPI/1.0"
                elif scenario == "mobile_retry":
                    paths = ["/api/sync", "/api/profile"]
                    statuses = [200, 503] * 6; methods = ["GET", "POST"] * 6; auth = ["unknown"] * n; ua = "ExampleMobile/1.0"
                else:  # api polling
                    paths = ["/api/poll"] * n; statuses = [200] * n; methods = ["GET"] * n; auth = ["unknown"] * n; ua = "Poller/1.0"
            elif category == "reconnaissance":
                paths = [f"/synthetic-catalog/{j}" for j in range(n)]; statuses = [404 if j % 2 == 0 else 403 for j in range(n)]
                methods = ["GET"] * n; auth = ["unknown"] * n; ua = "SyntheticRecon/1.0"
            elif category == "credential_abuse":
                paths = ["/login"] * n; statuses = [401] * n; methods = ["POST"] * n; auth = ["failure"] * n; ua = "SyntheticClient/1.0"
            elif category == "automated_bot":
                paths = ["/api/items", "/catalog", "/search"] * 4; statuses = [200] * n; methods = ["GET"] * n
                auth = ["unknown"] * n; ua = "SyntheticAutomation/1.0"
            elif category == "suspicious_post_authentication":
                paths = ["/login"] * 3 + ["/admin/overview", "/api/keys", "/backup/status"] * 3
                statuses = [401] * 3 + [200] * 9; methods = ["POST"] * 3 + ["GET"] * 9
                auth = ["failure"] * 2 + ["success"] + ["unknown"] * 9; ua = "ExampleBrowser/1.0"
            elif category == "possible_web_exploitation":
                # Non-executable, harmless route names and error statuses only.
                paths = ["/search", "/api/items", "/catalog", "/diagnostics"] * 3
                statuses = [400, 403, 404] * 4; methods = ["GET"] * n; auth = ["unknown"] * n; ua = "SyntheticClient/1.0"
            else:
                paths = ["/account", "/settings", "/api/export"] * 4; statuses = [200, 403, 404] * 4
                methods = ["GET"] * n; auth = ["unknown"] * n; ua = "SyntheticClient/1.0"
            # Distinct per-window date, stable cadence and safe synthetic IDs.
            for j in range(n):
                event = SecurityEvent(timestamp=start + timedelta(days=i, seconds=j * 4), source_ip=ip,
                    method=methods[j], path=paths[j % len(paths)], status=statuses[j], bytes_sent=512,
                    user_agent=ua, request_time=.08, request_id=f"synthetic-{i}-{j}",
                    session_hash=f"session-{i}", user_id=f"user-{i % 250}", auth_result=auth[j], source="synthetic")
                ef.write(event.model_dump_json() + "\n")
            split = split_for_index(i)
            labels.writerow([ip, category, scenario, split])
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "behavior_windows": entities,
        "seed": seed,
        "malicious_rate": malicious_rate,
        "split_policy": "entity-disjoint-index-6-2-2; benign scenario rotates once per 10-index block",
        "events_sha256": digest(events_path),
        "labels_sha256": digest(labels_path),
    }
    (out / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return events_path, labels_path
