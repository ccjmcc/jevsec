from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import SecurityEvent

CATEGORIES = ["benign", "reconnaissance", "credential_abuse", "automated_bot", "suspicious_post_authentication", "possible_web_exploitation", "unknown_suspicious"]
BENIGN = ["ordinary_browse", "normal_crawler", "internal_monitor", "high_volume_api", "forgot_password", "spa_404", "admin_sensitive_access", "health_check", "mobile_client", "api_polling"]


def generate_dataset(out: Path, entities: int = 1200, seed: int = 20261001) -> tuple[Path, Path]:
    rng = random.Random(seed)
    out.mkdir(parents=True, exist_ok=True)
    events_path, labels_path = out / "events.jsonl", out / "labels.csv"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event_count = 0
    with events_path.open("w") as ef, labels_path.open("w", newline="") as lf:
        labels = csv.writer(lf)
        labels.writerow(["entity", "category", "scenario", "split"])
        for i in range(entities):
            # Equal-ish strata; each seed produces the same entity assignment and event sequence.
            # Keep a balanced half-benign cohort for hard-negative review; distribute the attack half evenly.
            cat = "benign" if i % 2 == 0 else CATEGORIES[1 + ((i // 2) % (len(CATEGORIES) - 1))]
            scenario = rng.choice(BENIGN) if cat == "benign" else cat
            ip = f"198.51.{(i // 250) % 256}.{i % 250 + 1}"
            count = rng.randint(30, 50) if scenario == "high_volume_api" else rng.randint(7, 13)
            ua = rng.choice(["Mozilla/5.0 (X11; Linux x86_64) Chrome/124", "InternalHealth/2.1", "MobileApp/5.4", "ExampleCrawler/1.0"])
            method = "GET"
            for j in range(count):
                path, status, auth, method_j, ua_j = "/", 200, "unknown", method, ua
                if cat == "benign":
                    if scenario in {"ordinary_browse", "mobile_client"}:
                        path = rng.choice(["/", "/home", "/products", "/search", "/assets/app.js"])
                    elif scenario == "normal_crawler":
                        path, ua_j = rng.choice(["/robots.txt", "/sitemap.xml", "/about", "/news"]), "ExampleCrawler/1.0"
                    elif scenario == "internal_monitor":
                        path, ua_j = "/health", "InternalHealth/2.1"
                    elif scenario == "high_volume_api":
                        path = rng.choice(["/api/items", "/api/status", "/api/profile"])
                    elif scenario == "forgot_password":
                        path, status, auth = "/login", (401 if j < 2 else 200), ("failure" if j < 2 else "success")
                    elif scenario == "spa_404":
                        path, status = f"/app/route/{j}", 404
                    elif scenario == "admin_sensitive_access":
                        path, auth = rng.choice(["/admin", "/admin/reports", "/api/keys"]), "success"
                    elif scenario == "health_check":
                        path = "/healthz"
                    else:
                        path = "/api/poll"
                    method_j = rng.choice(["GET", "GET", "POST"]) if "api" in scenario else "GET"
                elif cat == "reconnaissance":
                    path, status = f"/synthetic-probe/{i % 31}/{j}", (404 if j % 2 == 0 else 403)
                    ua_j = "ExampleScanner/0.1"
                elif cat == "credential_abuse":
                    path, status, auth, method_j = "/login", 401, "failure", "POST"
                elif cat == "automated_bot":
                    path, status, ua_j = rng.choice(["/api/items", "/catalog", "/search"]), 200, "SyntheticBot/0.1"
                elif cat == "suspicious_post_authentication":
                    path = "/login" if j < 3 else rng.choice(["/admin", "/api/keys", "/backup/status"])
                    status, auth, method_j = ((401, "failure", "POST") if j < 3 else (200, "success", "GET"))
                elif cat == "possible_web_exploitation":
                    path, status = rng.choice(["/search", "/api/items", "/catalog"]), rng.choice([400, 403, 404])
                else:
                    path, status = rng.choice(["/account", "/settings", "/api/export"]), rng.choice([200, 403, 404])
                    ua_j = rng.choice(["Mozilla/5.0 Demo", "SyntheticClient/0.1"])
                # Attack-chain intervals remain well within the 1m/5m behavior windows.
                cadence = .05 if cat == "automated_bot" or scenario == "high_volume_api" else 3
                event_time = start + timedelta(days=i, seconds=j * cadence)
                event = SecurityEvent(timestamp=event_time, source_ip=ip, method=method_j, path=path, status=status,
                                      bytes_sent=rng.randint(80, 6000), user_agent=ua_j, request_time=round(rng.uniform(.01, .9), 3),
                                      request_id=f"synthetic-{i}-{j}", session_hash=f"sess-{i:05d}", auth_result=auth, source="synthetic")
                ef.write(event.model_dump_json() + "\n")
                event_count += 1
            split = "train_calibration" if i % 10 < 6 else "validation" if i % 10 < 8 else "test"
            labels.writerow([ip, cat, scenario, split])
    if event_count < 10_000:
        return generate_dataset(out, entities=entities + 300, seed=seed)
    return events_path, labels_path
