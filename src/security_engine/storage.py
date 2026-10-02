from __future__ import annotations

import json
import sqlite3
import statistics
from datetime import timedelta
from pathlib import Path

from .models import Assessment, SecurityEvent


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, source_ip TEXT, session_hash TEXT, user_id TEXT, body TEXT);
            CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS ix_events_ip ON events(source_ip);
            CREATE TABLE IF NOT EXISTS assessments(id INTEGER PRIMARY KEY, entity TEXT, entity_type TEXT, disposition TEXT, risk REAL, body TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS ix_assessments_risk ON assessments(risk DESC);
            CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY, entity TEXT NOT NULL, entity_type TEXT NOT NULL, window TEXT NOT NULL, label TEXT NOT NULL CHECK(label IN ('true_positive','false_positive','unsure')), created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            """)
            columns = {r[1] for r in db.execute("PRAGMA table_info(events)")}
            if "session_hash" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN session_hash TEXT")
            if "user_id" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN user_id TEXT")
            db.execute("CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_hash)")
            db.execute("CREATE INDEX IF NOT EXISTS ix_events_user ON events(user_id)")

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add_events(self, events: list[SecurityEvent]) -> int:
        with self.connect() as db:
            db.executemany("INSERT INTO events(ts,source_ip,session_hash,user_id,body) VALUES(?,?,?,?,?)",
                           [(e.timestamp.isoformat(), e.source_ip, e.session_hash, e.user_id, e.model_dump_json()) for e in events])
        return len(events)

    def context_history(self, events: list[SecurityEvent], days: int = 30) -> list[SecurityEvent]:
        """Load prior events for affected pseudonymous entities to establish baselines."""
        if not events:
            return []
        from datetime import timezone
        end = min(e.timestamp for e in events)
        start = (end - timedelta(days=days)).isoformat()
        identities = {"source_ip": {e.source_ip for e in events},
                      "session_hash": {e.session_hash for e in events if e.session_hash},
                      "user_id": {e.user_id for e in events if e.user_id}}
        rows_by_body = {}
        for column, values in identities.items():
            ordered = sorted(values)
            for offset in range(0, len(ordered), 400):
                part = ordered[offset:offset + 400]
                if part:
                    with self.connect() as db:
                        rows = db.execute(f"SELECT body FROM events WHERE ts>=? AND ts<? AND {column} IN ({','.join('?' for _ in part)}) ORDER BY ts", [start, end.isoformat(), *part]).fetchall()
                    rows_by_body.update((row["body"], row["body"]) for row in rows)
        return [SecurityEvent.model_validate_json(body) for body in rows_by_body]

    def events(self, limit: int = 100000) -> list[SecurityEvent]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM events ORDER BY ts LIMIT ?", (limit,)).fetchall()
        return [SecurityEvent.model_validate_json(r["body"]) for r in rows]

    def source_ips(self) -> set[str]:
        with self.connect() as db:
            return {r[0] for r in db.execute("SELECT DISTINCT source_ip FROM events")}

    def recent_events(self, since, source_ips: set[str], session_hashes: set[str] | None = None, user_ids: set[str] | None = None) -> list[SecurityEvent]:
        session_hashes = session_hashes or set()
        user_ids = user_ids or set()
        rows_by_body = {}
        if source_ips:
            for offset in range(0, len(source_ips), 400):
                part = sorted(source_ips)[offset:offset + 400]
                with self.connect() as db:
                    rows = db.execute("SELECT body FROM events WHERE ts>=? AND source_ip IN (" + ",".join("?" for _ in part) + ")", [since.isoformat(), *part]).fetchall()
                rows_by_body.update((row["body"], row["body"]) for row in rows)
        if session_hashes:
            for offset in range(0, len(session_hashes), 400):
                part = sorted(session_hashes)[offset:offset + 400]
                with self.connect() as db:
                    rows = db.execute("SELECT body FROM events WHERE ts>=? AND session_hash IN (" + ",".join("?" for _ in part) + ")", [since.isoformat(), *part]).fetchall()
                rows_by_body.update((row["body"], row["body"]) for row in rows)
        if user_ids:
            for offset in range(0, len(user_ids), 400):
                part = sorted(user_ids)[offset:offset + 400]
                with self.connect() as db:
                    rows = db.execute("SELECT body FROM events WHERE ts>=? AND user_id IN (" + ",".join("?" for _ in part) + ")", [since.isoformat(), *part]).fetchall()
                rows_by_body.update((row["body"], row["body"]) for row in rows)
        events = [SecurityEvent.model_validate_json(body) for body in rows_by_body]
        return sorted(events, key=lambda event: event.timestamp)

    def timeline(self, source_ip: str, limit: int = 100) -> list[SecurityEvent]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM events WHERE source_ip=? ORDER BY ts DESC LIMIT ?", (source_ip, limit)).fetchall()
        return [SecurityEvent.model_validate_json(r["body"]) for r in reversed(rows)]

    def feedback(self, entity: str, entity_type: str, window: str, label: str) -> None:
        if label not in {"true_positive", "false_positive", "unsure"}:
            raise ValueError("unsupported feedback label")
        with self.connect() as db:
            db.execute("INSERT INTO feedback(entity,entity_type,window,label) VALUES(?,?,?,?)", (entity, entity_type, window, label))

    def feedback_rows(self, limit: int = 1000) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT entity,entity_type,window,label,created_at FROM feedback ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def add_assessment(self, item: Assessment) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO assessments(entity,entity_type,disposition,risk,body) VALUES(?,?,?,?,?)",
                       (item.entity, item.entity_type, item.disposition, item.hybrid_risk, item.model_dump_json()))

    def assessments(self, limit: int = 500) -> list[Assessment]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM assessments ORDER BY risk DESC, created_at DESC LIMIT ?", (limit,)).fetchall()
        return [Assessment.model_validate_json(r["body"]) for r in rows]

    def risk_history(self, limit: int = 200) -> list[Assessment]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM assessments ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        items = [Assessment.model_validate_json(r["body"]) for r in reversed(rows)]
        return sorted(items, key=lambda item: (item.ended_at, item.entity_type, item.entity))

    def stats(self) -> dict:
        with self.connect() as db:
            events = db.execute("SELECT count(*) FROM events").fetchone()[0]
            entities = db.execute("SELECT count(DISTINCT source_ip) FROM events").fetchone()[0]
            rows = db.execute("SELECT body FROM assessments ORDER BY created_at DESC").fetchall()
        latest = {}
        for row in rows:
            item = Assessment.model_validate_json(row["body"])
            latest.setdefault((item.entity_type, item.entity), item)
        counts = {"suspicious": 0, "review": 0, "high_risk": 0, "uncertain": 0}
        rule_alerts = hybrid_alerts = 0
        for item in latest.values():
            counts[item.disposition.lower()] = counts.get(item.disposition.lower(), 0) + 1
            counts["review"] += item.disposition in {"REVIEW", "SUSPICIOUS"}
            rule_alerts += item.rule_risk >= 55
            hybrid_alerts += item.disposition in {"REVIEW", "SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"}
        reduction = (rule_alerts - hybrid_alerts) / rule_alerts if rule_alerts else None
        latency_values = [x.jev.latency_ms for x in latest.values() if x.jev is not None]
        with self.connect() as db:
            feedback_count = db.execute("SELECT count(*) FROM feedback").fetchone()[0]
        return {"total_events": events, "entities": entities, "feedback_count": feedback_count,
                "attack_retention": None, **counts,
                "traditional_alerts": rule_alerts, "hybrid_alerts": hybrid_alerts,
                "alert_reduction": None if reduction is None else f"{reduction * 100:.1f}%",
                "jev_latency_ms": None if not latency_values else round(statistics.median(latency_values), 1)}
