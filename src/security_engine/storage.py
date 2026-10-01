from __future__ import annotations

import json
import sqlite3
import statistics
from pathlib import Path

from .models import Assessment, SecurityEvent


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, source_ip TEXT, session_hash TEXT, body TEXT);
            CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS ix_events_ip ON events(source_ip);
            CREATE TABLE IF NOT EXISTS assessments(id INTEGER PRIMARY KEY, entity TEXT, entity_type TEXT, disposition TEXT, risk REAL, body TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS ix_assessments_risk ON assessments(risk DESC);
            """)
            columns = {r[1] for r in db.execute("PRAGMA table_info(events)")}
            if "session_hash" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN session_hash TEXT")
            db.execute("CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_hash)")

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def add_events(self, events: list[SecurityEvent]) -> int:
        with self.connect() as db:
            db.executemany("INSERT INTO events(ts,source_ip,session_hash,body) VALUES(?,?,?,?)",
                           [(e.timestamp.isoformat(), e.source_ip, e.session_hash, e.model_dump_json()) for e in events])
        return len(events)

    def events(self, limit: int = 100000) -> list[SecurityEvent]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM events ORDER BY ts LIMIT ?", (limit,)).fetchall()
        return [SecurityEvent.model_validate_json(r["body"]) for r in rows]

    def source_ips(self) -> set[str]:
        with self.connect() as db:
            return {r[0] for r in db.execute("SELECT DISTINCT source_ip FROM events")}

    def recent_events(self, since, source_ips: set[str], session_hashes: set[str] | None = None) -> list[SecurityEvent]:
        session_hashes = session_hashes or set()
        clauses, params = [], [since.isoformat()]
        if source_ips:
            clauses.append("source_ip IN (" + ",".join("?" for _ in source_ips) + ")")
            params.extend(sorted(source_ips))
        if session_hashes:
            clauses.append("session_hash IN (" + ",".join("?" for _ in session_hashes) + ")")
            params.extend(sorted(session_hashes))
        if not clauses:
            return []
        with self.connect() as db:
            rows = db.execute("SELECT body FROM events WHERE ts>=? AND (" + " OR ".join(clauses) + ") ORDER BY ts", params).fetchall()
        return [SecurityEvent.model_validate_json(r["body"]) for r in rows]

    def timeline(self, source_ip: str, limit: int = 100) -> list[SecurityEvent]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM events WHERE source_ip=? ORDER BY ts DESC LIMIT ?", (source_ip, limit)).fetchall()
        return [SecurityEvent.model_validate_json(r["body"]) for r in reversed(rows)]

    def add_assessment(self, item: Assessment) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO assessments(entity,entity_type,disposition,risk,body) VALUES(?,?,?,?,?)",
                       (item.entity, item.entity_type, item.disposition, item.hybrid_risk, item.model_dump_json()))

    def assessments(self, limit: int = 500) -> list[Assessment]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM assessments ORDER BY risk DESC, created_at DESC LIMIT ?", (limit,)).fetchall()
        return [Assessment.model_validate_json(r["body"]) for r in rows]

    def stats(self) -> dict:
        with self.connect() as db:
            events = db.execute("SELECT count(*) FROM events").fetchone()[0]
            entities = db.execute("SELECT count(DISTINCT source_ip) FROM events").fetchone()[0]
            rows = db.execute("SELECT body FROM assessments ORDER BY created_at DESC").fetchall()
        latest = {}
        for row in rows:
            item = Assessment.model_validate_json(row["body"])
            latest.setdefault((item.entity_type, item.entity), item)
        counts = {"suspicious": 0, "high_risk": 0, "uncertain": 0}
        rule_alerts = hybrid_alerts = 0
        for item in latest.values():
            counts[item.disposition.lower()] = counts.get(item.disposition.lower(), 0) + 1
            rule_alerts += item.rule_risk >= 55
            hybrid_alerts += item.disposition in {"SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"}
        reduction = (rule_alerts - hybrid_alerts) / rule_alerts if rule_alerts else None
        latency_values = [x.jev.latency_ms for x in latest.values() if x.jev is not None]
        return {"total_events": events, "entities": entities, **counts,
                "traditional_alerts": rule_alerts, "hybrid_alerts": hybrid_alerts,
                "alert_reduction": None if reduction is None else f"{reduction * 100:.1f}%",
                "jev_latency_ms": None if not latency_values else round(statistics.median(latency_values), 1)}
