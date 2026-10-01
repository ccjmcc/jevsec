from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .models import SecurityEvent

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^]]+)\] '
    r'"(?P<request>[^\"]*)" (?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^\"]*)" "(?P<agent>[^\"]*)"(?: (?P<request_time>[\d.]+))?'
)


def parse_nginx_line(line: str) -> SecurityEvent:
    match = _COMBINED.match(line.strip())
    if not match:
        raise ValueError("line does not match supported Nginx combined format")
    data = match.groupdict()
    request = data["request"].split()
    if len(request) < 2:
        raise ValueError("request line is malformed")
    try:
        timestamp = datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as exc:
        raise ValueError("invalid Nginx timestamp") from exc
    status = int(data["status"])
    auth_result = "failure" if status == 401 else "success" if request[0].upper() == "POST" and request[1].split("?", 1)[0].lower().rstrip("/") == "/login" and 200 <= status < 300 else "unknown"
    return SecurityEvent(
        timestamp=timestamp,
        source_ip=data["ip"],
        method=request[0].upper(),
        path=request[1].split("?", 1)[0],
        status=status,
        bytes_sent=int(data["bytes"]) if data["bytes"].isdigit() else 0,
        referer="" if data["referer"] == "-" else data["referer"],
        user_agent="" if data["agent"] == "-" else data["agent"],
        request_time=float(data["request_time"] or 0),
        auth_result=auth_result,
        source="nginx",
    )


def parse_json_line(line: str) -> SecurityEvent:
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ValueError("JSON event must be an object")
    # Deliberately whitelist fields. Credentials, cookies and unknown raw keys are discarded.
    allowed = {"timestamp", "source_ip", "method", "path", "status", "bytes_sent", "user_agent",
               "referer", "host", "request_time", "request_id", "session_hash", "auth_result"}
    data = {key: value for key, value in raw.items() if key in allowed}
    if "timestamp" in data and isinstance(data["timestamp"], str):
        try:
            data["timestamp"] = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
            if data["timestamp"].tzinfo is None:
                data["timestamp"] = data["timestamp"].replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError("invalid ISO timestamp") from exc
    data.setdefault("timestamp", datetime.now(timezone.utc))
    data["source"] = "jsonl"
    return SecurityEvent.model_validate(data)


def parse_line(line: str, fmt: str = "auto") -> SecurityEvent:
    if fmt == "nginx":
        return parse_nginx_line(line)
    if fmt == "jsonl":
        return parse_json_line(line)
    stripped = line.lstrip()
    return parse_json_line(line) if stripped.startswith("{") else parse_nginx_line(line)
