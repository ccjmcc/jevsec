from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    method: str = "GET"
    path: str = "/"
    status: int = 200
    bytes_sent: int = 0
    user_agent: str = ""
    referer: str = ""
    host: str = ""
    request_time: float = 0.0
    request_id: str = ""
    session_hash: str | None = None
    user_id: str | None = None
    auth_result: Literal["success", "failure", "unknown"] = "unknown"
    source: Literal["nginx", "jsonl", "synthetic", "api"] = "jsonl"

    @field_validator("source_ip", mode="before")
    @classmethod
    def validate_ip_address(cls, value):
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value):
        method = str(value or "GET").upper()
        allowed = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
        return method if method in allowed else "OTHER"

    @field_validator("session_hash", "request_id", "user_id", mode="before")
    @classmethod
    def pseudonymize_identifiers(cls, value):
        if value in (None, ""):
            return value
        if re.fullmatch(r"sde1_[0-9a-f]{32}", str(value)):
            return value
        return "sde1_" + hashlib.sha256(("sde-pseudonym-v1:" + str(value)).encode()).hexdigest()[:32]

    @field_validator("path", mode="before")
    @classmethod
    def strip_path_query(cls, value):
        return urlsplit(str(value or "/")).path or "/"

    @field_validator("referer", mode="before")
    @classmethod
    def drop_referer_path_and_query(cls, value):
        if not value or value == "-":
            return ""
        parsed = urlsplit(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        try:
            netloc = parsed.hostname + (f":{parsed.port}" if parsed.port else "")
        except ValueError:
            return ""
        return f"{parsed.scheme}://{netloc}"

    @field_validator("timestamp", mode="after")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class RuleMatch(BaseModel):
    rule_id: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    score: int = Field(ge=0, le=100)
    evidence: dict[str, object]


class JevDecision(BaseModel):
    provider: str = "mock"
    model: str = "mock-v1"
    malicious_probability: float = Field(ge=0, le=1)
    category: str = "unknown_suspicious"
    severity: int = Field(ge=0, le=4)
    review_probability: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    latency_ms: float = 0
    raw: dict[str, object] = Field(default_factory=dict)


class Assessment(BaseModel):
    entity: str
    entity_type: Literal["source_ip", "session", "user"]
    window: str
    started_at: datetime
    ended_at: datetime
    request_count: int
    features: dict[str, object]
    rules: list[RuleMatch]
    rule_risk: int
    jev: JevDecision | None = None
    jev_risk: float | None = None
    hybrid_risk: float
    disposition: Literal["BENIGN", "REVIEW", "SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"]
    category: str
    confidence: float
    mode: Literal["rules_only", "jev_only", "hybrid"]
