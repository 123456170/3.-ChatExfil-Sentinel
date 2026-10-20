"""
SecureChat DLP Simulation
=========================

Self-contained, local, synthetic simulation of a chat-platform message/file-share
event stream with autonomous data-loss-prevention responses.

Run commands:
    pip install -r requirements.txt
    streamlit run app.py
    pytest -q

Design note / threshold rationale:
- entropy_threshold = 4.0 bits/char:
  Chosen because ordinary English words and URLs usually fall below ~3.5-4.0,
  while random API-key-like tokens often exceed 4.0.
- min_token_length = 20:
  Avoids flagging short words while still catching key-shaped strings.
- manager_review_threshold = 10.0:
  Roughly equivalent to several repeated near-misses within a short window.
  It is intentionally a review trigger, not an enforcement trigger.
- half_life_days = 7.0:
  Rolling risk should forget old behavior gradually. One week is common for
  insider-risk style decay without overreacting to isolated historical events.
- acted_risk_multiplier = 0.5:
  If an autonomous control already blocked the event, the residual user risk is
  lower than an unblocked near-miss, but still nonzero.
- Fail-safe:
  Missing data, decryption failure, or internal errors produce a hold + audit +
  admin notification instead of silently allowing or destroying evidence.
"""

from __future__ import annotations

import base64
import copy
import html
import io
import json
import math
import os
import random
import re
import sqlite3
import string
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import numpy as np
from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "config.yaml"
DB_PATH = APP_DIR / "simulation.db"
DEMO_DB_PATH = APP_DIR / "demo_simulation.db"


BENIGN_FIXTURES = [
    "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210",
    "QwErTyUiOpAsDfGhJkLzXcVbNm1234567890",
]

AWS_KEY_1 = "Deploy bootstrap key AKIA1234567890ABCDEF rotated yesterday"
AWS_KEY_2 = "Legacy exporter AKIAZYXW9876543210AB still active?"
GITHUB_TOKEN_1 = "CI token ghp_1234567890abcdefghijklmnopqrstuvwxyz scoped repo"
GITHUB_TOKEN_2 = "Backup token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 for mirror"
PRIVATE_KEY_TEXT = (
    "Paste from laptop: -----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ synthetic-synthetic\n"
    "-----END PRIVATE KEY-----"
)
DB_CONN_1 = "Reporting DSN postgres://svc_report:Str0ngPassw0rd@db.internal:5432/analytics"


SENSITIVE_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"ghp_[A-Za-z0-9]{36}",
    "private_key_header": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "db_connection_string": r"postgres://[^\s:@/]+:[^\s@]+@[^\s/]+",
}

CREDENTIAL_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
    r"\s*[:=]\s*([^\s,;]+)"
)


DEFAULT_CONFIG = {
    "simulation": {
        "seed": 42,
        "event_count": 400,
        "users": 30,
        "channels": 8,
        "planted_secrets": 6,
        "confidential_files": 4,
        "benign_fixtures": 3,
        "base_time": "2026-10-20T09:00:00+00:00",
    },
    "detection": {
        "entropy_threshold": 4.0,
        "min_token_length": 20,
        "allowlisted_fixtures": BENIGN_FIXTURES,
        "pattern_weights": {
            "aws_access_key": 5.0,
            "github_token": 5.0,
            "private_key_header": 6.0,
            "db_connection_string": 5.0,
            "credential_keyword": 2.0,
        },
        "entropy_weight": 2.0,
        "confidential_weight": 3.0,
        "external_bonus": 5.0,
        "public_bonus": 3.0,
        "severity_thresholds": {
            "critical": 8.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5,
        },
    },
    "decision": {
        "manager_review_threshold": 10.0,
        "half_life_days": 7.0,
        "near_miss_min_score": 0.5,
        "acted_risk_multiplier": 0.5,
        "auto_action_severities": ["critical", "high"],
    },
    "actions": {
        "tombstone": "[removed by security: sensitive data]",
        "dry_run_default": False,
        "fail_safe_hold": True,
        "notify_owners": True,
    },
    "ui": {
        "demo_seconds": 120,
        "default_speed": 2.0,
        "events_per_second": 4.0,
        "video_frames": 18,
    },
}


class Channel(BaseModel):
    id: str
    name: str
    is_public: bool = False
    has_external_guest: bool = False
    members: list[str] = Field(default_factory=list)
    topic: str = ""


class User(BaseModel):
    id: str
    name: str
    email: str
    is_external_guest: bool = False
    role: str = "member"
    department: str = "general"


class FileAsset(BaseModel):
    id: str
    name: str
    owner_id: str
    metadata_tags: list[str] = Field(default_factory=list)
    share_url: Optional[str] = None
    acl: list[str] = Field(default_factory=list)
    size_kb: int = 100


class Event(BaseModel):
    id: str
    ts: str
    user_id: str
    channel_id: str
    event_type: str = "message"
    text: str = ""
    file_id: Optional[str] = None


class DetectionResult(BaseModel):
    event_id: str
    sensitive_pattern: bool = False
    high_entropy_token: bool = False
    confidential_file: bool = False
    external_member: bool = False
    public_channel: bool = False
    severity: str = "none"
    score: float = 0.0
    signals: list[str] = Field(default_factory=list)
    matched_patterns: list[str] = Field(default_factory=list)
    entropy_tokens: list[dict[str, Any]] = Field(default_factory=list)
    allowlisted_tokens: list[str] = Field(default_factory=list)
    reason: str = ""


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime] = None) -> str:
    return (dt or _now_dt()).astimezone(timezone.utc).isoformat()


def _parse_iso(ts: Optional[str]) -> datetime:
    if not ts:
        return _now_dt()
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return _now_dt()


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, sort_keys=False)


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        try:
            return model.model_dump(mode="json")
        except TypeError:
            return model.model_dump()
    return model.dict()


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def default_config() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_CONFIG)


def ensure_config(path: Path = CONFIG_PATH) -> None:
    path = Path(path)
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    save_config(default_config(), path)


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    ensure_config(path)
    import yaml

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        data = {}
    return _deep_merge(default_config(), data)


def save_config(cfg: dict[str, Any], path: Path = CONFIG_PATH) -> None:
    import yaml

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, default_flow_style=False)


def connect(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    path = Path(db_path or DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            data TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS channels (
            id TEXT PRIMARY KEY,
            data TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            data TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            user_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            text TEXT NOT NULL,
            file_id TEXT,
            original_text TEXT,
            redacted INTEGER NOT NULL DEFAULT 0,
            tombstone TEXT,
            detection TEXT,
            verdict TEXT,
            processed INTEGER NOT NULL DEFAULT 0,
            processed_ts TEXT,
            risk_delta REAL NOT NULL DEFAULT 0.0
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            created_ts TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            algorithm TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            trigger TEXT NOT NULL,
            evidence TEXT NOT NULL,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            reversible INTEGER NOT NULL,
            event_id TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS actions (
            id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target_id TEXT,
            status TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            created_ts TEXT NOT NULL,
            undone_ts TEXT,
            UNIQUE(event_id, action_type)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            user_id TEXT NOT NULL,
            channel_id TEXT,
            message TEXT NOT NULL,
            read INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS risk_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            weight REAL NOT NULL,
            kind TEXT NOT NULL,
            event_id TEXT
        );

        CREATE TABLE IF NOT EXISTS user_scores (
            user_id TEXT PRIMARY KEY,
            score REAL NOT NULL,
            updated_ts TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS manager_queue (
            user_id TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            created_ts TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
        );

        CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, ts);
        CREATE INDEX IF NOT EXISTS idx_events_channel ON events(channel_id, processed);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
        CREATE INDEX IF NOT EXISTS idx_risk_user_ts ON risk_events(user_id, ts);
        """
    )
    con.commit()


def _put_json(con: sqlite3.Connection, table: str, obj_id: str, obj: BaseModel) -> None:
    con.execute(
        f"INSERT OR REPLACE INTO {table} (id, data) VALUES (?, ?)",
        (obj_id, _json_dumps(model_to_dict(obj))),
    )


def _get_json(con: sqlite3.Connection, table: str, obj_id: str, cls: type[BaseModel]) -> Optional[BaseModel]:
    row = con.execute(f"SELECT data FROM {table} WHERE id = ?", (obj_id,)).fetchone()
    if not row:
        return None
    return cls(**json.loads(row["data"]))


def get_user(con: sqlite3.Connection, user_id: str) -> Optional[User]:
    obj = _get_json(con, "users", user_id, User)
    return obj if isinstance(obj, User) else None


def get_channel(con: sqlite3.Connection, channel_id: str) -> Optional[Channel]:
    obj = _get_json(con, "channels", channel_id, Channel)
    return obj if isinstance(obj, Channel) else None


def get_file(con: sqlite3.Connection, file_id: str) -> Optional[FileAsset]:
    obj = _get_json(con, "files", file_id, FileAsset)
    return obj if isinstance(obj, FileAsset) else None


def get_all_users(con: sqlite3.Connection) -> list[User]:
    rows = con.execute("SELECT data FROM users").fetchall()
    return [User(**json.loads(r["data"])) for r in rows]


def get_all_channels(con: sqlite3.Connection) -> list[Channel]:
    rows = con.execute("SELECT data FROM channels").fetchall()
    return [Channel(**json.loads(r["data"])) for r in rows]


def write_audit(
    con: sqlite3.Connection,
    actor: str,
    trigger: str,
    evidence: Any,
    action: str,
    outcome: str,
    reversible: bool,
    event_id: Optional[str] = None,
    details: Any = None,
    now: Optional[str] = None,
) -> None:
    con.execute(
        """
        INSERT INTO audit (ts, actor, trigger, evidence, action, outcome, reversible, event_id, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now or _iso(),
            actor,
            trigger,
            evidence if isinstance(evidence, str) else _json_dumps(evidence),
            action,
            outcome,
            1 if reversible else 0,
            event_id,
            _json_dumps(details or {}),
        ),
    )


def insert_notification(
    con: sqlite3.Connection,
    user_id: str,
    message: str,
    channel_id: Optional[str] = None,
    now: Optional[str] = None,
) -> None:
    con.execute(
        "INSERT INTO notifications (ts, user_id, channel_id, message, read) VALUES (?, ?, ?, ?, 0)",
        (now or _iso(), user_id, channel_id, message),
    )


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    ent = 0.0
    for count in counts.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def extract_tokens(text: str, min_len: int) -> list[str]:
    if min_len <= 0:
        return []
    pattern = rf"[A-Za-z0-9_\-./:+]{{{min_len},}}"
    return re.findall(pattern, text)


def mask_text(text: str, cfg: dict[str, Any]) -> str:
    out = text or ""
    for pattern in SENSITIVE_PATTERNS.values():
        out = re.sub(pattern, "[masked-signal]", out)
    out = CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}=[masked-signal]", out)
    return out


def detect_event(
    event: Event,
    channel: Optional[Channel],
    file_asset: Optional[FileAsset],
    user: Optional[User],
    cfg: dict[str, Any],
) -> DetectionResult:
    det = DetectionResult(event_id=event.id)

    if channel is None:
        det.severity = "error"
        det.reason = "missing channel"
        return det
    if user is None:
        det.severity = "error"
        det.reason = "missing user"
        return det

    text = event.text or ""
    weights = cfg["detection"]["pattern_weights"]

    for name, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, text):
            det.matched_patterns.append(name)
            det.score += float(weights.get(name, 1.0))
            det.signals.append(f"regex:{name}")

    if CREDENTIAL_RE.search(text):
        det.matched_patterns.append("credential_keyword")
        det.score += float(weights.get("credential_keyword", 1.0))
        det.signals.append("regex:credential_keyword")

    det.sensitive_pattern = bool(det.matched_patterns)

    min_len = int(cfg["detection"]["min_token_length"])
    threshold = float(cfg["detection"]["entropy_threshold"])
    allow = set(cfg["detection"]["allowlisted_fixtures"])

    for token in extract_tokens(text, min_len):
        if token in allow:
            det.allowlisted_tokens.append(token)
            det.signals.append("allowlisted_fixture")
            continue
        ent = shannon_entropy(token)
        if ent > threshold:
            det.entropy_tokens.append(
                {
                    "token_preview": token[:12] + "...",
                    "length": len(token),
                    "entropy": round(ent, 3),
                }
            )
            det.score += float(cfg["detection"]["entropy_weight"])
            det.signals.append("high_entropy_token")

    det.high_entropy_token = bool(det.entropy_tokens)

    if file_asset and any(str(tag).lower() == "confidential" for tag in file_asset.metadata_tags):
        det.confidential_file = True
        det.score += float(cfg["detection"]["confidential_weight"])
        det.signals.append("confidential_file_metadata")

    det.external_member = bool(channel.has_external_guest)
    det.public_channel = bool(channel.is_public)

    thresholds = cfg["detection"]["severity_thresholds"]

    def score_severity(score: float) -> str:
        if score >= float(thresholds["critical"]):
            return "critical"
        if score >= float(thresholds["high"]):
            return "high"
        if score >= float(thresholds["medium"]):
            return "medium"
        if score >= float(thresholds["low"]):
            return "low"
        return "none"

    if det.sensitive_pattern and det.external_member:
        det.severity = "critical"
        det.score += float(cfg["detection"]["external_bonus"])
        det.reason = "Sensitive pattern shared in channel with external member"
    elif det.confidential_file and (det.public_channel or det.external_member):
        det.severity = "high"
        det.score += float(cfg["detection"]["public_bonus"])
        det.reason = "Confidential file shared to public or guest channel"
    elif det.sensitive_pattern:
        sev = score_severity(det.score)
        det.severity = sev if sev in ("critical", "high") else "medium"
        det.reason = "Sensitive pattern detected"
    elif det.confidential_file:
        det.severity = "medium"
        det.reason = "Confidential file in non-public channel"
    elif det.high_entropy_token:
        det.severity = score_severity(det.score)
        det.reason = "High-entropy token detected"
    else:
        det.severity = "none"
        det.reason = "No sensitive signal"

    return det


def add_risk_event(
    con: sqlite3.Connection,
    user_id: str,
    weight: float,
    kind: str,
    event_id: Optional[str] = None,
    now: Optional[str] = None,
) -> None:
    con.execute(
        "INSERT INTO risk_events (user_id, ts, weight, kind, event_id) VALUES (?, ?, ?, ?, ?)",
        (user_id, now or _iso(), float(weight), kind, event_id),
    )


def calculate_user_score(
    con: sqlite3.Connection,
    user_id: str,
    cfg: dict[str, Any],
    now: Optional[datetime] = None,
) -> float:
    now_dt = now or _now_dt()
    rows = con.execute(
        "SELECT ts, weight FROM risk_events WHERE user_id = ?",
        (user_id,),
    ).fetchall()

    half_life = max(0.1, float(cfg["decision"]["half_life_days"]))

    if not rows:
        score = 0.0
    else:
        ages = []
        weights = []
        for row in rows:
            age_days = (now_dt - _parse_iso(row["ts"])).total_seconds() / 86400.0
            ages.append(max(0.0, age_days))
            weights.append(float(row["weight"]))
        decays = np.power(0.5, np.array(ages) / half_life)
        score = float(np.sum(np.array(weights) * decays))

    con.execute(
        """
        INSERT INTO user_scores (user_id, score, updated_ts)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET score=excluded.score, updated_ts=excluded.updated_ts
        """,
        (user_id, score, _iso(now_dt)),
    )
    return score


def update_manager_queue(
    con: sqlite3.Connection,
    user_id: str,
    score: float,
    cfg: dict[str, Any],
    now: Optional[str] = None,
) -> None:
    threshold = float(cfg["decision"]["manager_review_threshold"])
    if score < threshold:
        return

    existing = con.execute("SELECT user_id, status FROM manager_queue WHERE user_id = ?", (user_id,)).fetchone()
    ts = now or _iso()
    reason = f"Rolling exfiltration-risk score {score:.2f} >= {threshold:.2f}"

    if existing is None:
        con.execute(
            "INSERT INTO manager_queue (user_id, reason, created_ts, status) VALUES (?, ?, ?, 'open')",
            (user_id, reason, ts),
        )
        write_audit(
            con,
            actor="autonomous",
            trigger="risk_score_threshold",
            evidence={"user_id": user_id, "score": score},
            action="manager_queue",
            outcome="applied",
            reversible=False,
            details={"reason": reason},
            now=ts,
        )
    else:
        con.execute(
            "UPDATE manager_queue SET reason = ?, created_ts = ?, status = 'open' WHERE user_id = ?",
            (reason, ts, user_id),
        )


def get_cipher(db_path: Path | str):
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None

    key_path = Path(str(db_path) + ".key")
    try:
        if not key_path.exists():
            key_path.write_bytes(Fernet.generate_key())
        return Fernet(key_path.read_bytes())
    except Exception:
        return None


def encrypt_text(cipher, plaintext: str) -> Optional[str]:
    if cipher is None:
        return None
    try:
        return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception:
        return None


def decrypt_text(cipher, ciphertext: str) -> Optional[str]:
    if cipher is None:
        return None
    try:
        return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception:
        return None


def _action_exists(con: sqlite3.Connection, event_id: str, action_type: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM actions WHERE event_id = ? AND action_type = ?",
        (event_id, action_type),
    ).fetchone()
    return row is not None


def redact_message(
    con: sqlite3.Connection,
    db_path: Path | str,
    event_id: str,
    det: DetectionResult,
    cfg: dict[str, Any],
    dry_run: bool,
    now: Optional[str] = None,
) -> str:
    ts = now or _iso()

    if _action_exists(con, event_id, "redact_message"):
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id, "signals": det.signals},
            action="redact_message",
            outcome="skipped_already",
            reversible=False,
            event_id=event_id,
            now=ts,
        )
        return "skipped_already"

    row = con.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        write_audit(
            con,
            actor="autonomous",
            trigger="redact_message",
            evidence={"event_id": event_id},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event_id,
            details={"error": "missing event"},
            now=ts,
        )
        return "held"

    if int(row["redacted"] or 0):
        return "skipped_already"

    original = row["original_text"] or row["text"] or ""
    if not original:
        return "skipped_no_text"

    tombstone = cfg["actions"]["tombstone"]

    if dry_run:
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id, "signals": det.signals, "matched_patterns": det.matched_patterns},
            action="redact_message",
            outcome="dry_run",
            reversible=True,
            event_id=event_id,
            details={"would_replace_with": tombstone},
            now=ts,
        )
        return "dry_run"

    cipher = get_cipher(db_path)
    if cipher is None:
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id, "signals": det.signals},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event_id,
            details={"error": "encryption unavailable; fail-safe hold"},
            now=ts,
        )
        insert_notification(
            con,
            user_id="security-admin",
            message=f"Fail-safe hold: unable to encrypt evidence for event {event_id}.",
            now=ts,
        )
        return "held"

    ciphertext = encrypt_text(cipher, original)
    if ciphertext is None:
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event_id,
            details={"error": "encryption failure; fail-safe hold"},
            now=ts,
        )
        return "held"

    con.execute(
        "INSERT INTO evidence (event_id, created_ts, ciphertext, algorithm) VALUES (?, ?, ?, ?)",
        (event_id, ts, ciphertext, "fernet-aes128-cbc-hmac-sha256"),
    )

    con.execute(
        """
        UPDATE events
        SET original_text = ?, text = ?, redacted = 1, tombstone = ?
        WHERE id = ?
        """,
        (original, tombstone, tombstone, event_id),
    )

    con.execute(
        """
        INSERT INTO actions (id, event_id, action_type, target_id, status, old_value, new_value, created_ts)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """,
        (
            f"{event_id}:redact_message",
            event_id,
            "redact_message",
            event_id,
            _json_dumps({"text": original}),
            _json_dumps({"text": tombstone}),
            ts,
        ),
    )

    write_audit(
        con,
        actor="autonomous",
        trigger=f"detection:{det.severity}",
        evidence={"event_id": event_id, "signals": det.signals, "matched_patterns": det.matched_patterns},
        action="redact_message",
        outcome="applied",
        reversible=True,
        event_id=event_id,
        details={"tombstone": tombstone},
        now=ts,
    )

    return "applied"


def revoke_file_link(
    con: sqlite3.Connection,
    db_path: Path | str,
    event_id: str,
    file_id: str,
    det: DetectionResult,
    cfg: dict[str, Any],
    dry_run: bool,
    now: Optional[str] = None,
) -> str:
    ts = now or _iso()

    if _action_exists(con, event_id, "revoke_file_link"):
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id, "file_id": file_id},
            action="revoke_file_link",
            outcome="skipped_already",
            reversible=False,
            event_id=event_id,
            now=ts,
        )
        return "skipped_already"

    file_row = con.execute("SELECT data FROM files WHERE id = ?", (file_id,)).fetchone()
    if file_row is None:
        write_audit(
            con,
            actor="autonomous",
            trigger="revoke_file_link",
            evidence={"event_id": event_id, "file_id": file_id},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event_id,
            details={"error": "missing file"},
            now=ts,
        )
        return "held"

    data = json.loads(file_row["data"])
    share_url = data.get("share_url")

    if not share_url:
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id, "file_id": file_id},
            action="revoke_file_link",
            outcome="skipped_already",
            reversible=False,
            event_id=event_id,
            details={"reason": "share_url already absent"},
            now=ts,
        )
        return "skipped_already"

    old_value = {"share_url": share_url, "acl": data.get("acl", [])}

    if dry_run:
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_id, "file_id": file_id, "signals": det.signals},
            action="revoke_file_link",
            outcome="dry_run",
            reversible=True,
            event_id=event_id,
            details={"would_revoke": share_url},
            now=ts,
        )
        return "dry_run"

    data["share_url"] = None
    con.execute("UPDATE files SET data = ? WHERE id = ?", (_json_dumps(data), file_id))

    con.execute(
        """
        INSERT INTO actions (id, event_id, action_type, target_id, status, old_value, new_value, created_ts)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """,
        (
            f"{event_id}:revoke_file_link",
            event_id,
            "revoke_file_link",
            file_id,
            _json_dumps(old_value),
            _json_dumps({"share_url": None}),
            ts,
        ),
    )

    write_audit(
        con,
        actor="autonomous",
        trigger=f"detection:{det.severity}",
        evidence={"event_id": event_id, "file_id": file_id, "signals": det.signals},
        action="revoke_file_link",
        outcome="applied",
        reversible=True,
        event_id=event_id,
        details={"old_acl": old_value["acl"]},
        now=ts,
    )

    return "applied"


def notify_data_owner(
    con: sqlite3.Connection,
    event_row: sqlite3.Row,
    file_asset: Optional[FileAsset],
    det: DetectionResult,
    cfg: dict[str, Any],
    now: Optional[str] = None,
) -> None:
    if not cfg["actions"].get("notify_owners", True):
        return

    ts = now or _iso()
    owners = {event_row["user_id"]}
    if file_asset:
        owners.add(file_asset.owner_id)

    message = (
        f"Autonomous DLP action on event {event_row['id']}. "
        f"Severity={det.severity}. Signals={', '.join(det.signals[:5])}. "
        "Original evidence retained in encrypted audit store."
    )

    for owner in owners:
        insert_notification(con, owner, message, event_row["channel_id"], ts)

    write_audit(
        con,
        actor="autonomous",
        trigger=f"detection:{det.severity}",
        evidence={"event_id": event_row["id"], "owners": sorted(owners)},
        action="notify_owner",
        outcome="applied",
        reversible=False,
        event_id=event_row["id"],
        details={"message": message},
        now=ts,
    )


def perform_autonomous_response(
    con: sqlite3.Connection,
    db_path: Path | str,
    event_row: sqlite3.Row,
    det: DetectionResult,
    file_asset: Optional[FileAsset],
    cfg: dict[str, Any],
    dry_run: bool,
    now: Optional[str] = None,
) -> list[str]:
    ts = now or _iso()
    outcomes: list[str] = []

    if det.sensitive_pattern and (event_row["text"] or event_row["original_text"]):
        outcomes.append(
            redact_message(
                con=con,
                db_path=db_path,
                event_id=event_row["id"],
                det=det,
                cfg=cfg,
                dry_run=dry_run,
                now=ts,
            )
        )

    if det.confidential_file and file_asset and (det.public_channel or det.external_member):
        outcomes.append(
            revoke_file_link(
                con=con,
                db_path=db_path,
                event_id=event_row["id"],
                file_id=file_asset.id,
                det=det,
                cfg=cfg,
                dry_run=dry_run,
                now=ts,
            )
        )

    if any(o == "applied" for o in outcomes):
        notify_data_owner(con, event_row, file_asset, det, cfg, ts)
    elif dry_run and outcomes:
        write_audit(
            con,
            actor="autonomous",
            trigger=f"detection:{det.severity}",
            evidence={"event_id": event_row["id"], "outcomes": outcomes},
            action="notify_owner",
            outcome="dry_run",
            reversible=False,
            event_id=event_row["id"],
            now=ts,
        )

    return outcomes


def process_event(
    con: sqlite3.Connection,
    event_id: str,
    cfg: dict[str, Any],
    dry_run: bool = False,
    now: Optional[str] = None,
    db_path: Optional[Path | str] = None,
) -> tuple[Optional[DetectionResult], Any]:
    db_path = Path(db_path or DB_PATH)
    ts = now or _iso()

    row = con.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        write_audit(
            con,
            actor="autonomous",
            trigger="process_event",
            evidence={"event_id": event_id},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event_id,
            details={"error": "missing event"},
            now=ts,
        )
        con.commit()
        return None, "held"

    if int(row["processed"] or 0):
        det = None
        if row["detection"]:
            det = DetectionResult(**json.loads(row["detection"]))
        return det, row["verdict"] or "processed"

    event = Event(
        id=row["id"],
        ts=row["ts"],
        user_id=row["user_id"],
        channel_id=row["channel_id"],
        event_type=row["event_type"],
        text=row["text"] or "",
        file_id=row["file_id"],
    )

    channel = get_channel(con, event.channel_id)
    user = get_user(con, event.user_id)
    file_asset = get_file(con, event.file_id) if event.file_id else None

    if channel is None or user is None:
        det = DetectionResult(event_id=event.id, severity="error", reason="missing channel or user")
        write_audit(
            con,
            actor="autonomous",
            trigger="process_event",
            evidence={"event_id": event.id},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event.id,
            details={"error": det.reason},
            now=ts,
        )
        insert_notification(con, "security-admin", f"Fail-safe hold for event {event.id}: {det.reason}", None, ts)
        con.execute(
            """
            UPDATE events
            SET processed = 1, processed_ts = ?, detection = ?, verdict = 'held'
            WHERE id = ?
            """,
            (ts, _json_dumps(model_to_dict(det)), event.id),
        )
        con.commit()
        return det, "held"

    try:
        det = detect_event(event, channel, file_asset, user, cfg)
    except Exception as exc:
        det = DetectionResult(event_id=event.id, severity="error", reason=f"detection error: {exc}")
        write_audit(
            con,
            actor="autonomous",
            trigger="process_event",
            evidence={"event_id": event.id},
            action="hold",
            outcome="held",
            reversible=False,
            event_id=event.id,
            details={"error": str(exc)},
            now=ts,
        )
        con.execute(
            """
            UPDATE events
            SET processed = 1, processed_ts = ?, detection = ?, verdict = 'held'
            WHERE id = ?
            """,
            (ts, _json_dumps(model_to_dict(det)), event.id),
        )
        con.commit()
        return det, "held"

    outcomes: list[str] = []
    acted = False

    if det.severity in cfg["decision"]["auto_action_severities"]:
        outcomes = perform_autonomous_response(con, db_path, row, det, file_asset, cfg, dry_run, ts)
        acted = any(o == "applied" for o in outcomes)

    final_verdict = det.severity
    if "held" in outcomes:
        final_verdict = "held"

    if det.score >= float(cfg["decision"]["near_miss_min_score"]) and det.severity not in ("none", "error"):
        weight = float(det.score)
        if acted:
            weight *= float(cfg["decision"]["acted_risk_multiplier"])
        add_risk_event(con, event.user_id, weight, det.severity, event.id, row["ts"])

    score = calculate_user_score(con, event.user_id, cfg, _parse_iso(row["ts"]))
    update_manager_queue(con, event.user_id, score, cfg, ts)

    con.execute(
        """
        UPDATE events
        SET processed = 1,
            processed_ts = ?,
            detection = ?,
            verdict = ?,
            risk_delta = ?
        WHERE id = ?
        """,
        (ts, _json_dumps(model_to_dict(det)), final_verdict, score, event.id),
    )

    con.commit()
    return det, outcomes


def safe_process_event(
    con: sqlite3.Connection,
    event_id: str,
    cfg: dict[str, Any],
    dry_run: bool = False,
    db_path: Optional[Path | str] = None,
    now: Optional[str] = None,
) -> tuple[Optional[DetectionResult], Any]:
    try:
        return process_event(con, event_id, cfg, dry_run=dry_run, now=now, db_path=db_path)
    except Exception as exc:
        ts = now or _iso()
        write_audit(
            con,
            actor="autonomous",
            trigger="safe_process_event",
            evidence={"event_id": event_id},
            action="hold",
            outcome="error",
            reversible=False,
            event_id=event_id,
            details={"error": str(exc)},
            now=ts,
        )
        con.execute(
            """
            UPDATE events
            SET processed = 1, processed_ts = ?, verdict = 'held'
            WHERE id = ?
            """,
            (ts, event_id),
        )
        insert_notification(con, "security-admin", f"Internal error held event {event_id}: {exc}", None, ts)
        con.commit()
        return None, "held"


def undo_action(
    con: sqlite3.Connection,
    db_path: Path | str,
    action_id: str,
    actor: str = "admin",
    now: Optional[str] = None,
) -> str:
    ts = now or _iso()
    row = con.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
    if row is None:
        return "missing"
    if row["status"] != "active":
        return "skipped"

    action_type = row["action_type"]
    event_id = row["event_id"]

    if action_type == "redact_message":
        ev = con.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        if ev is None:
            write_audit(
                con,
                actor=actor,
                trigger="undo_action",
                evidence={"action_id": action_id, "event_id": event_id},
                action="restore_message",
                outcome="error",
                reversible=False,
                event_id=event_id,
                details={"error": "missing event"},
                now=ts,
            )
            con.commit()
            return "error"

        evidence_row = con.execute(
            "SELECT ciphertext FROM evidence WHERE event_id = ? ORDER BY id DESC LIMIT 1",
            (event_id,),
        ).fetchone()
        if evidence_row is None:
            write_audit(
                con,
                actor=actor,
                trigger="undo_action",
                evidence={"action_id": action_id, "event_id": event_id},
                action="restore_message",
                outcome="held",
                reversible=False,
                event_id=event_id,
                details={"error": "missing encrypted evidence"},
                now=ts,
            )
            con.commit()
            return "held"

        cipher = get_cipher(db_path)
        plain = decrypt_text(cipher, evidence_row["ciphertext"])
        if plain is None:
            write_audit(
                con,
                actor=actor,
                trigger="undo_action",
                evidence={"action_id": action_id, "event_id": event_id},
                action="restore_message",
                outcome="held",
                reversible=False,
                event_id=event_id,
                details={"error": "decryption failure; fail-safe hold"},
                now=ts,
            )
            insert_notification(con, "security-admin", f"Unable to decrypt evidence for event {event_id}.", None, ts)
            con.commit()
            return "held"

        con.execute(
            """
            UPDATE events
            SET text = ?, redacted = 0, tombstone = NULL, verdict = 'restored'
            WHERE id = ?
            """,
            (plain, event_id),
        )
        con.execute(
            "UPDATE actions SET status = 'undone', undone_ts = ? WHERE id = ?",
            (ts, action_id),
        )
        write_audit(
            con,
            actor=actor,
            trigger="admin_restore",
            evidence={"action_id": action_id, "event_id": event_id},
            action="restore_message",
            outcome="undone",
            reversible=False,
            event_id=event_id,
            details={"restored_length": len(plain)},
            now=ts,
        )
        con.commit()
        return "undone"

    if action_type == "revoke_file_link":
        file_id = row["target_id"]
        file_row = con.execute("SELECT data FROM files WHERE id = ?", (file_id,)).fetchone()
        if file_row is None:
            write_audit(
                con,
                actor=actor,
                trigger="undo_action",
                evidence={"action_id": action_id, "file_id": file_id},
                action="restore_file_link",
                outcome="error",
                reversible=False,
                event_id=event_id,
                details={"error": "missing file"},
                now=ts,
            )
            con.commit()
            return "error"

        old = json.loads(row["old_value"] or "{}")
        data = json.loads(file_row["data"])
        data["share_url"] = old.get("share_url")
        data["acl"] = old.get("acl", data.get("acl", []))

        con.execute("UPDATE files SET data = ? WHERE id = ?", (_json_dumps(data), file_id))
        con.execute(
            "UPDATE actions SET status = 'undone', undone_ts = ? WHERE id = ?",
            (ts, action_id),
        )
        write_audit(
            con,
            actor=actor,
            trigger="admin_restore",
            evidence={"action_id": action_id, "file_id": file_id},
            action="restore_file_link",
            outcome="undone",
            reversible=False,
            event_id=event_id,
            details={"restored_share_url": bool(old.get("share_url"))},
            now=ts,
        )
        con.commit()
        return "undone"

    return "unsupported"


def release_hold(
    con: sqlite3.Connection,
    event_id: str,
    actor: str = "admin",
    now: Optional[str] = None,
) -> str:
    ts = now or _iso()
    row = con.execute("SELECT verdict FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        return "missing"
    if row["verdict"] != "held":
        return "skipped"

    con.execute(
        "UPDATE events SET verdict = 'released' WHERE id = ?",
        (event_id,),
    )
    write_audit(
        con,
        actor=actor,
        trigger="admin_release",
        evidence={"event_id": event_id},
        action="release_hold",
        outcome="applied",
        reversible=False,
        event_id=event_id,
        now=ts,
    )
    con.commit()
    return "applied"


def remove_external_guest(
    con: sqlite3.Connection,
    channel_id: str,
    user_id: str,
    actor: str = "admin",
    now: Optional[str] = None,
) -> str:
    ts = now or _iso()
    channel = get_channel(con, channel_id)
    if channel is None:
        write_audit(
            con,
            actor=actor,
            trigger="membership_change",
            evidence={"channel_id": channel_id, "user_id": user_id},
            action="remove_external_guest",
            outcome="error",
            reversible=False,
            details={"error": "missing channel"},
            now=ts,
        )
        con.commit()
        return "error"

    if user_id not in channel.members:
        return "skipped"

    channel.members = [m for m in channel.members if m != user_id]

    external = False
    for member_id in channel.members:
        u = get_user(con, member_id)
        if u and u.is_external_guest:
            external = True
            break
    channel.has_external_guest = external

    _put_json(con, "channels", channel.id, channel)

    write_audit(
        con,
        actor=actor,
        trigger="incident_containment",
        evidence={"channel_id": channel_id, "user_id": user_id},
        action="remove_external_guest",
        outcome="applied",
        reversible=True,
        details={"note": "Does not re-trigger processed incidents by design"},
        now=ts,
    )
    con.commit()
    return "applied"


def rescan_unprocessed_events_in_channel(
    con: sqlite3.Connection,
    channel_id: str,
    cfg: dict[str, Any],
    dry_run: bool = False,
    db_path: Optional[Path | str] = None,
) -> int:
    rows = con.execute(
        "SELECT id FROM events WHERE channel_id = ? AND processed = 0 ORDER BY ts, id",
        (channel_id,),
    ).fetchall()
    count = 0
    for row in rows:
        safe_process_event(con, row["id"], cfg, dry_run=dry_run, db_path=db_path)
        count += 1
    return count


def _base_entities(cfg: dict[str, Any]) -> tuple[list[User], list[Channel], list[FileAsset]]:
    rng = random.Random(int(cfg["simulation"]["seed"]))

    first_names = [
        "Ada", "Grace", "Alan", "Katherine", "Edsger", "Barbara", "Linus", "Margaret",
        "Dennis", "Radia", "Ken", "Anita", "Tim", "Frances", "Guido", "Joan",
        "Donald", "Shafi", "Leslie", "Muriel", "James", "Hedy", "John", "Karen",
        "Vint", "Ruth", "Bob", "Donna", "Adele", "Peter"
    ]
    last_names = [
        "Lovelace", "Hopper", "Turing", "Johnson", "Dijkstra", "Liskov", "Torvalds",
        "Hamilton", "Ritchie", "Perlman", "Thompson", "Borg", "Berners", "Allen",
        "Rossum", "Clarke", "Knuth", "Goldwasser", "Valiant", "Lehman", "Gosling",
        "Lamarr", "McCarthy", "Spärck", "Cerf", "Lichterman", "Metcalfe", "Stewart",
        "Goldberg", "Naur"
    ]

    users: list[User] = []
    for i in range(1, int(cfg["simulation"]["users"]) + 1):
        first = first_names[(i - 1) % len(first_names)]
        last = last_names[(i - 1) % len(last_names)]
        is_external = i >= 28
        users.append(
            User(
                id=f"u{i:03d}",
                name=f"{first} {last}",
                email=f"{first.lower()}.{last.lower()}@example.invalid",
                is_external_guest=is_external,
                role="external-guest" if is_external else rng.choice(["engineer", "manager", "analyst", "support"]),
                department="partner" if is_external else rng.choice(["engineering", "sales", "finance", "security", "operations"]),
            )
        )

    internal_ids = [u.id for u in users if not u.is_external_guest]
    external_ids = [u.id for u in users if u.is_external_guest]

    channels = [
        Channel(id="ch-general", name="general", is_public=True, topic="Company-wide chatter"),
        Channel(id="ch-announcements", name="announcements", is_public=True, topic="Official announcements"),
        Channel(id="ch-engineering", name="engineering", topic="Engineering coordination"),
        Channel(id="ch-design", name="design", topic="Design reviews"),
        Channel(id="ch-marketing", name="marketing", topic="Campaign planning"),
        Channel(id="ch-sales", name="sales", topic="Pipeline discussion"),
        Channel(id="ch-security", name="security-ops", topic="Security operations"),
        Channel(id="ch-partner", name="partner-support", has_external_guest=True, topic="Partner support"),
    ]

    for ch in channels:
        if ch.id == "ch-partner":
            members = rng.sample(internal_ids, k=min(8, len(internal_ids))) + [external_ids[0]]
            ch.members = list(dict.fromkeys(members))
        elif ch.is_public:
            ch.members = internal_ids[:]
        else:
            ch.members = rng.sample(internal_ids, k=min(12, len(internal_ids)))

    file_defs = [
        ("file-001", "quarterly-financial-plan.xlsx", ["confidential"]),
        ("file-002", "customer-pii-export.csv", ["confidential"]),
        ("file-003", "architecture-diagram.pdf", ["confidential"]),
        ("file-004", "executive-compensation.docx", ["confidential"]),
        ("file-005", "marketing-deck.pdf", ["internal"]),
        ("file-006", "public-api-docs.md", ["public"]),
        ("file-007", "release-notes.txt", ["internal"]),
        ("file-008", "team-roster.csv", ["internal"]),
    ]

    files: list[FileAsset] = []
    for idx, (fid, fname, tags) in enumerate(file_defs, start=1):
        owner = users[(idx - 1) % len(users)]
        token = base64.urlsafe_b64encode(rng.getrandbits(128).to_bytes(16, "big")).decode().rstrip("=")
        files.append(
            FileAsset(
                id=fid,
                name=fname,
                owner_id=owner.id,
                metadata_tags=tags,
                share_url=f"https://files.invalid.local/{fid}?token={token}",
                acl=[ch.id for ch in channels if rng.random() < 0.35] or ["ch-engineering"],
                size_kb=rng.randint(50, 5000),
            )
        )

    return users, channels, files


def insert_event_row(con: sqlite3.Connection, event: Event) -> None:
    con.execute(
        """
        INSERT OR REPLACE INTO events
        (id, ts, user_id, channel_id, event_type, text, file_id, original_text,
         redacted, tombstone, detection, verdict, processed, processed_ts, risk_delta)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL, NULL, NULL, 0, NULL, 0.0)
        """,
        (
            event.id,
            event.ts,
            event.user_id,
            event.channel_id,
            event.event_type,
            event.text,
            event.file_id,
        ),
    )


def generate_seed_data(con: sqlite3.Connection, cfg: dict[str, Any]) -> None:
    users, channels, files = _base_entities(cfg)

    for u in users:
        _put_json(con, "users", u.id, u)
    for c in channels:
        _put_json(con, "channels", c.id, c)
    for f in files:
        _put_json(con, "files", f.id, f)

    rng = random.Random(int(cfg["simulation"]["seed"]) + 1)
    base = _parse_iso(cfg["simulation"]["base_time"])
    event_count = int(cfg["simulation"]["event_count"])

    special = {
        5: ("message", "u007", "ch-partner", AWS_KEY_1, None),
        15: ("message", "u003", "ch-engineering", f"Test fixture {BENIGN_FIXTURES[0]} should be ignored", None),
        25: ("file_share", "u002", "ch-announcements", "Sharing quarterly plan", "file-001"),
        35: ("message", "u009", "ch-sales", GITHUB_TOKEN_1, None),
        45: ("message", "u004", "ch-general", f"Benign fixture {BENIGN_FIXTURES[1]} in chat", None),
        55: ("message", "u010", "ch-partner", PRIVATE_KEY_TEXT, None),
        65: ("file_share", "u004", "ch-partner", "Confidential partner package", "file-002"),
        75: ("message", "u005", "ch-engineering", DB_CONN_1, None),
        85: ("message", "u006", "ch-design", f"Fixture {BENIGN_FIXTURES[2]} high entropy but allowed", None),
        95: ("message", "u008", "ch-announcements", AWS_KEY_2, None),
        115: ("file_share", "u001", "ch-general", "Confidential board summary", "file-003"),
        145: ("file_share", "u003", "ch-security", "Confidential incident notes", "file-004"),
        195: ("message", "u009", "ch-engineering", GITHUB_TOKEN_2, None),
    }

    normal_messages = [
        "Standup notes are in the wiki.",
        "Can someone review PR 482?",
        "Lunch order going in 10 minutes.",
        "Dashboard link: https://dash.invalid.local/overview",
        "I updated the runbook.",
        "Meeting moved to Thursday.",
        "Thanks for the quick fix.",
        "Please use the template for incident timelines.",
    ]

    non_conf_files = [f for f in files if "confidential" not in [t.lower() for t in f.metadata_tags]]

    for i in range(event_count):
        eid = f"evt-{i:04d}"
        ts = (base + timedelta(seconds=i * 15 + rng.randint(0, 10))).isoformat()

        if i in special:
            kind, uid, cid, text, fid = special[i]
            event = Event(id=eid, ts=ts, user_id=uid, channel_id=cid, event_type=kind, text=text, file_id=fid)
            insert_event_row(con, event)
            continue

        if 200 <= i < 220:
            token = "".join(rng.choices(string.ascii_letters + string.digits, k=24))
            event = Event(
                id=eid,
                ts=ts,
                user_id="u007",
                channel_id="ch-sales",
                event_type="message",
                text=f"api_key = {token}",
                file_id=None,
            )
            insert_event_row(con, event)
            continue

        user = rng.choice(users)
        channel = rng.choice(channels)

        if rng.random() < 0.12 and non_conf_files:
            f = rng.choice(non_conf_files)
            text = rng.choice(
                [
                    f"Sharing {f.name}",
                    f"Attached {f.name} for review",
                    f"{f.name} is in the channel",
                ]
            )
            event = Event(
                id=eid,
                ts=ts,
                user_id=user.id,
                channel_id=channel.id,
                event_type="file_share",
                text=text,
                file_id=f.id,
            )
        else:
            text = rng.choice(normal_messages)
            if rng.random() < 0.08:
                token = "".join(rng.choices(string.ascii_letters + string.digits, k=22))
                text = f"{text} debug-token {token}"
            event = Event(
                id=eid,
                ts=ts,
                user_id=user.id,
                channel_id=channel.id,
                event_type="message",
                text=text,
                file_id=None,
            )

        insert_event_row(con, event)

    con.commit()


def seed_if_empty(con: sqlite3.Connection, cfg: dict[str, Any]) -> None:
    count = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if int(count) == 0:
        generate_seed_data(con, cfg)


DEMO_SCRIPT = [
    {
        "offset": 0,
        "kind": "message",
        "title": "Baseline traffic",
        "user_id": "u001",
        "channel_id": "ch-general",
        "text": "Standup notes are in the wiki.",
        "expected": "none",
    },
    {
        "offset": 10,
        "kind": "message",
        "title": "AWS key shared with external guest",
        "user_id": "u007",
        "channel_id": "ch-partner",
        "text": AWS_KEY_1,
        "expected": "critical",
    },
    {
        "offset": 20,
        "kind": "file",
        "title": "Confidential file to public channel",
        "user_id": "u002",
        "channel_id": "ch-announcements",
        "text": "Quarterly plan attached",
        "file_id": "file-001",
        "expected": "high",
    },
    {
        "offset": 30,
        "kind": "message",
        "title": "Allow-listed high-entropy fixture",
        "user_id": "u003",
        "channel_id": "ch-engineering",
        "text": f"Fixture {BENIGN_FIXTURES[0]} is benign",
        "expected": "none",
    },
    {
        "offset": 40,
        "kind": "message",
        "title": "Near-miss credential text",
        "user_id": "u007",
        "channel_id": "ch-sales",
        "text": "api_key = sandbox-not-real-1234567890",
        "expected": "medium",
    },
    {
        "offset": 50,
        "kind": "message",
        "title": "Private key to external guest",
        "user_id": "u009",
        "channel_id": "ch-partner",
        "text": PRIVATE_KEY_TEXT,
        "expected": "critical",
    },
    {
        "offset": 60,
        "kind": "message",
        "title": "Same AWS key re-pasted internally",
        "user_id": "u007",
        "channel_id": "ch-engineering",
        "text": AWS_KEY_1,
        "expected": "high",
    },
    {
        "offset": 70,
        "kind": "file",
        "title": "Confidential file to guest channel",
        "user_id": "u004",
        "channel_id": "ch-partner",
        "text": "Partner package",
        "file_id": "file-002",
        "expected": "high",
    },
    {
        "offset": 80,
        "kind": "message",
        "title": "Another near-miss raises user risk",
        "user_id": "u007",
        "channel_id": "ch-sales",
        "text": "password = temp1234567890abcd",
        "expected": "medium",
    },
    {
        "offset": 90,
        "kind": "file",
        "title": "Idempotent revoke attempt",
        "user_id": "u002",
        "channel_id": "ch-announcements",
        "text": "Resending quarterly plan",
        "file_id": "file-001",
        "expected": "high/skipped",
    },
    {
        "offset": 100,
        "kind": "remove_guest",
        "title": "Remove external guest after incident",
        "channel_id": "ch-partner",
        "user_id": "u028",
        "expected": "membership",
    },
    {
        "offset": 110,
        "kind": "rescan",
        "title": "Rescan channel does not re-trigger closed incident",
        "channel_id": "ch-partner",
        "expected": "no-new-actions",
    },
]


def seed_demo_script(con: sqlite3.Connection, cfg: dict[str, Any]) -> None:
    con.executescript(
        """
        DELETE FROM users;
        DELETE FROM channels;
        DELETE FROM files;
        DELETE FROM events;
        DELETE FROM evidence;
        DELETE FROM audit;
        DELETE FROM actions;
        DELETE FROM notifications;
        DELETE FROM risk_events;
        DELETE FROM user_scores;
        DELETE FROM manager_queue;
        """
    )

    users, channels, files = _base_entities(cfg)
    for u in users:
        _put_json(con, "users", u.id, u)
    for c in channels:
        _put_json(con, "channels", c.id, c)
    for f in files:
        _put_json(con, "files", f.id, f)

    base = _parse_iso(cfg["simulation"]["base_time"])

    for idx, step in enumerate(DEMO_SCRIPT):
        if step["kind"] not in ("message", "file"):
            continue
        ts = (base + timedelta(seconds=int(step["offset"]))).isoformat()
        event = Event(
            id=f"demo-{idx:03d}",
            ts=ts,
            user_id=step["user_id"],
            channel_id=step["channel_id"],
            event_type="file_share" if step["kind"] == "file" else "message",
            text=step["text"],
            file_id=step.get("file_id"),
        )
        insert_event_row(con, event)

    con.commit()


def _wrap_text(text: str, width: int = 58) -> list[str]:
    words = (text or "").split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 <= width:
            cur = (cur + " " + w).strip()
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines[:4]


def generate_gif_from_events(
    con: sqlite3.Connection,
    cfg: dict[str, Any],
    limit: int = 18,
    use_stored: bool = False,
) -> Optional[bytes]:
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None

    rows = con.execute(
        "SELECT * FROM events ORDER BY ts, id LIMIT ?",
        (int(limit),),
    ).fetchall()

    infos: list[dict[str, Any]] = []

    for row in rows:
        if use_stored and row["detection"]:
            det = DetectionResult(**json.loads(row["detection"]))
            severity = row["verdict"] or det.severity
            score = float(row["risk_delta"] or det.score)
            text = row["text"] or ""
        else:
            channel = get_channel(con, row["channel_id"])
            user = get_user(con, row["user_id"])
            file_asset = get_file(con, row["file_id"]) if row["file_id"] else None
            event = Event(
                id=row["id"],
                ts=row["ts"],
                user_id=row["user_id"],
                channel_id=row["channel_id"],
                event_type=row["event_type"],
                text=row["text"] or "",
                file_id=row["file_id"],
            )
            det = detect_event(event, channel, file_asset, user, cfg)
            severity = det.severity
            score = det.score
            text = event.text

        user_obj = get_user(con, row["user_id"])
        channel_obj = get_channel(con, row["channel_id"])
        infos.append(
            {
                "ts": row["ts"],
                "user": user_obj.name if user_obj else row["user_id"],
                "channel": channel_obj.name if channel_obj else row["channel_id"],
                "text": mask_text(text, cfg),
                "severity": severity,
                "score": score,
            }
        )

    if not infos:
        infos = [
            {
                "ts": _iso(),
                "user": "System",
                "channel": "general",
                "text": "No events found.",
                "severity": "none",
                "score": 0.0,
            }
        ]

    colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e",
        "none": "#64748b",
        "held": "#a855f7",
        "error": "#dc2626",
        "restored": "#0ea5e9",
        "released": "#14b8a6",
    }

    frames = []
    for idx, info in enumerate(infos):
        img = Image.new("RGB", (760, 430), (10, 15, 30))
        d = ImageDraw.Draw(img)

        d.rectangle([0, 0, 760, 54], fill=(17, 24, 39))
        d.text((18, 16), "SecureChat DLP Simulation — Live Demo Video", fill=(226, 232, 240))

        d.text((18, 70), f"{info['ts']}", fill=(148, 163, 184))
        d.text((18, 92), f"{info['user']} → #{info['channel']}", fill=(203, 213, 225))

        y = 126
        for line in _wrap_text(info["text"], width=62):
            d.text((18, y), line, fill=(241, 245, 249))
            y += 22

        badge_color = colors.get(str(info["severity"]).lower(), "#64748b")
        d.rectangle([18, 300, 180, 332], fill=badge_color)
        d.text((28, 307), str(info["severity"]).upper(), fill=(10, 15, 30))
        d.text((200, 307), f"detection score: {float(info['score']):.2f}", fill=(203, 213, 225))

        progress_w = int(724 * ((idx + 1) / max(1, len(infos))))
        d.rectangle([18, 380, 18 + progress_w, 392], fill=(59, 130, 246))
        d.text((18, 400), f"Frame {idx + 1}/{len(infos)}", fill=(148, 163, 184))

        frames.append(img)

    buf = io.BytesIO()
    frames[0].save(
        buf,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        duration=650,
        loop=0,
        optimize=False,
    )
    return buf.getvalue()


def _remove_db_files(path: Path | str) -> None:
    base = Path(path)
    candidates = [
        base,
        Path(str(base) + "-wal"),
        Path(str(base) + "-shm"),
        Path(str(base) + ".key"),
    ]
    for p in candidates:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Pytest suite. Run with: pytest -q
# ---------------------------------------------------------------------------

def _create_minimal_db(tmp_path):
    db = Path(tmp_path) / "test.db"
    con = connect(db)
    init_db(con)
    cfg = default_config()
    users, channels, files = _base_entities(cfg)
    for u in users:
        _put_json(con, "users", u.id, u)
    for c in channels:
        _put_json(con, "channels", c.id, c)
    for f in files:
        _put_json(con, "files", f.id, f)
    con.commit()
    return con, db, cfg, users, channels, files


def test_entropy_filter_ignores_fixtures(tmp_path):
    con, db, cfg, users, channels, files = _create_minimal_db(tmp_path)
    eng = next(c for c in channels if c.id == "ch-engineering")
    user = users[0]
    event = Event(
        id="fixture-test",
        ts=_iso(),
        user_id=user.id,
        channel_id=eng.id,
        text=f"fixture {BENIGN_FIXTURES[0]}",
    )
    det = detect_event(event, eng, None, user, cfg)
    assert det.allowlisted_tokens
    assert not det.high_entropy_token
    assert det.severity == "none"


def test_same_secret_re_pasted_is_caught_again(tmp_path):
    con, db, cfg, users, channels, files = _create_minimal_db(tmp_path)
    e1 = Event(id="secret-1", ts=_iso(), user_id="u001", channel_id="ch-engineering", text=AWS_KEY_1)
    e2 = Event(id="secret-2", ts=_iso(), user_id="u002", channel_id="ch-engineering", text=AWS_KEY_1)
    insert_event_row(con, e1)
    insert_event_row(con, e2)

    det1, _ = process_event(con, "secret-1", cfg, dry_run=False, db_path=db)
    det2, _ = process_event(con, "secret-2", cfg, dry_run=False, db_path=db)

    assert det1 is not None and det1.sensitive_pattern
    assert det2 is not None and det2.sensitive_pattern

    r1 = con.execute("SELECT redacted, text FROM events WHERE id = ?", ("secret-1",)).fetchone()
    r2 = con.execute("SELECT redacted, text FROM events WHERE id = ?", ("secret-2",)).fetchone()

    assert int(r1["redacted"]) == 1
    assert int(r2["redacted"]) == 1
    assert cfg["actions"]["tombstone"] in r1["text"]
    assert cfg["actions"]["tombstone"] in r2["text"]


def test_revoke_is_idempotent(tmp_path):
    con, db, cfg, users, channels, files = _create_minimal_db(tmp_path)
    event = Event(
        id="revoke-test",
        ts=_iso(),
        user_id="u001",
        channel_id="ch-announcements",
        event_type="file_share",
        text="Confidential file",
        file_id="file-001",
    )
    insert_event_row(con, event)

    process_event(con, "revoke-test", cfg, dry_run=False, db_path=db)
    count1 = con.execute(
        "SELECT COUNT(*) AS c FROM actions WHERE event_id = ? AND action_type = ?",
        ("revoke-test", "revoke_file_link"),
    ).fetchone()["c"]

    process_event(con, "revoke-test", cfg, dry_run=False, db_path=db)
    count2 = con.execute(
        "SELECT COUNT(*) AS c FROM actions WHERE event_id = ? AND action_type = ?",
        ("revoke-test", "revoke_file_link"),
    ).fetchone()["c"]

    applied = con.execute(
        "SELECT COUNT(*) AS c FROM audit WHERE event_id = ? AND action = ? AND outcome = ?",
        ("revoke-test", "revoke_file_link", "applied"),
    ).fetchone()["c"]

    assert count1 == 1
    assert count2 == 1
    assert applied == 1


def test_external_guest_removal_after_incident_does_not_re_trigger(tmp_path):
    con, db, cfg, users, channels, files = _create_minimal_db(tmp_path)
    event = Event(
        id="guest-test",
        ts=_iso(),
        user_id="u007",
        channel_id="ch-partner",
        text=AWS_KEY_1,
    )
    insert_event_row(con, event)

    process_event(con, "guest-test", cfg, dry_run=False, db_path=db)

    actions_before = con.execute(
        "SELECT COUNT(*) AS c FROM actions WHERE event_id = ?",
        ("guest-test",),
    ).fetchone()["c"]

    audits_before = con.execute(
        "SELECT COUNT(*) AS c FROM audit WHERE event_id = ? AND outcome = 'applied' AND action IN ('redact_message','revoke_file_link')",
        ("guest-test",),
    ).fetchone()["c"]

    remove_external_guest(con, "ch-partner", "u028", actor="admin")
    rescanned = rescan_unprocessed_events_in_channel(con, "ch-partner", cfg, dry_run=False, db_path=db)

    actions_after = con.execute(
        "SELECT COUNT(*) AS c FROM actions WHERE event_id = ?",
        ("guest-test",),
    ).fetchone()["c"]

    audits_after = con.execute(
        "SELECT COUNT(*) AS c FROM audit WHERE event_id = ? AND outcome = 'applied' AND action IN ('redact_message','revoke_file_link')",
        ("guest-test",),
    ).fetchone()["c"]

    assert rescanned == 0
    assert actions_after == actions_before
    assert audits_after == audits_before


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------

def run_app() -> None:
    import streamlit as st
    import pandas as pd

    st.set_page_config(
        page_title="SecureChat DLP Simulation",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    cfg = load_config()

    st.session_state.setdefault("seed_input", int(cfg["simulation"]["seed"]))
    st.session_state.setdefault("dry_run_toggle", bool(cfg["actions"]["dry_run_default"]))
    st.session_state.setdefault("entropy_slider", float(cfg["detection"]["entropy_threshold"]))
    st.session_state.setdefault("min_token_slider", int(cfg["detection"]["min_token_length"]))
    st.session_state.setdefault("manager_slider", float(cfg["decision"]["manager_review_threshold"]))
    st.session_state.setdefault("half_life_slider", float(cfg["decision"]["half_life_days"]))
    st.session_state.setdefault("speed_slider", float(cfg["ui"]["default_speed"]))
    st.session_state.setdefault("live_playing", True)
    st.session_state.setdefault("live_start", time.time())

    def _save_sidebar_config() -> None:
        fresh = load_config()
        fresh["simulation"]["seed"] = int(st.session_state["seed_input"])
        fresh["actions"]["dry_run_default"] = bool(st.session_state["dry_run_toggle"])
        fresh["detection"]["entropy_threshold"] = float(st.session_state["entropy_slider"])
        fresh["detection"]["min_token_length"] = int(st.session_state["min_token_slider"])
        fresh["decision"]["manager_review_threshold"] = float(st.session_state["manager_slider"])
        fresh["decision"]["half_life_days"] = float(st.session_state["half_life_slider"])
        fresh["ui"]["default_speed"] = float(st.session_state["speed_slider"])
        save_config(fresh)

    with st.sidebar:
        st.header("Controls")
        st.caption("All thresholds persist to config.yaml.")

        st.number_input("Seed", key="seed_input", step=1, on_change=_save_sidebar_config)
        st.toggle("Dry-Run", key="dry_run_toggle", on_change=_save_sidebar_config)
        st.slider("Entropy threshold (bits/char)", 2.0, 6.0, key="entropy_slider", step=0.1, on_change=_save_sidebar_config)
        st.slider("Minimum token length", 8, 64, key="min_token_slider", step=1, on_change=_save_sidebar_config)
        st.slider("Manager review threshold", 1.0, 50.0, key="manager_slider", step=0.5, on_change=_save_sidebar_config)
        st.slider("Risk half-life (days)", 1.0, 30.0, key="half_life_slider", step=0.5, on_change=_save_sidebar_config)
        st.slider("Playback speed", 0.5, 10.0, key="speed_slider", step=0.5, on_change=_save_sidebar_config)

        st.divider()
        if st.button("Reset simulation database", use_container_width=True):
            _remove_db_files(DB_PATH)
            _remove_db_files(DEMO_DB_PATH)
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    cfg = load_config()
    dry_run = bool(cfg["actions"]["dry_run_default"])

    con = connect(DB_PATH)
    init_db(con)
    seed_if_empty(con, cfg)

    if "intro_video" not in st.session_state:
        with st.spinner("Generating live demo video..."):
            st.session_state["intro_video"] = generate_gif_from_events(
                con,
                cfg,
                limit=int(cfg["ui"]["video_frames"]),
                use_stored=False,
            )

    tabs = st.tabs(["Live Feed", "Evidence", "Audit Log", "Report", "Demo Mode"])

    def _render_live_body() -> None:
        total = con.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        processed = con.execute("SELECT COUNT(*) AS c FROM events WHERE processed = 1").fetchone()["c"]

        if st.session_state.get("live_playing", False) and processed < total:
            speed = float(st.session_state.get("speed_slider", cfg["ui"]["default_speed"]))
            batch = max(1, min(12, int(float(cfg["ui"]["events_per_second"]) * speed)))
            for _ in range(batch):
                nxt = con.execute(
                    "SELECT id FROM events WHERE processed = 0 ORDER BY ts, id LIMIT 1"
                ).fetchone()
                if nxt is None:
                    break
                safe_process_event(con, nxt["id"], cfg, dry_run=dry_run, db_path=DB_PATH)

        col1, col2, col3, col4 = st.columns([1, 1, 2, 4])
        with col1:
            if st.button("Pause" if st.session_state.get("live_playing") else "Play", use_container_width=True):
                st.session_state["live_playing"] = not st.session_state.get("live_playing", False)
        with col2:
            if st.button("Fast-forward", use_container_width=True):
                while True:
                    nxt = con.execute(
                        "SELECT id FROM events WHERE processed = 0 ORDER BY ts, id LIMIT 1"
                    ).fetchone()
                    if nxt is None:
                        break
                    safe_process_event(con, nxt["id"], cfg, dry_run=dry_run, db_path=DB_PATH)
                st.session_state["live_playing"] = False
        with col3:
            st.metric("Processed", f"{processed}/{total}")
        with col4:
            redacted = con.execute("SELECT COUNT(*) AS c FROM events WHERE redacted = 1").fetchone()["c"]
            revoked = con.execute(
                "SELECT COUNT(*) AS c FROM actions WHERE action_type = 'revoke_file_link' AND status = 'active'"
            ).fetchone()["c"]
            st.metric("Redacted", redacted)
            st.metric("Revoked links", revoked)

        if st.session_state.get("intro_video"):
            st.image(st.session_state["intro_video"], caption="Auto-generated live demo video (GIF)")
            st.download_button(
                "Download demo video (GIF)",
                st.session_state["intro_video"],
                file_name="securechat-live-demo.gif",
                mime="image/gif",
            )

        st.subheader("Event stream")
        rows = con.execute(
            "SELECT * FROM events WHERE processed = 1 ORDER BY processed_ts DESC, ts DESC LIMIT 30"
        ).fetchall()

        users_map = {u.id: u.name for u in get_all_users(con)}
        channels_map = {c.id: c.name for c in get_all_channels(con)}

        color_map = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#22c55e",
            "none": "#64748b",
            "held": "#a855f7",
            "restored": "#0ea5e9",
            "released": "#14b8a6",
        }

        if not rows:
            st.info("Waiting for first events...")
            return

        for row in rows:
            verdict = row["verdict"] or "none"
            color = color_map.get(str(verdict).lower(), "#64748b")
            det_score = 0.0
            if row["detection"]:
                try:
                    det_score = float(DetectionResult(**json.loads(row["detection"])).score)
                except Exception:
                    det_score = 0.0

            safe_text = html.escape(mask_text(row["text"] or "", cfg))
            user_name = html.escape(users_map.get(row["user_id"], row["user_id"]))
            channel_name = html.escape(channels_map.get(row["channel_id"], row["channel_id"]))

            st.markdown(
                f"""
                <div style="border-left:5px solid {color}; padding:10px 12px; margin-bottom:8px; background:#111827; border-radius:8px;">
                  <div style="color:#94a3b8; font-size:0.9rem;">
                    {html.escape(row['ts'])} · {user_name} → #{channel_name}
                  </div>
                  <div style="margin-top:4px;">
                    <span style="background:{color}; color:#111827; padding:2px 8px; border-radius:999px; font-weight:700; font-size:0.8rem;">
                      {html.escape(str(verdict).upper())}
                    </span>
                    <span style="color:#cbd5e1; margin-left:8px; font-size:0.9rem;">
                      event score {det_score:.2f} · rolling risk {float(row['risk_delta'] or 0.0):.2f}
                    </span>
                  </div>
                  <div style="margin-top:8px; color:#e5e7eb; font-family:monospace; white-space:pre-wrap;">{safe_text}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with tabs[0]:
        st.subheader("Live Feed")
        if hasattr(st, "fragment"):
            @st.fragment(run_every=1.0)
            def _live_fragment() -> None:
                _render_live_body()

            _live_fragment()
        else:
            _render_live_body()
            if st.session_state.get("live_playing"):
                time.sleep(1.0)
                st.rerun()

    with tabs[1]:
        st.subheader("Evidence")
        rows = con.execute(
            "SELECT id, ts, verdict, detection FROM events WHERE detection IS NOT NULL ORDER BY ts DESC LIMIT 200"
        ).fetchall()

        if not rows:
            st.info("No processed events yet.")
        else:
            event_ids = [r["id"] for r in rows]
            selected = st.selectbox(
                "Select event",
                event_ids,
                format_func=lambda x: next((r["id"] + " · " + (r["verdict"] or "none") for r in rows if r["id"] == x), x),
            )

            row = con.execute("SELECT * FROM events WHERE id = ?", (selected,)).fetchone()
            if row is None:
                st.error("Missing event.")
            else:
                channel = get_channel(con, row["channel_id"])
                user = get_user(con, row["user_id"])
                file_asset = get_file(con, row["file_id"]) if row["file_id"] else None

                st.write("**Context**")
                c1, c2, c3 = st.columns(3)
                c1.write(f"User: {user.name if user else row['user_id']}")
                c2.write(f"Channel: #{channel.name if channel else row['channel_id']}")
                c3.write(f"File: {file_asset.name if file_asset else '—'}")

                if row["detection"]:
                    det = DetectionResult(**json.loads(row["detection"]))
                    st.write("**Signals**")
                    st.json(model_to_dict(det))

                if int(row["redacted"] or 0):
                    st.warning("Message redacted. Original is encrypted in evidence store.")
                    reveal_key = f"reveal_{selected}"
                    if st.button("Reveal original evidence (admin audit)", key=f"btn_reveal_{selected}"):
                        evidence_row = con.execute(
                            "SELECT ciphertext FROM evidence WHERE event_id = ? ORDER BY id DESC LIMIT 1",
                            (selected,),
                        ).fetchone()
                        cipher = get_cipher(DB_PATH)
                        plain = decrypt_text(cipher, evidence_row["ciphertext"]) if evidence_row else None
                        if plain is None:
                            st.error("Unable to decrypt evidence.")
                            write_audit(
                                con,
                                actor="admin",
                                trigger="evidence_view",
                                evidence={"event_id": selected},
                                action="view_evidence",
                                outcome="error",
                                reversible=False,
                                event_id=selected,
                            )
                        else:
                            st.session_state[reveal_key] = plain
                            write_audit(
                                con,
                                actor="admin",
                                trigger="evidence_view",
                                evidence={"event_id": selected},
                                action="view_evidence",
                                outcome="applied",
                                reversible=False,
                                event_id=selected,
                            )
                        con.commit()

                    if reveal_key in st.session_state:
                        st.code(st.session_state[reveal_key], language="text")

                active_actions = con.execute(
                    "SELECT * FROM actions WHERE event_id = ? AND status = 'active'",
                    (selected,),
                ).fetchall()

                if active_actions:
                    st.write("**Active reversible actions**")
                    for a in active_actions:
                        ac1, ac2 = st.columns([4, 1])
                        ac1.write(f"`{a['action_type']}` → target `{a['target_id']}`")
                        if ac2.button("Undo / Restore", key=f"undo_{a['id']}"):
                            outcome = undo_action(con, DB_PATH, a["id"], actor="admin")
                            st.success(f"Undo outcome: {outcome}")
                            st.rerun()

                if row["verdict"] == "held":
                    if st.button("Release hold", key=f"release_{selected}"):
                        outcome = release_hold(con, selected, actor="admin")
                        st.success(f"Release outcome: {outcome}")
                        st.rerun()

    with tabs[2]:
        st.subheader("Audit Log")

        actors = [r["actor"] for r in con.execute("SELECT DISTINCT actor FROM audit").fetchall()]
        actions = [r["action"] for r in con.execute("SELECT DISTINCT action FROM audit").fetchall()]
        outcomes = [r["outcome"] for r in con.execute("SELECT DISTINCT outcome FROM audit").fetchall()]

        f1, f2, f3, f4 = st.columns(4)
        sel_actors = f1.multiselect("Actor", actors, default=actors)
        sel_actions = f2.multiselect("Action", actions, default=actions)
        sel_outcomes = f3.multiselect("Outcome", outcomes, default=outcomes)
        date_filter = f4.text_input("Date filter (YYYY-MM-DD)", "")

        clauses = []
        params: list[Any] = []

        if sel_actors:
            clauses.append("actor IN (" + ",".join("?" * len(sel_actors)) + ")")
            params.extend(sel_actors)
        if sel_actions:
            clauses.append("action IN (" + ",".join("?" * len(sel_actions)) + ")")
            params.extend(sel_actions)
        if sel_outcomes:
            clauses.append("outcome IN (" + ",".join("?" * len(sel_outcomes)) + ")")
            params.extend(sel_outcomes)
        if date_filter:
            clauses.append("DATE(ts) = ?")
            params.append(date_filter)

        sql = "SELECT * FROM audit"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT 1000"

        audit_rows = con.execute(sql, params).fetchall()
        df_audit = pd.DataFrame([dict(r) for r in audit_rows])

        st.dataframe(df_audit, use_container_width=True, height=420)

        if not df_audit.empty:
            st.download_button(
                "Export audit CSV",
                df_audit.to_csv(index=False).encode("utf-8"),
                file_name="audit-log.csv",
                mime="text/csv",
            )

    with tabs[3]:
        st.subheader("Report")

        redacted = con.execute("SELECT COUNT(*) AS c FROM events WHERE redacted = 1").fetchone()["c"]
        revoked = con.execute(
            "SELECT COUNT(*) AS c FROM actions WHERE action_type = 'revoke_file_link' AND status = 'active'"
        ).fetchone()["c"]
        held = con.execute("SELECT COUNT(*) AS c FROM events WHERE verdict = 'held'").fetchone()["c"]

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Redacted messages", redacted)
        m2.metric("Revoked links", revoked)
        m3.metric("Fail-safe holds", held)
        m4.metric("Dry-run mode", "ON" if dry_run else "OFF")

        st.write("### Top-5 rolling exfiltration-risk users")
        user_ids = [r["user_id"] for r in con.execute("SELECT DISTINCT user_id FROM risk_events").fetchall()]
        users_map = {u.id: u.name for u in get_all_users(con)}
        scored = []
        for uid in user_ids:
            score = calculate_user_score(con, uid, cfg, _now_dt())
            scored.append({"User": users_map.get(uid, uid), "Risk score": round(score, 2)})
        con.commit()

        df_risk = pd.DataFrame(scored).sort_values("Risk score", ascending=False).head(5)

        if df_risk.empty:
            st.info("No risk events yet.")
        else:
            st.bar_chart(df_risk.set_index("User")["Risk score"])
            st.dataframe(df_risk, use_container_width=True)

        st.write("### Manager review queue")
        qrows = con.execute("SELECT * FROM manager_queue ORDER BY created_ts DESC").fetchall()
        if qrows:
            st.dataframe(pd.DataFrame([dict(r) for r in qrows]), use_container_width=True)
        else:
            st.caption("Queue empty.")

    with tabs[4]:
        st.subheader("Demo Mode")
        st.caption(
            "Replays a deterministic 2-minute incident script on a simulated clock. "
            "Speed slider compresses wall-clock time without changing the simulated timestamps."
        )

        demo_speed = st.slider("Demo playback speed", 0.5, 10.0, float(cfg["ui"]["default_speed"]), 0.5, key="demo_speed_slider")

        if st.button("Run 2-minute scripted demo", type="primary", use_container_width=True):
            st.session_state["demo_command"] = "run"

        if st.session_state.get("demo_command") == "run":
            _remove_db_files(DEMO_DB_PATH)
            demo_con = connect(DEMO_DB_PATH)
            init_db(demo_con)
            seed_demo_script(demo_con, cfg)

            status = st.status("Running scripted demo", state="running")
            base = _parse_iso(cfg["simulation"]["base_time"])

            for idx, step in enumerate(DEMO_SCRIPT):
                sim_ts = (base + timedelta(seconds=int(step["offset"]))).isoformat()
                status.update(label=f"Step {idx + 1}/{len(DEMO_SCRIPT)}: {step['title']}", state="running")
                status.write(f"Simulated time: {sim_ts}")

                if step["kind"] in ("message", "file"):
                    event_id = f"demo-{idx:03d}"
                    det, outcomes = safe_process_event(
                        demo_con,
                        event_id,
                        cfg,
                        dry_run=dry_run,
                        db_path=DEMO_DB_PATH,
                        now=sim_ts,
                    )
                    row = demo_con.execute("SELECT verdict, text FROM events WHERE id = ?", (event_id,)).fetchone()
                    actual = row["verdict"] if row else "unknown"
                    status.write(f"Expected: `{step['expected']}` · Actual: `{actual}` · Outcomes: `{outcomes}`")

                elif step["kind"] == "remove_guest":
                    outcome = remove_external_guest(
                        demo_con,
                        step["channel_id"],
                        step["user_id"],
                        actor="admin",
                        now=sim_ts,
                    )
                    status.write(f"Remove external guest outcome: `{outcome}`")

                elif step["kind"] == "rescan":
                    count = rescan_unprocessed_events_in_channel(
                        demo_con,
                        step["channel_id"],
                        cfg,
                        dry_run=dry_run,
                        db_path=DEMO_DB_PATH,
                    )
                    status.write(f"Rescan processed `{count}` unprocessed events. Existing incident was not re-triggered.")

                next_offset = DEMO_SCRIPT[idx + 1]["offset"] if idx + 1 < len(DEMO_SCRIPT) else step["offset"] + 5
                delay = max(0.05, (float(next_offset) - float(step["offset"])) / max(0.1, float(demo_speed)))
                time.sleep(delay)

            gif = generate_gif_from_events(
                demo_con,
                cfg,
                limit=len([s for s in DEMO_SCRIPT if s["kind"] in ("message", "file")]),
                use_stored=True,
            )
            st.session_state["demo_video"] = gif

            redacted = demo_con.execute("SELECT COUNT(*) AS c FROM events WHERE redacted = 1").fetchone()["c"]
            revoked = demo_con.execute(
                "SELECT COUNT(*) AS c FROM actions WHERE action_type = 'revoke_file_link' AND status = 'active'"
            ).fetchone()["c"]

            status.update(label="Demo complete", state="complete")
            st.success(f"Demo finished. Redacted messages: {redacted}. Revoked links: {revoked}.")

            if st.session_state.get("demo_video"):
                st.image(st.session_state["demo_video"], caption="Scripted demo video (GIF)")
                st.download_button(
                    "Download scripted demo video (GIF)",
                    st.session_state["demo_video"],
                    file_name="securechat-scripted-demo.gif",
                    mime="image/gif",
                )

            demo_con.close()
            st.session_state["demo_command"] = None

        if st.session_state.get("demo_video"):
            st.divider()
            st.image(st.session_state["demo_video"], caption="Latest scripted demo video (GIF)")
            st.download_button(
                "Download latest demo video (GIF)",
                st.session_state["demo_video"],
                file_name="securechat-demo.gif",
                mime="image/gif",
            )


if __name__ == "__main__" and "pytest" not in sys.modules:
    run_app()