from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pandas as pd

try:
    from .features import FEATURE_COLUMNS, parse_http_request, extract_features_from_http
    from .log_ai import record_to_raw_http
except ImportError:
    from features import FEATURE_COLUMNS, parse_http_request, extract_features_from_http
    from log_ai import record_to_raw_http


DEFAULT_LABELS_DB = Path(__file__).resolve().parent / "data" / "labels.sqlite3"


def _getv(d: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return default


def _norm_text(v: Any) -> str:
    return str(v or "").strip()


def _norm_lower(v: Any) -> str:
    return _norm_text(v).lower()


def _normalize_content_type(v: Any) -> str:
    """
    Normalize content-type so multipart boundaries do not break matching.
    """
    s = _norm_lower(v)
    if ";" in s:
        s = s.split(";", 1)[0].strip()
    return s


def normalize_record(record: Dict[str, Any]) -> Dict[str, str]:
    """
    Create a stable normalized view of a record for suppression matching.
    Ignore volatile fields like timestamp, src_port, multipart boundary, etc.
    """
    return {
        "method": _norm_lower(_getv(record, "method")),
        "uri": _norm_text(_getv(record, "uri")),
        "username": _norm_text(_getv(record, "username")),
        "host": _norm_lower(_getv(record, "host")),
        "dst_ip": _norm_text(_getv(record, "dst_ip")),
        "dst_port": _norm_text(_getv(record, "dst_port")),
        "filename": _norm_text(_getv(record, "filename")),
        "sha256": _norm_lower(_getv(record, "SHA256", "file_sha256")),
        "content_type": _normalize_content_type(_getv(record, "content-type", "content_type", "Content_Type")),
    }


def build_safe_signature(record: Dict[str, Any]) -> Dict[str, str]:
    """
    Signature used to suppress future alerts for known-safe events.
    """
    return normalize_record(record)


def init_labels_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                label INTEGER NOT NULL,
                attack_type TEXT,
                analyst TEXT,
                source TEXT,
                record_json TEXT NOT NULL,
                features_json TEXT NOT NULL
            )
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_labels_created_at ON labels(created_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_labels_label ON labels(label)")

        # New: safe suppression rules
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS safe_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                analyst TEXT,
                source TEXT,
                record_json TEXT NOT NULL,
                signature_json TEXT NOT NULL,
                method TEXT,
                uri TEXT,
                username TEXT,
                host TEXT,
                dst_ip TEXT,
                dst_port TEXT,
                filename TEXT,
                sha256 TEXT,
                content_type TEXT
            )
            """
        )

        con.execute("CREATE INDEX IF NOT EXISTS idx_safe_rules_method_uri ON safe_rules(method, uri)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_safe_rules_sha256 ON safe_rules(sha256)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_safe_rules_filename ON safe_rules(filename)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_safe_rules_username ON safe_rules(username)")
        con.commit()


def _extract_features_from_record(record: Dict[str, Any]) -> Dict[str, float]:
    raw_http = record_to_raw_http(record)
    parsed = parse_http_request(raw_http)
    feats = extract_features_from_http(parsed)
    for c in FEATURE_COLUMNS:
        feats.setdefault(c, 0.0)
    return feats


def add_safe_rule(
    record: Dict[str, Any],
    db_path: Path = DEFAULT_LABELS_DB,
    analyst: Optional[str] = None,
    source: Optional[str] = None,
) -> int:
    """
    Store a deterministic suppression rule for analyst-labeled safe traffic.
    """
    init_labels_db(db_path)
    sig = build_safe_signature(record)

    with sqlite3.connect(str(db_path)) as con:
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO safe_rules(
                analyst, source, record_json, signature_json,
                method, uri, username, host, dst_ip, dst_port, filename, sha256, content_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(analyst) if analyst else None,
                str(source) if source else None,
                json.dumps(record, ensure_ascii=False),
                json.dumps(sig, ensure_ascii=False),
                sig["method"],
                sig["uri"],
                sig["username"],
                sig["host"],
                sig["dst_ip"],
                sig["dst_port"],
                sig["filename"],
                sig["sha256"],
                sig["content_type"],
            ),
        )
        con.commit()
        return int(cur.lastrowid)


def remove_matching_safe_rules(
    record: Dict[str, Any],
    db_path: Path = DEFAULT_LABELS_DB,
) -> int:
    """
    If an analyst later marks the same pattern malicious, remove matching safe rules.
    """
    init_labels_db(db_path)
    sig = build_safe_signature(record)

    with sqlite3.connect(str(db_path)) as con:
        cur = con.cursor()
        cur.execute(
            """
            DELETE FROM safe_rules
            WHERE method=?
              AND uri=?
              AND username=?
              AND host=?
              AND dst_ip=?
              AND dst_port=?
              AND filename=?
              AND sha256=?
              AND content_type=?
            """,
            (
                sig["method"],
                sig["uri"],
                sig["username"],
                sig["host"],
                sig["dst_ip"],
                sig["dst_port"],
                sig["filename"],
                sig["sha256"],
                sig["content_type"],
            ),
        )
        con.commit()
        return int(cur.rowcount)


def is_safelisted_record(
    record: Dict[str, Any],
    db_path: Path = DEFAULT_LABELS_DB,
) -> bool:
    """
    Return True if this record matches a stored safe suppression rule.
    """
    if not db_path.exists():
        return False

    sig = build_safe_signature(record)

    with sqlite3.connect(str(db_path)) as con:
        row = con.execute(
            """
            SELECT id
            FROM safe_rules
            WHERE method=?
              AND uri=?
              AND username=?
              AND host=?
              AND dst_ip=?
              AND dst_port=?
              AND filename=?
              AND sha256=?
              AND content_type=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                sig["method"],
                sig["uri"],
                sig["username"],
                sig["host"],
                sig["dst_ip"],
                sig["dst_port"],
                sig["filename"],
                sig["sha256"],
                sig["content_type"],
            ),
        ).fetchone()

    return row is not None


def add_label(
    record: Dict[str, Any],
    label: int,
    db_path: Path = DEFAULT_LABELS_DB,
    attack_type: Optional[str] = None,
    analyst: Optional[str] = None,
    source: Optional[str] = None,
) -> int:
    """
    Store one labeled event.
    label: 0=benign, 1=malicious
    Returns inserted row id.
    """
    init_labels_db(db_path)
    feats = _extract_features_from_record(record)

    with sqlite3.connect(str(db_path)) as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO labels(label, attack_type, analyst, source, record_json, features_json) VALUES (?,?,?,?,?,?)",
            (
                int(label),
                str(attack_type) if attack_type else None,
                str(analyst) if analyst else None,
                str(source) if source else None,
                json.dumps(record, ensure_ascii=False),
                json.dumps(feats, ensure_ascii=False),
            ),
        )
        con.commit()
        row_id = int(cur.lastrowid)

    # Deterministic behavior:
    # benign => add safe suppression rule
    # malicious => remove conflicting safe suppression rule
    if int(label) == 0:
        add_safe_rule(record=record, db_path=db_path, analyst=analyst, source=source)
    else:
        remove_matching_safe_rules(record=record, db_path=db_path)

    return row_id


def load_labels_df(db_path: Path = DEFAULT_LABELS_DB) -> Tuple[pd.DataFrame, pd.Series]:
    if not db_path.exists():
        return pd.DataFrame(columns=FEATURE_COLUMNS), pd.Series([], dtype=int)

    with sqlite3.connect(str(db_path)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT label, features_json FROM labels").fetchall()

    if not rows:
        return pd.DataFrame(columns=FEATURE_COLUMNS), pd.Series([], dtype=int)

    feats_list = []
    y_list = []
    for r in rows:
        y_list.append(int(r["label"]))
        try:
            d = json.loads(r["features_json"])
        except Exception:
            d = {}
        row = {c: float(d.get(c, 0.0)) for c in FEATURE_COLUMNS}
        feats_list.append(row)

    X = pd.DataFrame(feats_list, columns=FEATURE_COLUMNS)
    y = pd.Series(y_list, dtype=int)
    return X, y