import hashlib
import json
import sqlite3
from typing import Any, Dict, Optional, Tuple

DB_PATH = "cases.db"


def get_conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def get_value(d: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return default


def cleaning(v: Any) -> str:
    return str(v or "").strip()


def lowercasing(v: Any) -> str:
    return cleaning(v).lower()


def normalization(v: Any) -> str:
    s = lowercasing(v)
    if ";" in s:
        s = s.split(";", 1)[0].strip()
    return s


def normalize_record_for_fingerprint(record: Dict[str, Any]) -> Dict[str, str]:
    return {
        "method": lowercasing(get_value(record, "method")),
        "uri": cleaning(get_value(record, "uri")),
        "username": cleaning(get_value(record, "username")),
        "host": lowercasing(get_value(record, "host")),
        "dst_ip": cleaning(get_value(record, "dst_ip")),
        "dst_port": cleaning(get_value(record, "dst_port")),
        "filename": cleaning(get_value(record, "filename")),
        "sha256": lowercasing(get_value(record, "SHA256", "file_sha256")),
        "content_type": normalization(get_value(record, "content-type", "content_type", "Content_Type")),
    }


def build_event_fingerprint(record: Dict[str, Any]) -> str:
    payload = normalize_record_for_fingerprint(record)
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ensure_schema() -> None:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_hash TEXT UNIQUE,
                event_timestamp TEXT,
                action TEXT,
                protocol TEXT,
                user_agent TEXT,
                referrer TEXT,
                host TEXT,
                Content_Type TEXT,
                src_ip TEXT,
                src_port TEXT,
                direction TEXT,
                dst_ip TEXT,
                dst_port TEXT,
                method TEXT,
                uri TEXT,
                http_status TEXT,
                username TEXT,
                password_hash TEXT,
                filename TEXT,
                file_sha256 TEXT,
                result_info TEXT,
                status INTEGER DEFAULT 1,
                datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                label INTEGER
            )
            """
        )

        cols = {row[1].lower() for row in cur.execute("PRAGMA table_info(cases)").fetchall()}
        if "event_fingerprint" not in cols:
            cur.execute("ALTER TABLE cases ADD COLUMN event_fingerprint TEXT")
        if "occurrence_count" not in cols:
            cur.execute("ALTER TABLE cases ADD COLUMN occurrence_count INTEGER DEFAULT 1")
        if "last_seen" not in cols:
            cur.execute("ALTER TABLE cases ADD COLUMN last_seen DATETIME")

        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_log_hash ON cases(log_hash)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_event_fp_status ON cases(event_fingerprint, status)")
        conn.commit()


ensure_schema()


def insert_case(log, log_hash, result, event_fingerprint: Optional[str] = None):
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        parsed = json.loads(log) if isinstance(log, str) else dict(log)
        if event_fingerprint is None:
            event_fingerprint = build_event_fingerprint(parsed)

        cursor.execute(
            """
            INSERT INTO cases (
                log_hash, event_timestamp, action, protocol,
                user_agent, referrer, host, Content_Type,
                src_ip, src_port, direction,
                dst_ip, dst_port,
                method, uri, http_status,
                username, password_hash,
                filename, file_sha256, result_info,
                event_fingerprint, occurrence_count, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                log_hash,
                get_value(parsed, "timestamp"),
                get_value(parsed, "action"),
                get_value(parsed, "protocol"),
                get_value(parsed, "user_agent"),
                get_value(parsed, "referrer", "referer"),
                get_value(parsed, "host"),
                get_value(parsed, "content-type", "content_type", "Content_Type"),
                get_value(parsed, "src_ip"),
                get_value(parsed, "src_port"),
                get_value(parsed, "direction"),
                get_value(parsed, "dst_ip"),
                get_value(parsed, "dst_port"),
                get_value(parsed, "method"),
                get_value(parsed, "uri"),
                get_value(parsed, "status", "http_status"),
                get_value(parsed, "username"),
                get_value(parsed, "password", "password_hash"),
                get_value(parsed, "filename"),
                get_value(parsed, "SHA256", "file_sha256"),
                f"{result}",
                event_fingerprint,
                1,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_cases():
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases")
        return cursor.fetchall()


def get_open_cases():
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cases WHERE status = 1")
        return cursor.fetchall()


def get_case_by_hash(log_hash):
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status FROM cases WHERE log_hash = ?", (log_hash,))
        return cursor.fetchone()


def get_open_case_by_fingerprint(event_fingerprint: str) -> Optional[Tuple[int, int, int]]:
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, status, COALESCE(occurrence_count, 1)
            FROM cases
            WHERE event_fingerprint = ? AND status = 1
            ORDER BY id DESC
            LIMIT 1
            """,
            (event_fingerprint,),
        )
        return cursor.fetchone()


def touch_case_occurrence(case_id: int) -> None:
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE cases
            SET occurrence_count = COALESCE(occurrence_count, 1) + 1,
                last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (case_id,),
        )
        conn.commit()


def is_case_open(log_hash):
    row = get_case_by_hash(log_hash)
    if row is None:
        return False, None
    case_id, status = row
    return status == 1, case_id


def update_case_status(status, case_id):
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE cases
            SET status = ?
            WHERE id = ?
            """,
            (status, case_id),
        )
        conn.commit()


def update_case_label(label, case_id):
    ensure_schema()
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE cases
            SET label = ?
            WHERE id = ?
            """,
            (label, case_id),
        )
        conn.commit()
