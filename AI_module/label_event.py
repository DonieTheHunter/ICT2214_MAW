# ============================================
# label_event.py
# CLI tool: store analyst label for one event (for daily retraining).
#
# Supports:
# - label from MAW cases.db by case-id
# - label from a raw JSON line
# ============================================
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from .label_store import add_label, DEFAULT_LABELS_DB
except ImportError:
    from label_store import add_label, DEFAULT_LABELS_DB


def _parse_label(s: str) -> int:
    s2 = (s or "").strip().lower()
    if s2 in {"1", "mal", "malicious", "attack", "bad", "true"}:
        return 1
    if s2 in {"0", "benign", "good", "false", "safe"}:
        return 0
    raise ValueError("label must be one of: malicious/benign/1/0")


def _g(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return default


def fetch_case_record(cases_db: Path, case_id: int) -> Dict[str, Any]:
    if not cases_db.exists():
        raise FileNotFoundError(f"cases db not found: {cases_db}")

    with sqlite3.connect(str(cases_db)) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM cases WHERE id=?", (int(case_id),)).fetchone()
        if not row:
            raise ValueError(f"case_id not found in cases db: {case_id}")
        d = dict(row)

    record = {
        "timestamp": _g(d, "event_timestamp", "timestamp", default=""),
        "action": _g(d, "action", default=""),
        "protocol": _g(d, "protocol", default="HTTP/1.1"),
        "user_agent": _g(d, "user_agent", default=""),
        "referrer": _g(d, "referrer", "referer", default=""),
        "host": _g(d, "host", default=""),
        "content_type": _g(d, "content_type", "Content_Type", "Content-type", default=""),
        "src_ip": _g(d, "src_ip", default=""),
        "src_port": _g(d, "src_port", default=""),
        "direction": _g(d, "direction", default="->"),
        "dst_ip": _g(d, "dst_ip", default=""),
        "dst_port": _g(d, "dst_port", default=""),
        "method": _g(d, "method", default=""),
        "uri": _g(d, "uri", default=""),
        "status": _g(d, "http_status", "status", default=""),
        "username": _g(d, "username", default=""),
        "password": _g(d, "password_hash", "password", default=""),
        "filename": _g(d, "filename", default=""),
        "SHA256": _g(d, "file_sha256", "SHA256", default=""),
    }

    return record


def ensure_cases_label_columns(cases_db: Path) -> None:
    with sqlite3.connect(str(cases_db)) as con:
        cols = [r[1] for r in con.execute("PRAGMA table_info(cases)").fetchall()]
        def add(col_sql: str):
            con.execute(col_sql)

        if "analyst_label" not in cols:
            add("ALTER TABLE cases ADD COLUMN analyst_label INTEGER")
        if "analyst_attack_type" not in cols:
            add("ALTER TABLE cases ADD COLUMN analyst_attack_type TEXT")
        if "analyst" not in cols:
            add("ALTER TABLE cases ADD COLUMN analyst TEXT")
        if "analyst_labeled_at" not in cols:
            add("ALTER TABLE cases ADD COLUMN analyst_labeled_at DATETIME")
        con.commit()


def update_cases_db_label(
    cases_db: Path,
    case_id: int,
    label: int,
    attack_type: Optional[str],
    analyst: Optional[str],
) -> None:
    ensure_cases_label_columns(cases_db)
    with sqlite3.connect(str(cases_db)) as con:
        con.execute(
            """
            UPDATE cases
            SET analyst_label=?,
                analyst_attack_type=?,
                analyst=?,
                analyst_labeled_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (int(label), attack_type, analyst, int(case_id)),
        )
        con.commit()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--json-line", help="Raw JSON log line (string)")
    src.add_argument("--case-id", type=int, help="Case id from MAW cases.db")

    p.add_argument("--cases-db", default="../cases.db", help="Path to MAW cases.db (used with --case-id)")
    p.add_argument("--labels-db", default=str(DEFAULT_LABELS_DB), help="SQLite DB to store labels")
    p.add_argument("--label", required=True, help="malicious|benign|1|0")
    p.add_argument("--attack-type", default=None, help="Optional: xss/sql_injection/recon/etc.")
    p.add_argument("--analyst", default=None, help="Optional analyst name")
    p.add_argument("--update-cases-db", action="store_true", help="Also write label back into cases.db")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    label = _parse_label(args.label)

    script_dir = Path(__file__).resolve().parent
    def _resolve(p: str) -> Path:
        pp = Path(p).expanduser()
        if not pp.is_absolute():
            pp = (script_dir / pp).resolve()
        return pp

    labels_db = _resolve(args.labels_db)

    record: Dict[str, Any]
    source = None
    if args.json_line:
        record = json.loads(args.json_line)
        source = "json_line"
    else:
        cases_db = _resolve(args.cases_db)
        record = fetch_case_record(cases_db, args.case_id)
        source = f"cases_db:{cases_db.name}#id={args.case_id}"

        if args.update_cases_db:
            update_cases_db_label(
                cases_db=cases_db,
                case_id=args.case_id,
                label=label,
                attack_type=args.attack_type,
                analyst=args.analyst,
            )

    row_id = add_label(
        record=record,
        label=label,
        db_path=labels_db,
        attack_type=args.attack_type,
        analyst=args.analyst,
        source=source,
    )

    with open("log/labeling_log.log", "a") as label_file:
        label_file.write(f"[+] Stored label id={row_id} label={label} db={labels_db}")
        if args.update_cases_db and args.case_id:
            label_file.write(f"[+] Updated cases.db label for case_id={args.case_id}\n")


if __name__ == "__main__":
    main()
