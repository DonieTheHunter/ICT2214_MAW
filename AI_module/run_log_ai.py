"""run_log_ai.py
Scan a JSON-lines log file (one JSON dict per line) and print alerts.

Now supports OPTIONAL OpenAI LLM judging.

Examples:
  python run_log_ai.py merged.jsonl --pretty --min-tier LOW
  python run_log_ai.py merged.jsonl --llm --pretty --min-tier LOW
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Dict, Any

from log_ai import score_log_record

TIER_RANK = {"LOW": 0, "MED": 1, "HIGH": 2}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to JSON-lines log file")
    p.add_argument("--follow", action="store_true", help="Tail the log (like tail -f)")
    p.add_argument(
        "--min-tier",
        choices=["LOW", "MED", "HIGH"],
        default="MED",
        help="Only PRINT results at or above this tier (default: MED)",
    )
    p.add_argument("--pretty", action="store_true", help="Pretty-print full JSON decision")

    # LLM
    p.add_argument("--llm", action="store_true", help="Enable OpenAI LLM verdict (requires OPENAI_API_KEY)")
    p.add_argument(
        "--llm-min-tier",
        choices=["LOW", "MED", "HIGH"],
        default="MED",
        help="Only CALL the LLM at or above this tier (default: MED)",
    )
    p.add_argument("--llm-model", default=None, help="Override model id (default: env OPENAI_MODEL or gpt-5-mini)")
    return p.parse_args()


def should_print(tier: str, min_tier: str) -> bool:
    return TIER_RANK.get(tier, 0) >= TIER_RANK.get(min_tier, 1)


def format_one(record: Dict[str, Any], out: Dict[str, Any]) -> str:
    ts = record.get("timestamp", "")
    src = record.get("src_ip", "")
    method = record.get("method", "")
    uri = record.get("uri", "")
    tier = out.get("tier", "")
    p = out.get("prob_attack", 0.0)
    suspicion = out.get("suspicion", "")

    llm_summary = ""
    if isinstance(out.get("llm"), dict) and out["llm"].get("available") and isinstance(out["llm"].get("result"), dict):
        r = out["llm"]["result"]
        llm_summary = f" || LLM={r.get('verdict')}({r.get('confidence')}) {r.get('attack_type')}"

    return f"[{tier}] p={p:.3f} {ts} {src} {method} {uri} | {suspicion}{llm_summary}"


def process_line(line: str, args: argparse.Namespace) -> None:
    line = line.strip()
    if not line:
        return
    try:
        record = json.loads(line)
        if not isinstance(record, dict):
            return
    except json.JSONDecodeError:
        return

    out = score_log_record(
        record,
        enable_llm=args.llm,
        llm_min_tier=args.llm_min_tier,
        llm_model=args.llm_model,
    )

    if should_print(out.get("tier", "LOW"), args.min_tier):
        print(format_one(record, out))
        if args.pretty:
            print(json.dumps(out, indent=2, ensure_ascii=False))


def follow_file(path: str, args: argparse.Namespace) -> None:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            process_line(line, args)


def main() -> None:
    args = parse_args()
    if args.follow:
        follow_file(args.logfile, args)
        return
    with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            process_line(line, args)


if __name__ == "__main__":
    main()
