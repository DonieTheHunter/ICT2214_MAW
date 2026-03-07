# run_web_log_ai.py (auto-detect uploads dir)
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict

from merge_web_log import merge_records
from log_ai import score_log_record
from file_inspector import inspect_from_record
from llm_judge import llm_verdict

TIER_RANK = {"LOW": 0, "MED": 1, "HIGH": 2}

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to reverse-proxy log (JSON lines)")
    p.add_argument("--follow", action="store_true", help="Tail the log (like tail -f)")
    p.add_argument("--min-tier", choices=["LOW","MED","HIGH"], default="MED")
    p.add_argument("--pretty", action="store_true")

    p.add_argument("--upload-dir", default=None, help="Folder where uploads are stored, e.g. ..\\uploads")
    p.add_argument("--file-path-key", default="file_path")
    p.add_argument("--max-file-bytes", type=int, default=2_000_000)

    p.add_argument("--llm", action="store_true")
    p.add_argument("--llm-min-tier", choices=["LOW","MED","HIGH"], default="MED")
    p.add_argument("--llm-model", default=None)
    p.add_argument("--llm-cache", action="store_true")
    return p.parse_args()

def _resolve_upload_dir(upload_dir: str | None) -> str | None:
    if upload_dir:
        p = Path(upload_dir)
        # Resolve relative to script folder, not current working directory
        if not p.is_absolute():
            p = (Path(__file__).resolve().parent / p).resolve()
        return str(p)

    # Auto-detect ..\uploads relative to script folder
    candidate = (Path(__file__).resolve().parent / ".." / "uploads").resolve()
    if candidate.exists() and candidate.is_dir():
        return str(candidate)
    return None

def should_print(tier: str, min_tier: str) -> bool:
    return TIER_RANK.get(tier, 0) >= TIER_RANK.get(min_tier, 1)

def process_record(record: Dict[str, Any], args: argparse.Namespace, resolved_upload_dir: str | None) -> None:
    out = score_log_record(record)

    out["file"] = inspect_from_record(
        record,
        upload_dir=resolved_upload_dir,
        file_path_key=args.file_path_key,
        max_bytes_read=args.max_file_bytes,
    )

    # LLM verdict (optional)
    if args.llm:
        out["llm"] = llm_verdict(
            record=record,
            ml_result=out,
            file_report=out["file"],
            model=args.llm_model,
            use_cache=args.llm_cache,
        )

    # Combine final decision
    llm = out.get("llm", {})
    if llm.get("available") and llm.get("result"):
        r = llm["result"]
        out["final_verdict"] = r.get("verdict", "uncertain")
        out["final_attack_type"] = r.get("attack_type", "other")
        out["final_recommended_action"] = r.get("recommended_action", "review")
        out["is_malicious"] = (out["final_verdict"] == "malicious")
    else:
        tier = out.get("tier", "LOW")
        if tier == "HIGH":
            out.update(final_verdict="malicious", final_attack_type="other", final_recommended_action="block", is_malicious=True)
        elif tier == "MED":
            out.update(final_verdict="uncertain", final_attack_type="other", final_recommended_action="review", is_malicious=False)
        else:
            out.update(final_verdict="benign", final_attack_type="other", final_recommended_action="allow", is_malicious=False)

    if should_print(out.get("tier", "LOW"), args.min_tier):
        ts = record.get("timestamp", "")
        src = record.get("src_ip", "")
        method = record.get("method", "")
        uri = record.get("uri", "")
        tier = out.get("tier", "")
        p = out.get("prob_attack", 0.0)
        suspicion = out.get("suspicion", "")

        file_rep = out.get("file", {})
        file_tag = ""
        if file_rep.get("available"):
            file_tag = f" FILE={file_rep.get('magic','?')} size={file_rep.get('size_bytes','?')}"
        elif file_rep.get("error"):
            file_tag = f" FILEERR={file_rep.get('error')}"

        llm_tag = ""
        if llm.get("available") and llm.get("result"):
            rr = llm["result"]
            llm_tag = f" || LLM={rr.get('verdict','?')}({rr.get('confidence',0):.2f}) {rr.get('attack_type','other')}"
        elif llm.get("error"):
            llm_tag = " || LLM=ERROR"

        print(f"[{tier}] p={p:.3f} {ts} {src} {method} {uri} | {suspicion}{file_tag}{llm_tag}")
        if args.pretty:
            if resolved_upload_dir:
                out.setdefault("_debug", {})["uploads_dir"] = resolved_upload_dir
            print(json.dumps(out, indent=2, ensure_ascii=False))

def scan_file(path: str, args: argparse.Namespace, resolved_upload_dir: str | None) -> None:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for rec in merge_records(f):
            if isinstance(rec, dict):
                process_record(rec, args, resolved_upload_dir)

def follow_file(path: str, args: argparse.Namespace, resolved_upload_dir: str | None) -> None:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        buf = []
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            buf.append(line)
            for rec in merge_records(buf):
                if isinstance(rec, dict):
                    process_record(rec, args, resolved_upload_dir)
            buf = []

def main() -> None:
    args = parse_args()
    resolved_upload_dir = _resolve_upload_dir(args.upload_dir)

    if args.follow:
        follow_file(args.logfile, args, resolved_upload_dir)
    else:
        scan_file(args.logfile, args, resolved_upload_dir)

if __name__ == "__main__":
    main()
