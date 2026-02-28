# ============================================
# merge_web_log.py
# Merge packet+form JSON lines into one record per request.
#
# Supports both orders:
#   form -> packet   (pending_form merged into next non-GET packet)
#   packet -> form   (pending_packet merged with trailing form)
#
# Avoids attaching form data to GET requests.
# ============================================
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Iterator, Optional


def _is_packet(rec: Dict[str, Any]) -> bool:
    return "method" in rec and "uri" in rec and "timestamp" in rec


def _is_form(rec: Dict[str, Any]) -> bool:
    return (("filename" in rec) or ("SHA256" in rec) or ("username" in rec)) and not _is_packet(rec)


def _packet_is_candidate(packet: Dict[str, Any]) -> bool:
    return str(packet.get("method", "")).upper() != "GET"


def merge_records(lines: Iterable[str]) -> Iterator[Dict[str, Any]]:
    pending_packet: Optional[Dict[str, Any]] = None
    pending_form: Optional[Dict[str, Any]] = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue

        if _is_packet(rec):
            if pending_packet is not None:
                yield pending_packet
                pending_packet = None

            if pending_form is not None and _packet_is_candidate(rec):
                rec.update(pending_form)
                pending_form = None
                yield rec
                continue

            if _packet_is_candidate(rec):
                pending_packet = rec
            else:
                yield rec
            continue

        if _is_form(rec):
            if pending_packet is not None:
                pending_packet.update(rec)
                yield pending_packet
                pending_packet = None
            else:
                pending_form = rec
            continue

        if pending_packet is not None:
            yield pending_packet
            pending_packet = None
        if pending_form is not None:
            yield pending_form
            pending_form = None
        yield rec

    if pending_packet is not None:
        yield pending_packet
    if pending_form is not None:
        yield pending_form


def merge_file_to_jsonl(in_path: str, out_path: str) -> None:
    with open(in_path, "r", encoding="utf-8", errors="ignore") as f:
        merged = list(merge_records(f))
    with open(out_path, "w", encoding="utf-8") as w:
        for rec in merged:
            w.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("infile")
    p.add_argument("outfile")
    args = p.parse_args()
    merge_file_to_jsonl(args.infile, args.outfile)
    print(f"[+] Wrote merged JSONL: {args.outfile}")
