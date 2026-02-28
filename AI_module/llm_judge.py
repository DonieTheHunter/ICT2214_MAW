# llm_judge.py (v3)
# Fixes your JSONDecodeError on some events by using the SDK's native structured parsing.
#
# Problem you saw:
#   JSONDecodeError: Unterminated string ...
# Cause:
#   Sometimes the model output_text is not clean JSON (e.g., contains an unescaped quote/newline),
#   so json.loads() fails.
#
# Fix:
#   Use client.responses.parse(..., text_format=<PydanticModel>)
#   so the SDK requests structured output and parses it safely.
#
# Notes:
# - Uses Responses API
# - Does NOT send temperature
# - Keeps output short
# - Optional SQLite cache

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional, List, Literal

from openai import OpenAI
from pydantic import BaseModel, Field, conlist, confloat

CACHE_DB = Path(__file__).resolve().parent / "llm_cache.sqlite3"

DEFAULT_MODEL = os.environ.get("OPENAI_LLM_MODEL", "gpt-5-mini")
DEFAULT_MAX_OUTPUT_TOKENS = int(os.environ.get("OPENAI_LLM_MAX_OUTPUT_TOKENS", "450"))
DEFAULT_REASONING_EFFORT = os.environ.get("OPENAI_LLM_REASONING_EFFORT", "low")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _init_cache():
    with sqlite3.connect(CACHE_DB) as con:
        con.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT NOT NULL)")


def _cache_get(k: str) -> Optional[Dict[str, Any]]:
    _init_cache()
    with sqlite3.connect(CACHE_DB) as con:
        row = con.execute("SELECT v FROM cache WHERE k=?", (k,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except Exception:
        return None


def _cache_set(k: str, v: Dict[str, Any]) -> None:
    _init_cache()
    with sqlite3.connect(CACHE_DB) as con:
        con.execute("INSERT OR REPLACE INTO cache(k,v) VALUES(?,?)", (k, json.dumps(v, ensure_ascii=False)))


def _mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3] + ["x"])
    return ip[:8] + "..."


def _redact(record: Dict[str, Any]) -> Dict[str, Any]:
    r = dict(record)

    for ipk in ("src_ip", "dst_ip"):
        if isinstance(r.get(ipk), str):
            r[ipk] = _mask_ip(r[ipk])

    if isinstance(r.get("username"), str) and r["username"]:
        r["username"] = f"sha256:{_sha256(r['username'])}"

    # Password: never send raw
    if "password" in r:
        pw = str(r.get("password") or "")
        looks_like_sha = (len(pw) == 64 and all(c in "0123456789abcdefABCDEF" for c in pw))
        r["password"] = {"present": bool(pw), "len": len(pw), "looks_like_sha256": looks_like_sha}

    # Optional: shorten long hashes to reduce prompt noise
    for hk in ("SHA256", "sha256"):
        if isinstance(r.get(hk), str) and len(r[hk]) > 16:
            r[hk] = r[hk][:16] + "…"

    return r


class Verdict(BaseModel):
    verdict: Literal["malicious", "benign", "uncertain"]
    confidence: confloat(ge=0.0, le=1.0)
    attack_type: Literal[
        "sql_injection", "xss", "path_traversal", "command_injection",
        "credential_attack", "file_upload_malware", "recon", "dos", "other"
    ]
    suspicion: str = Field(max_length=300)
    evidence: conlist(str, max_length=6) = []
    recommended_action: Literal["allow", "review", "block"]


def _extract_parsed_verdict(resp) -> Optional[Dict[str, Any]]:
    # openai-python responses.parse places parsed content on output_text items as .parsed
    try:
        for output in resp.output:
            if getattr(output, "type", None) != "message":
                continue
            for item in output.content:
                if getattr(item, "type", None) != "output_text":
                    continue
                parsed = getattr(item, "parsed", None)
                if parsed:
                    # parsed is a Pydantic model instance
                    if hasattr(parsed, "model_dump"):
                        return parsed.model_dump()
                    return dict(parsed)
    except Exception:
        return None
    return None


def llm_verdict(
    record: Dict[str, Any],
    ml_result: Dict[str, Any],
    file_report: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
    use_cache: bool = True,
    reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
) -> Dict[str, Any]:
    """
    Returns:
      {"available": True, "cached": bool, "result": {...}} or {"available": False, "error": "..."}
    """
    client = OpenAI()

    safe_record = _redact(record)

    safe_file = None
    if file_report and file_report.get("available"):
        safe_file = dict(file_report)
        if "strings_head_sample" in safe_file:
            safe_file["strings_head_sample"] = safe_file["strings_head_sample"][:10]
        if isinstance(safe_file.get("zip"), dict):
            z = dict(safe_file["zip"])
            if "members_sample" in z:
                z["members_sample"] = z["members_sample"][:20]
            safe_file["zip"] = z

    prompt = {
        "record": safe_record,
        "ml": {
            "tier": ml_result.get("tier"),
            "prob_attack": ml_result.get("prob_attack"),
            "signals": ml_result.get("signals", {}),
            "suspicion": ml_result.get("suspicion", ""),
        },
        "file": safe_file,
        "rules": [
            "Output must match the schema exactly.",
            "Keep suspicion <= 1 sentence.",
            "Evidence: 3-6 short bullets max.",
        ],
        "task": "Classify the web event as malicious/benign/uncertain and recommend allow/review/block."
    }

    cache_key = _sha256(json.dumps(prompt, sort_keys=True, ensure_ascii=False))
    if use_cache:
        cached = _cache_get(cache_key)
        if cached:
            return {"available": True, "cached": True, "result": cached}

    try:
        resp = client.responses.parse(
            model=model or DEFAULT_MODEL,
            reasoning={"effort": reasoning_effort},
            input=[
                {"role": "system", "content": "You are a cautious SOC analyst. Return structured JSON only."},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
            text_format=Verdict,
            max_output_tokens=max_output_tokens,
        )

        parsed = _extract_parsed_verdict(resp)
        if not parsed:
            return {"available": False, "cached": False, "error": "Could not parse structured output (no parsed payload)"}

        if use_cache:
            _cache_set(cache_key, parsed)

        return {"available": True, "cached": False, "result": parsed}

    except Exception as e:
        # Retry once with more output tokens (some models may need slightly more room)
        try:
            resp = client.responses.parse(
                model=model or DEFAULT_MODEL,
                reasoning={"effort": reasoning_effort},
                input=[
                    {"role": "system", "content": "Return ONLY JSON matching the schema. No extra text."},
                    {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
                ],
                text_format=Verdict,
                max_output_tokens=max(max_output_tokens, 800),
            )
            parsed = _extract_parsed_verdict(resp)
            if parsed:
                if use_cache:
                    _cache_set(cache_key, parsed)
                return {"available": True, "cached": False, "result": parsed, "retry": True}
        except Exception:
            pass

        return {"available": False, "cached": False, "error": f"{type(e).__name__}: {e}"}
