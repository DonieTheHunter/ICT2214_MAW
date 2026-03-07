# ============================================
# log_ai.py
# Convert ONE JSON log record -> pseudo raw HTTP -> ML score + suspicion label.
# ============================================
from __future__ import annotations

import json
from typing import Any, Dict

try:
    from .inference import score_request
except ImportError:
    from inference import score_request


_META_KEYS = {
    "timestamp", "action", "protocol",
    "src_ip", "src_port", "direction", "dst_ip", "dst_port",
    "status",
}

_HEADER_HINT_KEYS = {"host", "user_agent", "content_type", "referer", "cookie", "body"}


def record_to_raw_http(record: Dict[str, Any]) -> str:
    method = str(record.get("method", "GET")).upper()
    uri = str(record.get("uri", "/"))
    proto = str(record.get("protocol", "HTTP/1.1"))

    host = record.get("host") or record.get("dst_ip") or "localhost"
    user_agent = record.get("user_agent") or "web-ids-ai/1.0"
    content_type = record.get("content_type") or "application/json"

    headers = {
        "Host": host,
        "User-Agent": user_agent,
        "Content-Type": content_type,
    }
    if record.get("src_ip"):
        headers["X-Forwarded-For"] = str(record["src_ip"])
    if record.get("referer"):
        headers["Referer"] = str(record["referer"])
    if record.get("cookie"):
        headers["Cookie"] = str(record["cookie"])

    body = record.get("body")
    if body is None:
        payload: Dict[str, Any] = {}
        for k, v in record.items():
            if k in _META_KEYS or k in {"method", "uri"} or k in _HEADER_HINT_KEYS:
                continue
            payload[k] = v
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) if payload else ""
    else:
        body = str(body)

    request_line = f"{method} {uri} {proto}"
    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items() if v not in (None, ""))
    return f"{request_line}\n{header_lines}\n\n{body}".strip()


def brief_suspicion(record: Dict[str, Any], scored: Dict[str, Any]) -> str:
    sig = scored.get("signals", {}) or {}
    uri = str(record.get("uri", "")).lower()
    method = str(record.get("method", "")).upper()

    reasons = []

    if sig.get("has_sql_union") or sig.get("has_or_1_eq_1") or (sig.get("sql_keyword_count", 0) > 0) or sig.get("has_sql_comment"):
        reasons.append("SQL injection-like payload")

    if sig.get("has_script_tag") or sig.get("has_on_event") or sig.get("has_iframe") or sig.get("has_javascript_scheme"):
        reasons.append("XSS / HTML injection-like payload")

    if sig.get("has_path_traversal") or sig.get("has_encoded_traversal") or ("../" in uri) or ("%2e%2e" in uri):
        reasons.append("Path traversal-like attempt")

    if sig.get("has_shell_meta") or sig.get("has_command_keywords"):
        reasons.append("Command injection-like payload")

    filename = record.get("filename") or record.get("file") or ""
    if filename:
        reasons.append(f"File indicator: {filename}")

    sha256 = record.get("SHA256") or record.get("sha256") or ""
    if sha256:
        reasons.append("Hash provided (possible file/malware triage)")

    if "upload" in uri or "multipart" in str(record.get("content_type", "")).lower() or (method == "POST" and filename):
        reasons.append("Upload-ish request")

    if "download" in uri or "export" in uri or "file=" in uri:
        reasons.append("Download/file fetch-ish request")

    if record.get("username") or record.get("password"):
        reasons.append("Credential fields present")

    if not reasons:
        p = scored.get("prob_attack", 0.0)
        reasons.append(f"Generic anomaly (model prob={p:.3f})")

    return "; ".join(reasons[:3])


def score_log_record(record: Dict[str, Any]) -> Dict[str, Any]:
    raw_http = record_to_raw_http(record)
    scored = score_request(raw_http)
    scored["suspicion"] = brief_suspicion(record, scored)
    return scored
