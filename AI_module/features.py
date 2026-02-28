# ============================================
# features.py
# Feature extraction for web traffic IDS.
# Converts a raw HTTP-ish text blob into numeric features.
# ============================================
from __future__ import annotations

import math
import re
import urllib.parse
from typing import Dict, Any

import pandas as pd


_SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "alter", "create",
    "where", "from", "into", "sleep", "benchmark", "information_schema",
    "xp_cmdshell", "load_file", "outfile",
]

_CMD_KEYWORDS = [
    "cmd.exe", "powershell", "bash", "sh ", "curl ", "wget ", "nc ", "netcat",
    "python ", "perl ", "ruby ", "whoami", "id ", "uname", "cat ", "ls ",
]

_SPECIAL_CHARS = set("!@#$%^&*()[]{}<>;:'\"\\|`~")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return float(ent)


def _count_special(s: str) -> int:
    return sum(1 for ch in s if ch in _SPECIAL_CHARS)


def parse_http_request(raw_http: str) -> Dict[str, Any]:
    """
    Parse a raw HTTP request text blob:
      REQUEST_LINE
      Headers...
      blank line
      Body...

    Returns dict: method, url, headers (lowercased keys), body
    """
    raw = (raw_http or "").replace("\r\n", "\n")
    parts = raw.split("\n\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = [ln for ln in head.split("\n") if ln.strip() != ""]
    if not lines:
        return {"method": "", "url": "", "headers": {}, "body": body}

    request_line = lines[0].strip()
    m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)$", request_line)
    if m:
        method, path, proto = m.group(1), m.group(2), m.group(3)
    else:
        parts_rl = request_line.split()
        method = parts_rl[0] if len(parts_rl) > 0 else ""
        path = parts_rl[1] if len(parts_rl) > 1 else ""
        proto = parts_rl[2] if len(parts_rl) > 2 else "HTTP/1.1"

    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    host = headers.get("host", "")
    if host and not path.startswith("http"):
        url = f"http://{host}{path}"
    else:
        url = path

    return {"method": method.upper(), "url": url, "headers": headers, "body": body}


def extract_features_from_http(parsed: Dict[str, Any]) -> Dict[str, float]:
    method = (parsed.get("method") or "").upper()
    url = parsed.get("url") or ""
    headers = parsed.get("headers") or {}
    body = parsed.get("body") or ""

    try:
        u = urllib.parse.urlsplit(url)
        path = u.path or ""
        query = u.query or ""
    except Exception:
        path = url
        query = ""

    combined = f"{method} {url}\n{body}\n" + "\n".join(f"{k}:{v}" for k, v in headers.items())
    lower = combined.lower()

    url_length = len(url)
    payload_length = len(body)

    param_count_url = 0
    if query:
        param_count_url = len(urllib.parse.parse_qs(query, keep_blank_values=True))
    param_count_body = 0
    if "=" in body and "&" in body and len(body) <= 4096:
        try:
            param_count_body = len(urllib.parse.parse_qs(body, keep_blank_values=True))
        except Exception:
            param_count_body = 0

    encoding_detected = 1 if ("%2f" in lower or "%2e" in lower or "%3c" in lower or "%3e" in lower) else 0

    sql_keyword_count = sum(lower.count(k) for k in _SQL_KEYWORDS)
    has_sql_union = 1 if "union select" in lower or "union%20select" in lower else 0
    has_or_1_eq_1 = 1 if re.search(r"\bor\b\s+1\s*=\s*1\b", lower) else 0
    has_sql_comment = 1 if ("--" in lower or "/*" in lower or "*/" in lower or "# " in lower) else 0

    has_script_tag = 1 if ("<script" in lower or "%3cscript" in lower) else 0
    has_on_event = 1 if re.search(r"on\w+\s*=", lower) else 0
    has_iframe = 1 if ("<iframe" in lower or "%3ciframe" in lower) else 0
    has_javascript_scheme = 1 if ("javascript:" in lower or "vbscript:" in lower) else 0

    dot_dot_count = lower.count("..")
    has_path_traversal = 1 if ("../" in lower or "..\\" in lower) else 0
    has_encoded_traversal = 1 if ("%2e%2e" in lower or "%2f" in lower or "%5c" in lower) else 0

    has_shell_meta = 1 if any(x in lower for x in [";","|","&&","||","`","$(" ,")&"]) else 0
    has_command_keywords = 1 if any(k in lower for k in _CMD_KEYWORDS) else 0

    total_len = max(1, len(combined))
    special_char_ratio = _count_special(combined) / total_len
    entropy = _shannon_entropy(combined)

    return {
        "url_length": float(url_length),
        "payload_length": float(payload_length),
        "param_count_url": float(param_count_url),
        "param_count_body": float(param_count_body),
        "encoding_detected": float(encoding_detected),
        "sql_keyword_count": float(sql_keyword_count),
        "has_sql_union": float(has_sql_union),
        "has_or_1_eq_1": float(has_or_1_eq_1),
        "has_sql_comment": float(has_sql_comment),
        "has_script_tag": float(has_script_tag),
        "has_on_event": float(has_on_event),
        "has_iframe": float(has_iframe),
        "has_javascript_scheme": float(has_javascript_scheme),
        "dot_dot_count": float(dot_dot_count),
        "has_path_traversal": float(has_path_traversal),
        "has_encoded_traversal": float(has_encoded_traversal),
        "has_shell_meta": float(has_shell_meta),
        "has_command_keywords": float(has_command_keywords),
        "special_char_ratio": float(special_char_ratio),
        "entropy": float(entropy),
    }


def align_features_to_training_columns(feature_dict: Dict[str, float], training_columns: list[str]) -> pd.DataFrame:
    row = {col: float(feature_dict.get(col, 0.0)) for col in training_columns}
    return pd.DataFrame([row])


def choose_threshold_by_precision(y_true, y_prob, target_precision: float):
    from sklearn.metrics import precision_recall_curve
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    best_thr = 1.0
    best_prec = 0.0
    best_rec = 0.0
    for i, thr in enumerate(thresholds):
        prec = precisions[i]
        rec = recalls[i]
        if prec >= target_precision:
            best_thr = float(thr)
            best_prec = float(prec)
            best_rec = float(rec)
            break
    return best_thr, best_prec, best_rec


def choose_threshold_by_recall(y_true, y_prob, target_recall: float):
    from sklearn.metrics import precision_recall_curve
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    best_thr = 0.0
    best_prec = 0.0
    best_rec = 0.0
    for i, thr in enumerate(thresholds):
        prec = precisions[i]
        rec = recalls[i]
        if rec >= target_recall:
            best_thr = float(thr)
            best_prec = float(prec)
            best_rec = float(rec)
    return best_thr, best_prec, best_rec
