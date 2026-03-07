# ============================================
# features.py
# Feature extraction for MAW web-traffic IDS.
#
# Goal:
# - Convert a raw HTTP-ish text blob into numeric features.
# - Feature set matches the baseline CSV columns (except dataset_is_test2).
# ============================================
from __future__ import annotations

import math
import re
import urllib.parse
from typing import Any, Dict, Tuple, Optional

import pandas as pd

# ---- Canonical feature columns (50) ----
FEATURE_COLUMNS = [
    "method_is_get",
    "method_is_post",
    "method_is_other",
    "url_length",
    "path_length",
    "query_length",
    "param_count_url",
    "param_count_body",
    "payload_length",
    "total_length",
    "sql_keyword_count",
    "special_char_ratio",
    "encoding_detected",
    "entropy",
    "digit_ratio",
    "uppercase_ratio",
    "slash_count",
    "dot_count",
    "dot_dot_count",
    "has_at_sign",
    "has_percent",
    "has_plus_in_params",
    "has_script_tag",
    "has_on_event",
    "has_iframe",
    "has_document_cookie",
    "has_javascript_scheme",
    "has_sql_union",
    "has_sql_select",
    "has_or_1_eq_1",
    "has_sql_comment",
    "has_sleep_or_benchmark",
    "has_path_traversal",
    "has_shell_meta",
    "has_command_keywords",
    "has_encoded_traversal",
    "has_php_ext",
    "host_length",
    "path_depth",
    "user_agent_length",
    "user_agent_is_empty",
    "cookie_length",
    "cookie_entropy",
    "has_referer",
    "referer_same_host",
    "content_type_flag",
    "accept_any",
    "language_is_english",
    "content_length_header_present",
    "content_length_mismatch",
]

_SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "alter", "create",
    "where", "from", "into", "sleep", "benchmark", "information_schema",
    "xp_cmdshell", "load_file", "outfile",
]

_CMD_KEYWORDS = [
    "cmd.exe", "powershell", "bash", "sh ", "curl ", "wget ", "nc ", "netcat",
    "python ", "perl ", "ruby ", "whoami", " id ", "uname", "cat ", "ls ",
]

# Keep consistent with your previous code; avoid counting normal URL characters.
_SPECIAL_CHARS = set("!@#$%^&*()[]{}<>;:'\"\\|`~")

_RE_OR_1_EQ_1 = re.compile(r"\bor\b\s+1\s*=\s*1\b", re.IGNORECASE)
_RE_ONEVENT = re.compile(r"on\w+\s*=", re.IGNORECASE)
_RE_PCT_ENC = re.compile(r"%[0-9a-fA-F]{2}")

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return float(ent)

def _ratio(count: int, total: int) -> float:
    return float(count) / float(total) if total > 0 else 0.0

def _count_special(s: str) -> int:
    return sum(1 for ch in s if ch in _SPECIAL_CHARS)

def _safe_urlsplit(url: str) -> Tuple[str, str, str]:
    """
    Returns (host, path, query) from url.
    Handles urls that are just paths like "/login?x=1".
    """
    if not url:
        return "", "", ""
    try:
        u = urllib.parse.urlsplit(url)
        # If it's a bare path, urlsplit puts it into path; netloc empty.
        host = u.netloc or ""
        path = u.path or ""
        query = u.query or ""
        return host, path, query
    except Exception:
        return "", url, ""

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

    # Keep empty lines out of the header section
    lines = [ln for ln in head.split("\n") if ln.strip() != ""]
    if not lines:
        return {"method": "", "url": "", "headers": {}, "body": body}

    request_line = lines[0].strip()
    m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)$", request_line)
    if m:
        method, path, _proto = m.group(1), m.group(2), m.group(3)
    else:
        parts_rl = request_line.split()
        method = parts_rl[0] if len(parts_rl) > 0 else ""
        path = parts_rl[1] if len(parts_rl) > 1 else ""
        _proto = parts_rl[2] if len(parts_rl) > 2 else "HTTP/1.1"

    headers: Dict[str, str] = {}
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

def _content_type_flag(ct: str) -> float:
    """
    Encode content-type into a small numeric bucket.
    (This is intentionally simple; you can one-hot later if you want.)
    """
    if not ct:
        return 0.0
    c = ct.lower()
    if "multipart/form-data" in c:
        return 1.0
    if "application/x-www-form-urlencoded" in c:
        return 2.0
    if "application/json" in c:
        return 3.0
    if "text/plain" in c:
        return 4.0
    return 5.0

def extract_features_from_http(parsed: Dict[str, Any]) -> Dict[str, float]:
    method = (parsed.get("method") or "").upper()
    url = parsed.get("url") or ""
    headers: Dict[str, str] = parsed.get("headers") or {}
    body = parsed.get("body") or ""

    # Normalized header values (lowercase keys already)
    host_hdr = headers.get("host", "") or ""
    ua = headers.get("user-agent", "") or ""
    cookie = headers.get("cookie", "") or ""
    referer = headers.get("referer", "") or headers.get("referrer", "") or ""
    accept = headers.get("accept", "") or ""
    accept_lang = headers.get("accept-language", "") or ""
    ct = headers.get("content-type", "") or headers.get("content_type", "") or ""
    content_len_hdr = headers.get("content-length", "") or ""

    host_from_url, path, query = _safe_urlsplit(url)
    host = host_hdr or host_from_url

    # Build combined text for a few "global" features.
    header_blob = "\n".join(f"{k}:{v}" for k, v in headers.items() if v)
    combined = f"{method} {url}\n{header_blob}\n\n{body}"
    lower = combined.lower()

    total_len = len(combined)
    if total_len <= 0:
        total_len = 1

    # --- Method flags ---
    method_is_get = 1.0 if method == "GET" else 0.0
    method_is_post = 1.0 if method == "POST" else 0.0
    method_is_other = 1.0 if method not in ("GET", "POST") else 0.0

    # --- URL/body lengths ---
    url_length = float(len(url))
    path_length = float(len(path))
    query_length = float(len(query))
    payload_length = float(len(body))
    total_length = float(len(combined))

    # --- Parameter counts ---
    param_count_url = 0
    if query:
        try:
            param_count_url = len(urllib.parse.parse_qs(query, keep_blank_values=True))
        except Exception:
            param_count_url = 0

    param_count_body = 0
    # Only attempt parsing small-ish URL encoded bodies
    if len(body) <= 8192 and ("=" in body) and ("&" in body or ct.lower().startswith("application/x-www-form-urlencoded")):
        try:
            param_count_body = len(urllib.parse.parse_qs(body, keep_blank_values=True))
        except Exception:
            param_count_body = 0

    # --- Encodings / anomaly markers ---
    encoding_detected = 1.0 if (_RE_PCT_ENC.search(lower) is not None) else 0.0

    sql_keyword_count = float(sum(lower.count(k) for k in _SQL_KEYWORDS))
    has_sql_union = 1.0 if ("union select" in lower or "union%20select" in lower) else 0.0
    has_sql_select = 1.0 if ("select" in lower) else 0.0
    has_or_1_eq_1 = 1.0 if (_RE_OR_1_EQ_1.search(lower) is not None) else 0.0
    has_sql_comment = 1.0 if ("--" in lower or "/*" in lower or "*/" in lower or "# " in lower) else 0.0
    has_sleep_or_benchmark = 1.0 if ("sleep" in lower or "benchmark" in lower) else 0.0

    has_script_tag = 1.0 if ("<script" in lower or "%3cscript" in lower) else 0.0
    has_on_event = 1.0 if (_RE_ONEVENT.search(lower) is not None) else 0.0
    has_iframe = 1.0 if ("<iframe" in lower or "%3ciframe" in lower) else 0.0
    has_document_cookie = 1.0 if ("document.cookie" in lower) else 0.0
    has_javascript_scheme = 1.0 if ("javascript:" in lower or "vbscript:" in lower) else 0.0

    dot_dot_count = float(lower.count(".."))
    has_path_traversal = 1.0 if ("../" in lower or "..\\" in lower) else 0.0
    has_encoded_traversal = 1.0 if ("%2e%2e" in lower or "%2f" in lower or "%5c" in lower) else 0.0

    has_shell_meta = 1.0 if any(x in lower for x in [";", "|", "&&", "||", "`", "$("]) else 0.0
    has_command_keywords = 1.0 if any(k in lower for k in _CMD_KEYWORDS) else 0.0

    # --- Basic ratios / counts ---
    special_char_ratio = float(_count_special(combined)) / float(total_len)
    entropy = float(_shannon_entropy(combined))

    digit_ratio = _ratio(sum(ch.isdigit() for ch in combined), total_len)
    uppercase_ratio = _ratio(sum(ch.isupper() for ch in combined), total_len)

    slash_count = float(combined.count("/"))
    dot_count = float(combined.count("."))
    has_at_sign = 1.0 if ("@" in combined) else 0.0
    has_percent = 1.0 if ("%" in combined) else 0.0
    has_plus_in_params = 1.0 if ("+" in query or "+" in body) else 0.0

    has_php_ext = 1.0 if (path.lower().endswith(".php") or ".php" in path.lower()) else 0.0

    # --- Header-derived features ---
    host_length = float(len(host))
    # Path depth: number of non-empty segments
    path_depth = float(len([seg for seg in path.split("/") if seg]))

    user_agent_length = float(len(ua))
    user_agent_is_empty = 1.0 if (ua.strip() == "") else 0.0

    cookie_length = float(len(cookie))
    cookie_entropy = float(_shannon_entropy(cookie)) if cookie else 0.0

    has_referer = 1.0 if (referer.strip() != "") else 0.0
    referer_same_host = 0.0
    if referer and host:
        try:
            ru = urllib.parse.urlsplit(referer)
            referer_host = ru.netloc or ""
            referer_same_host = 1.0 if (referer_host.lower() == host.lower()) else 0.0
        except Exception:
            referer_same_host = 0.0

    content_type_flag = _content_type_flag(ct)
    accept_any = 1.0 if ("*/*" in accept) else 0.0
    language_is_english = 1.0 if ("en" in accept_lang.lower()) else 0.0

    content_length_header_present = 1.0 if (content_len_hdr.strip() != "") else 0.0
    content_length_mismatch = 0.0
    if content_length_header_present:
        try:
            claimed = int(content_len_hdr.strip())
            actual = len(body.encode("utf-8", errors="ignore"))
            content_length_mismatch = 1.0 if (claimed != actual) else 0.0
        except Exception:
            content_length_mismatch = 0.0

    feats: Dict[str, float] = {
        "method_is_get": method_is_get,
        "method_is_post": method_is_post,
        "method_is_other": method_is_other,
        "url_length": url_length,
        "path_length": path_length,
        "query_length": query_length,
        "param_count_url": float(param_count_url),
        "param_count_body": float(param_count_body),
        "payload_length": payload_length,
        "total_length": total_length,
        "sql_keyword_count": sql_keyword_count,
        "special_char_ratio": special_char_ratio,
        "encoding_detected": encoding_detected,
        "entropy": entropy,
        "digit_ratio": digit_ratio,
        "uppercase_ratio": uppercase_ratio,
        "slash_count": slash_count,
        "dot_count": dot_count,
        "dot_dot_count": dot_dot_count,
        "has_at_sign": has_at_sign,
        "has_percent": has_percent,
        "has_plus_in_params": has_plus_in_params,
        "has_script_tag": has_script_tag,
        "has_on_event": has_on_event,
        "has_iframe": has_iframe,
        "has_document_cookie": has_document_cookie,
        "has_javascript_scheme": has_javascript_scheme,
        "has_sql_union": has_sql_union,
        "has_sql_select": has_sql_select,
        "has_or_1_eq_1": has_or_1_eq_1,
        "has_sql_comment": has_sql_comment,
        "has_sleep_or_benchmark": has_sleep_or_benchmark,
        "has_path_traversal": has_path_traversal,
        "has_shell_meta": has_shell_meta,
        "has_command_keywords": has_command_keywords,
        "has_encoded_traversal": has_encoded_traversal,
        "has_php_ext": has_php_ext,
        "host_length": host_length,
        "path_depth": path_depth,
        "user_agent_length": user_agent_length,
        "user_agent_is_empty": user_agent_is_empty,
        "cookie_length": cookie_length,
        "cookie_entropy": cookie_entropy,
        "has_referer": has_referer,
        "referer_same_host": referer_same_host,
        "content_type_flag": content_type_flag,
        "accept_any": accept_any,
        "language_is_english": language_is_english,
        "content_length_header_present": content_length_header_present,
        "content_length_mismatch": content_length_mismatch,
    }

    # Ensure all 50 exist
    for col in FEATURE_COLUMNS:
        feats.setdefault(col, 0.0)

    return feats

def align_features_to_columns(feature_dict: Dict[str, float], columns: Optional[list[str]] = None) -> pd.DataFrame:
    cols = columns or FEATURE_COLUMNS
    row = {col: float(feature_dict.get(col, 0.0)) for col in cols}
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
