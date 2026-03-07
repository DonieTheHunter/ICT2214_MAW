# ============================================
# inference.py
# Load the trained model bundle and score raw HTTP text.
# ============================================
from __future__ import annotations

from pathlib import Path
from functools import lru_cache
import joblib

try:
    from .features import parse_http_request, extract_features_from_http, align_features_to_columns
except ImportError:
    from features import parse_http_request, extract_features_from_http, align_features_to_columns

SCRIPT_DIR = Path(__file__).resolve().parent
CURRENT_MODEL_FILE = SCRIPT_DIR / "models" / "current_model.pkl"
LEGACY_MODEL_FILE = SCRIPT_DIR / "rf_web_ids_model.pkl"


def _resolve_model_file() -> Path:
    if CURRENT_MODEL_FILE.exists():
        return CURRENT_MODEL_FILE
    if LEGACY_MODEL_FILE.exists():
        return LEGACY_MODEL_FILE
    raise FileNotFoundError(
        "Model bundle not found. Looked for:\n"
        f"- {CURRENT_MODEL_FILE}\n"
        f"- {LEGACY_MODEL_FILE}"
    )


@lru_cache(maxsize=4)
def _load_bundle_cached(model_path: str, mtime_ns: int) -> dict:
    bundle = joblib.load(model_path)
    for k in ("model", "feature_names", "thr_high", "thr_med"):
        if k not in bundle:
            raise ValueError(f"Invalid model bundle: missing key '{k}'")
    bundle["__model_path__"] = model_path
    bundle["__model_mtime_ns__"] = mtime_ns
    return bundle


def load_bundle() -> dict:
    model_file = _resolve_model_file()
    stat = model_file.stat()
    return _load_bundle_cached(str(model_file), int(stat.st_mtime_ns))


def score_request(raw_http: str) -> dict:
    b = load_bundle()
    model = b["model"]
    cols = b["feature_names"]
    thr_high = float(b["thr_high"])
    thr_med = float(b["thr_med"])

    parsed = parse_http_request(raw_http)
    feats = extract_features_from_http(parsed)
    X = align_features_to_columns(feats, cols)

    prob_attack = float(model.predict_proba(X)[:, 1][0])
    risk_score = prob_attack * 100.0

    if prob_attack >= thr_high:
        tier = "HIGH"
        action = "AUTO-ALERT (high confidence)"
    elif prob_attack >= thr_med:
        tier = "MED"
        action = "SEND TO LLM / ANALYST REVIEW (suspicious)"
    else:
        tier = "LOW"
        action = "LOG / IGNORE (low risk)"

    explain_keys = [
        "sql_keyword_count", "has_sql_union", "has_or_1_eq_1", "has_sql_comment",
        "has_script_tag", "has_on_event", "has_iframe", "has_javascript_scheme",
        "dot_dot_count", "has_path_traversal", "has_encoded_traversal",
        "has_shell_meta", "has_command_keywords",
        "encoding_detected", "special_char_ratio", "entropy",
        "param_count_url", "param_count_body",
        "payload_length", "url_length"
    ]
    signals = {k: feats.get(k, 0.0) for k in explain_keys}

    return {
        "prob_attack": prob_attack,
        "prob_benign": 1.0 - prob_attack,
        "risk_score": risk_score,
        "tier": tier,
        "action": action,
        "model_path": b.get("__model_path__", ""),
        "parsed": {
            "method": parsed.get("method", ""),
            "url": parsed.get("url", ""),
            "host": (parsed.get("headers", {}) or {}).get("host", ""),
            "user_agent": (parsed.get("headers", {}) or {}).get("user-agent", ""),
        },
        "signals": signals,
    }
