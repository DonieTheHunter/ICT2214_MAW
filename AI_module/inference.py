# ============================================
# inference.py
# Load the trained model bundle and score raw HTTP text.
# ============================================
from __future__ import annotations

from pathlib import Path
from functools import lru_cache
import joblib

from features import parse_http_request, extract_features_from_http, align_features_to_training_columns


MODEL_FILE = Path(__file__).resolve().parent / "rf_web_ids_model.pkl"


@lru_cache(maxsize=1)
def load_bundle() -> dict:
    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Model bundle not found: {MODEL_FILE}\n"
            "Place rf_web_ids_model.pkl in the same folder as inference.py."
        )
    bundle = joblib.load(MODEL_FILE)
    for k in ("model", "feature_names", "thr_high", "thr_med"):
        if k not in bundle:
            raise ValueError(f"Invalid model bundle: missing key '{k}'")
    return bundle


def score_request(raw_http: str) -> dict:
    b = load_bundle()
    model = b["model"]
    cols = b["feature_names"]
    thr_high = float(b["thr_high"])
    thr_med = float(b["thr_med"])

    parsed = parse_http_request(raw_http)
    feats = extract_features_from_http(parsed)
    X = align_features_to_training_columns(feats, cols)

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
        "parsed": {
            "method": parsed.get("method", ""),
            "url": parsed.get("url", ""),
            "host": (parsed.get("headers", {}) or {}).get("host", ""),
            "user_agent": (parsed.get("headers", {}) or {}).get("user-agent", ""),
        },
        "signals": signals,
    }
