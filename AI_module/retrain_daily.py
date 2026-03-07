# ============================================
# retrain_daily.py
# Train/refresh the MAW AI model bundle.
#
# Combines:
# - optional baseline CSV (with 'classification' column)
# - analyst labels stored in data/labels.sqlite3
#
# Output:
# - models/current_model.pkl (bundle)
# - models/report_latest.json (metrics + thresholds)
# ============================================
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score

from features import FEATURE_COLUMNS, choose_threshold_by_precision, choose_threshold_by_recall
from label_store import load_labels_df


def pr_at_threshold(y_true: np.ndarray, y_prob: np.ndarray, thr: float):
    y_hat = (y_prob >= thr).astype(int)
    tp = int(((y_hat == 1) & (y_true == 1)).sum())
    fp = int(((y_hat == 1) & (y_true == 0)).sum())
    fn = int(((y_hat == 0) & (y_true == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall, tp, fp, fn


def load_base_csv(csv_path: Path) -> Tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(csv_path)
    if "classification" not in df.columns:
        raise ValueError("Base CSV must contain a 'classification' column (0=benign, 1=attack).")

    y = df["classification"].astype(int)

    # Keep only the feature columns we expect; fill missing with 0
    X = pd.DataFrame({c: pd.to_numeric(df[c], errors="coerce") if c in df.columns else 0.0 for c in FEATURE_COLUMNS})
    X = X.apply(pd.to_numeric, errors="coerce")

    return X, y


def atomic_joblib_dump(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    joblib.dump(obj, tmp)
    tmp.replace(path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--base-csv", default=None, help="Optional baseline CSV (with classification column).")
    p.add_argument("--labels-db", default="data/labels.sqlite3", help="SQLite labels DB.")
    p.add_argument("--out", default="models/current_model.pkl", help="Output model bundle path.")
    p.add_argument("--model-type", choices=["logreg", "rf"], default="logreg")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--test-size", type=float, default=0.20)
    p.add_argument("--val-size", type=float, default=0.20)
    p.add_argument("--target-high-precision", type=float, default=0.95)
    p.add_argument("--target-med-recall", type=float, default=0.95)
    p.add_argument("--min-rows", type=int, default=200, help="Minimum rows needed to train.")
    p.add_argument("--history-dir", default="models/history", help="Where to store timestamped copies (optional).")
    p.add_argument("--keep-last", type=int, default=14, help="Keep last N history models (0 disables cleanup).")
    return p.parse_args()


def cleanup_history(history_dir: Path, keep_last: int) -> None:
    if keep_last <= 0:
        return
    if not history_dir.exists():
        return
    # Keep newest keep_last by filename sort (timestamp prefix)
    files = sorted(history_dir.glob("model_*.pkl"))
    if len(files) <= keep_last:
        return
    for f in files[:-keep_last]:
        try:
            f.unlink()
        except Exception:
            pass
    reports = sorted(history_dir.glob("report_*.json"))
    if len(reports) <= keep_last:
        return
    for r in reports[:-keep_last]:
        try:
            r.unlink()
        except Exception:
            pass


def main() -> None:
    args = parse_args()

    script_dir = Path(__file__).resolve().parent

    def _resolve(p: str) -> Path:
        pp = Path(p).expanduser()
        if not pp.is_absolute():
            pp = (script_dir / pp).resolve()
        return pp

    out_path = _resolve(args.out)
    labels_db = _resolve(args.labels_db)
    base_csv = _resolve(args.base_csv) if args.base_csv else None

    X_parts = []
    y_parts = []

    if base_csv and base_csv.exists():
        Xb, yb = load_base_csv(base_csv)
        X_parts.append(Xb)
        y_parts.append(yb)

    Xl, yl = load_labels_df(labels_db)
    if len(yl) > 0:
        X_parts.append(Xl)
        y_parts.append(yl)

    if not X_parts:
        raise FileNotFoundError(
            "No training data found.\n"
            "Provide --base-csv or create labels in data/labels.sqlite3 using label_event.py."
        )

    X = pd.concat(X_parts, ignore_index=True)
    y = pd.concat(y_parts, ignore_index=True).astype(int)

    if len(X) < args.min_rows:
        raise ValueError(f"Not enough rows to train (have {len(X)}, need at least {args.min_rows}).")

    if y.nunique() < 2:
        raise ValueError("Training data contains only one class. Need both benign and malicious labels.")

    # Split train/val/test
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=args.val_size, random_state=args.seed, stratify=y_temp
    )

    if args.model_type == "logreg":
        model = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=600,
                class_weight="balanced",
                random_state=args.seed,
            )),
        ])
    else:
        model = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", RandomForestClassifier(
                n_estimators=500,
                max_depth=None,
                min_samples_split=2,
                min_samples_leaf=1,
                class_weight="balanced",
                random_state=args.seed,
                n_jobs=-1,
            )),
        ])

    model.fit(X_train, y_train)

    val_prob = model.predict_proba(X_val)[:, 1]
    thr_high, thr_high_prec, thr_high_rec = choose_threshold_by_precision(
        y_val, val_prob, args.target_high_precision
    )
    thr_med, thr_med_prec, thr_med_rec = choose_threshold_by_recall(
        y_val, val_prob, args.target_med_recall
    )
    thr_med = min(float(thr_med), float(thr_high))

    test_prob = model.predict_proba(X_test)[:, 1]
    ap_val = float(average_precision_score(y_val, val_prob))
    ap_test = float(average_precision_score(y_test, test_prob))

    pH, rH, tpH, fpH, fnH = pr_at_threshold(y_test.to_numpy(), test_prob, float(thr_high))
    pM, rM, tpM, fpM, fnM = pr_at_threshold(y_test.to_numpy(), test_prob, float(thr_med))

    trained_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    bundle = {
        "model": model,
        "model_type": args.model_type,
        "feature_names": list(FEATURE_COLUMNS),
        "thr_high": float(thr_high),
        "thr_med": float(thr_med),
        "trained_at": trained_at,
        "metrics": {
            "rows_total": int(len(X)),
            "rows_base": int(len(X_parts[0])) if (base_csv and base_csv.exists()) else 0,
            "rows_labels": int(len(yl)),
            "val_average_precision": ap_val,
            "test_average_precision": ap_test,
            "thr_high_target_precision": float(args.target_high_precision),
            "thr_med_target_recall": float(args.target_med_recall),
            "thr_high_val_precision": float(thr_high_prec),
            "thr_high_val_recall": float(thr_high_rec),
            "thr_med_val_precision": float(thr_med_prec),
            "thr_med_val_recall": float(thr_med_rec),
            "test_at_thr_high": {"precision": pH, "recall": rH, "tp": tpH, "fp": fpH, "fn": fnH},
            "test_at_thr_med": {"precision": pM, "recall": rM, "tp": tpM, "fp": fpM, "fn": fnM},
        },
    }

    # Save main bundle
    atomic_joblib_dump(bundle, out_path)

    # Save report
    report_path = out_path.parent / "report_latest.json"
    report = {"trained_at": trained_at, "out": str(out_path), **bundle["metrics"], "thr_high": float(thr_high), "thr_med": float(thr_med)}
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # History copy (timestamped)
    history_dir = Path(args.history_dir).expanduser().resolve()
    history_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    hist_model = history_dir / f"model_{ts}.pkl"
    hist_report = history_dir / f"report_{ts}.json"
    try:
        atomic_joblib_dump(bundle, hist_model)
        hist_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
        cleanup_history(history_dir, args.keep_last)
    except Exception:
        pass

    print(f"[+] Saved model bundle: {out_path}")
    print(f"    trained_at: {trained_at}")
    print(f"    VAL AP:  {ap_val:.4f}")
    print(f"    TEST AP: {ap_test:.4f}")
    print(f"    THR_HIGH={thr_high:.4f} | TEST precision={pH:.3f}, recall={rH:.3f} (TP={tpH}, FP={fpH}, FN={fnH})")
    print(f"    THR_MED ={thr_med:.4f} | TEST precision={pM:.3f}, recall={rM:.3f} (TP={tpM}, FP={fpM}, FN={fnM})")


if __name__ == "__main__":
    main()
