# ============================================
# trained_model.py
# Retrain the web IDS RandomForest and save rf_web_ids_model.pkl
# ============================================
from __future__ import annotations

import argparse
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score

from features import choose_threshold_by_precision, choose_threshold_by_recall


def pr_at_threshold(y_true: np.ndarray, y_prob: np.ndarray, thr: float):
    y_hat = (y_prob >= thr).astype(int)
    tp = int(((y_hat == 1) & (y_true == 1)).sum())
    fp = int(((y_hat == 1) & (y_true == 0)).sum())
    fn = int(((y_hat == 0) & (y_true == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall, tp, fp, fn


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default="AI_module/merged_web_traffic_features_rich_numeric.csv",
                   help="Labeled feature CSV with 'classification' column")
    p.add_argument("--out", default="AI_module/rf_web_ids_model.pkl", help="Output model bundle path")
    p.add_argument("--no-tune", action="store_true", help="Disable tuning (faster)")
    p.add_argument("--trees", type=int, default=400, help="RF trees (used when --no-tune)")
    p.add_argument("--n-iter", type=int, default=25, help="RandomizedSearch iterations (tuning)")
    p.add_argument("--cv", type=int, default=3, help="CV folds (tuning)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--test-size", type=float, default=0.20)
    p.add_argument("--val-size", type=float, default=0.20)
    p.add_argument("--target-high-precision", type=float, default=0.95)
    p.add_argument("--target-med-recall", type=float, default=0.95)
    return p.parse_args()


def main():
    args = parse_args()
    csv_path = Path(args.csv)
    out_path = Path(args.out)

    if not csv_path.exists():
        raise FileNotFoundError(f"Training CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)
    if "classification" not in df.columns:
        raise ValueError("CSV must contain a 'classification' column (0=benign, 1=attack).")

    X = df.drop(columns=["classification"]).apply(pd.to_numeric, errors="coerce")
    y = df["classification"].astype(int)
    feature_names = list(X.columns)

    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=args.val_size, random_state=args.seed, stratify=y_temp
    )

    base_rf = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1,
    )

    pipe = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("rf", base_rf),
    ])

    best_params = None
    if args.no_tune:
        model = pipe.fit(X_train, y_train)
    else:
        param_distributions = {
            "rf__n_estimators": [300, 500, 800, 1200],
            "rf__max_depth": [None, 10, 20, 40, 80],
            "rf__min_samples_split": [2, 5, 10, 20],
            "rf__min_samples_leaf": [1, 2, 4, 8],
            "rf__max_features": ["sqrt", "log2", None],
            "rf__bootstrap": [True, False],
            "rf__class_weight": ["balanced", "balanced_subsample"],
        }
        cv = StratifiedKFold(n_splits=args.cv, shuffle=True, random_state=args.seed)
        search = RandomizedSearchCV(
            estimator=pipe,
            param_distributions=param_distributions,
            n_iter=args.n_iter,
            scoring="average_precision",
            cv=cv,
            verbose=1,
            random_state=args.seed,
            n_jobs=-1,
        )
        search.fit(X_train, y_train)
        model = search.best_estimator_
        best_params = search.best_params_

    val_prob = model.predict_proba(X_val)[:, 1]
    thr_high, _, _ = choose_threshold_by_precision(y_val, val_prob, args.target_high_precision)
    thr_med, _, _ = choose_threshold_by_recall(y_val, val_prob, args.target_med_recall)
    thr_med = min(float(thr_med), float(thr_high))

    test_prob = model.predict_proba(X_test)[:, 1]
    ap_val = float(average_precision_score(y_val, val_prob))
    ap_test = float(average_precision_score(y_test, test_prob))

    pH, rH, tpH, fpH, fnH = pr_at_threshold(y_test.to_numpy(), test_prob, thr_high)
    pM, rM, tpM, fpM, fnM = pr_at_threshold(y_test.to_numpy(), test_prob, thr_med)

    bundle = {
        "model": model,
        "feature_names": feature_names,
        "thr_high": float(thr_high),
        "thr_med": float(thr_med),
        "policy": {
            "high_precision_target": float(args.target_high_precision),
            "med_recall_target": float(args.target_med_recall),
            "val_average_precision": ap_val,
            "test_average_precision": ap_test,
            "best_params": best_params,
        },
    }

    joblib.dump(bundle, out_path)
    print(f"[+] Saved model bundle: {out_path.resolve()}")
    print(f"    VAL AP:  {ap_val:.4f}")
    print(f"    TEST AP: {ap_test:.4f}")
    print(f"    THR_HIGH={thr_high:.4f} | TEST precision={pH:.3f}, recall={rH:.3f} (TP={tpH}, FP={fpH}, FN={fnH})")
    print(f"    THR_MED ={thr_med:.4f} | TEST precision={pM:.3f}, recall={rM:.3f} (TP={tpM}, FP={fpM}, FN={fnM})")


if __name__ == "__main__":
    main()
