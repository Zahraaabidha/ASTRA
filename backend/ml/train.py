"""
Tier 1 classifier training script for ASTRA.

Usage:
    python train.py --csv path/to/CICMalDroid2020_features.csv --out ../../data/models/classifier.pkl

The CSV must have a 'Label' column. Banking malware and other malware classes
are treated as positive (malicious=1). Benign samples are negative (0).
"""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


def load_and_prepare(csv_path: str):
    df = pd.read_csv(csv_path, low_memory=False)

    if "Label" not in df.columns:
        raise ValueError("CSV must have a 'Label' column")

    y = (df["Label"].str.lower().str.strip() != "benign").astype(int)

    # Drop metadata columns that aren't features
    drop_cols = [c for c in ["Label", "file", "Unnamed: 0"] if c in df.columns]
    X = df.drop(columns=drop_cols)

    # Drop non-numeric columns
    non_numeric = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric:
        print(f"Dropping {len(non_numeric)} non-numeric columns: {non_numeric[:5]} ...")
        X = X.drop(columns=non_numeric)

    X = X.fillna(0)

    print(f"Dataset: {len(df)} samples, {X.shape[1]} features")
    print(f"Malicious: {y.sum()} ({y.mean()*100:.1f}%)  |  Benign: {(1-y).sum()}")
    return X, y


def train(csv_path: str, output_path: str):
    X, y = load_and_prepare(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Class imbalance weight
    neg = (y_train == 0).sum()
    pos = (y_train == 1).sum()
    scale = neg / pos if pos > 0 else 1.0

    base_model = XGBClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=6,
        min_child_weight=3,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    n_folds = min(5, min((y_train == 0).sum(), (y_train == 1).sum()))
    n_folds = max(n_folds, 2)
    print(f"\nTraining with Platt calibration ({n_folds}-fold CV) ...")
    calibrated = CalibratedClassifierCV(base_model, cv=n_folds, method="sigmoid")
    calibrated.fit(X_train, y_train)

    y_prob = calibrated.predict_proba(X_test)[:, 1]

    # Find threshold that maximises precision at recall >= 0.85
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_prob)
    valid = [(p, r, t) for p, r, t in zip(precisions, recalls, thresholds) if r >= 0.85]
    if valid:
        best_p, best_r, best_t = max(valid, key=lambda x: x[0])
    else:
        best_t = 0.5
        best_p = best_r = 0.0

    print(f"\nBest threshold: {best_t:.3f}  "
          f"(precision={best_p:.3f}, recall={best_r:.3f})")
    print("Using threshold 0.85 for banking precision-first policy\n")

    y_pred = (y_prob >= 0.85).astype(int)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    # SHAP feature importance
    feature_importance = {}
    if SHAP_AVAILABLE:
        print("\nComputing SHAP values ...")
        inner_model = calibrated.calibrated_classifiers_[0].estimator
        explainer = shap.TreeExplainer(inner_model)
        shap_values = explainer.shap_values(X_test[:500])
        mean_abs = np.abs(shap_values).mean(axis=0)
        feature_importance = dict(
            sorted(zip(X.columns.tolist(), mean_abs.tolist()),
                   key=lambda x: x[1], reverse=True)[:30]
        )
        print("Top 10 features by SHAP:")
        for f, v in list(feature_importance.items())[:10]:
            print(f"  {f}: {v:.4f}")

    # Anomaly detector on benign class
    print("\nTraining anomaly detector ...")
    X_benign = X_train[y_train == 0]
    anomaly_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    anomaly_model.fit(X_benign)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump({
        "classifier": calibrated,
        "anomaly_detector": anomaly_model,
        "feature_names": X.columns.tolist(),
        "threshold": 0.85,
        "feature_importance": feature_importance,
    }, output_path)

    print(f"\nModel saved to {output_path}")
    return str(output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to features CSV")
    parser.add_argument("--out", default="../../data/models/classifier.pkl",
                        help="Output path for saved model")
    args = parser.parse_args()
    train(args.csv, args.out)
