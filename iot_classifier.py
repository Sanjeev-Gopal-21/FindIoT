"""
iot_classifier.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IoT vs Non-IoT Traffic Classification Pipeline

Input  : flow-level CSV produced by pcap_flow_extractor
Output : trained model, feature report, evaluation artefacts

Pipeline stages
  1. Load & sanity-check
  2. Preprocessing  (encode categoricals, scale numerics)
  3. Labelling      (heuristic iot_hint  OR  device inventory override)
  4. Feature selection
       Stage A – Variance threshold  (drop near-constant columns)
       Stage B – Pearson correlation  (drop redundant pairs)
       Stage C – Mutual information  (score each surviving feature vs label)
       Stage D – RF permutation importance  (confirm with a quick model)
  5. Model training  (Random Forest + optional XGBoost, 5-fold CV)
  6. Evaluation      (Accuracy, F1, ROC-AUC, Confusion Matrix)
  7. Persistence     (model.joblib, selected_features.json, importance.csv)

Usage
  python iot_classifier.py <flows.csv> [OPTIONS]

Options
  --label-col    STR    Column to use as label (default: iot_hint)
  --top-k        INT    Features to keep after MI stage (default: 20)
  --trees        INT    RF n_estimators (default: 300)
  --threshold    FLOAT  Classification threshold (default: 0.5)
  --no-xgb             Skip XGBoost (if not installed)
  --out-dir      PATH   Output directory (default: ./model_output)

References
  Koroniotis et al. (2019) – UNSW-NB15 network intrusion dataset
  Meidan et al. (2018)     – N-BaIoT: IoT device fingerprinting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")           # headless-safe
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import (
    VarianceThreshold, SelectKBest, mutual_info_classif,
)
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    roc_auc_score, roc_curve, ConfusionMatrixDisplay,
)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

warnings.filterwarnings("ignore", category=UserWarning)


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

# Columns to drop before any modelling (identifiers / leakage / metadata)
DROP_COLS = ["src_ip", "dst_ip", "src_oui", "file_tag"]

# Columns that are categorical and need encoding
CATEGORICAL_COLS: list[str] = []   # protocol is already an int; extend if needed

# Well-known IoT port bins used to create engineered features
IOT_PORTS   = {1883, 8883, 5683, 5684, 5353, 1900, 502, 47808}
NON_IOT_PORTS = {80, 443, 8080, 25, 21, 22, 53}

RANDOM_SEED = 42


# ─────────────────────────────────────────────────────────────────────────────
#  1. Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_data(csv_path: str) -> pd.DataFrame:
    print(f"[1] Loading {csv_path} …")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"    Shape: {df.shape[0]:,} rows × {df.shape[1]} cols")

    # Basic sanity: check required columns exist
    for col in ["iot_hint", "protocol", "fwd_pkts", "pkt_len_mean"]:
        if col not in df.columns:
            sys.exit(f"ERROR: required column '{col}' not found in CSV.")

    print(f"    IoT (hint=1) : {(df['iot_hint'] == 1).sum():,}")
    print(f"    Non-IoT (0)  : {(df['iot_hint'] == 0).sum():,}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
#  2. Preprocessing  (feature engineering + encoding)
# ─────────────────────────────────────────────────────────────────────────────

def preprocess(df: pd.DataFrame, label_col: str) -> tuple[pd.DataFrame, pd.Series]:
    print("\n[2] Preprocessing …")
    df = df.copy()

    # ── Port-based binary features ──────────────────────────────────────────
    df["src_port_is_iot"]     = df["src_port"].isin(IOT_PORTS).astype(int)
    df["dst_port_is_iot"]     = df["dst_port"].isin(IOT_PORTS).astype(int)
    df["src_port_is_noniot"]  = df["src_port"].isin(NON_IOT_PORTS).astype(int)
    df["dst_port_is_noniot"]  = df["dst_port"].isin(NON_IOT_PORTS).astype(int)

    # ── Derived ratio features ──────────────────────────────────────────────
    df["bytes_ratio"]  = df["fwd_bytes"] / (df["bwd_bytes"] + 1)
    df["pkts_ratio"]   = df["fwd_pkts"]  / (df["bwd_pkts"]  + 1)
    df["pkt_rate"]     = (df["fwd_pkts"] + df["bwd_pkts"]) / (df["duration"] + 1e-9)
    df["byte_rate"]    = (df["fwd_bytes"] + df["bwd_bytes"]) / (df["duration"] + 1e-9)
    df["syn_to_total"] = df["syn_cnt"] / (df["fwd_pkts"] + df["bwd_pkts"] + 1)
    df["rst_to_total"] = df["rst_cnt"] / (df["fwd_pkts"] + df["bwd_pkts"] + 1)
    df["iat_cv"]       = df["iat_std"] / (df["iat_mean"] + 1e-9)  # coeff of variation

    # ── Log-scale skewed features ──────────────────────────────────────────
    for col in ["fwd_bytes", "bwd_bytes", "fwd_pkts", "bwd_pkts",
                "pkt_len_max", "duration", "pkt_rate", "byte_rate"]:
        if col in df.columns:
            df[f"log_{col}"] = np.log1p(df[col])

    # ── Drop identifier columns ────────────────────────────────────────────
    to_drop = [c for c in DROP_COLS if c in df.columns]
    df.drop(columns=to_drop, inplace=True)

    # ── Extract label then drop it from features ────────────────────────────
    if label_col not in df.columns:
        sys.exit(f"ERROR: label column '{label_col}' not found.")

    y = df[label_col].astype(int)
    X = df.drop(columns=[label_col])

    # Also drop highly correlated iot_score if using iot_hint as label
    # (they encode almost the same information — would cause data leakage)
    if label_col == "iot_hint" and "iot_score" in X.columns:
        X.drop(columns=["iot_score"], inplace=True)

    # ── Handle remaining string columns ────────────────────────────────────
    str_cols = X.select_dtypes(include="object").columns.tolist()
    for col in str_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))

    # ── Impute NaN / Inf ──────────────────────────────────────────────────
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0.0, inplace=True)

    print(f"    Feature matrix: {X.shape[0]:,} rows × {X.shape[1]} features")
    print(f"    Class balance  : {y.value_counts().to_dict()}")
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
#  3. Feature selection  (4-stage pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def feature_selection(X: pd.DataFrame, y: pd.Series,
                      top_k: int = 20) -> tuple[pd.DataFrame, list[str], pd.DataFrame]:
    """
    Returns
    -------
    X_sel        : DataFrame with selected features only
    selected     : list of selected column names
    report_df    : DataFrame with MI score + RF importance for every surviving feature
    """
    print("\n[3] Feature selection …")
    all_features = X.columns.tolist()

    # ── Stage A: Variance threshold ──────────────────────────────────────────
    # Remove features that barely vary (< 1% of max variance).
    # Catches binary flags that are almost always 0 or 1.
    vt = VarianceThreshold(threshold=0.01)
    vt.fit(X)
    mask_var = vt.get_support()
    X_var = X.loc[:, mask_var]
    dropped_var = [c for c, m in zip(all_features, mask_var) if not m]
    print(f"    Stage A (Variance): dropped {len(dropped_var)} low-variance → "
          f"{X_var.shape[1]} remain")

    # ── Stage B: Pearson correlation filter ──────────────────────────────────
    # For each pair with |r| > 0.95, drop the one with lower MI with the label.
    # Computes MI first so we know which to keep.
    mi_all = mutual_info_classif(X_var, y, random_state=RANDOM_SEED)
    mi_map = dict(zip(X_var.columns, mi_all))

    corr_matrix = X_var.corr().abs()
    upper = corr_matrix.where(
        np.triu(np.ones(corr_matrix.shape, dtype=bool), k=1)
    )
    drop_corr = set()
    for col in upper.columns:
        high_corr = upper.index[upper[col] > 0.95].tolist()
        for partner in high_corr:
            # Keep whichever has higher MI; drop the other
            drop = col if mi_map.get(col, 0) < mi_map.get(partner, 0) else partner
            drop_corr.add(drop)

    X_corr = X_var.drop(columns=list(drop_corr))
    print(f"    Stage B (Correlation): dropped {len(drop_corr)} redundant → "
          f"{X_corr.shape[1]} remain")

    # ── Stage C: Mutual Information top-K ────────────────────────────────────
    # Score each feature's non-linear dependency with the label.
    actual_k = min(top_k, X_corr.shape[1])
    mi_scores = mutual_info_classif(X_corr, y, random_state=RANDOM_SEED)
    mi_series = pd.Series(mi_scores, index=X_corr.columns).sort_values(ascending=False)

    top_mi_feats = mi_series.head(actual_k).index.tolist()
    X_mi = X_corr[top_mi_feats]
    print(f"    Stage C (Mutual Info): kept top {actual_k} → {X_mi.shape[1]} features")

    # ── Stage D: Random Forest permutation importance ─────────────────────────
    # Quick 100-tree forest to validate the MI ranking.
    rf_sel = RandomForestClassifier(n_estimators=100, random_state=RANDOM_SEED,
                                    n_jobs=-1, class_weight="balanced")
    rf_sel.fit(X_mi, y)
    perm = permutation_importance(rf_sel, X_mi, y, n_repeats=5,
                                  random_state=RANDOM_SEED, n_jobs=-1)
    perm_mean = pd.Series(perm.importances_mean, index=X_mi.columns)

    # Drop features where permutation importance is negative (hurt the model)
    drop_perm = perm_mean[perm_mean < 0].index.tolist()
    X_sel = X_mi.drop(columns=drop_perm)
    selected = X_sel.columns.tolist()
    print(f"    Stage D (RF Importance): removed {len(drop_perm)} negative-impact → "
          f"{len(selected)} final features")

    # ── Build report ──────────────────────────────────────────────────────────
    report_df = pd.DataFrame({
        "feature":    selected,
        "mi_score":   [mi_series.get(f, 0.0)   for f in selected],
        "rf_perm_imp":[perm_mean.get(f, 0.0)   for f in selected],
    }).sort_values("mi_score", ascending=False).reset_index(drop=True)

    print("\n    Top-10 selected features:")
    print(report_df.head(10).to_string(index=False))
    return X_sel, selected, report_df


# ─────────────────────────────────────────────────────────────────────────────
#  4. Model training + cross-validation
# ─────────────────────────────────────────────────────────────────────────────

def train_models(X: pd.DataFrame, y: pd.Series,
                 n_trees: int = 300,
                 use_xgb: bool = True) -> dict:
    """
    Returns a dict of {model_name: fitted_pipeline}.
    Pipelines include StandardScaler + classifier so inference
    needs only raw features.
    """
    print("\n[4] Training …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    results: dict = {}

    def _run(name: str, clf):
        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    clf),
        ])
        scores = cross_validate(
            pipe, X, y, cv=cv, scoring=["accuracy", "f1", "roc_auc"],
            n_jobs=-1, return_train_score=False,
        )
        print(f"\n    ── {name} (5-fold CV) ──────────────────────────")
        print(f"    Accuracy : {scores['test_accuracy'].mean():.4f} "
              f"± {scores['test_accuracy'].std():.4f}")
        print(f"    F1       : {scores['test_f1'].mean():.4f} "
              f"± {scores['test_f1'].std():.4f}")
        print(f"    ROC-AUC  : {scores['test_roc_auc'].mean():.4f} "
              f"± {scores['test_roc_auc'].std():.4f}")
        pipe.fit(X, y)   # final fit on all data
        results[name] = pipe

    # Random Forest (always run)
    _run("RandomForest", RandomForestClassifier(
        n_estimators=n_trees,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    ))

    # XGBoost (optional)
    if use_xgb:
        try:
            import xgboost as xgb
            scale_pos = int((y == 0).sum()) / max(int((y == 1).sum()), 1)
            _run("XGBoost", xgb.XGBClassifier(
                n_estimators=n_trees,
                max_depth=6,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                scale_pos_weight=scale_pos,
                use_label_encoder=False,
                eval_metric="logloss",
                random_state=RANDOM_SEED,
                n_jobs=-1,
            ))
        except ImportError:
            print("    [!] XGBoost not installed — skipping (pip install xgboost)")

    return results


# ─────────────────────────────────────────────────────────────────────────────
#  5. Evaluation on a held-out test split
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(models: dict,
             X_test: pd.DataFrame, y_test: pd.Series,
             out_dir: Path,
             threshold: float = 0.5) -> None:
    print("\n[5] Evaluation on held-out test set …")
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, pipe in models.items():
        y_prob = pipe.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= threshold).astype(int)

        acc    = accuracy_score(y_test, y_pred)
        auc    = roc_auc_score(y_test, y_prob)
        report = classification_report(y_test, y_pred,
                                       target_names=["Non-IoT", "IoT"])

        print(f"\n    ── {name} ──")
        print(f"    Accuracy: {acc:.4f}   ROC-AUC: {auc:.4f}")
        print(report)

        # ── Confusion matrix plot ────────────────────────────────────────────
        cm  = confusion_matrix(y_test, y_pred)
        fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

        ConfusionMatrixDisplay(cm, display_labels=["Non-IoT", "IoT"]).plot(
            ax=axes[0], cmap="Blues", colorbar=False)
        axes[0].set_title(f"{name} – Confusion Matrix")

        # ── ROC curve ────────────────────────────────────────────────────────
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        axes[1].plot(fpr, tpr, lw=2, label=f"AUC = {auc:.3f}")
        axes[1].plot([0, 1], [0, 1], "k--", lw=1)
        axes[1].set_xlabel("False Positive Rate")
        axes[1].set_ylabel("True Positive Rate")
        axes[1].set_title(f"{name} – ROC Curve")
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        fig.tight_layout()
        fig.savefig(out_dir / f"{name.lower()}_eval.png", dpi=150)
        plt.close(fig)


# ─────────────────────────────────────────────────────────────────────────────
#  6. Feature importance visualisation
# ─────────────────────────────────────────────────────────────────────────────

def plot_importance(report_df: pd.DataFrame, out_dir: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(14, max(4, len(report_df) * 0.3)))

    for ax, col, title, colour in [
        (axes[0], "mi_score",    "Mutual Information Score", "#2196F3"),
        (axes[1], "rf_perm_imp", "RF Permutation Importance", "#4CAF50"),
    ]:
        data = report_df.sort_values(col)
        ax.barh(data["feature"], data[col], color=colour, edgecolor="white")
        ax.set_title(title, fontweight="bold")
        ax.set_xlabel("Score")
        ax.grid(axis="x", alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_dir / "feature_importance.png", dpi=150)
    plt.close(fig)
    print(f"    Importance plot saved → {out_dir / 'feature_importance.png'}")


# ─────────────────────────────────────────────────────────────────────────────
#  7. Persistence
# ─────────────────────────────────────────────────────────────────────────────

def save_artefacts(models: dict,
                   selected: list[str],
                   report_df: pd.DataFrame,
                   out_dir: Path) -> None:
    print("\n[6] Saving artefacts …")
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, pipe in models.items():
        model_path = out_dir / f"{name.lower()}_model.joblib"
        joblib.dump(pipe, model_path)
        print(f"    Model  → {model_path}")

    feat_path = out_dir / "selected_features.json"
    feat_path.write_text(json.dumps(selected, indent=2))
    print(f"    Features → {feat_path}")

    imp_path = out_dir / "feature_importance.csv"
    report_df.to_csv(imp_path, index=False)
    print(f"    Importance CSV → {imp_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  Inference helper  (use after training)
# ─────────────────────────────────────────────────────────────────────────────

def predict_new(model_path: str, features_path: str, csv_in: str) -> None:
    """
    Load a saved model + feature list and score a new flows CSV.
    Writes predictions to <csv_in>_predictions.csv.
    """
    pipe     = joblib.load(model_path)
    selected = json.loads(Path(features_path).read_text())

    df = pd.read_csv(csv_in, low_memory=False)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0.0, inplace=True)

    missing = [c for c in selected if c not in df.columns]
    if missing:
        print(f"WARNING: {len(missing)} features missing from input — filling with 0")
        for c in missing:
            df[c] = 0.0

    X = df[selected]
    probs = pipe.predict_proba(X)[:, 1]
    df["iot_prob"]  = probs
    df["iot_pred"]  = (probs >= 0.5).astype(int)

    out = Path(csv_in).stem + "_predictions.csv"
    df.to_csv(out, index=False)
    print(f"Predictions written to {out}")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="IoT vs Non-IoT traffic classifier for UNSW-NB15 flow CSV")
    p.add_argument("csv",         help="Flow CSV from pcap_flow_extractor")
    p.add_argument("--label-col", default="iot_hint",
                   help="Column to use as label (default: iot_hint)")
    p.add_argument("--top-k",     type=int,   default=20,
                   help="Features to keep after MI stage (default: 20)")
    p.add_argument("--trees",     type=int,   default=300,
                   help="RF n_estimators (default: 300)")
    p.add_argument("--threshold", type=float, default=0.5,
                   help="Classification threshold (default: 0.5)")
    p.add_argument("--no-xgb",   action="store_true",
                   help="Skip XGBoost")
    p.add_argument("--out-dir",   default="./model_output",
                   help="Output directory (default: ./model_output)")
    p.add_argument("--test-size", type=float, default=0.2,
                   help="Held-out test fraction (default: 0.2)")
    return p.parse_args()


def main():
    args   = parse_args()
    out_dir = Path(args.out_dir)

    # ── Load ──────────────────────────────────────────────────────────────────
    df = load_data(args.csv)

    # ── Preprocess ────────────────────────────────────────────────────────────
    X, y = preprocess(df, label_col=args.label_col)

    # ── Train / test split (stratified) ───────────────────────────────────────
    from sklearn.model_selection import train_test_split
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size,
        stratify=y, random_state=RANDOM_SEED,
    )
    print(f"\n    Train: {len(X_tr):,}  |  Test: {len(X_te):,}")

    # ── Feature selection  (on training set only to prevent leakage) ──────────
    X_tr_sel, selected, report_df = feature_selection(
        X_tr, y_tr, top_k=args.top_k)
    X_te_sel = X_te[selected]

    # ── Train ─────────────────────────────────────────────────────────────────
    models = train_models(X_tr_sel, y_tr,
                          n_trees=args.trees,
                          use_xgb=not args.no_xgb)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    evaluate(models, X_te_sel, y_te, out_dir, threshold=args.threshold)
    plot_importance(report_df, out_dir)

    # ── Save ──────────────────────────────────────────────────────────────────
    save_artefacts(models, selected, report_df, out_dir)

    print("\n✓ Done. Artefacts in:", out_dir)


if __name__ == "__main__":
    main()
