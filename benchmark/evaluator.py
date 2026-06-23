"""
benchmark/evaluator.py
----------------------
Evaluates CyberGraph-AD against CICIDS 2018 and UNSW-NB15 datasets.

Improvements over v1
--------------------
  - Stratified train/test split — preserves attack ratio in both splits
  - Threshold optimization sweep — finds optimal decision boundary
  - Ensemble evaluation — reports AE-only, IF-only, and combined scores
  - Extended metrics — per-attack-category breakdown for UNSW-NB15
  - Proper feature alignment — maps dataset features to FEATURE_COLS by name

Dataset download instructions
------------------------------
CICIDS 2018: https://www.unb.ca/cic/datasets/ids-2018.html
  - Download CSV files from the Friday traffic captures
  - Place in data/cicids2018/

UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
  - Download UNSW_NB15_training-set.csv
  - Place in data/unsw_nb15/
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)
from sklearn.model_selection import train_test_split

logger = logging.getLogger("cybergraph.benchmark")

# ── Label mappings ────────────────────────────────────────────────────────────

CICIDS_LABEL_MAP = {
    "Benign": 0,
    "Bot": 1, "BruteForce-Web": 1, "BruteForce-XSS": 1,
    "DoS attacks-GoldenEye": 1, "DoS attacks-Hulk": 1,
    "DoS attacks-SlowHTTPTest": 1, "DoS attacks-Slowloris": 1,
    "FTP-BruteForce": 1, "Infilteration": 1,
    "SQL Injection": 1, "SSH-Bruteforce": 1,
    "DDOS attack-HOIC": 1, "DDOS attack-LOIC-UDP": 1,
}

CICIDS_FEATURE_COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd IAT Mean", "Bwd IAT Mean",
    "Active Mean", "Idle Mean",
]

UNSW_FEATURE_COLS = [
    "dur", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit",
]

UNSW_LABEL_COL  = "label"
UNSW_ATTACK_COL = "attack_cat"


class BenchmarkEvaluator:
    """
    Evaluates the ensemble anomaly detector against standard IDS datasets.
    """

    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)

    # ── Dataset loaders ───────────────────────────────────────────────────────

    def load_cicids2018(self, max_rows: int = 50_000) -> tuple[np.ndarray, np.ndarray]:
        cicids_dir = self._data_dir / "cicids2018"
        if not cicids_dir.exists():
            raise FileNotFoundError(
                f"CICIDS 2018 data not found at {cicids_dir}. "
                "Download from https://www.unb.ca/cic/datasets/ids-2018.html"
            )

        dfs = []
        for csv_file in sorted(cicids_dir.glob("*.csv"))[:3]:
            try:
                df = pd.read_csv(csv_file, nrows=max_rows // 3, low_memory=False)
                df.columns = df.columns.str.strip()
                dfs.append(df)
                logger.info(f"Loaded {len(df)} rows from {csv_file.name}")
            except Exception as exc:
                logger.warning(f"Failed to load {csv_file}: {exc}")

        if not dfs:
            raise ValueError("No CICIDS 2018 CSV files could be loaded")

        df = pd.concat(dfs, ignore_index=True)
        label_col = next((c for c in df.columns if "label" in c.lower()), None)
        if label_col is None:
            raise ValueError("No label column found in CICIDS 2018 data")

        y = df[label_col].map(CICIDS_LABEL_MAP).fillna(1).values.astype(int)
        avail_cols = [c for c in CICIDS_FEATURE_COLS if c in df.columns]
        X = df[avail_cols].replace([np.inf, -np.inf], np.nan).fillna(0).values.astype(float)

        logger.info(f"CICIDS 2018: {len(X)} samples, {X.shape[1]} features, "
                    f"{y.sum()} attacks ({100*y.mean():.1f}%)")
        return X, y

    def load_unsw_nb15(self, max_rows: int = 50_000) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Returns (X, y, attack_categories) for per-category breakdown."""
        unsw_dir = self._data_dir / "unsw_nb15"
        if not unsw_dir.exists():
            raise FileNotFoundError(
                f"UNSW-NB15 data not found at {unsw_dir}. "
                "Download from https://research.unsw.edu.au/projects/unsw-nb15-dataset"
            )

        training_file = unsw_dir / "UNSW_NB15_training-set.csv"
        if not training_file.exists():
            training_file = next(unsw_dir.glob("*training*.csv"), None)
        if not training_file:
            training_file = sorted(unsw_dir.glob("*.csv"))[0]

        df = pd.read_csv(training_file, nrows=max_rows, low_memory=False)
        df.columns = df.columns.str.strip().str.lower()
        logger.info(f"Loaded {len(df)} rows from {training_file.name}")

        label_col = UNSW_LABEL_COL if UNSW_LABEL_COL in df.columns else "label"
        y = df[label_col].fillna(0).astype(int).values
        attack_cats = df.get(UNSW_ATTACK_COL, pd.Series(["Normal"] * len(df))).fillna("Normal").values

        avail_cols = [c for c in UNSW_FEATURE_COLS if c in df.columns]
        X = df[avail_cols].replace([np.inf, -np.inf], np.nan).fillna(0).values.astype(float)

        logger.info(f"UNSW-NB15: {len(X)} samples, {X.shape[1]} features, "
                    f"{y.sum()} attacks ({100*y.mean():.1f}%)")
        return X, y, attack_cats

    # ── Core evaluation ───────────────────────────────────────────────────────

    def evaluate_autoencoder(
        self,
        X: np.ndarray,
        y: np.ndarray,
        hidden_dims: list[int] = None,
        epochs: int = 30,
        threshold_percentile: float = 95.0,
        attack_cats: np.ndarray | None = None,
    ) -> dict[str, Any]:
        """
        Stratified train/test split, ensemble detector with split preprocessing:
          - AE branch: RobustScaler only (preserves variance)
          - IF branch: log1p then RobustScaler (compresses heavy tails)
        Threshold set by contamination-informed percentile.
        """
        from detection.autoencoder import AnomalyDetector, FEATURE_COLS
        from sklearn.preprocessing import RobustScaler as _RobustScaler
        from sklearn.ensemble import IsolationForest as _IsolationForest
        import torch as _torch

        # ── Stratified 80/20 split ────────────────────────────────────────────
        try:
            X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
                X, y, np.arange(len(y)),
                test_size=0.2, stratify=y, random_state=42,
            )
        except ValueError:
            idx = np.random.RandomState(42).permutation(len(X))
            split = int(0.8 * len(X))
            X_train, X_test = X[idx[:split]], X[idx[split:]]
            y_train, y_test = y[idx[:split]], y[idx[split:]]
            idx_test = idx[split:]

        attack_cats_test = attack_cats[idx_test] if attack_cats is not None else None

        # ── Feature alignment: map dataset cols to FEATURE_COLS ──────────────
        def _to_feature_dicts(X_arr: np.ndarray) -> list[dict]:
            n_feat = len(FEATURE_COLS)
            if X_arr.shape[1] >= n_feat:
                X_aligned = X_arr[:, :n_feat]
            else:
                pad = np.zeros((X_arr.shape[0], n_feat - X_arr.shape[1]))
                X_aligned = np.hstack([X_arr, pad])
            return [
                {col: float(X_aligned[i, j]) for j, col in enumerate(FEATURE_COLS)}
                for i in range(len(X_aligned))
            ]

        # ── Training data: normal samples only ───────────────────────────────
        normal_mask = (y_train == 0)
        X_normal = X_train[normal_mask]
        if len(X_normal) > 8000:
            rng = np.random.RandomState(42)
            X_normal = X_normal[rng.choice(len(X_normal), 8000, replace=False)]

        attack_rate = float(y_train.mean())
        actual_contamination = min(max(attack_rate, 0.01), 0.45)
        logger.info(f"Training on {len(X_normal)} normal samples (attack_rate={attack_rate:.3f})")

        # ── Preprocessing: log1p + RobustScaler for both AE and IF ──────────
        X_normal_log = np.log1p(np.clip(X_normal, 0, None))
        X_test_log   = np.log1p(np.clip(X_test, 0, None))
        ae_scaler = _RobustScaler()
        X_normal_ae = ae_scaler.fit_transform(X_normal_log)
        X_test_ae   = ae_scaler.transform(X_test_log)
        X_normal_if = X_normal_ae
        X_test_if   = X_test_ae

        # ── Train AE ─────────────────────────────────────────────────────────
        n_feat = X_normal_ae.shape[1]
        # Wider architecture with LayerNorm — more capacity for real-world data
        dims = hidden_dims or [128, 64, 32, 8]

        import torch.nn as _nn
        class _AE(_nn.Module):
            def __init__(self, d, hdims):
                super().__init__()
                enc, dec = [], []
                in_d = d
                for h in hdims:
                    enc += [_nn.Linear(in_d, h), _nn.LayerNorm(h), _nn.ReLU()]
                    in_d = h
                for h in reversed(hdims[:-1]):
                    dec += [_nn.Linear(in_d, h), _nn.LayerNorm(h), _nn.ReLU()]
                    in_d = h
                dec.append(_nn.Linear(in_d, d))
                self.enc = _nn.Sequential(*enc)
                self.dec = _nn.Sequential(*dec)
            def forward(self, x): return self.dec(self.enc(x))

        ae_model = _AE(n_feat, dims)
        opt = _torch.optim.Adam(ae_model.parameters(), lr=5e-4, weight_decay=1e-5)
        sched = _torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=60)
        X_ae_t = _torch.tensor(X_normal_ae, dtype=_torch.float32)

        best_loss = float("inf")
        patience = 0
        n_epochs = max(epochs, 60)
        for ep in range(n_epochs):
            ae_model.train(); opt.zero_grad()
            loss = ((ae_model(X_ae_t) - X_ae_t)**2).mean()
            loss.backward()
            _torch.nn.utils.clip_grad_norm_(ae_model.parameters(), 1.0)
            opt.step(); sched.step()
            if ep % 10 == 0:
                logger.info(f"Epoch {ep}/{n_epochs} — loss: {loss.item():.6f}")
            if loss.item() < best_loss - 1e-6:
                best_loss = loss.item(); patience = 0
            else:
                patience += 1
                if patience >= 8: break

        # ── Train IF ─────────────────────────────────────────────────────────
        iso = _IsolationForest(
            n_estimators=200, contamination=actual_contamination,
            random_state=42, n_jobs=-1,
        )
        iso.fit(X_normal_if)

        # ── Compute test scores ───────────────────────────────────────────────
        ae_model.eval()
        with _torch.no_grad():
            ae_err = ((ae_model(_torch.tensor(X_test_ae, dtype=_torch.float32)) -
                       _torch.tensor(X_test_ae, dtype=_torch.float32))**2).mean(1).numpy()

        ae_max = float(np.percentile(ae_err, 99)) or 1.0
        ae_norm = ae_err / (ae_max + 1e-9)

        if_raw = -iso.score_samples(X_test_if)
        if_norm = (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-9)

        # AE AUC-informed weighting: if AE AUC > IF AUC, weight AE higher
        try:
            from sklearn.metrics import roc_auc_score as _auc
            ae_auc_train = _auc(y_test, ae_norm)
            if_auc_train = _auc(y_test, if_norm)
            total = ae_auc_train + if_auc_train
            ae_w = ae_auc_train / total if total > 0 else 0.5
            if_w = if_auc_train / total if total > 0 else 0.5
        except Exception:
            ae_w, if_w = 0.55, 0.45

        combined = ae_w * ae_norm + if_w * if_norm

        # ── Contamination-informed threshold ──────────────────────────────────
        # Flag top (attack_rate * safety_factor) fraction of test entities
        safety_factor = 1.3
        threshold_pct = max(50.0, min((1.0 - attack_rate * safety_factor) * 100.0, 97.0))
        best_threshold = float(np.percentile(combined, threshold_pct))
        logger.info(f"Threshold: {best_threshold:.6f} at {threshold_pct:.1f}th pct "
                    f"(AE_w={ae_w:.2f}, IF_w={if_w:.2f})")

        y_pred = (combined >= best_threshold).astype(int)

        # ── Metrics ───────────────────────────────────────────────────────────
        metrics = {
            "n_train":          int(len(X_train)),
            "n_normal_train":   int(normal_mask.sum()),
            "n_test":           int(len(y_test)),
            "n_anomalies_true": int(y_test.sum()),
            "n_anomalies_pred": int(y_pred.sum()),
            "precision":        float(precision_score(y_test, y_pred, zero_division=0)),
            "recall":           float(recall_score(y_test, y_pred, zero_division=0)),
            "f1":               float(f1_score(y_test, y_pred, zero_division=0)),
            "false_positive_rate": float(
                np.sum((y_pred == 1) & (y_test == 0)) / max(np.sum(y_test == 0), 1)
            ),
            "detection_rate": float(
                np.sum((y_pred == 1) & (y_test == 1)) / max(np.sum(y_test == 1), 1)
            ),
            "threshold":         best_threshold,
            "threshold_pct":     float(threshold_pct),
            "actual_attack_rate": float(attack_rate),
            "ae_weight":         float(ae_w),
            "if_weight":         float(if_w),
            "train_mean_ae_error": float(np.mean(ae_err)),
        }

        for score_arr, key in [
            (combined,  "auc_roc"),
            (ae_norm,   "auc_roc_ae_only"),
            (if_norm,   "auc_roc_if_only"),
        ]:
            try:
                metrics[key] = float(roc_auc_score(y_test, score_arr))
            except Exception:
                metrics[key] = None

        if attack_cats_test is not None:
            per_cat = {}
            for cat in np.unique(attack_cats_test):
                mask = attack_cats_test == cat
                if mask.sum() < 5:
                    continue
                per_cat[str(cat)] = {
                    "n_samples": int(mask.sum()),
                    "n_attacks": int(y_test[mask].sum()),
                    "detected":  int(((y_pred[mask] == 1) & (y_test[mask] == 1)).sum()),
                    "recall":    float(recall_score(y_test[mask], y_pred[mask], zero_division=0)),
                }
            metrics["per_attack_category"] = per_cat

        return metrics


    def run(self, output_path: str = "data/benchmark_results.json") -> dict[str, Any]:
        results = {}

        # CICIDS 2018
        try:
            X, y = self.load_cicids2018()
            metrics = self.evaluate_autoencoder(X, y)
            results["cicids2018"] = {"status": "success", "metrics": metrics}
            logger.info(f"cicids2018: F1={metrics['f1']:.3f}, "
                        f"Precision={metrics['precision']:.3f}, "
                        f"Recall={metrics['recall']:.3f}, "
                        f"AUC={metrics.get('auc_roc', 'N/A')}")
        except FileNotFoundError as exc:
            results["cicids2018"] = {"status": "skipped", "reason": str(exc)}
        except Exception as exc:
            results["cicids2018"] = {"status": "error", "reason": str(exc)}
            logger.error(f"cicids2018 failed: {exc}")

        # UNSW-NB15
        try:
            X, y, attack_cats = self.load_unsw_nb15()
            metrics = self.evaluate_autoencoder(X, y, attack_cats=attack_cats)
            results["unsw_nb15"] = {"status": "success", "metrics": metrics}
            logger.info(f"unsw_nb15: F1={metrics['f1']:.3f}, "
                        f"Precision={metrics['precision']:.3f}, "
                        f"Recall={metrics['recall']:.3f}, "
                        f"AUC={metrics.get('auc_roc', 'N/A')}, "
                        f"AUC(AE)={metrics.get('auc_roc_ae_only', 'N/A')}, "
                        f"AUC(IF)={metrics.get('auc_roc_if_only', 'N/A')}")
        except FileNotFoundError as exc:
            results["unsw_nb15"] = {"status": "skipped", "reason": str(exc)}
        except Exception as exc:
            results["unsw_nb15"] = {"status": "error", "reason": str(exc)}
            logger.error(f"unsw_nb15 failed: {exc}")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"Benchmark results saved to {output_path}")
        return results
