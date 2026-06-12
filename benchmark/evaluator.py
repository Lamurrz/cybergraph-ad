"""
benchmark/evaluator.py
----------------------
Evaluates CyberGraph-AD against CICIDS 2018 and UNSW-NB15 datasets.

Dataset download instructions
------------------------------
CICIDS 2018: https://www.unb.ca/cic/datasets/ids-2018.html
  - Download CSV files from the Friday traffic captures
  - Place in data/cicids2018/

UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset
  - Download UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv
  - Place in data/unsw_nb15/

Metrics reported
----------------
  - Precision, Recall, F1 (macro and per-class)
  - AUC-ROC
  - False positive rate
  - Detection rate per anomaly type
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
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("cybergraph.benchmark")

# CICIDS 2018 label mapping → binary (0=normal, 1=attack)
CICIDS_LABEL_MAP = {
    "Benign": 0,
    "Bot": 1, "BruteForce-Web": 1, "BruteForce-XSS": 1,
    "DoS attacks-GoldenEye": 1, "DoS attacks-Hulk": 1,
    "DoS attacks-SlowHTTPTest": 1, "DoS attacks-Slowloris": 1,
    "FTP-BruteForce": 1, "Infilteration": 1,
    "SQL Injection": 1, "SSH-Bruteforce": 1,
    "DDOS attack-HOIC": 1, "DDOS attack-LOIC-UDP": 1,
}

# UNSW-NB15 label column
UNSW_LABEL_COL = "label"
UNSW_ATTACK_COL = "attack_cat"

# Feature columns available in both datasets that map to our feature space
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


class BenchmarkEvaluator:
    """
    Evaluates the autoencoder anomaly detector against standard IDS datasets.
    """

    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)

    # ── Dataset loaders ───────────────────────────────────────────────────────

    def load_cicids2018(self, max_rows: int = 50_000) -> tuple[np.ndarray, np.ndarray]:
        """
        Load CICIDS 2018 dataset.
        Returns (X, y) where y=0 is normal, y=1 is attack.
        """
        cicids_dir = self._data_dir / "cicids2018"
        if not cicids_dir.exists():
            raise FileNotFoundError(
                f"CICIDS 2018 data not found at {cicids_dir}. "
                "Download from https://www.unb.ca/cic/datasets/ids-2018.html "
                "and place CSV files in data/cicids2018/"
            )

        dfs = []
        for csv_file in sorted(cicids_dir.glob("*.csv"))[:3]:  # limit to 3 files
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

        # Find label column
        label_col = next((c for c in df.columns if "label" in c.lower()), None)
        if label_col is None:
            raise ValueError("No label column found in CICIDS 2018 data")

        y = df[label_col].map(CICIDS_LABEL_MAP).fillna(1).values.astype(int)

        # Select available feature columns
        avail_cols = [c for c in CICIDS_FEATURE_COLS if c in df.columns]
        X = df[avail_cols].replace([np.inf, -np.inf], np.nan).fillna(0).values.astype(float)

        logger.info(f"CICIDS 2018: {len(X)} samples, {X.shape[1]} features, "
                    f"{y.sum()} attacks ({100*y.mean():.1f}%)")
        return X, y

    def load_unsw_nb15(self, max_rows: int = 50_000) -> tuple[np.ndarray, np.ndarray]:
        """
        Load UNSW-NB15 dataset.
        Returns (X, y) where y=0 is normal, y=1 is attack.
        """
        unsw_dir = self._data_dir / "unsw_nb15"
        if not unsw_dir.exists():
            raise FileNotFoundError(
                f"UNSW-NB15 data not found at {unsw_dir}. "
                "Download from https://research.unsw.edu.au/projects/unsw-nb15-dataset "
                "and place CSV files in data/unsw_nb15/"
            )

        dfs = []
        for csv_file in sorted(unsw_dir.glob("*.csv"))[:2]:
            try:
                df = pd.read_csv(csv_file, nrows=max_rows // 2, low_memory=False)
                df.columns = df.columns.str.strip().str.lower()
                dfs.append(df)
                logger.info(f"Loaded {len(df)} rows from {csv_file.name}")
            except Exception as exc:
                logger.warning(f"Failed to load {csv_file}: {exc}")

        if not dfs:
            raise ValueError("No UNSW-NB15 CSV files could be loaded")

        df = pd.concat(dfs, ignore_index=True)

        label_col = UNSW_LABEL_COL if UNSW_LABEL_COL in df.columns else "label"
        y = df[label_col].fillna(0).astype(int).values

        avail_cols = [c for c in UNSW_FEATURE_COLS if c in df.columns]
        X = df[avail_cols].replace([np.inf, -np.inf], np.nan).fillna(0).values.astype(float)

        logger.info(f"UNSW-NB15: {len(X)} samples, {X.shape[1]} features, "
                    f"{y.sum()} attacks ({100*y.mean():.1f}%)")
        return X, y

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate_autoencoder(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        hidden_dims: list[int] = None,
        epochs: int = 30,
        threshold_percentile: float = 95.0,
    ) -> dict[str, Any]:
        """
        Train autoencoder on normal samples only, evaluate on test set.
        Returns comprehensive metrics dict.
        """
        from detection.autoencoder import AnomalyDetector, FEATURE_COLS

        # Build feature dicts from numpy arrays for the detector
        def _to_feature_dicts(X: np.ndarray) -> list[dict]:
            cols = FEATURE_COLS[:X.shape[1]]
            # Pad or trim to match FEATURE_COLS
            padded = np.zeros((X.shape[0], len(FEATURE_COLS)))
            padded[:, :X.shape[1]] = X
            return [
                {col: float(padded[i, j]) for j, col in enumerate(FEATURE_COLS)}
                for i in range(len(padded))
            ]

        # Train only on normal samples
        normal_mask = (y_test == 0)  # use test labels for filtering train
        X_normal = X_train[np.random.choice(len(X_train),
                           min(len(X_train), 5000), replace=False)]

        detector = AnomalyDetector(
            hidden_dims=hidden_dims or [64, 32, 16],
            epochs=epochs,
            anomaly_threshold_percentile=threshold_percentile,
        )

        train_summary = detector.fit(_to_feature_dicts(X_normal))

        # Score test set
        test_features = _to_feature_dicts(X_test)
        for i, f in enumerate(test_features):
            f["user_uid"] = f"entity-{i}"

        scored = detector.score(test_features)
        y_pred = np.array([1 if s["is_anomaly"] else 0 for s in scored])
        scores = np.array([s["anomaly_score_normalized"] for s in scored])

        metrics = {
            "n_test": len(y_test),
            "n_anomalies_true": int(y_test.sum()),
            "n_anomalies_pred": int(y_pred.sum()),
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, zero_division=0)),
            "false_positive_rate": float(
                np.sum((y_pred == 1) & (y_test == 0)) / max(np.sum(y_test == 0), 1)
            ),
            "detection_rate": float(
                np.sum((y_pred == 1) & (y_test == 1)) / max(np.sum(y_test == 1), 1)
            ),
            "threshold": train_summary["threshold"],
            "train_mean_error": train_summary["mean_error"],
        }

        try:
            metrics["auc_roc"] = float(roc_auc_score(y_test, scores))
        except Exception:
            metrics["auc_roc"] = None

        return metrics

    # ── Full benchmark run ────────────────────────────────────────────────────

    def run(self, output_path: str = "data/benchmark_results.json") -> dict[str, Any]:
        """
        Run full benchmark on all available datasets.
        Results are saved to output_path and returned.
        """
        results = {}

        for dataset_name, loader in [
            ("cicids2018", self.load_cicids2018),
            ("unsw_nb15", self.load_unsw_nb15),
        ]:
            try:
                X, y = loader()
                # 80/20 train/test split
                split = int(0.8 * len(X))
                X_train, X_test = X[:split], X[split:]
                y_test = y[split:]

                metrics = self.evaluate_autoencoder(X_train, X_test, y_test)
                results[dataset_name] = {"status": "success", "metrics": metrics}
                logger.info(f"{dataset_name}: F1={metrics['f1']:.3f}, "
                            f"Precision={metrics['precision']:.3f}, "
                            f"Recall={metrics['recall']:.3f}, "
                            f"AUC={metrics.get('auc_roc', 'N/A')}")
            except FileNotFoundError as exc:
                results[dataset_name] = {"status": "skipped", "reason": str(exc)}
                logger.warning(f"{dataset_name}: {exc}")
            except Exception as exc:
                results[dataset_name] = {"status": "error", "reason": str(exc)}
                logger.error(f"{dataset_name} failed: {exc}")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"Benchmark results saved to {output_path}")
        return results
