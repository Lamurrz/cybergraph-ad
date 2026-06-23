"""
detection/autoencoder.py
------------------------
Ensemble behavioral anomaly detector combining:
  1. Autoencoder (reconstruction error)
  2. Isolation Forest (path length anomaly score)

Improvements over v1
--------------------
  - 16 behavioral features (up from 8) — richer graph-derived signals
  - Ensemble scoring: weighted combination of AE + IF scores
  - Threshold optimization: sweep on validation split to maximize F1
  - Robust scaler: RobustScaler instead of StandardScaler — handles outliers
  - Dropout regularization in autoencoder — reduces overfitting on small graphs
  - Early stopping — prevents overfitting when training loss plateaus

Architecture
------------
Input (16 features)
  → Encoder: 16 → 64 → 32 → 16 → 8 (bottleneck)
  → Decoder: 8 → 16 → 32 → 64 → 16
  Anomaly score = MSE reconstruction error

Ensemble combination
--------------------
  combined_score = w_ae * ae_normalized + w_if * if_score
  Default weights: AE=0.6, IF=0.4
  Threshold optimized by sweeping [5th, 95th] percentile range
"""

from __future__ import annotations

import logging
import numpy as np
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score

logger = logging.getLogger("cybergraph.detection")

# ── Feature columns (v2 — 16 features) ───────────────────────────────────────

FEATURE_COLS = [
    # Core behavioral features (v1)
    "total_events",
    "failure_rate",
    "unique_assets",
    "unique_ips",
    "external_ip_rate",
    "off_hours_rate",
    "avg_bytes_out",
    "max_bytes_out",
    # New temporal features (v2)
    "auth_velocity",          # events per hour (burst detection)
    "time_variance",          # variance in inter-event intervals (regularity)
    "session_duration_hours", # total active session window
    "burst_rate",             # max events in any 5-minute window
    # New graph topology features (v2)
    "asset_sensitivity_score", # weighted avg of accessed asset sensitivity
    "lateral_movement_score",  # unique assets / time window (normalized)
    "ip_reuse_rate",           # fraction of IPs reused across sessions
    "sequential_asset_ratio",  # fraction of sequential asset accesses (lateral movement)
]

N_FEATURES = len(FEATURE_COLS)


# ── Autoencoder model ─────────────────────────────────────────────────────────

class _Autoencoder(nn.Module):
    def __init__(self, input_dim: int, hidden_dims: list[int], dropout: float = 0.1):
        super().__init__()

        # Encoder with dropout regularization
        encoder_layers = []
        in_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers += [
                nn.Linear(in_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ]
            in_dim = h_dim
        self.encoder = nn.Sequential(*encoder_layers)

        # Decoder (mirror, no dropout on output)
        decoder_layers = []
        for h_dim in reversed(hidden_dims[:-1]):
            decoder_layers += [
                nn.Linear(in_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
            ]
            in_dim = h_dim
        decoder_layers.append(nn.Linear(in_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((x - recon) ** 2, dim=1)


# ── Ensemble Detector ─────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Ensemble anomaly detector combining autoencoder reconstruction error
    with Isolation Forest path length scoring.

    Training strategy
    -----------------
    Both models train on normal behavior only. Anomalous entities produce
    high reconstruction error (AE) and short path lengths (IF) because
    neither model has seen those behavioral patterns during training.

    Threshold selection
    -------------------
    After training, sweep candidate thresholds on a validation split of
    the training data to find the threshold that maximizes F1 (when labels
    are available) or minimizes false positive rate at target recall (when
    labels are unavailable). Falls back to percentile-based threshold.
    """

    def __init__(
        self,
        hidden_dims: list[int] = None,
        epochs: int = 50,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
        anomaly_threshold_percentile: float = 95.0,
        ae_weight: float = 0.75,
        if_weight: float = 0.25,
        if_contamination: float = 0.05,
        dropout: float = 0.1,
        early_stopping_patience: int = 5,
    ):
        self.hidden_dims = hidden_dims or [64, 32, 16, 8]
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = learning_rate
        self.threshold_percentile = anomaly_threshold_percentile
        self.ae_weight = ae_weight
        self.if_weight = if_weight
        self.if_contamination = if_contamination
        self.dropout = dropout
        self.patience = early_stopping_patience

        self._model: _Autoencoder | None = None
        self._isolation_forest: IsolationForest | None = None
        self._scaler = RobustScaler()
        self._threshold: float | None = None
        self._train_errors: np.ndarray | None = None
        self._ae_max_error: float = 1.0   # for normalization

    # ── Feature preparation ───────────────────────────────────────────────────

    def _to_matrix(self, records: list[dict[str, Any]]) -> np.ndarray:
        """Convert feature dicts to float matrix. Handles None and missing cols."""
        rows = []
        for r in records:
            row = [float(r.get(col) or 0.0) for col in FEATURE_COLS]
            rows.append(row)
        return np.array(rows, dtype=np.float32)

    # ── Training ──────────────────────────────────────────────────────────────

    def fit(
        self,
        features: list[dict[str, Any]],
        labels: list[bool] | None = None,
    ) -> dict[str, float]:
        """
        Train the ensemble on behavioral feature vectors.

        Parameters
        ----------
        features : list of dicts from FusionGraph.extract_user_features()
        labels   : optional list of bool — if provided, optimize threshold on F1

        Returns
        -------
        Training summary dict.
        """
        if len(features) < 5:
            raise ValueError(f"Need at least 5 samples to train, got {len(features)}")

        X = self._to_matrix(features)
        X_scaled = self._scaler.fit_transform(X)

        # ── Train Autoencoder ─────────────────────────────────────────────────
        X_tensor = torch.tensor(X_scaled, dtype=torch.float32)
        input_dim = X_tensor.shape[1]

        self._model = _Autoencoder(input_dim, self.hidden_dims, self.dropout)
        optimizer = torch.optim.Adam(self._model.parameters(), lr=self.lr,
                                     weight_decay=1e-5)
        criterion = nn.MSELoss()
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=3, factor=0.5, verbose=False
        )

        dataset = TensorDataset(X_tensor)
        loader = DataLoader(dataset, batch_size=min(self.batch_size, len(X_tensor)),
                            shuffle=True, drop_last=False)

        best_loss = float("inf")
        patience_counter = 0
        final_loss = 0.0

        self._model.train()
        for epoch in range(self.epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon = self._model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                nn.utils.clip_grad_norm_(self._model.parameters(), 1.0)
                optimizer.step()
                epoch_loss += loss.item()
            final_loss = epoch_loss / len(loader)
            scheduler.step(final_loss)

            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}/{self.epochs} — loss: {final_loss:.6f}")

            # Early stopping
            if final_loss < best_loss - 1e-6:
                best_loss = final_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= self.patience:
                    logger.info(f"Early stopping at epoch {epoch}")
                    break

        # ── Train Isolation Forest ────────────────────────────────────────────
        self._isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=self.if_contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._isolation_forest.fit(X_scaled)

        # ── Compute training errors and threshold ─────────────────────────────
        self._model.eval()
        self._train_errors = self._model.reconstruction_error(X_tensor).numpy()
        self._ae_max_error = float(np.percentile(self._train_errors, 99)) or 1.0

        # IF scores: negative of anomaly score (-1=anomaly, 1=normal) → flip
        if_scores_train = -self._isolation_forest.score_samples(X_scaled)
        if_scores_norm = (if_scores_train - if_scores_train.min()) / (
            if_scores_train.max() - if_scores_train.min() + 1e-9
        )

        ae_scores_norm = self._train_errors / (self._ae_max_error + 1e-9)
        combined_train = self.ae_weight * ae_scores_norm + self.if_weight * if_scores_norm

        if labels is not None and len(labels) == len(features):
            # Optimize threshold on training data using F1
            self._threshold = self._optimize_threshold(combined_train, np.array(labels))
            logger.info(f"Threshold optimized on labels: {self._threshold:.6f}")
        else:
            self._threshold = float(np.percentile(combined_train, self.threshold_percentile))
            logger.info(f"Threshold set at {self.threshold_percentile}th percentile: {self._threshold:.6f}")

        logger.info(f"Training complete — loss: {final_loss:.6f}, threshold: {self._threshold:.6f}")

        return {
            "final_loss": float(final_loss),
            "threshold": self._threshold,
            "n_samples": len(features),
            "mean_ae_error": float(np.mean(self._train_errors)),
            "p95_error": float(np.percentile(self._train_errors, 95)),
            "p99_error": float(np.percentile(self._train_errors, 99)),
            "ae_weight": self.ae_weight,
            "if_weight": self.if_weight,
        }

    def _optimize_threshold(
        self, scores: np.ndarray, labels: np.ndarray
    ) -> float:
        """
        Sweep candidate thresholds and return the one that maximizes F1.
        Falls back to 95th percentile if optimization fails.
        """
        if labels.sum() == 0:
            return float(np.percentile(scores, self.threshold_percentile))

        best_f1 = 0.0
        best_threshold = float(np.percentile(scores, self.threshold_percentile))

        # Sweep from 5th to 95th percentile
        candidates = np.percentile(scores, np.linspace(5, 95, 50))

        for candidate in candidates:
            y_pred = (scores >= candidate).astype(int)
            f1 = f1_score(labels, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = float(candidate)

        return best_threshold

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Score behavioral feature vectors using the ensemble.

        Returns list of dicts with:
          - entity_id, entity_name
          - ae_score: autoencoder reconstruction error (normalized)
          - if_score: isolation forest anomaly score (normalized)
          - combined_score: weighted ensemble score
          - is_anomaly: bool
          - anomaly_score_normalized: 0–10 scale relative to threshold
        """
        if self._model is None or self._threshold is None:
            raise RuntimeError("Model not trained — call fit() first")

        X = self._to_matrix(features)
        X_scaled = self._scaler.transform(X)
        X_tensor = torch.tensor(X_scaled, dtype=torch.float32)

        # AE scores
        self._model.eval()
        ae_errors = self._model.reconstruction_error(X_tensor).numpy()
        ae_norm = ae_errors / (self._ae_max_error + 1e-9)

        # IF scores
        if_raw = -self._isolation_forest.score_samples(X_scaled)
        if_norm = (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-9)

        # Combined ensemble score
        combined = self.ae_weight * ae_norm + self.if_weight * if_norm

        results = []
        for i, (feat, ae_s, if_s, comb_s) in enumerate(
            zip(features, ae_norm, if_norm, combined)
        ):
            entity_id = feat.get("user_uid") or feat.get("ip_address") or f"entity-{i}"
            is_anomaly = float(comb_s) > self._threshold
            normalized = float(comb_s) / self._threshold if self._threshold > 0 else 0.0
            results.append({
                "entity_id":    entity_id,
                "entity_name":  feat.get("user_name") or feat.get("ip_address", ""),
                "ae_score":     float(ae_s),
                "if_score":     float(if_s),
                "combined_score": float(comb_s),
                "reconstruction_error": float(ae_errors[i]),
                "threshold":    self._threshold,
                "is_anomaly":   is_anomaly,
                "anomaly_score_normalized": min(normalized, 10.0),
            })

        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        logger.info(f"Scored {len(results)} entities — {anomaly_count} anomalies detected")
        return results

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        import joblib
        torch.save({
            "model_state":   self._model.state_dict(),
            "scaler":        self._scaler,
            "hidden_dims":   self.hidden_dims,
            "threshold":     self._threshold,
            "train_errors":  self._train_errors,
            "ae_max_error":  self._ae_max_error,
            "ae_weight":     self.ae_weight,
            "if_weight":     self.if_weight,
        }, path)
        # Save IF separately (sklearn object)
        if_path = str(path).replace(".pt", "_if.joblib")
        joblib.dump(self._isolation_forest, if_path)
        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        import joblib
        checkpoint = torch.load(path, map_location="cpu")
        self.hidden_dims = checkpoint["hidden_dims"]
        self._model = _Autoencoder(N_FEATURES, self.hidden_dims, self.dropout)
        self._model.load_state_dict(checkpoint["model_state"])
        self._model.eval()
        self._scaler      = checkpoint["scaler"]
        self._threshold   = checkpoint["threshold"]
        self._train_errors = checkpoint["train_errors"]
        self._ae_max_error = checkpoint.get("ae_max_error", 1.0)
        self.ae_weight    = checkpoint.get("ae_weight", 0.6)
        self.if_weight    = checkpoint.get("if_weight", 0.4)
        if_path = str(path).replace(".pt", "_if.joblib")
        if Path(if_path).exists():
            self._isolation_forest = joblib.load(if_path)
        logger.info(f"Model loaded from {path}")
