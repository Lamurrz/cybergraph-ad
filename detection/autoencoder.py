"""
detection/autoencoder.py
------------------------
Autoencoder-based behavioral anomaly detector.

Architecture
------------
Input  → Encoder (Linear → ReLU stack) → Bottleneck → Decoder → Reconstruction
Anomaly score = MSE reconstruction error on the input feature vector.

Users/IPs whose reconstruction error exceeds the threshold percentile
(default: 95th percentile of training errors) are flagged as anomalous.

This implements the anomaly detection layer from the dissertation's
multisensor graph fusion framework, applied to the behavioral feature
vectors extracted by FusionGraph.extract_user_features().

Training strategy
-----------------
Train only on normal behavior (status_id != 2, known IPs, business hours).
The autoencoder learns to reconstruct "normal" — anomalous events produce
high reconstruction error because the model hasn't seen those patterns.
"""

from __future__ import annotations

import logging
import numpy as np
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("cybergraph.detection")

FEATURE_COLS = [
    "total_events",
    "failure_rate",
    "unique_assets",
    "unique_ips",
    "external_ip_rate",
    "off_hours_rate",
    "avg_bytes_out",
    "max_bytes_out",
]


# ── Model definition ──────────────────────────────────────────────────────────

class _Autoencoder(nn.Module):
    def __init__(self, input_dim: int, hidden_dims: list[int]):
        super().__init__()

        # Encoder
        encoder_layers = []
        in_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers += [nn.Linear(in_dim, h_dim), nn.ReLU()]
            in_dim = h_dim
        self.encoder = nn.Sequential(*encoder_layers)

        # Decoder (mirror of encoder)
        decoder_layers = []
        for h_dim in reversed(hidden_dims[:-1]):
            decoder_layers += [nn.Linear(in_dim, h_dim), nn.ReLU()]
            in_dim = h_dim
        decoder_layers.append(nn.Linear(in_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            recon = self.forward(x)
            return torch.mean((x - recon) ** 2, dim=1)


# ── Detector ──────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Trains an autoencoder on normal behavioral feature vectors and
    scores new observations by reconstruction error.
    """

    def __init__(
        self,
        hidden_dims: list[int] = None,
        epochs: int = 50,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
        anomaly_threshold_percentile: float = 95.0,
    ):
        self.hidden_dims = hidden_dims or [64, 32, 16]
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = learning_rate
        self.threshold_percentile = anomaly_threshold_percentile

        self._model: _Autoencoder | None = None
        self._scaler = StandardScaler()
        self._threshold: float | None = None
        self._train_errors: np.ndarray | None = None

    # ── Feature preparation ───────────────────────────────────────────────────

    def _to_matrix(self, records: list[dict[str, Any]]) -> np.ndarray:
        """Convert feature dicts to a float matrix, handling None values."""
        rows = []
        for r in records:
            row = []
            for col in FEATURE_COLS:
                val = r.get(col)
                row.append(float(val) if val is not None else 0.0)
            rows.append(row)
        return np.array(rows, dtype=np.float32)

    # ── Training ──────────────────────────────────────────────────────────────

    def fit(self, features: list[dict[str, Any]]) -> dict[str, float]:
        """
        Train the autoencoder on behavioral feature vectors.

        Parameters
        ----------
        features : list of dicts from FusionGraph.extract_user_features()

        Returns
        -------
        Training summary dict with final loss and threshold value.
        """
        if len(features) < 10:
            raise ValueError(f"Need at least 10 samples to train, got {len(features)}")

        X = self._to_matrix(features)
        X_scaled = self._scaler.fit_transform(X)
        X_tensor = torch.tensor(X_scaled, dtype=torch.float32)

        input_dim = X_tensor.shape[1]
        self._model = _Autoencoder(input_dim, self.hidden_dims)
        optimizer = torch.optim.Adam(self._model.parameters(), lr=self.lr)
        criterion = nn.MSELoss()

        dataset = TensorDataset(X_tensor)
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        self._model.train()
        final_loss = 0.0
        for epoch in range(self.epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon = self._model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
            final_loss = epoch_loss / len(loader)
            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}/{self.epochs} — loss: {final_loss:.6f}")

        # Compute threshold from training reconstruction errors
        self._model.eval()
        self._train_errors = self._model.reconstruction_error(X_tensor).numpy()
        self._threshold = float(np.percentile(self._train_errors, self.threshold_percentile))

        logger.info(f"Training complete — loss: {final_loss:.6f}, threshold: {self._threshold:.6f}")
        return {
            "final_loss": final_loss,
            "threshold": self._threshold,
            "n_samples": len(features),
            "mean_error": float(np.mean(self._train_errors)),
            "p95_error": float(np.percentile(self._train_errors, 95)),
            "p99_error": float(np.percentile(self._train_errors, 99)),
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Score behavioral feature vectors.

        Returns a list of dicts with:
          - user_uid / ip_address: entity identifier
          - reconstruction_error: float anomaly score
          - is_anomaly: bool (error > threshold)
          - anomaly_score_normalized: 0-1 score relative to threshold
        """
        if self._model is None or self._threshold is None:
            raise RuntimeError("Model not trained — call fit() first")

        X = self._to_matrix(features)
        X_scaled = self._scaler.transform(X)
        X_tensor = torch.tensor(X_scaled, dtype=torch.float32)

        self._model.eval()
        errors = self._model.reconstruction_error(X_tensor).numpy()

        results = []
        for i, (feat, error) in enumerate(zip(features, errors)):
            entity_id = feat.get("user_uid") or feat.get("ip_address") or f"entity-{i}"
            normalized = float(error) / self._threshold if self._threshold > 0 else 0.0
            results.append({
                "entity_id": entity_id,
                "entity_name": feat.get("user_name") or feat.get("ip_address", ""),
                "reconstruction_error": float(error),
                "threshold": self._threshold,
                "is_anomaly": float(error) > self._threshold,
                "anomaly_score_normalized": min(normalized, 10.0),  # cap at 10x threshold
            })

        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        logger.info(f"Scored {len(results)} entities — {anomaly_count} anomalies detected")
        return results

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model_state": self._model.state_dict(),
            "scaler_mean": self._scaler.mean_,
            "scaler_scale": self._scaler.scale_,
            "hidden_dims": self.hidden_dims,
            "threshold": self._threshold,
            "train_errors": self._train_errors,
        }, path)
        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        checkpoint = torch.load(path, map_location="cpu")
        self.hidden_dims = checkpoint["hidden_dims"]
        input_dim = len(FEATURE_COLS)
        self._model = _Autoencoder(input_dim, self.hidden_dims)
        self._model.load_state_dict(checkpoint["model_state"])
        self._model.eval()
        self._scaler.mean_ = checkpoint["scaler_mean"]
        self._scaler.scale_ = checkpoint["scaler_scale"]
        self._threshold = checkpoint["threshold"]
        self._train_errors = checkpoint["train_errors"]
        logger.info(f"Model loaded from {path}")
