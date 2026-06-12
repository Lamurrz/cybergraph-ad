"""
output/finding_emitter.py
-------------------------
Emits OCSF Detection Finding (class_uid 2004) events when the anomaly
detector flags an entity. These events are ready for ingestion into a
downstream SIEM or the Meridian Risk Scoring API.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _uid(parts: list[str]) -> str:
    raw = "|".join(parts)
    return str(uuid.UUID(hashlib.sha256(raw.encode()).hexdigest()[:32]))


def _now_epoch_ms() -> int:
    return int(time.time() * 1000)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# OCSF severity mapping based on normalized anomaly score
def _severity(normalized_score: float) -> tuple[int, str]:
    if normalized_score >= 5.0:
        return 4, "High"
    elif normalized_score >= 3.0:
        return 3, "Medium"
    elif normalized_score >= 1.5:
        return 2, "Low"
    else:
        return 1, "Informational"


class FindingEmitter:
    """
    Converts anomaly detector results into OCSF Detection Finding events.
    """

    def __init__(self, output_dir: str = "data/findings"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def emit(self, scored_entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Convert scored entities into OCSF Detection Finding events.
        Only emits findings for entities flagged as anomalous.

        Returns list of OCSF Detection Finding dicts.
        """
        findings = []
        for entity in scored_entities:
            if not entity.get("is_anomaly"):
                continue

            severity_id, severity = _severity(entity["anomaly_score_normalized"])
            now = _now_epoch_ms()
            entity_id = entity.get("entity_id", "unknown")

            finding = {
                "ocsf_version": "1.3.0",
                "class_uid": 2004,
                "class_name": "Detection Finding",
                "category_uid": 2,
                "category_name": "Findings",
                "activity_id": 1,
                "activity_name": "Create",
                "time": now,
                "severity_id": severity_id,
                "severity": severity,
                "status_id": 1,
                "status": "New",
                "metadata": {
                    "uid": _uid(["cybergraph-ad", entity_id, str(now)]),
                    "product": {
                        "vendor_name": "CyberGraph-AD",
                        "name": "Behavioral Anomaly Detector",
                        "version": "0.1.0",
                    },
                    "processed_time": now,
                    "schema_url": "https://schema.ocsf.io",
                },
                "finding": {
                    "title": f"Behavioral anomaly detected: {entity.get('entity_name', entity_id)}",
                    "description": (
                        f"Entity {entity_id} produced reconstruction error "
                        f"{entity['reconstruction_error']:.4f} "
                        f"({entity['anomaly_score_normalized']:.1f}x threshold). "
                        f"Threshold: {entity['threshold']:.4f}."
                    ),
                    "remediation": {
                        "desc": "Investigate entity activity in the fusion graph. "
                                "Review authentication patterns, network connections, "
                                "and accessed assets for the flagged time window."
                    },
                    "type": "Behavioral Anomaly",
                    "uid": _uid(["finding", entity_id, str(now)]),
                },
                "analytic": {
                    "name": "Autoencoder Behavioral Baseline",
                    "type_id": 1,
                    "type": "Rule",
                    "desc": "Reconstruction error exceeds learned behavioral baseline",
                },
                "actor": {
                    "entity": {
                        "uid": entity_id,
                        "name": entity.get("entity_name", ""),
                        "type": "User",
                    }
                },
                "risk_score": min(int(entity["anomaly_score_normalized"] * 20), 100),
                "risk_level_id": severity_id,
                "risk_level": severity,
                "unmapped": {
                    "reconstruction_error": entity["reconstruction_error"],
                    "anomaly_score_normalized": entity["anomaly_score_normalized"],
                    "detector": "autoencoder",
                    "source": "cybergraph-ad",
                },
            }
            findings.append(finding)

        return findings

    def save(self, findings: list[dict[str, Any]], filename: str = None) -> str:
        """Save findings to a JSON file. Returns the output path."""
        if not filename:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"findings_{timestamp}.json"
        path = self._output_dir / filename
        with open(path, "w") as f:
            json.dump(findings, f, indent=2)
        return str(path)

    def emit_and_save(self, scored_entities: list[dict[str, Any]]) -> tuple[list[dict], str]:
        """Emit findings and save to disk. Returns (findings, output_path)."""
        findings = self.emit(scored_entities)
        if findings:
            path = self.save(findings)
            return findings, path
        return findings, ""
