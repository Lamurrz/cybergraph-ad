"""
simulator/ocsf_simulator.py
---------------------------
Generates synthetic OCSF 1.3.0 events for:
  - Authentication (class_uid 3002)
  - Network Activity (class_uid 4001)
  - Configuration Finding (class_uid 5019)

Normal behavior patterns:
  - Business hours logins (08:00-18:00) from known IPs
  - Regular API calls within rate limits
  - Stable configuration states

Anomaly patterns (labeled for benchmark evaluation):
  - Brute force: high-frequency auth failures from single IP
  - Credential stuffing: auth failures across many users from single IP
  - Lateral movement: single user authenticating to many assets rapidly
  - Data exfiltration: abnormally large outbound network transfers
  - Privilege escalation: access to resources outside normal scope
  - Off-hours access: logins at unusual times from new locations
"""

from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


# ── Anomaly types ─────────────────────────────────────────────────────────────

class AnomalyType(str, Enum):
    NONE             = "none"
    BRUTE_FORCE      = "brute_force"
    CRED_STUFFING    = "credential_stuffing"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL       = "data_exfiltration"
    PRIV_ESCALATION  = "privilege_escalation"
    OFF_HOURS_ACCESS = "off_hours_access"


# ── Synthetic entity pools ────────────────────────────────────────────────────

USERS = [
    {"uid": f"user-{i:03d}", "name": f"user{i:03d}@corp.local",
     "dept": dept, "clearance": clr}
    for i, (dept, clr) in enumerate([
        ("engineering", "standard"), ("engineering", "standard"),
        ("engineering", "elevated"), ("finance", "standard"),
        ("finance", "elevated"), ("hr", "standard"),
        ("security", "elevated"), ("security", "admin"),
        ("executive", "admin"), ("devops", "admin"),
        ("ml-team", "elevated"), ("ml-team", "standard"),
        ("data-science", "elevated"), ("data-science", "standard"),
        ("legal", "standard"),
    ])
]

ASSETS = [
    {"asset_id": "api-fraud-inference",   "name": "Fraud scoring API",         "type": "InferenceAPI",  "sensitivity": "high"},
    {"asset_id": "api-support-chat",      "name": "Customer support chat API", "type": "InferenceAPI",  "sensitivity": "medium"},
    {"asset_id": "model-fraud-xgb-v3",   "name": "Fraud XGBoost v3",          "type": "AIModel",       "sensitivity": "high"},
    {"asset_id": "model-support-llm",    "name": "Support LLM",               "type": "AIModel",       "sensitivity": "medium"},
    {"asset_id": "pipeline-fraud-001",   "name": "Fraud detection pipeline",  "type": "MLPipeline",    "sensitivity": "high"},
    {"asset_id": "pipeline-nlp-001",     "name": "Customer support pipeline", "type": "MLPipeline",    "sensitivity": "medium"},
    {"asset_id": "data-fraud-training",  "name": "Fraud training dataset",    "type": "TrainingData",  "sensitivity": "critical"},
    {"asset_id": "mlflow-registry",      "name": "MLflow model registry",     "type": "ModelRegistry", "sensitivity": "high"},
    {"asset_id": "jupyter-hub",          "name": "JupyterHub",                "type": "InferenceAPI",  "sensitivity": "medium"},
    {"asset_id": "data-lake-raw",        "name": "Raw data lake",             "type": "TrainingData",  "sensitivity": "critical"},
]

KNOWN_IPS = [f"10.0.{subnet}.{host}" for subnet in range(1, 6) for host in range(10, 50)]
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 50)]
SERVICES = ["okta", "azure-ad", "internal-sso", "vpn-gateway", "api-gateway"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _now_epoch_ms() -> int:
    return int(time.time() * 1000)


def _uid(parts: list[str]) -> str:
    raw = "|".join(parts)
    return str(uuid.UUID(hashlib.sha256(raw.encode()).hexdigest()[:32]))


def _business_hours_ts(rng: random.Random, base_date: datetime) -> datetime:
    hour = rng.randint(8, 17)
    minute = rng.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute,
                             second=rng.randint(0, 59), microsecond=0)


def _off_hours_ts(rng: random.Random, base_date: datetime) -> datetime:
    hour = rng.choice(list(range(0, 7)) + list(range(22, 24)))
    return base_date.replace(hour=hour, minute=rng.randint(0, 59),
                             second=rng.randint(0, 59), microsecond=0)


# ── OCSF envelope builder ─────────────────────────────────────────────────────

def _base_envelope(
    class_uid: int,
    category_uid: int,
    activity_id: int,
    activity_name: str,
    time_ms: int,
    status_id: int,
    severity_id: int,
    vendor: str,
    event_id: str,
    anomaly_type: AnomalyType = AnomalyType.NONE,
) -> dict[str, Any]:
    return {
        "ocsf_version": "1.3.0",
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "time": time_ms,
        "status_id": status_id,
        "severity_id": severity_id,
        "metadata": {
            "uid": _uid([vendor, event_id]),
            "product": {"vendor_name": vendor},
            "processed_time": _now_epoch_ms(),
            "schema_url": "https://schema.ocsf.io",
        },
        # Ground-truth label for benchmark evaluation
        "_label": {
            "is_anomaly": anomaly_type != AnomalyType.NONE,
            "anomaly_type": anomaly_type.value,
        },
    }


# ── Event generators ──────────────────────────────────────────────────────────

class OCSFSimulator:
    """
    Generates labeled OCSF events for normal and anomalous behavior.
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._base_date = datetime(2024, 6, 1, tzinfo=timezone.utc)

    def _random_date(self, days: int = 30) -> datetime:
        delta = timedelta(
            days=self._rng.randint(0, days - 1),
            hours=self._rng.randint(0, 23),
        )
        return self._base_date + delta

    # ── Authentication (3002) ─────────────────────────────────────────────────

    def auth_success(self, user: dict, ip: str, asset: dict,
                     ts: datetime, anomaly: AnomalyType = AnomalyType.NONE) -> dict:
        ev = _base_envelope(
            class_uid=3002, category_uid=3,
            activity_id=1, activity_name="Logon",
            time_ms=_epoch_ms(ts),
            status_id=1, severity_id=1,
            vendor="internal-sso",
            event_id=f"{user['uid']}-{_epoch_ms(ts)}",
            anomaly_type=anomaly,
        )
        ev.update({
            "user": {"uid": user["uid"], "name": user["name"]},
            "src_endpoint": {"ip": ip},
            "dst_endpoint": {"name": asset["name"], "uid": asset["asset_id"]},
            "service": {"name": self._rng.choice(SERVICES)},
        })
        return ev

    def auth_failure(self, user: dict, ip: str, asset: dict,
                     ts: datetime, anomaly: AnomalyType = AnomalyType.NONE) -> dict:
        ev = _base_envelope(
            class_uid=3002, category_uid=3,
            activity_id=1, activity_name="Logon",
            time_ms=_epoch_ms(ts),
            status_id=2, severity_id=2,
            vendor="internal-sso",
            event_id=f"fail-{user['uid']}-{_epoch_ms(ts)}",
            anomaly_type=anomaly,
        )
        ev.update({
            "user": {"uid": user["uid"], "name": user["name"]},
            "src_endpoint": {"ip": ip},
            "dst_endpoint": {"name": asset["name"], "uid": asset["asset_id"]},
        })
        return ev

    # ── Network Activity (4001) ───────────────────────────────────────────────

    def network_activity(self, src_ip: str, dst_asset: dict,
                         bytes_out: int, ts: datetime,
                         anomaly: AnomalyType = AnomalyType.NONE) -> dict:
        ev = _base_envelope(
            class_uid=4001, category_uid=4,
            activity_id=1, activity_name="Open",
            time_ms=_epoch_ms(ts),
            status_id=1, severity_id=1,
            vendor="network-monitor",
            event_id=f"net-{src_ip}-{_epoch_ms(ts)}",
            anomaly_type=anomaly,
        )
        ev.update({
            "src_endpoint": {"ip": src_ip},
            "dst_endpoint": {"name": dst_asset["name"], "uid": dst_asset["asset_id"]},
            "traffic": {"bytes_out": bytes_out, "bytes_in": self._rng.randint(100, 5000)},
            "connection_info": {"protocol_name": "HTTPS", "direction": "outbound"},
        })
        return ev

    # ── Normal behavior ───────────────────────────────────────────────────────

    def generate_normal(self, n: int) -> list[dict]:
        events = []
        for _ in range(n):
            user = self._rng.choice(USERS)
            asset = self._rng.choice(ASSETS)
            ip = self._rng.choice(KNOWN_IPS)
            ts = _business_hours_ts(self._rng, self._random_date())

            # 90% success, 10% legitimate failure
            if self._rng.random() < 0.9:
                events.append(self.auth_success(user, ip, asset, ts))
            else:
                events.append(self.auth_failure(user, ip, asset, ts))

            # Network activity following auth
            if self._rng.random() < 0.7:
                bytes_out = self._rng.randint(1_000, 500_000)
                events.append(self.network_activity(ip, asset, bytes_out, ts))

        return events

    # ── Anomaly generators ────────────────────────────────────────────────────

    def generate_brute_force(self, n: int = 50) -> list[dict]:
        """Single IP hammering one account with rapid auth failures."""
        events = []
        attacker_ip = self._rng.choice(EXTERNAL_IPS)
        target_user = self._rng.choice(USERS)
        target_asset = self._rng.choice(ASSETS)
        base_ts = self._random_date()
        for i in range(n):
            ts = base_ts + timedelta(seconds=i * 2)
            events.append(self.auth_failure(
                target_user, attacker_ip, target_asset, ts,
                anomaly=AnomalyType.BRUTE_FORCE,
            ))
        return events

    def generate_credential_stuffing(self, n: int = 40) -> list[dict]:
        """Single IP trying many different user accounts."""
        events = []
        attacker_ip = self._rng.choice(EXTERNAL_IPS)
        target_asset = self._rng.choice(ASSETS)
        base_ts = self._random_date()
        for i in range(n):
            user = self._rng.choice(USERS)
            ts = base_ts + timedelta(seconds=i * 5)
            events.append(self.auth_failure(
                user, attacker_ip, target_asset, ts,
                anomaly=AnomalyType.CRED_STUFFING,
            ))
        return events

    def generate_lateral_movement(self, n: int = 30) -> list[dict]:
        """Single user authenticating to many assets in rapid succession."""
        events = []
        user = self._rng.choice(USERS)
        ip = self._rng.choice(KNOWN_IPS)
        base_ts = self._random_date()
        shuffled_assets = self._rng.sample(ASSETS, min(n, len(ASSETS)))
        for i, asset in enumerate(shuffled_assets):
            ts = base_ts + timedelta(seconds=i * 10)
            events.append(self.auth_success(
                user, ip, asset, ts,
                anomaly=AnomalyType.LATERAL_MOVEMENT,
            ))
        return events

    def generate_data_exfiltration(self, n: int = 20) -> list[dict]:
        """Abnormally large outbound transfers from sensitive assets."""
        events = []
        sensitive = [a for a in ASSETS if a["sensitivity"] in ("high", "critical")]
        ip = self._rng.choice(KNOWN_IPS)
        base_ts = self._random_date()
        for i in range(n):
            asset = self._rng.choice(sensitive)
            ts = base_ts + timedelta(minutes=i * 3)
            bytes_out = self._rng.randint(50_000_000, 500_000_000)  # 50MB–500MB
            events.append(self.network_activity(
                ip, asset, bytes_out, ts,
                anomaly=AnomalyType.DATA_EXFIL,
            ))
        return events

    def generate_off_hours_access(self, n: int = 20) -> list[dict]:
        """Logins at unusual times from external IPs."""
        events = []
        for _ in range(n):
            user = self._rng.choice(USERS)
            ip = self._rng.choice(EXTERNAL_IPS)
            asset = self._rng.choice(ASSETS)
            ts = _off_hours_ts(self._rng, self._random_date())
            events.append(self.auth_success(
                user, ip, asset, ts,
                anomaly=AnomalyType.OFF_HOURS_ACCESS,
            ))
        return events

    def generate_privilege_escalation(self, n: int = 15) -> list[dict]:
        """Standard-clearance user accessing high-sensitivity assets."""
        events = []
        low_clearance = [u for u in USERS if u["clearance"] == "standard"]
        high_sensitivity = [a for a in ASSETS if a["sensitivity"] in ("high", "critical")]
        ip = self._rng.choice(KNOWN_IPS)
        base_ts = self._random_date()
        for i in range(n):
            user = self._rng.choice(low_clearance)
            asset = self._rng.choice(high_sensitivity)
            ts = base_ts + timedelta(minutes=i * 5)
            events.append(self.auth_success(
                user, ip, asset, ts,
                anomaly=AnomalyType.PRIV_ESCALATION,
            ))
        return events

    # ── Main generation entry point ───────────────────────────────────────────

    def generate_dataset(
        self,
        n_normal: int = 5000,
        n_anomaly: int = 500,
        output_path: str | None = None,
    ) -> list[dict]:
        """
        Generate a labeled dataset of normal + anomalous OCSF events.
        Anomaly events are distributed across all anomaly types.
        """
        events = self.generate_normal(n_normal)

        per_type = n_anomaly // 6
        events += self.generate_brute_force(per_type)
        events += self.generate_credential_stuffing(per_type)
        events += self.generate_lateral_movement(per_type)
        events += self.generate_data_exfiltration(per_type)
        events += self.generate_off_hours_access(per_type)
        events += self.generate_privilege_escalation(per_type)

        # Shuffle so anomalies aren't all at the end
        self._rng.shuffle(events)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(events, f, indent=2)

        return events
