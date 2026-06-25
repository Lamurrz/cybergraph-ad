"""
pipeline.py
-----------
Wires OCSF Transformer output directly into CyberGraph-AD's FusionGraph,
implementing the normalize → detect pipeline connection.

Two modes
---------
File mode (default)
  Reads raw vendor event files from a watch directory, transforms them to
  OCSF, ingests into the fusion graph, runs anomaly detection, and
  optionally forwards Detection Findings to the Meridian Bridge.

Live mode (--live, future)
  Polls vendor APIs on a schedule, normalizes, and ingests continuously.
  Stub endpoints are included for each supported vendor.

Usage
-----
  # Process a single file
  python pipeline.py --file data/entra_signin.json --vendor entra

  # Process all files in a directory
  python pipeline.py --dir data/raw_events

  # Auto-detect vendor from file contents
  python pipeline.py --file data/unknown_events.json

  # Process and forward findings to Meridian Bridge
  python pipeline.py --dir data/raw_events --bridge

  # Watch directory for new files (polling)
  python pipeline.py --watch data/raw_events --interval 30

  # Dry-run: transform only, no graph ingestion
  python pipeline.py --file data/entra_signin.json --vendor entra --dry-run

  # List supported vendors
  python pipeline.py --list-vendors

Supported vendors (file mode)
------------------------------
  entra    Microsoft Entra ID sign-in logs
  okta     Okta System Log events
  wiz      Wiz security findings
  pan      Palo Alto PAN-OS auth logs
  windows  Windows Security Event Log

Roadmap vendors (live mode stubs)
----------------------------------
  entra-live    Microsoft Graph API polling (Entra audit + signin)
  okta-live     Okta System Log API polling
  sentinel      Microsoft Sentinel workspace query
  defender      Microsoft Defender for Endpoint streaming API
  crowdstrike   CrowdStrike Falcon streaming API
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pipeline")

# ── Constants ─────────────────────────────────────────────────────────────────

# OCSF class UIDs handled by FusionGraph.ingest_events()
FUSION_GRAPH_CLASSES = {3002, 4001}

# OCSF class UIDs produced by the transformer but not yet handled by FusionGraph
UNHANDLED_CLASSES = {
    1007: "Process Activity",
    5001: "Account Change",
    5019: "Configuration Finding",
    2004: "Detection Finding",
}

# Vendor file extensions for auto-detection from filename
VENDOR_FILE_HINTS = {
    "entra": ["entra", "azure", "signin", "aad"],
    "okta": ["okta", "okta_system"],
    "wiz": ["wiz", "finding"],
    "pan": ["pan", "panos", "panorama"],
    "windows": ["windows", "winsec", "security_event", "evtx"],
}


# ── Pipeline ──────────────────────────────────────────────────────────────────

class Pipeline:
    """
    Normalize → Detect pipeline connecting OCSF Transformer to CyberGraph-AD.
    """

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "meridian123",
        meridian_url: str = "http://127.0.0.1:8000",
        dry_run: bool = False,
        run_detector: bool = True,
        forward_to_bridge: bool = False,
        findings_output_dir: str = "data/findings",
    ):
        self._neo4j_uri = neo4j_uri
        self._neo4j_user = neo4j_user
        self._neo4j_password = neo4j_password
        self._meridian_url = meridian_url
        self._dry_run = dry_run
        self._run_detector = run_detector
        self._forward_to_bridge = forward_to_bridge
        self._findings_dir = Path(findings_output_dir)
        self._findings_dir.mkdir(parents=True, exist_ok=True)

        self._graph = None
        self._detector = None

        if not dry_run:
            self._init_graph()

    def _init_graph(self) -> None:
        """Initialize FusionGraph connection."""
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from graph.fusion_graph import FusionGraph
            self._graph = FusionGraph(
                uri=self._neo4j_uri,
                user=self._neo4j_user,
                password=self._neo4j_password,
            )
            self._graph.ensure_schema()
            logger.info("FusionGraph connected")
        except Exception as exc:
            logger.error(f"FusionGraph connection failed: {exc}")
            logger.error("Is Neo4j running? Check bolt://localhost:7687")
            sys.exit(1)

    def _init_detector(self) -> None:
        """Lazy-initialize anomaly detector."""
        if self._detector is not None:
            return
        try:
            from detection.autoencoder import AnomalyDetector
            self._detector = AnomalyDetector()
            logger.info("AnomalyDetector initialized")
        except Exception as exc:
            logger.warning(f"AnomalyDetector unavailable: {exc}")
            self._run_detector = False

    # ── Main entry points ─────────────────────────────────────────────────────

    def process_file(
        self,
        path: str | Path,
        vendor: str | None = None,
    ) -> dict[str, Any]:
        """
        Process a single raw event file through the full pipeline.

        Parameters
        ----------
        path   : path to raw vendor event JSON file
        vendor : vendor name (auto-detected from file content if None)

        Returns
        -------
        Pipeline result dict with counts and any findings generated.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {path}")

        logger.info(f"Processing: {path.name}")

        # Load raw events
        raw_events = self._load_json(path)
        if not raw_events:
            logger.warning(f"No events in {path.name}")
            return {"status": "empty", "file": str(path)}

        # Hint vendor from filename if not specified
        if not vendor:
            vendor = self._hint_vendor(path.name)

        return self._run_pipeline(raw_events, vendor, source=path.name)

    def process_directory(
        self,
        directory: str | Path,
        vendor: str | None = None,
        pattern: str = "*.json",
    ) -> dict[str, Any]:
        """
        Process all matching files in a directory.

        Returns aggregated pipeline result across all files.
        """
        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        files = sorted(directory.glob(pattern))
        if not files:
            logger.warning(f"No {pattern} files in {directory}")
            return {"status": "empty", "directory": str(directory)}

        logger.info(f"Processing {len(files)} files from {directory}")

        totals = {
            "files_processed": 0,
            "events_loaded": 0,
            "events_transformed": 0,
            "events_failed": 0,
            "graph_edges": {},
            "findings_generated": 0,
            "files": [],
        }

        for file in files:
            try:
                file_vendor = vendor or self._hint_vendor(file.name)
                result = self.process_file(file, vendor=file_vendor)
                totals["files_processed"] += 1
                totals["events_loaded"] += result.get("events_loaded", 0)
                totals["events_transformed"] += result.get("events_transformed", 0)
                totals["events_failed"] += result.get("events_failed", 0)
                totals["findings_generated"] += result.get("findings_generated", 0)
                for k, v in result.get("graph_edges", {}).items():
                    totals["graph_edges"][k] = totals["graph_edges"].get(k, 0) + v
                totals["files"].append({
                    "file": file.name,
                    "status": result.get("status"),
                    "transformed": result.get("events_transformed", 0),
                })
            except Exception as exc:
                logger.error(f"Failed to process {file.name}: {exc}")
                totals["files"].append({"file": file.name, "status": "error", "error": str(exc)})

        totals["status"] = "success"
        return totals

    def watch_directory(
        self,
        directory: str | Path,
        interval: int = 30,
        vendor: str | None = None,
        pattern: str = "*.json",
    ) -> None:
        """
        Poll a directory for new files and process them as they arrive.
        Tracks processed files to avoid reprocessing.

        Runs until interrupted with Ctrl+C.
        """
        directory = Path(directory)
        processed = set()

        logger.info(f"Watching {directory} every {interval}s — Ctrl+C to stop")

        try:
            while True:
                files = set(directory.glob(pattern))
                new_files = files - processed

                if new_files:
                    logger.info(f"Found {len(new_files)} new file(s)")
                    for file in sorted(new_files):
                        try:
                            file_vendor = vendor or self._hint_vendor(file.name)
                            result = self.process_file(file, vendor=file_vendor)
                            self._print_result(result)
                            processed.add(file)
                        except Exception as exc:
                            logger.error(f"Failed: {file.name}: {exc}")
                            processed.add(file)  # don't retry failures
                else:
                    logger.debug(f"No new files — next check in {interval}s")

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Watch stopped")

    # ── Core pipeline ─────────────────────────────────────────────────────────

    def _run_pipeline(
        self,
        raw_events: list[dict],
        vendor: str | None,
        source: str = "unknown",
    ) -> dict[str, Any]:
        """
        Execute the full normalize → ingest → detect pipeline.

        Steps:
          1. Transform raw events to OCSF via OCSF Transformer
          2. Filter to classes handled by FusionGraph (3002, 4001)
          3. Ingest into Neo4j fusion graph
          4. Run anomaly detector on updated graph features
          5. Emit OCSF Detection Findings
          6. Optionally forward to Meridian Bridge
        """
        result: dict[str, Any] = {
            "source": source,
            "vendor": vendor or "auto-detect",
            "events_loaded": len(raw_events),
            "status": "success",
        }

        # Step 1: Transform
        ocsf_events, failures = self._transform(raw_events, vendor)
        result["events_transformed"] = len(ocsf_events)
        result["events_failed"] = len(failures)

        if failures:
            logger.warning(f"{len(failures)} events failed transformation in {source}")

        if not ocsf_events:
            result["status"] = "no_output"
            return result

        # Log class distribution
        class_counts: dict[int, int] = {}
        for e in ocsf_events:
            uid = e.get("class_uid", 0)
            class_counts[uid] = class_counts.get(uid, 0) + 1

        for uid, count in class_counts.items():
            label = UNHANDLED_CLASSES.get(uid, f"class_{uid}")
            handled = "→ FusionGraph" if uid in FUSION_GRAPH_CLASSES else f"→ skipped ({label})"
            logger.info(f"  class_uid {uid}: {count} events {handled}")

        result["class_distribution"] = class_counts

        # Step 1b: Promote unmapped fields to top level if top-level fields are null
        # The Entra transformer puts real data in unmapped when input is already OCSF
        ocsf_events = [self._promote_unmapped(e) for e in ocsf_events]

        # Step 2: Filter to classes FusionGraph handles
        ingestible = [e for e in ocsf_events if e.get("class_uid") in FUSION_GRAPH_CLASSES]
        skipped = len(ocsf_events) - len(ingestible)
        result["events_skipped"] = skipped

        if not ingestible:
            logger.warning(f"No ingestible events (class 3002/4001) in {source}")
            result["status"] = "no_ingestible_events"
            return result

        # Step 3: Ingest into FusionGraph
        if self._dry_run:
            logger.info(f"[DRY-RUN] Would ingest {len(ingestible)} events into FusionGraph")
            result["graph_edges"] = {}
        else:
            graph_counts = self._graph.ingest_events(ingestible)
            result["graph_edges"] = graph_counts
            logger.info(f"Ingested {len(ingestible)} events → {graph_counts}")

        # Step 4: Run anomaly detector
        findings = []
        if self._run_detector and not self._dry_run:
            findings = self._run_anomaly_detection()
            result["findings_generated"] = len(findings)

            if findings:
                findings_path = self._save_findings(findings, source)
                result["findings_path"] = str(findings_path)
                logger.info(f"Generated {len(findings)} Detection Findings → {findings_path}")

        # Step 5: Forward to Meridian Bridge
        if self._forward_to_bridge and findings and not self._dry_run:
            bridge_result = self._forward_findings(findings)
            result["bridge_result"] = bridge_result

        return result

    def _promote_unmapped(self, event: dict) -> dict:
        """
        Promote fields from unmapped to top level when top-level fields are null.

        The Entra transformer can produce events where the actual data ends up
        in the unmapped block (when the input is already OCSF-formatted).
        This ensures FusionGraph always sees populated top-level fields.
        """
        unmapped = event.get("unmapped", {})
        if not isinstance(unmapped, dict):
            return event

        promoted = dict(event)

        # Fields to promote if top-level value is None or missing
        promote_fields = ["user", "src_endpoint", "dst_endpoint", "service",
                          "device", "status_id", "severity_id", "status"]

        for field in promote_fields:
            top_val = promoted.get(field)
            unmapped_val = unmapped.get(field)

            # Promote if top-level is None/empty dict with all None values
            if unmapped_val and (
                top_val is None or
                (isinstance(top_val, dict) and all(v is None for v in top_val.values()))
            ):
                promoted[field] = unmapped_val

        # Also promote dst_endpoint from service if missing
        if not promoted.get("dst_endpoint") and promoted.get("service", {}).get("uid"):
            svc = promoted["service"]
            promoted["dst_endpoint"] = {
                "uid": svc.get("uid"),
                "name": svc.get("name"),
            }

        return promoted

    # ── Transform ─────────────────────────────────────────────────────────────

    def _transform(
        self,
        raw_events: list[dict],
        vendor: str | None,
    ) -> tuple[list[dict], list[dict]]:
        """Run OCSF Transformer on raw events."""
        try:
            # Import from the ocsf-transformer project
            transformer_path = Path(__file__).parent.parent / "ocsf-transformer"
            if transformer_path.exists():
                sys.path.insert(0, str(transformer_path))

            from ocsf_transformer import ingest
            return ingest(raw_events, vendor)

        except ImportError:
            logger.error(
                "ocsf_transformer not found. "
                "Expected at ../ocsf-transformer/ocsf_transformer.py"
            )
            logger.error("Set PYTHONPATH or copy ocsf_transformer.py to this directory.")
            sys.exit(1)

    # ── Anomaly detection ─────────────────────────────────────────────────────

    def _run_anomaly_detection(self) -> list[dict]:
        """
        Extract features from the fusion graph and run anomaly detection.
        Returns OCSF Detection Finding dicts for anomalous entities.

        Requires a trained model at models/anomaly_detector.pt.
        If no model exists, logs a warning and returns empty list.
        """
        if not self._run_detector:
            return []

        self._init_detector()
        if not self._detector:
            return []

        try:
            features = self._graph.extract_user_features()
            if not features:
                logger.info("No user features available for detection")
                return []

            logger.info(f"Running detector on {len(features)} user feature vectors")

            # Load trained model if available
            model_path = Path(__file__).parent / "data" / "models" / "autoencoder.pt"
            if not model_path.exists():
                logger.warning(
                    f"No trained model at {model_path} — "
                    "run the benchmark/training pipeline first to generate a model"
                )
                return []

            self._detector.load(str(model_path))
            scores = self._detector.score(features)

            # Convert scores to OCSF Detection Findings
            findings = []
            for score in scores:
                if score.get("is_anomaly"):
                    finding = self._score_to_finding(score)
                    findings.append(finding)

            logger.info(f"Generated {len(findings)} Detection Findings from {len(scores)} scored entities")
            return findings

        except Exception as exc:
            logger.warning(f"Anomaly detection failed: {exc}")
            return []

    def _score_to_finding(self, score: dict) -> dict:
        """Convert an AnomalyDetector score result to an OCSF Detection Finding."""
        import uuid
        from datetime import datetime, timezone

        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        entity_id = score.get("entity_id", "unknown")
        entity_name = score.get("entity_name", "")
        recon_error = score.get("reconstruction_error", 0.0)
        threshold = score.get("threshold", 1.0)
        normalized = score.get("anomaly_score_normalized", 0.0)

        return {
            "ocsf_version": "1.3.0",
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "time": now_ms,
            "severity_id": 3 if normalized > 5.0 else 2 if normalized > 2.0 else 1,
            "severity": "High" if normalized > 5.0 else "Medium" if normalized > 2.0 else "Informational",
            "status": "New",
            "status_id": 1,
            "risk_score": min(int(normalized * 10), 100),
            "risk_level": "High" if normalized > 5.0 else "Medium" if normalized > 2.0 else "Informational",
            "risk_level_id": 3 if normalized > 5.0 else 2 if normalized > 2.0 else 1,
            "actor": {
                "entity": {
                    "uid": entity_id,
                    "name": entity_name,
                    "type": "User",
                }
            },
            "finding": {
                "uid": str(uuid.uuid4()),
                "title": f"Behavioral anomaly detected: {entity_name or entity_id}",
                "description": (
                    f"Entity {entity_id} produced reconstruction error "
                    f"{recon_error:.4f} ({recon_error/threshold:.1f}x threshold). "
                    f"Threshold: {threshold:.4f}."
                ),
                "type": "Behavioral Anomaly",
                "remediation": {
                    "desc": (
                        "Investigate entity activity in the fusion graph. "
                        "Review authentication patterns, network connections, "
                        "and accessed assets for the flagged time window."
                    )
                },
            },
            "analytic": {
                "name": "Autoencoder Behavioral Baseline",
                "desc": "Reconstruction error exceeds learned behavioral baseline",
                "type": "Rule",
                "type_id": 1,
            },
            "metadata": {
                "uid": str(uuid.uuid4()),
                "version": "1.3.0",
                "product": {
                    "name": "Behavioral Anomaly Detector",
                    "vendor_name": "CyberGraph-AD",
                    "version": "0.1.0",
                },
                "schema_url": "https://schema.ocsf.io",
                "processed_time": now_ms,
            },
            "unmapped": {
                "reconstruction_error": recon_error,
                "anomaly_score_normalized": normalized,
                "detector": "autoencoder",
                "source": "cybergraph-ad",
            },
        }

    # ── Findings ──────────────────────────────────────────────────────────────

    def _save_findings(self, findings: list[dict], source: str) -> Path:
        """Save Detection Findings to JSON file."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_source = Path(source).stem.replace(" ", "_")[:30]
        filename = f"findings_{safe_source}_{ts}.json"
        path = self._findings_dir / filename

        with open(path, "w") as f:
            json.dump(findings, f, indent=2)

        return path

    def _forward_findings(self, findings: list[dict]) -> dict:
        """Forward Detection Findings to Meridian Bridge."""
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent / "meridian-api"))
            from meridian_bridge import MeridianBridge
            import asyncio

            bridge = MeridianBridge(meridian_url=self._meridian_url)
            result = asyncio.run(bridge.run(findings=findings))
            logger.info(
                f"Bridge: {len(result.get('assets_updated', []))} assets updated, "
                f"{result.get('summary', {}).get('findings_enriched_with_ttp', 0)} enriched with TTP"
            )
            return result
        except Exception as exc:
            logger.warning(f"Bridge forwarding failed: {exc}")
            return {"status": "error", "message": str(exc)}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_json(self, path: Path) -> list[dict]:
        """Load JSON file — handles both list and single-object files."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        raise ValueError(f"Unexpected JSON structure in {path.name}")

    def _hint_vendor(self, filename: str) -> str | None:
        """Guess vendor from filename keywords."""
        lower = filename.lower()
        for vendor, hints in VENDOR_FILE_HINTS.items():
            if any(hint in lower for hint in hints):
                logger.debug(f"Vendor hint from filename: {vendor}")
                return vendor
        return None

    def _print_result(self, result: dict) -> None:
        """Print a single-file pipeline result."""
        print(
            f"  {result.get('source', '?'):35} "
            f"loaded={result.get('events_loaded', 0):4}  "
            f"transformed={result.get('events_transformed', 0):4}  "
            f"ingested={sum(result.get('graph_edges', {}).values()):4}  "
            f"findings={result.get('findings_generated', 0):3}  "
            f"status={result.get('status', '?')}"
        )

    def close(self) -> None:
        if self._graph:
            self._graph.close()


# ── Live mode stubs ───────────────────────────────────────────────────────────

class LiveVendorPoller:
    """
    Stub base class for live vendor API polling.
    Implement poll() in each subclass to fetch new events.

    Roadmap vendors:
      EntraLivePoller      — Microsoft Graph API (signin + audit logs)
      OktaLivePoller       — Okta System Log API
      SentinelPoller       — Microsoft Sentinel workspace query
      DefenderPoller       — Microsoft Defender for Endpoint streaming
      CrowdStrikePoller    — CrowdStrike Falcon streaming API
    """

    VENDOR_NAME: str = ""

    def __init__(self, credentials: dict):
        self._creds = credentials
        self._cursor: str | None = None  # pagination / continuation token

    def poll(self) -> list[dict]:
        """
        Fetch new events since last poll.
        Returns list of raw vendor event dicts.
        Must be implemented by each vendor subclass.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.poll() not yet implemented. "
            f"This is a live mode stub — see roadmap in pipeline.py."
        )

    def vendor_name(self) -> str:
        return self.VENDOR_NAME


class EntraLivePoller(LiveVendorPoller):
    """
    Microsoft Entra ID live poller via Microsoft Graph API.

    Endpoints:
      GET /v1.0/auditLogs/signIns?$filter=createdDateTime ge {cursor}
      GET /v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge {cursor}

    Auth: OAuth2 client credentials (tenant_id, client_id, client_secret)
    Rate limit: 2000 requests / 10 min per app
    """
    VENDOR_NAME = "entra"

    def poll(self) -> list[dict]:
        raise NotImplementedError("EntraLivePoller not yet implemented")


class OktaLivePoller(LiveVendorPoller):
    """
    Okta System Log live poller.

    Endpoint: GET /api/v1/logs?since={cursor}&limit=1000
    Auth: API token (header: Authorization: SSWS {token})
    Rate limit: 600 requests / min
    """
    VENDOR_NAME = "okta"

    def poll(self) -> list[dict]:
        raise NotImplementedError("OktaLivePoller not yet implemented")


class SentinelPoller(LiveVendorPoller):
    """
    Microsoft Sentinel workspace query poller.

    Uses Azure Monitor Query API to run KQL queries against
    Log Analytics workspace and retrieve new events.
    Auth: Azure AD service principal
    """
    VENDOR_NAME = "sentinel"

    def poll(self) -> list[dict]:
        raise NotImplementedError("SentinelPoller not yet implemented")


class DefenderPoller(LiveVendorPoller):
    """
    Microsoft Defender for Endpoint streaming API poller.

    Streams DeviceEvents, AlertEvents, and NetworkConnectionEvents
    via Azure Event Hub integration.
    Auth: Azure AD service principal + Event Hub connection string
    """
    VENDOR_NAME = "defender"

    def poll(self) -> list[dict]:
        raise NotImplementedError("DefenderPoller not yet implemented")


class CrowdStrikePoller(LiveVendorPoller):
    """
    CrowdStrike Falcon streaming API poller.

    Endpoint: GET /sensors/entities/datafeed/v2
    Auth: OAuth2 client credentials
    """
    VENDOR_NAME = "crowdstrike"

    def poll(self) -> list[dict]:
        raise NotImplementedError("CrowdStrikePoller not yet implemented")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Meridian Pipeline — OCSF Transformer → CyberGraph-AD"
    )

    # Input sources
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Process a single raw event JSON file")
    source.add_argument("--dir", help="Process all JSON files in a directory")
    source.add_argument("--watch", help="Watch directory for new files (polling)")
    source.add_argument("--list-vendors", action="store_true",
                        help="List supported vendors and exit")

    # Options
    parser.add_argument("--vendor",
                        choices=["entra", "okta", "wiz", "pan", "windows"],
                        help="Force vendor parser (default: auto-detect)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Watch interval in seconds (default: 30)")
    parser.add_argument("--pattern", default="*.json",
                        help="File glob pattern for --dir and --watch (default: *.json)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Transform only — no graph ingestion")
    parser.add_argument("--no-detector", action="store_true",
                        help="Skip anomaly detection after ingestion")
    parser.add_argument("--bridge", action="store_true",
                        help="Forward Detection Findings to Meridian Bridge")
    parser.add_argument("--findings-dir", default="data/findings",
                        help="Directory for Detection Finding output (default: data/findings)")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687",
                        help="Neo4j URI (default: bolt://localhost:7687)")
    parser.add_argument("--neo4j-password", default="meridian123",
                        help="Neo4j password (default: meridian123)")
    parser.add_argument("--meridian-url", default="http://127.0.0.1:8000",
                        help="Meridian Risk API URL (default: http://127.0.0.1:8000)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_vendors:
        print("\nSupported vendors (file mode):")
        print("  entra    Microsoft Entra ID sign-in logs")
        print("  okta     Okta System Log events")
        print("  wiz      Wiz security findings")
        print("  pan      Palo Alto PAN-OS auth logs")
        print("  windows  Windows Security Event Log")
        print("\nRoadmap vendors (live mode stubs):")
        print("  entra-live    Microsoft Graph API polling")
        print("  okta-live     Okta System Log API polling")
        print("  sentinel      Microsoft Sentinel workspace query")
        print("  defender      Microsoft Defender for Endpoint streaming")
        print("  crowdstrike   CrowdStrike Falcon streaming API")
        return

    pipeline = Pipeline(
        neo4j_uri=args.neo4j_uri,
        neo4j_user="neo4j",
        neo4j_password=args.neo4j_password,
        meridian_url=args.meridian_url,
        dry_run=args.dry_run,
        run_detector=not args.no_detector,
        forward_to_bridge=args.bridge,
        findings_output_dir=args.findings_dir,
    )

    try:
        if args.file:
            result = pipeline.process_file(args.file, vendor=args.vendor)
            pipeline._print_result(result)
            print(f"\n  Graph edges:  {result.get('graph_edges', {})}")
            print(f"  Findings:     {result.get('findings_generated', 0)}")
            if result.get("findings_path"):
                print(f"  Findings →    {result['findings_path']}")

        elif args.dir:
            result = pipeline.process_directory(
                args.dir, vendor=args.vendor, pattern=args.pattern
            )
            print(f"\n{'='*55}")
            print(f"  Pipeline — {result.get('status', '').upper()}")
            print(f"{'='*55}")
            print(f"  Files processed:     {result.get('files_processed', 0)}")
            print(f"  Events loaded:       {result.get('events_loaded', 0)}")
            print(f"  Events transformed:  {result.get('events_transformed', 0)}")
            print(f"  Events failed:       {result.get('events_failed', 0)}")
            print(f"  Graph edges:         {result.get('graph_edges', {})}")
            print(f"  Findings generated:  {result.get('findings_generated', 0)}")
            print(f"{'='*55}\n")

        elif args.watch:
            pipeline.watch_directory(
                args.watch,
                interval=args.interval,
                vendor=args.vendor,
                pattern=args.pattern,
            )

    finally:
        pipeline.close()


if __name__ == "__main__":
    main()
