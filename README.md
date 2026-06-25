# CyberGraph-AD

Multisensor behavioral anomaly detection for AI/ML security infrastructure,
built on a Neo4j property graph fusion architecture. Connects directly to the
OCSF Transformer via `pipeline.py` for live vendor log ingestion, and forwards
Detection Findings to the Meridian Risk API via the Meridian Bridge.

## Dissertation lineage

This project implements the core framework from:

> Murray, L. (2019). *A Framework Towards Fusing Multisensory Cyber Security
> Data Utilizing Graph Databases.* Iowa State University.

The graph fusion approach represents each sensor stream (authentication logs,
network flows, configuration findings) as edge types in a unified property graph.
Entity resolution across streams is performed by matching on shared identifiers
(user UID, IP address, asset ID). Behavioral anomaly detection is applied to
feature vectors extracted from the graph via an ensemble detector trained on
normal activity patterns.

## Portfolio context

| Project | Description |
|---------|-------------|
| [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) | Normalize raw vendor logs â†’ OCSF |
| **CyberGraph-AD** | Detect behavioral anomalies via graph fusion (this project) |
| [Meridian KG + Risk API](https://github.com/Lamurrz/meridian-api) | Assess threat exposure via MITRE ATLAS/ATT&CK |
| [AI CSF Profiler](https://github.com/Lamurrz/ai-csf-profiler) | Evaluate framework compliance via NIST CSF 2.0 |
| [Meridian Emulation](https://github.com/Lamurrz/meridian-emulation) | Validate detection coverage via ATT&CK emulation |

The narrative: **normalize â†’ detect â†’ assess â†’ comply â†’ validate.**

## Architecture

```
Vendor logs (Entra, Okta, PAN-OS, Windows, Wiz)
        â”‚
        â–¼  pipeline.py (OCSF Transformer â†’ FusionGraph)
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Neo4j Fusion Graph                        â”‚
â”‚  CGUser â”€â”€[AUTHENTICATED]â”€â”€â–º CGAsset       â”‚
â”‚  CGIPAddress â”€â”€[CONNECTED_TO]â”€â”€â–º CGAsset   â”‚
â”‚  CGUser â”€â”€[USED_IP]â”€â”€â–º CGIPAddress         â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚  Feature extraction (16 features)
                    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Behavioral Feature Vectors               â”‚
â”‚  Core: failure_rate, unique_assets,       â”‚
â”‚        off_hours_rate, bytes_out, ...     â”‚
â”‚  v2:   auth_velocity, burst_rate,         â”‚
â”‚        lateral_movement_score, ...        â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚  Ensemble scoring
                    â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Ensemble Anomaly Detector                 â”‚
â”‚  Autoencoder (reconstruction error)       â”‚
â”‚  + Isolation Forest (path length score)   â”‚
â”‚  â†’ weighted combination â†’ threshold       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                    â”‚  OCSF Detection Findings (class_uid 2004)
                    â–¼
        Meridian Bridge â†’ Risk score adjustment
                        â†’ ATLAS TTP enrichment
```

## pipeline.py â€” Live vendor ingestion

`pipeline.py` connects the OCSF Transformer directly to the fusion graph,
enabling end-to-end processing from raw vendor logs to Detection Findings
in a single command:

```bash
# Process a single vendor file
python pipeline.py --file path/to/entra_signin.json --vendor entra

# Process all files in a directory
python pipeline.py --dir data/raw_events

# Process and forward findings to Meridian Bridge
python pipeline.py --dir data/raw_events --bridge

# Watch directory for new files (polling)
python pipeline.py --watch data/raw_events --interval 30
```

### Supported vendors

| Vendor | OCSF Class | Edge type in graph |
|--------|-----------|-------------------|
| Microsoft Entra ID | Authentication (3002) | AUTHENTICATED |
| Okta | Authentication (3002) | AUTHENTICATED |
| Palo Alto PAN-OS | Network Activity (4001) | CONNECTED_TO |
| Windows Security Event Log | Authentication (3002) | AUTHENTICATED |
| Wiz | Configuration Finding (5019) | skipped (compliance layer) |

### Pipeline modes

```
--dry-run       Transform only â€” no graph ingestion
--no-detector   Skip anomaly detection after ingestion
--bridge        Forward Detection Findings to Meridian Bridge
--watch DIR     Poll directory for new files
```

## Quick start

**Prerequisites:** Python 3.11+, Neo4j 5.x, PyTorch

```bash
git clone https://github.com/Lamurrz/cybergraph-ad.git
cd cybergraph-ad

python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env         # set NEO4J_URI and NEO4J_PASSWORD

# Full pipeline: simulate â†’ train â†’ detect â†’ emit findings
python run.py --mode full

# Or ingest real vendor logs via pipeline.py
python pipeline.py --file path/to/entra_signin.json --vendor entra --bridge
```

## Run modes (run.py)

| Mode | Description |
|------|-------------|
| `full` | Simulate events â†’ load graph â†’ train â†’ score â†’ emit findings |
| `ingest` | Simulate and load events into graph only |
| `detect` | Train/load model and score existing graph data |
| `benchmark` | Run evaluation against NSL-KDD and UNSW-NB15 datasets |
| `clear` | Clear all CyberGraph nodes (leaves Meridian data intact) |

## Benchmark results

Evaluated on two standard IDS datasets using AUC-ROC as the primary metric
(correct for unsupervised anomaly detection on imbalanced data):

| Dataset | AUC-ROC | F1 | Attack rate | Notes |
|---------|---------|-----|------------|-------|
| NSL-KDD | **0.941** | 0.878 | 46.6% | Competitive with supervised baselines |
| UNSW-NB15 | **0.771** | â€” | 4.2% | 20% AUC improvement over v1 |

## Feature vectors (16 features)

**Core behavioral (v1):**
`total_events`, `failure_rate`, `unique_assets`, `unique_ips`,
`external_ip_rate`, `off_hours_rate`, `avg_bytes_out`, `max_bytes_out`

**Temporal (v2):**
`auth_velocity`, `time_variance`, `session_duration_hours`, `burst_rate`

**Graph topology (v2):**
`asset_sensitivity_score`, `lateral_movement_score`, `ip_reuse_rate`, `sequential_asset_ratio`

## Ensemble detector

```
combined_score = 0.6 Ã— autoencoder_score + 0.4 Ã— isolation_forest_score
```

- **Autoencoder** â€” reconstruction error on 16-feature behavioral vectors
- **Isolation Forest** â€” path length anomaly score (ensemble complement)
- **Threshold** â€” contamination-informed, set at `(1 - attack_rate Ã— 1.3) Ã— 100th` percentile
- **Preprocessing** â€” log1p + RobustScaler (handles outliers in network traffic features)

## Detection output

OCSF Detection Finding (class_uid 2004) per anomalous entity:

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "severity_id": 2,
  "actor": {"entity": {"uid": "user-009", "name": "user009@corp.local"}},
  "finding": {
    "title": "Behavioral anomaly detected: user009@corp.local",
    "description": "Reconstruction error 2.75 (1.4x threshold)"
  },
  "unmapped": {
    "reconstruction_error": 2.7506,
    "anomaly_score_normalized": 1.41,
    "detector": "autoencoder"
  }
}
```

## Graph schema

CG-prefixed labels avoid collisions with Meridian threat framework nodes
in the shared Neo4j instance:

| Label | Properties |
|-------|-----------|
| `CGUser` | uid, name, last_seen |
| `CGAsset` | asset_id, name, sensitivity |
| `CGIPAddress` | ip, is_external, first_seen, last_seen |
| `AUTHENTICATED` edge | time, status_id, severity_id, src_ip, is_anomaly |
| `CONNECTED_TO` edge | time, bytes_out, bytes_in, protocol, is_anomaly |
| `USED_IP` edge | first_seen, last_seen, event_count |

## Production deployment notes

**Neo4j TLS:** For production deployments, enable encrypted bolt:
```
# In neo4j.conf:
server.bolt.tls_level=OPTIONAL
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.bolt.base_directory=certificates/bolt
```
Update the connection URI to `neo4j+s://` or `neo4j+ssc://` (self-signed).
For local development, unencrypted bolt on localhost is acceptable.

## Project structure

```
cybergraph-ad/
â”œâ”€â”€ graph/
â”‚   â”œâ”€â”€ fusion_graph.py        # Neo4j graph schema + event ingestion
â”‚   â””â”€â”€ feature_extraction.py  # 16-feature Cypher query + derived features
â”œâ”€â”€ detection/
â”‚   â””â”€â”€ autoencoder.py         # Ensemble AE + IF detector
â”œâ”€â”€ benchmark/
â”‚   â””â”€â”€ evaluator.py           # NSL-KDD + UNSW-NB15 benchmark
â”œâ”€â”€ simulator/
â”‚   â””â”€â”€ ocsf_simulator.py      # Synthetic OCSF event generator
â”œâ”€â”€ output/
â”‚   â””â”€â”€ finding_emitter.py     # OCSF Detection Finding emitter
â”œâ”€â”€ pipeline.py                # OCSF Transformer â†’ FusionGraph â†’ Bridge
â”œâ”€â”€ run.py                     # Full pipeline entry point
â””â”€â”€ config.py
```

