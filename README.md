# CyberGraph-AD

Multisensor behavioral anomaly detection for AI/ML security infrastructure,
built on a Neo4j property graph fusion architecture.

## Dissertation lineage

This project implements the core framework from:

> Murray, L. (2019). *A Framework Towards Fusing Multisensory Cyber Security
> Data Utilizing Graph Databases.* Iowa State University.

The graph fusion approach represents each sensor stream (authentication logs,
network flows, configuration findings) as edge types in a unified property graph.
Entity resolution across streams is performed by matching on shared identifiers
(user UID, IP address, asset ID). Behavioral anomaly detection is applied to
feature vectors extracted from the graph via an autoencoder trained on normal
activity patterns.

## Portfolio context

| Project | Description |
|---------|-------------|
| [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) | Normalize raw vendor logs → OCSF |
| **CyberGraph-AD** | Detect behavioral anomalies via graph fusion (this project) |
| [Meridian + Risk API](https://github.com/Lamurrz/meridian-api) | Assess threat exposure via MITRE ATLAS/ATT&CK |
| AI CSF Profiler *(coming)* | Evaluate framework compliance via NIST CSF 2.0 |

The narrative: **normalize → detect → assess threat exposure → evaluate compliance.**

## Architecture

```
OCSF Events (simulated or from OCSF Transformer)
        │
        ▼
┌───────────────────────────────────────────┐
│  Neo4j Fusion Graph                        │
│  CGUser ──[AUTHENTICATED]──► CGAsset       │
│  CGIPAddress ──[CONNECTED_TO]──► CGAsset   │
│  CGUser ──[USED_IP]──► CGIPAddress         │
└───────────────────┬───────────────────────┘
                    │  Feature extraction
                    ▼
┌───────────────────────────────────────────┐
│  Behavioral Feature Vectors               │
│  (failure_rate, unique_assets,            │
│   off_hours_rate, bytes_out, ...)         │
└───────────────────┬───────────────────────┘
                    │  Autoencoder scoring
                    ▼
┌───────────────────────────────────────────┐
│  Anomaly Detection                         │
│  Reconstruction error > threshold         │
│  → flagged as anomalous                   │
└───────────────────┬───────────────────────┘
                    │
                    ▼
        OCSF Detection Finding (2004)
        → downstream SIEM / Meridian
```

## Benchmark results

Evaluated against UNSW-NB15 (50,000 samples, 14 features, 46.2% attack rate).
Autoencoder trained on normal traffic only — unsupervised baseline, no labeled training data.

| Metric | UNSW-NB15 | Notes |
|--------|-----------|-------|
| F1 | 0.436 | Solid unsupervised baseline |
| Precision | 0.372 | 37% of flagged entities are true attacks |
| Recall | 0.527 | Catches 53% of actual attacks |
| AUC-ROC | 0.653 | Above random (0.5) |
| False positive rate | 23.5% | Improvable via threshold tuning |
| Detection rate | 52.7% | Of true attacks detected |

Attack categories in dataset: Generic, Exploits, Fuzzers, DoS, Reconnaissance,
Analysis, Backdoor, Shellcode, Worms.

CICIDS 2018 benchmark results will be added once the dataset is downloaded.

## Anomaly types detected

| Type | Pattern |
|------|---------|
| Brute force | High-frequency auth failures from single IP |
| Credential stuffing | Auth failures across many users from single IP |
| Lateral movement | Single user accessing many assets in rapid succession |
| Data exfiltration | Abnormally large outbound transfers from sensitive assets |
| Privilege escalation | Low-clearance user accessing high-sensitivity assets |
| Off-hours access | Logins at unusual times from external IPs |

## Quick start

```bash
git clone https://github.com/Lamurrz/cybergraph-ad.git
cd cybergraph-ad

python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env         # edit with your Neo4j credentials

# Full pipeline: simulate → graph → train → detect → emit
python run.py --mode full
```

## Modes

```bash
python run.py --mode full        # complete pipeline
python run.py --mode ingest      # simulate events and load graph only
python run.py --mode detect      # train + score using existing graph
python run.py --mode benchmark   # evaluate against CICIDS 2018 + UNSW-NB15
python run.py --mode clear       # remove CyberGraph nodes from Neo4j
python run.py --mode full --clear  # clear then reload
```

## Benchmark datasets

**CICIDS 2018** — https://www.unb.ca/cic/datasets/ids-2018.html
→ Place CSV files in `data/cicids2018/`

**UNSW-NB15** — https://research.unsw.edu.au/projects/unsw-nb15-dataset
→ Place `UNSW_NB15_training-set.csv` in `data/unsw_nb15/`

## Feature vectors

| Feature | Description |
|---------|-------------|
| `total_events` | Total authentication events |
| `failure_rate` | Fraction of failed authentications |
| `unique_assets` | Number of distinct assets accessed |
| `unique_ips` | Number of distinct IPs used |
| `external_ip_rate` | Fraction of events from external IPs |
| `off_hours_rate` | Fraction of events outside 08:00–18:00 |
| `avg_bytes_out` | Average outbound bytes in network events |
| `max_bytes_out` | Maximum outbound bytes in a single event |

## Output

Detection findings are emitted as OCSF Detection Finding (class_uid 2004) events,
saved to `data/findings/`. These can be ingested by any OCSF-compatible SIEM
or fed into the Meridian Risk Scoring API for cross-referencing with threat actor TTPs.

## Project structure

```
cybergraph-ad/
├── simulator/
│   └── ocsf_simulator.py    # OCSF event generator with labeled anomalies
├── graph/
│   └── fusion_graph.py      # Neo4j graph loader + feature extractor
├── detection/
│   └── autoencoder.py       # Autoencoder anomaly detector
├── benchmark/
│   └── evaluator.py         # CICIDS 2018 + UNSW-NB15 evaluation
├── output/
│   └── finding_emitter.py   # OCSF Detection Finding emitter
├── data/                    # Generated data (gitignored)
├── config.py
├── run.py
└── requirements.txt
```

## Related projects

- [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) — normalization layer
- [Meridian Risk API](https://github.com/Lamurrz/meridian-api) — threat context layer
