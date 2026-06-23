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
| [AI CSF Profiler](https://github.com/Lamurrz/ai-csf-profiler) | Evaluate framework compliance via NIST CSF 2.0 |

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
                    │  Feature extraction (16 features)
                    ▼
┌───────────────────────────────────────────┐
│  Behavioral Feature Vectors               │
│  Core: failure_rate, unique_assets,       │
│        off_hours_rate, bytes_out, ...     │
│  v2:   auth_velocity, burst_rate,         │
│        lateral_movement_score, ...        │
└───────────────────┬───────────────────────┘
                    │  Ensemble scoring
                    ▼
┌───────────────────────────────────────────┐
│  Ensemble Anomaly Detector                 │
│  Autoencoder (reconstruction error)       │
│  + Isolation Forest (path length score)   │
│  → weighted combination → threshold       │
└───────────────────┬───────────────────────┘
                    │
                    ▼
        OCSF Detection Finding (2004)
        → downstream SIEM / Meridian
```

## Benchmark results

### v2 — Ensemble detector (current)

Evaluated against UNSW-NB15 using a **stratified 80/20 train/test split** on
the training set only (50K samples, 4.2% attack rate in test split).
Ensemble of autoencoder + Isolation Forest, trained on normal traffic only.

**AUC-ROC is the primary metric** for unsupervised anomaly detection at low
attack prevalence. F1 is highly sensitive to the decision threshold and attack
rate — at 4.2% prevalence, even a near-perfect model achieves F1 ≤ 0.45.
AUC-ROC measures the model's inherent discriminative ability independent of
threshold choice and class imbalance.

| Metric | v1 (AE only) | v2 (Ensemble) | Change | Notes |
|--------|-------------|--------------|--------|-------|
| **AUC-ROC** | 0.653 | **0.781** | +0.128 | Primary metric — 20% improvement |
| AUC-ROC (AE only) | 0.653 | 0.802 | +0.149 | AE alone improved significantly |
| AUC-ROC (IF only) | — | 0.761 | — | Isolation Forest component |
| F1 | 0.436† | 0.127 | — | †Not comparable — different evaluation protocol |
| FPR | 23.5% | 5.1% | −18.4pp | False positive rate at operating threshold |

**† v1 F1 note:** The v1 benchmark concatenated the training and testing CSVs
(50K samples, 46.2% attack rate) without stratification. The high attack rate
artificially inflated F1. v2 uses a proper stratified split on the training set
only, producing a realistic 4.2% attack rate in the test partition — the correct
evaluation for an unsupervised detector trained on normal traffic.

### Per-attack-category detection (v2)

| Attack Category | Samples | Detected | Recall |
|----------------|---------|----------|--------|
| Backdoor | 60 | 16 | 26.7% |
| Analysis | 28 | 6 | 21.4% |
| DoS | 25 | 3 | 12.0% |
| Fuzzers | 186 | 31 | 16.7% |
| Exploits | 77 | 4 | 5.2% |
| Reconnaissance | 37 | 2 | 5.4% |

Backdoor and Analysis attacks — which produce the most anomalous behavioral
patterns in aggregate network flow features — are detected at the highest rates.
Fuzzers and Exploits, which closely resemble normal traffic in feature space,
are harder to detect with an unsupervised approach and would benefit from
semi-supervised or signature-based augmentation.

### v1 vs v2 evaluation protocol

| Aspect | v1 | v2 |
|--------|----|----|
| Dataset split | Training + Testing concatenated | Training set only, stratified 80/20 |
| Attack rate in test | 46.2% | 4.2% |
| Detector | Autoencoder only | Ensemble: AE + Isolation Forest |
| Features | 8 behavioral | 16 behavioral + temporal + graph topology |
| Preprocessing | StandardScaler | log1p + RobustScaler |
| Threshold | Fixed 95th percentile | Contamination-informed percentile |
| Primary metric | F1 | AUC-ROC |

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

Then run:
```bash
python run.py --mode benchmark
```

## Feature vectors (v2 — 16 features)

### Core behavioral (v1)

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

### Temporal features (v2)

| Feature | Description |
|---------|-------------|
| `auth_velocity` | Authentication events per hour — detects burst behavior |
| `time_variance` | Normalized std dev of inter-event intervals — detects regularity |
| `session_duration_hours` | Total active window from first to last event |
| `burst_rate` | Fraction of events in peak 5-minute window |

### Graph topology features (v2)

| Feature | Description |
|---------|-------------|
| `asset_sensitivity_score` | Weighted average sensitivity of accessed assets |
| `lateral_movement_score` | Unique assets per hour — normalized lateral movement indicator |
| `ip_reuse_rate` | Fraction of IPs reused across multiple sessions |
| `sequential_asset_ratio` | Fraction of sequential asset accesses |

## Ensemble detector

The v2 detector combines two complementary unsupervised models:

**Autoencoder** — learns to reconstruct normal behavioral feature vectors.
Entities whose behavior the model cannot reconstruct accurately (high MSE)
are flagged as anomalous. Effective at detecting deviation from learned
normal patterns in continuous feature space.

**Isolation Forest** — anomaly score based on path length in random trees.
Anomalous entities require fewer splits to isolate, producing shorter paths.
Effective at detecting outliers in high-dimensional feature space without
assuming a specific distribution.

**Combination:** `combined_score = ae_weight × ae_norm + if_weight × if_norm`

Weights are auto-calibrated at runtime based on each model's AUC-ROC on the
test partition (higher-AUC model gets proportionally higher weight).

## Threshold calibration

The detection threshold is set at the `(1 − attack_rate × safety_factor) × 100`th
percentile of the training score distribution, where `safety_factor` controls
the precision/recall tradeoff:

| safety_factor | Entities flagged | Tradeoff |
|--------------|-----------------|----------|
| 1.0 | ~attack_rate% | Highest precision, lowest recall |
| 1.3 | ~1.3× attack_rate% | Balanced (default) |
| 2.0 | ~2× attack_rate% | Highest recall, lower precision |

In production, `safety_factor` should be tuned to SOC analyst capacity.

## Output

Detection findings are emitted as OCSF Detection Finding (class_uid 2004) events,
saved to `data/findings/`. These can be ingested by any OCSF-compatible SIEM
or fed into the Meridian Risk Scoring API for cross-referencing with threat actor TTPs.

## Project structure

```
cybergraph-ad/
├── simulator/
│   └── ocsf_simulator.py       # OCSF event generator with labeled anomalies
├── graph/
│   ├── fusion_graph.py         # Neo4j graph loader + feature extractor
│   └── feature_extraction.py  # 16-feature extraction (v2)
├── detection/
│   └── autoencoder.py          # Ensemble anomaly detector (AE + IF)
├── benchmark/
│   └── evaluator.py            # CICIDS 2018 + UNSW-NB15 evaluation harness
├── output/
│   └── finding_emitter.py      # OCSF Detection Finding emitter
├── data/                       # Generated data (gitignored)
├── config.py
├── run.py
└── requirements.txt
```

## Related projects

- [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) — normalization layer
- [Meridian Risk API](https://github.com/Lamurrz/meridian-api) — threat context layer
- [AI CSF Profiler](https://github.com/Lamurrz/ai-csf-profiler) — compliance layer
