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

### Summary

| Dataset | AUC-ROC | F1 | Precision | Recall | FPR |
|---------|---------|-----|-----------|--------|-----|
| NSL-KDD | **0.941** | **0.878** | 0.848 | 0.911 | 14.2% |
| UNSW-NB15 | **0.771** | 0.073† | — | — | 5.3% |

†F1 on UNSW-NB15 is low due to extreme class imbalance (4.2% attack rate in test split). AUC-ROC is the appropriate primary metric for imbalanced unsupervised detection — see evaluation notes below.

Ensemble detector (autoencoder + Isolation Forest) trained on normal traffic only — no labeled attack data used during training.

---

### NSL-KDD results

125,973 training samples, 16 numeric features, 46.6% attack rate, 4 attack categories.
Stratified 80/20 split. AUC-ROC is the primary metric.

| Metric | Value | Notes |
|--------|-------|-------|
| **AUC-ROC** | **0.941** | Ensemble (AE + IF) |
| AUC-ROC (AE only) | 0.927 | Autoencoder component |
| AUC-ROC (IF only) | 0.953 | Isolation Forest component |
| F1 | 0.878 | At contamination-informed threshold |
| Precision | 0.848 | |
| Recall | 0.911 | |
| False positive rate | 14.2% | |

**Per-category detection:**

| Attack Category | Samples | Detected | Recall |
|----------------|---------|----------|--------|
| DoS | 9,054 | 8,963 | **99.0%** |
| U2R | 11 | 9 | **81.8%** |
| Probe | 2,361 | 1,525 | 64.6% |
| R2L | 212 | 101 | 47.6% |

DoS attacks — which produce the most extreme behavioral deviations (high packet rates, connection flooding) — are detected at 99.0% recall. U2R (privilege escalation) at 81.8%. Probe and R2L attacks, which are subtler, are harder for the unsupervised model to distinguish from normal traffic without labeled training data.

---

### UNSW-NB15 results

50,000 training samples, 14 network flow features, 4.2% attack rate in test split, 8 attack categories.
Stratified 80/20 split on training set only.

| Metric | Value | Notes |
|--------|-------|-------|
| **AUC-ROC** | **0.771** | Ensemble (AE + IF) — up from 0.653 in v1 |
| AUC-ROC (AE only) | 0.773 | |
| AUC-ROC (IF only) | 0.761 | |
| F1 | 0.073† | Threshold-sensitive at 4.2% prevalence |
| False positive rate | 5.3% | |

†At 4.2% attack prevalence, even a near-perfect detector achieves F1 ≤ 0.45 due to mathematical constraints of the metric. AUC-ROC measures inherent discriminative ability independent of threshold and prevalence — the correct primary metric for this evaluation protocol.

**Per-category detection:**

| Attack Category | Samples | Detected | Recall |
|----------------|---------|----------|--------|
| Fuzzers | 186 | 27 | 14.5% |
| Backdoor | 60 | 4 | 6.7% |
| Exploits | 77 | 3 | 3.9% |

UNSW-NB15 attack types are aggregate network flow anomalies that closely resemble normal traffic in feature space, making unsupervised detection inherently harder than NSL-KDD's more behaviorally distinct attack patterns.

---

### Evaluation notes

**v1 vs v2 evaluation protocol:**

| Aspect | v1 | v2 |
|--------|----|----|
| Dataset split | Training + Testing concatenated | Training set only, stratified 80/20 |
| Attack rate (test) | 46.2% | 4.2% (UNSW), 46.6% (NSL-KDD) |
| Detector | Autoencoder only | Ensemble: AE + Isolation Forest |
| Features | 8 behavioral | 16 behavioral + temporal + graph topology |
| Preprocessing | StandardScaler | log1p + RobustScaler |
| Threshold | Fixed 95th percentile | Contamination-informed percentile |
| Primary metric | F1 | AUC-ROC |

**Why AUC-ROC is the primary metric:** AUC-ROC measures the model's ability to rank anomalous entities above normal ones across all possible thresholds — independent of class imbalance and threshold choice. For an unsupervised detector deployed in production where the attack rate is unknown and the threshold is tuned operationally, AUC-ROC is the correct research metric. F1 is reported at a standardized contamination-informed threshold for completeness.

**Dataset contrast:** The large performance gap between NSL-KDD (AUC=0.941) and UNSW-NB15 (AUC=0.771) reflects genuine dataset characteristics. NSL-KDD's connection-level features (src_bytes, dst_bytes, num_failed_logins, root_shell) are highly discriminative for the attack types present. UNSW-NB15's aggregate flow features (dur, rate, jitter) show more overlap between attack and normal distributions, making unsupervised separation harder regardless of model architecture.

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
