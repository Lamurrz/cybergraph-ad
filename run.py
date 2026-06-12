"""
run.py
------
CyberGraph-AD entry point.

Usage
-----
# Full pipeline: simulate → load graph → train → score → emit findings
python run.py --mode full

# Just simulate and load events into the graph
python run.py --mode ingest

# Train and score using existing graph data
python run.py --mode detect

# Run benchmark evaluation (requires dataset downloads)
python run.py --mode benchmark

# Clear the fusion graph and start fresh
python run.py --mode clear
"""

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cybergraph")


def mode_full(args):
    from config import settings
    from simulator.ocsf_simulator import OCSFSimulator
    from graph.fusion_graph import FusionGraph
    from detection.autoencoder import AnomalyDetector
    from output.finding_emitter import FindingEmitter

    logger.info("=== CyberGraph-AD: full pipeline ===")

    # 1. Simulate events
    logger.info(f"Simulating {settings.sim_normal_events} normal + "
                f"{settings.sim_anomaly_events} anomaly events...")
    sim = OCSFSimulator(seed=settings.sim_seed)
    events = sim.generate_dataset(
        n_normal=settings.sim_normal_events,
        n_anomaly=settings.sim_anomaly_events,
        output_path="data/simulated_events.json",
    )
    logger.info(f"Generated {len(events)} events")

    # 2. Load into fusion graph
    logger.info("Loading events into Neo4j fusion graph...")
    graph = FusionGraph()
    graph.ensure_schema()
    if args.clear:
        graph.clear()
    ingest_counts = graph.ingest_events(events)
    logger.info(f"Graph loaded: {ingest_counts}")

    # 3. Extract features
    logger.info("Extracting behavioral features from graph...")
    user_features = graph.extract_user_features()
    logger.info(f"Extracted features for {len(user_features)} users")

    if len(user_features) < 10:
        logger.error("Too few user features to train — check graph data")
        graph.close()
        return

    # 4. Train autoencoder
    logger.info("Training autoencoder...")
    detector = AnomalyDetector(
        hidden_dims=settings.ae_hidden_dims,
        epochs=settings.ae_epochs,
        batch_size=settings.ae_batch_size,
        learning_rate=settings.ae_learning_rate,
        anomaly_threshold_percentile=settings.ae_anomaly_threshold * 100,
    )
    train_summary = detector.fit(user_features)
    logger.info(f"Training complete: {train_summary}")
    detector.save("data/models/autoencoder.pt")

    # 5. Score entities
    logger.info("Scoring behavioral features...")
    scored = detector.score(user_features)
    anomalies = [s for s in scored if s["is_anomaly"]]
    logger.info(f"Detected {len(anomalies)} anomalous entities out of {len(scored)}")

    # 6. Get ground truth and evaluate
    ground_truth = graph.get_anomaly_ground_truth()
    if ground_truth:
        y_true = [ground_truth.get(s["entity_id"], False) for s in scored]
        y_pred = [s["is_anomaly"] for s in scored]
        tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
        fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        logger.info(f"Evaluation — Precision: {precision:.3f}, "
                    f"Recall: {recall:.3f}, F1: {f1:.3f}")

    # 7. Emit findings
    emitter = FindingEmitter(output_dir=settings.output_dir)
    findings, path = emitter.emit_and_save(scored)
    logger.info(f"Emitted {len(findings)} Detection Finding events → {path}")

    graph.close()

    # Summary
    logger.info("=== Pipeline complete ===")
    logger.info(f"  Events simulated:  {len(events)}")
    logger.info(f"  Users profiled:    {len(user_features)}")
    logger.info(f"  Anomalies flagged: {len(anomalies)}")
    logger.info(f"  Findings emitted:  {len(findings)}")
    if path:
        logger.info(f"  Output:            {path}")


def mode_ingest(args):
    from config import settings
    from simulator.ocsf_simulator import OCSFSimulator
    from graph.fusion_graph import FusionGraph

    sim = OCSFSimulator(seed=settings.sim_seed)
    events = sim.generate_dataset(
        n_normal=settings.sim_normal_events,
        n_anomaly=settings.sim_anomaly_events,
    )
    graph = FusionGraph()
    graph.ensure_schema()
    if args.clear:
        graph.clear()
    counts = graph.ingest_events(events)
    graph.close()
    logger.info(f"Ingest complete: {counts}")


def mode_detect(args):
    from config import settings
    from graph.fusion_graph import FusionGraph
    from detection.autoencoder import AnomalyDetector
    from output.finding_emitter import FindingEmitter

    graph = FusionGraph()
    user_features = graph.extract_user_features()
    graph.close()

    if not user_features:
        logger.error("No user features found — run --mode ingest first")
        return

    model_path = "data/models/autoencoder.pt"
    detector = AnomalyDetector()
    if Path(model_path).exists():
        detector.load(model_path)
    else:
        logger.info("No saved model found — training fresh...")
        detector = AnomalyDetector(
            hidden_dims=settings.ae_hidden_dims,
            epochs=settings.ae_epochs,
        )
        detector.fit(user_features)
        detector.save(model_path)

    scored = detector.score(user_features)
    emitter = FindingEmitter(output_dir=settings.output_dir)
    findings, path = emitter.emit_and_save(scored)
    logger.info(f"Findings: {len(findings)} → {path}")


def mode_benchmark(args):
    from benchmark.evaluator import BenchmarkEvaluator
    evaluator = BenchmarkEvaluator()
    results = evaluator.run()
    print(json.dumps(results, indent=2))


def mode_clear(args):
    from graph.fusion_graph import FusionGraph
    graph = FusionGraph()
    graph.clear()
    graph.close()
    logger.info("Fusion graph cleared")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGraph-AD — Behavioral Anomaly Detector")
    parser.add_argument("--mode", default="full",
                        choices=["full", "ingest", "detect", "benchmark", "clear"])
    parser.add_argument("--clear", action="store_true",
                        help="Clear existing graph data before ingesting")
    parser.add_argument("--uri",      default=None, help="Neo4j URI override")
    parser.add_argument("--user",     default=None, help="Neo4j username override")
    parser.add_argument("--password", default=None, help="Neo4j password override")

    args = parser.parse_args()

    modes = {
        "full":      mode_full,
        "ingest":    mode_ingest,
        "detect":    mode_detect,
        "benchmark": mode_benchmark,
        "clear":     mode_clear,
    }
    modes[args.mode](args)
