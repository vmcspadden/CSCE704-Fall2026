"""Compare single models and model pools on one labelled evaluation set.

Evaluates already-trained model bundles; it does not generate adversarial
malware. Features are extracted once and reused for every system.

Every --model is scored on its own, then (with two or more) the pool of all
of them with each strategy in src/mtd.py. Add --adversarial-samples /
--adversarial-labels to also report how many evasive variants each system
still catches.

Example:
    python -m src.experiments.compare_defenses \
        --samples data/eval --labels data/eval_labels.csv \
        --model models/detector --model models/adversarial_lightgbm \
        --adversarial-samples data/adv --adversarial-labels data/adv_labels.csv
"""

from __future__ import annotations

import argparse
import os

import numpy as np

from src.dataset import build_dataset
from src.metrics import compute_metrics
from src.model import ModelWrapper, vectors_to_matrix
from src.mtd import STRATEGIES, ModelPool


def _xy(samples):
    X = vectors_to_matrix([s.vector for s in samples])
    y = np.asarray([s.label for s in samples], dtype=int)
    return X, y


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", required=True, help="Evaluation PE files (benign and malware)")
    ap.add_argument("--labels", required=True, help="CSV with filename,label for --samples")
    ap.add_argument("--model", action="append", required=True, help="Model folder; repeat for several")
    ap.add_argument("--adversarial-samples", default=None, help="Evasive malware variants (optional)")
    ap.add_argument("--adversarial-labels", default=None)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    samples, report = build_dataset(args.samples, args.labels)
    if not samples:
        raise SystemExit("No usable evaluation samples found.")
    print(report.summary())
    X, y = _xy(samples)

    X_adv = None
    if args.adversarial_samples:
        adv, adv_report = build_dataset(args.adversarial_samples, args.adversarial_labels)
        print(adv_report.summary())
        if adv:
            X_adv, _ = _xy(adv)

    systems = []
    for model_dir in args.model:
        systems.append((os.path.basename(model_dir.rstrip("/")), ModelWrapper.load(model_dir)))
    if len(args.model) > 1:
        for strategy in STRATEGIES:
            systems.append((f"pool:{strategy}", ModelPool(args.model, strategy=strategy, seed=args.seed)))

    print("\nDefense comparison (goal: FPR <= 1%, TPR >= 95%)")
    print("=" * 78)
    for name, model in systems:
        m = compute_metrics(y, model.predict_proba(X), model.threshold)
        line = (f"{name:28s} TPR={m['recall_tpr']:.4f} FPR={m['fpr']:.4f} "
                f"F1={m['f1']:.4f}")
        if X_adv is not None:
            caught = float(np.mean(model.predict_proba(X_adv) >= model.threshold))
            line += f" adversarial-caught={caught:.4f}"
        print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
