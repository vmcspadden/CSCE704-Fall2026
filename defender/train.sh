#!/usr/bin/env bash
# Train the detector. Usage:
#   ./train.sh <samples_dir> <labels_csv> <output_model_dir>
# Defaults to data/train, data/labels.csv, defender/models/my_model if omitted.
# Models saved under defender/models/ ship in the Docker image; add one to the
# served pool with DF_MODEL_DIR=models/detector,models/my_model (see README).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SAMPLES="${1:-data/train}"
LABELS="${2:-data/labels.csv}"
OUTPUT="${3:-defender/models/my_model}"

python3 -m src.train --samples "$SAMPLES" --labels "$LABELS" --output "$OUTPUT"
