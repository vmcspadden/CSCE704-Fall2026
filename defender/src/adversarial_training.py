"""Utilities for adversarial training.

This module does not generate adversarial malware. It takes adversarial PE
samples that already exist, keeps their malicious labels, and adds them to
the training split only.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

import numpy as np

from src.dataset import Sample
from src.model import vectors_to_matrix


def validate_adversarial_samples(samples: List[Sample]) -> None:
    """Require adversarial training samples to remain labeled as malware."""
    mislabeled = [s.filename for s in samples if s.label != 1]
    if mislabeled:
        preview = ", ".join(mislabeled[:5])
        raise ValueError(
            "Adversarial training samples must be labeled malware (1). "
            f"Found non-malware labels for: {preview}"
        )


def combine_training_samples(
    clean_train_samples: List[Sample],
    adversarial_samples: List[Sample],
    held_out_samples: Sequence[Sample] = (),
) -> List[Sample]:
    """Add adversarial samples to the clean training split.

    Validation/test samples must not be passed as adversarial samples. Any
    adversarial sample whose content hash is already in ``held_out_samples``
    (the validation split) or in the training split is dropped, so the same
    file can neither leak into validation nor be counted twice.
    """
    validate_adversarial_samples(adversarial_samples)
    seen = {s.sha256 for s in held_out_samples} | {s.sha256 for s in clean_train_samples}
    extra = []
    for s in adversarial_samples:
        if s.sha256 and s.sha256 in seen:
            continue
        seen.add(s.sha256)
        extra.append(s)
    return list(clean_train_samples) + extra


def samples_to_xy(samples: List[Sample]) -> Tuple[np.ndarray, np.ndarray]:
    """Convert Sample objects into model-ready X/y arrays."""
    if not samples:
        raise ValueError("Training sample list cannot be empty.")

    X = vectors_to_matrix([s.vector for s in samples])
    y = np.asarray([s.label for s in samples], dtype=int)
    return X, y
