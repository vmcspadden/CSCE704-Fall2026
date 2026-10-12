"""Model pool: several detectors behind one predict_proba().

A pool loads several model bundles (each one a models/<name>/ folder saved by
ModelWrapper.save) and turns their answers into one score per sample. Every
member must use the same feature extractor (src/features.py); ModelWrapper.load
already refuses a bundle whose feature schema does not match.

Each member has its own tuned threshold, so raw probabilities from different
members are not comparable. The pool therefore works with each member's
*margin*:

    margin_i = logit(p_i) - logit(threshold_i)

margin_i >= 0 exactly when member i on its own would say "malware". The pool
returns sigmoid(combined margin), so its threshold is always 0.5 and
``prob >= pool.threshold`` means "malware", just like a single ModelWrapper.
That makes a ModelPool a drop-in replacement wherever a ModelWrapper is used.

Strategies (how the margins are combined):

  average  every member scores every sample; the margins are averaged.
           Deterministic, and an attacker has to push the *average* below the
           line, i.e. fool most members at once. Recommended.
  hash     Moving Target Defense, deterministic: the member is picked from a
           hash of the sample's feature vector, so different files meet
           different members but re-sending the same file always gets the
           same member (and the same answer).
  random   Moving Target Defense, random: a member is drawn per sample.
           Re-sending a file can change the answer, which gives an attacker
           extra tries; kept for experiments, not recommended for serving.

With a single member every strategy gives exactly that member's verdict.
"""

from __future__ import annotations

import hashlib
import random
from typing import List, Optional, Tuple

import numpy as np

from src.model import ModelWrapper

STRATEGIES = ("average", "hash", "random")

_EPS = 1e-12


def _logit(p):
    p = np.clip(np.asarray(p, dtype=np.float64), _EPS, 1 - _EPS)
    return np.log(p / (1 - p))


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=np.float64)))


def _single_thread(model) -> None:
    """The grading container has one CPU: extra threads only add contention."""
    if hasattr(model, "num_threads"):
        model.num_threads = 1
    estimator = getattr(model, "estimator", None)
    if estimator is not None and hasattr(estimator, "set_params"):
        try:
            estimator.set_params(n_jobs=1)
        except ValueError:
            pass


class MTDSelector:
    """Random Moving Target Defense: one member, drawn at random, per call.

    Kept with its original interface (used by tests and experiments). For
    serving, use ModelPool, which also offers deterministic strategies.
    """

    def __init__(self, model_dirs: List[str], seed: int = 42):
        if not model_dirs:
            raise ValueError("MTD requires at least one model.")

        self.model_dirs = list(model_dirs)
        self.models: List[Tuple[str, ModelWrapper]] = []

        for model_dir in self.model_dirs:
            model = ModelWrapper.load(model_dir)
            _single_thread(model)
            self.models.append((model_dir, model))

        self.rng = random.Random(seed)

    def select_model(self) -> Tuple[str, ModelWrapper]:
        return self.rng.choice(self.models)

    def predict_proba(self, X: np.ndarray):
        model_name, model = self.select_model()
        probability = float(model.predict_proba(X)[0])

        return {
            "model_name": model_name,
            "model": model,
            "probability": probability,
        }


class ModelPool:
    """Several ModelWrappers combined into one scorer (see module docstring)."""

    backend = "model_pool"
    # sigmoid(margin) >= 0.5  <=>  margin >= 0
    threshold = 0.5

    def __init__(self, model_dirs: List[str], strategy: str = "average", seed: int = 42):
        if not model_dirs:
            raise ValueError("A model pool requires at least one model.")
        if strategy not in STRATEGIES:
            raise ValueError(f"Unknown pool strategy {strategy!r}; choose one of {STRATEGIES}.")

        self.strategy = strategy
        self.model_dirs = list(model_dirs)
        self.members: List[Tuple[str, ModelWrapper]] = []
        for model_dir in self.model_dirs:
            model = ModelWrapper.load(model_dir)
            _single_thread(model)
            self.members.append((model_dir, model))

        # all members passed the same schema check in ModelWrapper.load
        self.feature_schema = list(self.members[0][1].feature_schema)
        self.rng = random.Random(seed)
        # names of the member(s) used for the most recent call, for logging
        self.last_members: List[str] = []

    @property
    def num_threads(self) -> int:
        return 1

    @num_threads.setter
    def num_threads(self, value) -> None:
        for _, model in self.members:
            if hasattr(model, "num_threads"):
                model.num_threads = value

    def member_margins(self, X: np.ndarray) -> np.ndarray:
        """Margin of every member on every row: shape (n_members, n_rows)."""
        return np.vstack([
            _logit(model.predict_proba(X)) - _logit(model.threshold)
            for _, model in self.members
        ])

    def _pick(self, row: np.ndarray) -> int:
        if self.strategy == "random":
            return self.rng.randrange(len(self.members))
        digest = hashlib.sha256(np.ascontiguousarray(row, dtype=np.float64).tobytes()).digest()
        return int.from_bytes(digest[:8], "big") % len(self.members)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Pool score per row; malware when score >= 0.5 (self.threshold)."""
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)

        if self.strategy == "average" or len(self.members) == 1:
            margins = self.member_margins(X).mean(axis=0)
            self.last_members = [name for name, _ in self.members]
            return _sigmoid(margins)

        scores = np.empty(X.shape[0])
        picked = []
        for i, row in enumerate(X):
            name, model = self.members[self._pick(row)]
            margin = _logit(model.predict_proba(row.reshape(1, -1)))[0] - _logit(model.threshold)
            scores[i] = _sigmoid(margin)
            picked.append(name)
        self.last_members = picked
        return scores

    def predict_label(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        thr = self.threshold if threshold is None else threshold
        return (self.predict_proba(X) >= thr).astype(int)


def load_detector(model_dirs: List[str], strategy: str = "average", seed: int = 42):
    """One model folder -> its ModelWrapper; several -> a ModelPool.

    Either way the result has predict_proba(X) and threshold, and
    ``predict_proba(X) >= threshold`` means malware.
    """
    model_dirs = [d for d in model_dirs if d]
    if not model_dirs:
        raise ValueError("No model directory given.")
    if len(model_dirs) == 1:
        model = ModelWrapper.load(model_dirs[0])
        _single_thread(model)
        return model
    return ModelPool(model_dirs, strategy=strategy, seed=seed)


def split_dirs(value: str) -> List[str]:
    """Parse a comma-separated list of model folders (as used in env vars)."""
    return [p.strip() for p in (value or "").split(",") if p.strip()]
