"""Tests for the model pool (src/mtd.py) and the servers that use it.

Fake members stand in for real model bundles, so these tests need neither
the EMBER data nor the 80 MB detector.
"""

import numpy as np
import pytest

import src.mtd as mtd_module
from src.adversarial_training import combine_training_samples
from src.dataset import Sample
from src.features import FEATURE_DIM
from src.mtd import ModelPool, load_detector


class FakeModel:
    def __init__(self, probability, threshold=0.5):
        self.probability = probability
        self.threshold = threshold
        self.num_threads = 0
        self.feature_schema = ["f"] * FEATURE_DIM

    def predict_proba(self, X):
        X = np.asarray(X)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return np.full(X.shape[0], self.probability, dtype=float)


def _patch(monkeypatch, models):
    monkeypatch.setattr(mtd_module.ModelWrapper, "load", staticmethod(lambda d: models[d]))


def _rows(n):
    return np.arange(n * 4, dtype=float).reshape(n, 4)


def test_single_member_pool_matches_the_model(monkeypatch):
    for p, t in [(0.9, 0.5), (0.6, 0.8), (0.8, 0.8), (0.1, 0.05)]:
        _patch(monkeypatch, {"a": FakeModel(p, t)})
        for strategy in mtd_module.STRATEGIES:
            pool = ModelPool(["a"], strategy=strategy)
            verdict = int(pool.predict_proba(_rows(1))[0] >= pool.threshold)
            assert verdict == int(p >= t), (p, t, strategy)


def test_each_member_is_judged_against_its_own_threshold(monkeypatch):
    # 0.6 is "malware" for a 0.5-threshold model but "benign" for a 0.9 one
    _patch(monkeypatch, {"low": FakeModel(0.6, 0.5), "high": FakeModel(0.6, 0.9)})
    assert ModelPool(["low"]).predict_label(_rows(1))[0] == 1
    assert ModelPool(["high"]).predict_label(_rows(1))[0] == 0


def test_average_needs_the_members_together(monkeypatch):
    # one confident "malware" outweighs one mild "benign"
    _patch(monkeypatch, {"a": FakeModel(0.99), "b": FakeModel(0.4), "c": FakeModel(0.01)})
    assert ModelPool(["a", "b"]).predict_label(_rows(3)).tolist() == [1, 1, 1]
    # two confident "benign" outweigh one "malware"
    assert ModelPool(["a", "b", "c"]).predict_label(_rows(1))[0] == 0


def test_average_is_deterministic(monkeypatch):
    _patch(monkeypatch, {"a": FakeModel(0.7), "b": FakeModel(0.45)})
    pool = ModelPool(["a", "b"], strategy="average")
    first = pool.predict_proba(_rows(5))
    for _ in range(5):
        assert np.array_equal(pool.predict_proba(_rows(5)), first)


def test_hash_strategy_same_file_same_member(monkeypatch):
    _patch(monkeypatch, {"yes": FakeModel(0.9), "no": FakeModel(0.1)})
    X = _rows(50)
    a = ModelPool(["yes", "no"], strategy="hash").predict_label(X)
    b = ModelPool(["yes", "no"], strategy="hash", seed=7).predict_label(X)
    # independent of call order, seed and process: depends only on the sample
    assert a.tolist() == b.tolist()
    assert a.tolist() == ModelPool(["yes", "no"], strategy="hash").predict_label(X[::-1]).tolist()[::-1]
    # different samples do meet different members
    assert 0 < a.sum() < len(a)


def test_random_strategy_is_reproducible_with_a_seed(monkeypatch):
    _patch(monkeypatch, {"yes": FakeModel(0.9), "no": FakeModel(0.1)})
    X = _rows(40)
    a = ModelPool(["yes", "no"], strategy="random", seed=3).predict_label(X)
    b = ModelPool(["yes", "no"], strategy="random", seed=3).predict_label(X)
    assert a.tolist() == b.tolist()
    assert 0 < a.sum() < len(a)


def test_bad_pool_arguments(monkeypatch):
    _patch(monkeypatch, {"a": FakeModel(0.9)})
    with pytest.raises(ValueError, match="at least one model"):
        ModelPool([])
    with pytest.raises(ValueError, match="Unknown pool strategy"):
        ModelPool(["a"], strategy="bogus")


def test_load_detector_one_folder_is_the_plain_model(monkeypatch):
    model = FakeModel(0.9)
    _patch(monkeypatch, {"a": model, "b": FakeModel(0.1)})
    assert load_detector(["a"]) is model
    assert model.num_threads == 1  # single CPU in the grading container
    assert isinstance(load_detector(["a", "b"]), ModelPool)


def test_src_server_starts_in_pool_mode(monkeypatch):
    """Regression: the first MTD version crashed at startup in pool mode."""
    import src.server as server

    _patch(monkeypatch, {"a": FakeModel(0.9), "b": FakeModel(0.2)})
    detector = server.Detector(["a", "b"], "average")

    class Ok:
        status = "ok"
        vector = [0.0] * FEATURE_DIM

    monkeypatch.setattr(server, "extract_features", lambda data: Ok())
    result, detail = detector.classify(b"MZ")
    assert result in (0, 1)
    assert detail.startswith("ok p=")


def test_template_model_serves_a_pool(monkeypatch):
    from defender.models import ember_ensemble

    _patch(monkeypatch, {"a": FakeModel(0.9), "b": FakeModel(0.3)})

    class Ok:
        status = "ok"
        vector = [0.0] * FEATURE_DIM

    monkeypatch.setattr(ember_ensemble, "extract_features", lambda data: Ok())
    model = ember_ensemble.EmberEnsembleModel(["a", "b"], pool_strategy="average")
    assert model.threshold == 0.5
    assert model.predict(b"MZ") == 1
    info = model.model_info()
    assert info["pool_strategy"] == "average" and info["models"] == ["a", "b"]

    # the threshold override still applies (to the pool's combined score)
    strict = ember_ensemble.EmberEnsembleModel(["a", "b"], threshold=0.99)
    assert strict.predict(b"MZ") == 0


def _sample(name, sha, label):
    return Sample(filename=name, sha256=sha, label=label, vector=[0.0] * 4)


def test_adversarial_samples_never_leak_into_validation():
    train = [_sample("t1", "h1", 0), _sample("t2", "h2", 1)]
    val = [_sample("v1", "h3", 1)]
    adv = [_sample("a1", "h3", 1),   # same file as a validation sample -> dropped
           _sample("a2", "h2", 1),   # already in training -> dropped
           _sample("a3", "h4", 1),
           _sample("a4", "h4", 1)]   # duplicate within the adversarial set -> dropped
    combined = combine_training_samples(train, adv, held_out_samples=val)
    assert [s.filename for s in combined] == ["t1", "t2", "a3"]


def test_adversarial_samples_must_be_malware():
    with pytest.raises(ValueError, match="labeled malware"):
        combine_training_samples([], [_sample("a", "h", 0)])
