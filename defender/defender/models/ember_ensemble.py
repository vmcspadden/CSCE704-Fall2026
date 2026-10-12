"""Adapter between the template's web server and the group's detector.

The detector itself (feature extraction and model) lives in the ``src``
package and the model bundle in ``models/detector``; both are used unchanged.
This class only gives them the one method the server calls:

    predict(bytez) -> 0 (benign) or 1 (malicious)

Behaviour mirrors the detector's own server (src/server.py):
  * only the first ``max_score_bytes`` of a sample are scored;
  * scoring runs under a deadline, so a slow sample is answered instead of
    timing out (a timeout is counted as an evasion);
  * a sample that cannot be scored (empty, not a PE, error, deadline) gets
    ``verdict_on_failure``.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

from src.features import extract_features
from src.model import ModelWrapper, vectors_to_matrix

log = logging.getLogger("defender")


class EmberEnsembleModel(object):

    def __init__(self, model_dir, threshold=None, max_score_bytes=16 << 20,
                 deadline_seconds=4.0, verdict_on_failure=1):
        self.wrapper = ModelWrapper.load(model_dir)
        # the container gets one CPU: extra LightGBM threads only add contention
        self.wrapper.num_threads = 1
        if hasattr(self.wrapper.estimator, "set_params"):
            try:
                self.wrapper.estimator.set_params(n_jobs=1)
            except ValueError:
                pass

        # CUSTOMIZE: the threshold saved with the model is used unless one is given.
        # A sample is malicious when its malware probability is >= threshold,
        # so LOWERING the threshold flags more files.
        self.threshold = float(self.wrapper.threshold if threshold is None else threshold)
        self.max_score_bytes = int(max_score_bytes)
        self.deadline_seconds = float(deadline_seconds)
        self.verdict_on_failure = int(verdict_on_failure)
        # what happened to the most recent sample (for the server's log line)
        self.last_detail = ""
        # one scorer at a time, in its own thread so that it can be given a deadline
        self._pool = ThreadPoolExecutor(max_workers=1)

    def _score(self, bytez):
        result = extract_features(bytez[:self.max_score_bytes])
        if result.status != "ok" or result.vector is None:
            return self.verdict_on_failure, result.status
        prob = float(self.wrapper.predict_proba(vectors_to_matrix([result.vector]))[0])
        return int(prob >= self.threshold), "ok p=%.4f" % prob

    def predict(self, bytez):
        future = self._pool.submit(self._score, bytez)
        try:
            verdict, detail = future.result(timeout=self.deadline_seconds)
        except FutureTimeout:
            verdict, detail = self.verdict_on_failure, "deadline_exceeded"
        except Exception as e:  # never let one file break the service
            verdict, detail = self.verdict_on_failure, "error %s: %s" % (type(e).__name__, e)
        self.last_detail = detail
        return int(verdict)

    # short description of the model, served at GET /model
    def model_info(self):
        info = {
            "backend": self.wrapper.backend,
            "features": len(self.wrapper.feature_schema),
            "max_score_bytes": self.max_score_bytes,
            "deadline_seconds": self.deadline_seconds,
            "verdict_on_failure": self.verdict_on_failure,
        }
        members = getattr(self.wrapper.estimator, "members", None)
        if members:
            info["members"] = [name for name, _, _ in members]
        return info