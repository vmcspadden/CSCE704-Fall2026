import os
import sys
import time
import logging
from defender.apps import create_app

# CUSTOMIZE: import model to be used
from defender.models.ember_ensemble import EmberEnsembleModel

log = logging.getLogger("defender")


def env_number(name, cast, default):
    value = os.environ.get(name, "")
    return cast(value) if value.strip() else default


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s")

    # retrive config values from environment variables (see the ENV lines in the Dockerfile)
    model_dir = os.environ.get("DF_MODEL_DIR", "models/detector")
    model_name = os.environ.get("DF_MODEL_NAME", "ember_ensemble")
    # empty / unset = use the threshold saved with the model (threshold.json)
    model_thresh = env_number("DF_MODEL_THRESH", float, None)
    max_score_bytes = env_number("DF_MAX_SCORE_BYTES", int, 16 << 20)
    score_deadline = env_number("DF_SCORE_DEADLINE", float, 4.0)

    # construct absolute path to ensure the correct model is loaded
    if not os.path.isabs(model_dir):
        model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), model_dir)

    if not os.path.isfile(os.path.join(model_dir, "model.joblib")):
        sys.exit("Model not found: {}\n"
                 "Run ./get_detector.sh in the folder that contains the Dockerfile, then rebuild."
                 .format(os.path.join(model_dir, "model.joblib")))

    # CUSTOMIZE: app and model instance
    log.info("loading model from %s ...", model_dir)
    start = time.time()
    model = EmberEnsembleModel(model_dir,
                               threshold=model_thresh,
                               max_score_bytes=max_score_bytes,
                               deadline_seconds=score_deadline)
    # warm-up, so the first real request does not pay one-time start-up costs
    model.predict(b"MZ" + b"\0" * 4096)
    log.info("model loaded in %.1fs (%s, threshold %.6f)",
             time.time() - start, type(model).__name__, model.threshold)

    app = create_app(model, model.threshold, model_name)

    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080

    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer(('', port), app)
    log.info("listening on port %d", port)
    http_server.serve_forever()

    # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"