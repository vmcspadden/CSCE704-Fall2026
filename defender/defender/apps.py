import logging
import time

from flask import Flask, jsonify, request

log = logging.getLogger("defender")

# Verdict returned when the model itself raises. (The model has its own policy
# for samples it cannot score; this is the last line of defence behind it.)
# An HTTP error or a timeout is scored as an evasion, so fail towards
# "malicious" instead of answering with an error.
VERDICT_ON_ERROR = 1

# The assignment allows 5 seconds per sample; warn in the log well before that.
SLOW_REQUEST_SECONDS = 4.0


def create_app(model, threshold, model_name="defender"):
    app = Flask(__name__)
    app.config['model'] = model
    app.config['threshold'] = threshold
    app.config['model_name'] = model_name

    # analyse a sample
    @app.route('/', methods=['POST'])
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        # The template answered HTTP 400 unless the content type was exactly
        # application/octet-stream. A grader that sends another (or no) content
        # type would then count every sample as an evasion, so the body is
        # scored whatever the header says.
        bytez = request.get_data()
        start = time.time()

        model = app.config['model']
        try:
            # CUSTOMIZE: query the model. It takes the raw bytes and returns the
            # int 0 or 1 (feature extraction happens inside the model).
            result = model.predict(bytez)
        except Exception as e:
            # any failure on a sample ends up here; an HTTP 500 would count as an evasion
            log.warning("could not analyse sample (%d bytes): %s: %s",
                        len(bytez), type(e).__name__, e)
            result = VERDICT_ON_ERROR

        elapsed = time.time() - start

        # a wrong type or value here is a bug in the model code, not in the sample
        if isinstance(result, bool) or not isinstance(result, int) or result not in {0, 1}:
            log.error("unexpected model result %r (must be the int 0 or 1)", result)
            resp = jsonify({'error': 'unexpected model result (not in [0,1])'})
            resp.status_code = 500  # Internal Server Error
            return resp

        if elapsed > SLOW_REQUEST_SECONDS:
            log.warning("slow sample: %.2fs for %d bytes", elapsed, len(bytez))
        # models may explain their verdict (score, or why a sample was not scored)
        log.info("label=%d bytes=%d seconds=%.3f %s", result, len(bytez), elapsed,
                 getattr(model, "last_detail", ""))

        resp = jsonify({'result': result})
        resp.status_code = 200
        return resp

    # readiness probe: answers once the model is loaded and the server is up
    @app.route('/', methods=['GET'])
    def ready():
        resp = jsonify({'status': 'ready'})
        resp.status_code = 200
        return resp

    # get the model info
    @app.route('/model', methods=['GET'])
    def get_model():
        # curl -XGET http://127.0.0.1:8080/model
        model = app.config['model']
        info = {
            'name': app.config['model_name'],
            'class': type(model).__name__,
            'threshold': app.config['threshold'],
        }
        # models may describe themselves further by defining model_info()
        if hasattr(model, 'model_info'):
            info.update(model.model_info())
        resp = jsonify(info)
        resp.status_code = 200
        return resp

    return app