# Defender

A Docker image that answers one question over HTTP: is this Windows PE file
malicious?

* The **web server and test harness** come from the defender template of the
  [2021 Machine Learning Security Evasion Competition](https://github.com/Azure/2021-machine-learning-security-evasion-competition)
  (MIT license).
* The **detector** (feature extraction, training and model code in `src/`) is
  the group's [`malware_detector`](https://github.com/Qingxiao-X/CSCE704-Fall2026/tree/main/malware_detector):
  EMBER 2018 features and an average of two LightGBM models.
* The **model pool** (`src/mtd.py`) can serve several trained models at once,
  and `src/train.py` can add adversarial samples to training. Both are off by
  default: the image serves the single detector unless told otherwise.

## Requirements of the assignment

| | |
|---|---|
| Interface | `POST /` on port 8080, PE file bytes in the body (`Content-Type: application/octet-stream`) |
| Answer | `{"result": 0}` for benign, `{"result": 1}` for malicious |
| False positive rate | at most 1% |
| True positive rate | at least 95% |
| Memory | at most 1 GB RAM |
| Response time | at most 5 seconds per sample (a timeout counts as an evasion) |

## Layout

```
defender/                    <- run every command from here
├── Dockerfile
├── .dockerignore            only docker-requirements.txt, defender/ and src/ are sent to Docker
├── docker-requirements.txt  packages installed INSIDE the image (pinned)
├── requirements.txt         packages for your machine, to run the test harness
├── make_submission.sh       builds dist/defense-<version>.zip (Dockerfile at its root)
├── train.sh                 trains a model from your own labelled samples
├── configs/                 training settings (default.yaml, adversarial.yaml)
├── src/                     the detector: features, training, model pool, tools
│   ├── mtd.py               model pool (average / hash / random)
│   ├── adversarial_training.py
│   └── experiments/compare_defenses.py   single models vs. pools on one test set
├── defender/                the web server (this is what the image runs)
│   ├── __main__.py          loads the model(s), starts the web server
│   ├── apps.py              the HTTP endpoints
│   └── models/
│       ├── ember_ensemble.py   adapter: bytes -> 0/1, using src/
│       └── detector/           the trained model bundle that is served
├── tests/                   unit tests (pytest)
└── test/                    test harness: sends samples, reports FPR / TPR / time
```

There are two nested folders called `defender`. Commands are run from the
outer one (the one with the `Dockerfile`).

## Build and run

```
docker build -t mydefender .
docker run --rm -p 8080:8080 --memory=1g --memory-swap=1g --cpus=1 mydefender
```

(On Linux, put `sudo` in front of the `docker` commands unless your user is in
the `docker` group.) `--memory=1g --memory-swap=1g --cpus=1` reproduces the
assignment's limits; without `--memory-swap`, Docker lets the container use
swap and hides a memory problem. A container that exits with code 137 ran out
of memory.

When the log says `listening on port 8080`, try it from a second terminal:

```
curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
curl http://127.0.0.1:8080/model
docker stats --no-stream
```

The server log shows one line per sample with the verdict, size, time and the
model's score, for example `label=0 bytes=468992 seconds=0.210 ok p=0.0312`.

## Test

```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m test -m <malicious samples> -b <benign samples>
```

Each of the two sample sets is a folder or a `zip`, `tar`, `tar.gz`, `tgz` or
`tar.bz2` archive. Zips may be encrypted with the password `infected`, so the
malware never has to be unpacked. (AES-encrypted zips, such as the ones from
MalwareBazaar, need `pyzipper`, which `requirements.txt` installs.)

Useful options: `--recursive` (also test files in sub-folders), `--max BYTES`
(files larger than this are skipped, default 2 MiB), `--stopafter N`,
`--timeout SECONDS`, `--url`.

Things to know when reading the result:

* Only files that start with `MZ` are tested; everything else is skipped silently.
* An error or a timeout is counted as the answer "benign", exactly as the
  assignment counts it, so a crash on a malicious sample lowers the TPR.
* `fp` and `fn` in the summary are rates; `false_positives` / `false_negatives` are counts.
* The files behind the mistakes are written to `fps.txt`, `fns.txt` and `errors.txt`.

## Behaviour of the server

* `POST /` always answers `{"result": 0}` or `{"result": 1}` with HTTP 200,
  whatever the content type of the request.
* A sample that cannot be scored (empty, does not start with `MZ`, an error,
  or scoring that overruns its deadline) is answered with `1`.
* Only the first 16 MiB of a sample are scored.
* `GET /` answers `{"status": "ready"}` once the model is loaded;
  `GET /model` describes the model.

Settings (the `ENV` lines in the `Dockerfile`; override with `--env`):

| Variable | Default | Meaning |
|---|---|---|
| `DF_MODEL_THRESH` | empty | empty = the threshold saved with the model. A sample is malicious when its score is >= threshold, so **lowering it flags more files** |
| `DF_SCORE_DEADLINE` | `4.0` | seconds a sample may take before it is answered with `1` |
| `DF_MAX_SCORE_BYTES` | `16777216` | how much of a sample is scored |
| `DF_MODEL_DIR` | `models/detector` | model bundle, relative to the inner `defender` folder. Several, separated by commas, make a model pool |
| `DF_POOL_STRATEGY` | `average` | how a pool combines its models: `average`, `hash` or `random` (see below) |

## Model pool

Every model folder holds `model.joblib` plus `threshold.json` (and the other
files `ModelWrapper.save` writes). To serve several at once, put each folder
in `defender/models/` and list them:

```
docker run --rm -p 8080:8080 --memory=1g --memory-swap=1g --cpus=1 \
    --env DF_MODEL_DIR=models/detector,models/my_model mydefender
```

(or change the `ENV DF_MODEL_DIR` line in the `Dockerfile`, which is what the
grader will use). Each model is first judged against its own threshold; the
pool then combines those judgements:

| `DF_POOL_STRATEGY` | What happens | Same file twice |
|---|---|---|
| `average` (recommended) | every model scores every file; their margins over their own thresholds are averaged | same answer |
| `hash` | moving target defense: one model per file, picked from a hash of the file's features | same answer |
| `random` | moving target defense: one model per file, drawn at random | can differ, so an attacker gets extra tries |

Before switching the image to a pool, check three things:

1. **Same features.** Every model must be trained on this repository's
   extractor (`src/features.py`, EMBER v2, 2381 features, LIEF 1.0).
   `ModelWrapper.load` refuses a model whose saved feature schema differs.
2. **Better on held-out data.** Compare the pool with the single detector:
   ```
   python -m src.experiments.compare_defenses --samples <eval dir> --labels <eval csv> \
       --model defender/models/detector --model defender/models/my_model
   ```
   With `hash` or `random`, *every* model must meet FPR <= 1% / TPR >= 95% on
   its own, since any one of them may answer.
3. **Memory and time.** Run the image with `--memory=1g --memory-swap=1g`,
   check `docker stats`, and run the harness (`python -m test ...`). The
   detector alone uses about 370 MiB.

## Training another model (optional: with adversarial samples)

Training needs the packages in `docker-requirements.txt` plus `pandas` and
`PyYAML` (and `xgboost` for that backend), on Python 3.12.

```
./train.sh <samples dir> <labels csv> defender/models/my_model
# with adversarial (evasive) malware added to the training split only:
python -m src.train --samples <dir> --labels <csv> --output defender/models/my_model \
    --config configs/adversarial.yaml \
    --adversarial-samples <adv dir> --adversarial-labels <adv csv>
```

The labels CSV has `filename,label` rows (0 = benign, 1 = malware); every
adversarial sample must be labelled 1. The threshold is tuned on the held-out
split for FPR < 1% and saved with the model. Adversarial samples are never
put in the held-out split, and a copy of a held-out file is dropped from them.

## Changing the model

`defender/models/ember_ensemble.py` is the only place that knows about the
detector. To serve something else, write a class with a
`predict(bytez) -> int` method (0 or 1), import it in `defender/__main__.py`
(marked `CUSTOMIZE`), and list any new packages in `docker-requirements.txt`.