# Defender

A Docker image that answers one question over HTTP: is this Windows PE file
malicious?

* The **web server and test harness** come from the defender template of the
  [2021 Machine Learning Security Evasion Competition](https://github.com/Azure/2021-machine-learning-security-evasion-competition)
  (MIT license, see `../LICENSE`).
* The **detector** (feature extraction and model) is the group's
  [`malware_detector`](https://github.com/Qingxiao-X/CSCE704-Fall2026/tree/main/malware_detector):
  EMBER 2018 features and an average of two LightGBM models. It is used
  unchanged; `get_detector.sh` copies it in.

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
├── get_detector.sh          fetches src/ and defender/models/detector/
├── DETECTOR_SOURCE.txt      which commit of the detector was fetched (written by the script)
├── src/                     the detector's code, unchanged (fetched)
├── defender/                the web server
│   ├── __main__.py          loads the model, starts the web server
│   ├── apps.py              the HTTP endpoints
│   └── models/
│       ├── ember_ensemble.py   adapter: bytes -> 0/1, using src/
│       └── detector/           the trained model bundle (fetched)
└── test/                    test harness: sends samples, reports FPR / TPR / time
```

There are two nested folders called `defender`. Commands are run from the
outer one (the one with the `Dockerfile`).

## Build and run

```
./get_detector.sh            # once, and again whenever the detector changes
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
| `DF_MODEL_DIR` | `models/detector` | model bundle, relative to the inner `defender` folder |

## Changing the model

`defender/models/ember_ensemble.py` is the only place that knows about the
detector. To serve something else, write a class with a
`predict(bytez) -> int` method (0 or 1), import it in `defender/__main__.py`
(marked `CUSTOMIZE`), and list any new packages in `docker-requirements.txt`.