# The detector was trained and tested on Python 3.12 with the package versions
# in docker-requirements.txt; the image uses exactly those.
FROM python:3.12-slim

#############################
# INSTALL PYTHON DEPENDENCIES
#############################

# create a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# copy and install python requirements
# (nothing here needs a C compiler or git)
COPY docker-requirements.txt .
RUN pip install --no-cache-dir -r docker-requirements.txt

#############################
# REBASE & DEPLOY CODE
#############################

# rebase to make a smaller image
FROM python:3.12-slim

# OpenMP runtime used by LightGBM
RUN apt-get -o Acquire::Max-FutureTime=100000 update \
    && apt-get -y --no-install-recommends install \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# copy python virtual env (all dependencies) from previous image
COPY --from=0 /opt/venv /opt/venv

# copy the web server (and the model bundle in defender/models/detector) to /opt/defender/defender
COPY defender /opt/defender/defender
# copy the detector's feature extraction and model code to /opt/defender/src
COPY src /opt/defender/src

#############################
# SETUP ENVIRONMENT
#############################

# update environmental variables
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/opt/defender"
# show log lines immediately in `docker logs`
ENV PYTHONUNBUFFERED=1
# compile now, write nothing at run time (the container may run on a read-only filesystem)
ENV PYTHONDONTWRITEBYTECODE=1
RUN python -m compileall -q /opt/defender
# the container gets a single CPU
ENV OMP_NUM_THREADS=1

# open port 8080
EXPOSE 8080

# add a defender user and switch user
RUN groupadd -r defender && useradd --no-log-init -r -g defender defender
USER defender

# change working directory
WORKDIR /opt/defender/

# one may tune the model via environmental variables
# (DF_MODEL_DIR is relative to /opt/defender/defender)
# For a model pool, list several folders separated by commas, e.g.
#   DF_MODEL_DIR=models/detector,models/my_model
# and pick how they are combined: average (recommended), hash or random.
ENV DF_MODEL_DIR=models/detector
ENV DF_POOL_STRATEGY=average
ENV DF_MODEL_NAME=ember_ensemble
# Empty = use the threshold saved with the model (models/detector/threshold.json;
# a pool's combined score always uses 0.5). A sample is malicious when its
# score is >= threshold, so LOWERING it flags more files.
ENV DF_MODEL_THRESH=""
# only this many bytes of a sample are scored; scoring gets this many seconds
ENV DF_MAX_SCORE_BYTES=16777216
ENV DF_SCORE_DEADLINE=4.0

#############################
# RUN CODE
#############################
CMD ["python","-m","defender"]

## TO BUILD IMAGE (from the folder containing this Dockerfile):
# docker build -t mydefender .
## TO RUN IMAGE UNDER THE ASSIGNMENT'S LIMITS (ENVIRONMENTAL VARIABLES DECLARED ABOVE)
# docker run --rm -p 8080:8080 --memory=1g --memory-swap=1g --cpus=1 mydefender
## TO RUN IMAGE (OVERRIDE ENVIRONMENTAL VARIABLES DECLARED ABOVE)
# docker run --rm -p 8080:8080 --memory=1g --memory-swap=1g --cpus=1 --env DF_MODEL_THRESH=0.7 mydefender
# docker run --rm -p 8080:8080 --memory=1g --memory-swap=1g --cpus=1 --env DF_MODEL_DIR=models/detector,models/my_model mydefender