#!/usr/bin/env bash
# Fetch the group's detector (feature-extraction code and trained model) into
# this folder, where the Dockerfile expects them:
#
#   src/                        <- malware_detector/src           (used unchanged)
#   defender/models/detector/   <- malware_detector/models/detector
#
# Usage:  ./get_detector.sh            the commit this integration was written against
#         ./get_detector.sh main       the latest version
set -euo pipefail

REPO="https://github.com/Qingxiao-X/CSCE704-Fall2026"
REF="${1:-12f0fb06a2b8b3bfb4d1cfe69f7696f64429de55}"

cd "$(dirname "${BASH_SOURCE[0]}")"
[ -f Dockerfile ] || { echo "error: run this from the folder that contains the Dockerfile" >&2; exit 1; }
# refuse to overwrite a src/ folder that is not a copy of the detector
if [ -e src ] && [ ! -f src/ember_extractor.py ]; then
    echo "error: ./src exists and is not the detector's code; move it away first" >&2; exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "cloning $REPO ..."
git clone --quiet "$REPO" "$tmp/repo"
git -C "$tmp/repo" checkout --quiet "$REF"
commit="$(git -C "$tmp/repo" rev-parse HEAD)"

rm -rf src defender/models/detector
cp -r "$tmp/repo/malware_detector/src" src
mkdir -p defender/models
cp -r "$tmp/repo/malware_detector/models/detector" defender/models/detector
find src -name __pycache__ -type d -prune -exec rm -rf {} +

printf 'repository: %s\ncommit: %s\n' "$REPO" "$commit" > DETECTOR_SOURCE.txt
echo "detector code  -> src/"
echo "detector model -> defender/models/detector/ ($(du -sh defender/models/detector | cut -f1))"
echo "from commit $commit (recorded in DETECTOR_SOURCE.txt)"