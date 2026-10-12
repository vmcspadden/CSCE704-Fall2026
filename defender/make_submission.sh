#!/usr/bin/env bash
# Build the submission ZIP: everything the Docker build needs, with the
# Dockerfile at the root of the ZIP. Usage:
#   ./make_submission.sh [version]      -> dist/defense-<version>.zip
# Only files tracked by git (or new and not ignored) are included, so local
# data, samples, virtual environments and caches never leak in.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${1:-1.0.0}"
OUT="dist/defense-${VERSION}.zip"
FILES=(Dockerfile .dockerignore docker-requirements.txt defender src)

mkdir -p dist
rm -f "$OUT"
git ls-files --cached --others --exclude-standard -- "${FILES[@]}" \
    | grep -v -e '__pycache__/' -e '\.pyc$' \
    | python3 -c '
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    for path in sys.stdin.read().splitlines():
        if os.path.isfile(path):
            z.write(path)
' "$OUT"

list_zip() { python3 -c 'import sys, zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$OUT"; }

if ! list_zip | grep -qx 'Dockerfile'; then
    echo "error: $OUT has no Dockerfile at its root" >&2
    exit 1
fi
if ! list_zip | grep -q '^defender/models/detector/model.joblib$'; then
    echo "error: $OUT is missing the model (defender/models/detector/model.joblib)" >&2
    exit 1
fi
if list_zip | grep -qiE '\.(exe|dll|sys|scr)$'; then
    echo "error: $OUT contains PE binaries; the submission must not include samples" >&2
    exit 1
fi

echo "wrote $OUT ($(du -h "$OUT" | cut -f1)), $(list_zip | wc -l) files"
