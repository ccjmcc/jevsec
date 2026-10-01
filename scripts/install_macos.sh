#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v uv >/dev/null || { echo "Install uv first: https://docs.astral.sh/uv/" >&2; exit 1; }
uv sync --all-extras --python 3.12
echo "Ready. Install local-jev separately; run it natively on Apple Silicon for MPS support."
