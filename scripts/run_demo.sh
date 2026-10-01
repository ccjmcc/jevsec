#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
JEV_DIR="${LOCAL_JEV_DIR:-$(cd .. && pwd)/.local-jev}"
MODEL="${LOCAL_JEV_MODEL:-nli-deberta-large}"
export SDE_DECISION_PROVIDER="${SDE_DECISION_PROVIDER:-local_jev}"
export LOCAL_JEV_MODEL="$MODEL"
uv sync --all-extras --python 3.12 >/dev/null
if ! curl -fsS http://127.0.0.1:8765/healthz >/dev/null 2>&1; then
  if [[ ! -d "$JEV_DIR/.git" ]]; then
    git clone https://github.com/amithgc/local-jev.git "$JEV_DIR"
    (cd "$JEV_DIR" && uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e .)
  fi
  if [[ -x "$JEV_DIR/.venv/bin/local-jev" ]]; then
    nohup "$JEV_DIR/.venv/bin/local-jev" serve --model "$MODEL" > /tmp/local-jev.log 2>&1 &
  else
    echo "local-jev missing at $JEV_DIR; clone/install it as documented in README.md" >&2; exit 1
  fi
  for _ in $(seq 1 300); do curl -fsS http://127.0.0.1:8765/healthz >/dev/null 2>&1 && break; sleep 1; done
fi
curl -fsS http://127.0.0.1:8765/healthz >/dev/null || { echo "local-jev did not become healthy; see /tmp/local-jev.log" >&2; exit 1; }
if ! curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
  nohup .venv/bin/security-engine serve > /tmp/security-engine.log 2>&1 &
  for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1 && break; sleep 1; done
fi
if ! curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then echo "backend did not become healthy; see /tmp/security-engine.log" >&2; exit 1; fi
.venv/bin/security-engine ingest demo/sample_access.log --format nginx
echo "Dashboard: http://127.0.0.1:8000 (model=$MODEL)"
