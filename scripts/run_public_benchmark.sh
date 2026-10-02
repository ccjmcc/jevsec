#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

WINDOWS="${SDE_PUBLIC_WINDOWS:-20000}"
SEED="${SDE_PUBLIC_SEED:-20261001}"
MODEL="llm-qwen3-4b"
[[ "${LOCAL_JEV_MODEL:-$MODEL}" == "$MODEL" ]] || { echo "JevSec benchmark supports only $MODEL" >&2; exit 2; }
curl -fsS "${LOCAL_JEV_BASE_URL:-http://127.0.0.1:8765}/healthz" >/dev/null || {
  echo "local-jev must be running natively (M5/MPS recommended). See README.md." >&2; exit 1;
}
uv sync --all-extras --python 3.12
for rate in 0.01 0.05 0.10; do
  key="$(python3 -c 'import sys; print(str(int(float(sys.argv[1])*100))+"pct")' "$rate")"
  data="datasets/public_v2/$key"
  uv run security-engine generate-dataset --out "$data" --behavior-windows "$WINDOWS" --seed "$SEED" --malicious-rate "$rate"
done

# Evaluate one model across all rates before switching models to avoid repeated
# weight eviction and reloads on memory-limited Macs.
for rate in 0.01 0.05 0.10; do
  key="$(python3 -c 'import sys; print(str(int(float(sys.argv[1])*100))+"pct")' "$rate")"
  data="datasets/public_v2/$key"
  report="reports/public_v2/$MODEL/$key"
  if [[ "${SDE_PUBLIC_RESUME:-0}" == "1" && -s "$report/benchmark_results.csv" ]] && \
     python3 -c 'import hashlib,json,sys; r=json.load(open(sys.argv[1])); m=json.load(open(sys.argv[2])); fp=hashlib.sha256((m["events_sha256"]+m["labels_sha256"]).encode("ascii")).hexdigest(); sys.exit(0 if r.get("model")==sys.argv[3] and r.get("dataset_fingerprint")==fp and r.get("windows_evaluated")==int(m["behavior_windows"]*.2) else 1)' \
       "$report/benchmark_results.json" "$data/dataset_manifest.json" "$MODEL"; then
    echo "reuse verified completed benchmark: $MODEL $key"
    continue
  fi
  LOCAL_JEV_MODEL="$MODEL" uv run python -m security_engine.benchmark_v2 \
    --data "$data" --reports "$report" --model "$MODEL" \
    --base-url "${LOCAL_JEV_BASE_URL:-http://127.0.0.1:8765}" --provider local_jev
done
uv run python scripts/compile_public_reports.py --root reports/public_v2
echo "Public v2 benchmark reports: reports/BENCHMARK_V2.md and reports/FAILURE_ANALYSIS.md"
