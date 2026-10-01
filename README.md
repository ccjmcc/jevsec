# Self-hosted AI Security Decision Engine

Self-hosted behavior-based detection and AI-assisted triage for Nginx and web application logs. Once model weights are downloaded, local inference traffic stays on the machine; no event data is sent to a vendor. The first release is detection and shadow mode only. It never blocks traffic, isolates systems, or scans targets.

## Quick start

Requirements: Python 3.12, `uv`, `git`, and (for local AI) the separate [local-jev](https://github.com/amithgc/local-jev) service. Start local-jev natively on Apple Silicon to use Metal/MPS; Docker is not used for the model. The demo script clones/installs local-jev to a sibling `.local-jev` checkout when it is not already installed, then starts it locally. The first launch downloads the selected model weights.

```sh
uv sync --all-extras
./scripts/run_demo.sh
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The dashboard labels Rules, Jev and Hybrid values separately. Set `LOCAL_JEV_MODEL` before running the demo to choose a model. `nli-deberta-large` is the default for a modest-memory demo; `llm-qwen3-4b` and `llm-qwen3.5-4b` need substantially more RAM and disk.

To run without local-jev, set `SDE_DECISION_PROVIDER=mock`; this is only a deterministic demo fallback and is not a model benchmark. For real local inference, set `SDE_DECISION_PROVIDER=local_jev` and `LOCAL_JEV_BASE_URL`.

## CLI

```sh
.venv/bin/security-engine doctor
.venv/bin/security-engine serve
.venv/bin/security-engine ingest /var/log/nginx/access.log --format nginx --follow
.venv/bin/security-engine ingest sample.jsonl --format jsonl
.venv/bin/security-engine generate-dataset
.venv/bin/security-engine benchmark --provider local_jev --model nli-deberta-large
```

The supported Nginx format is Combined Log Format with optional trailing request time. JSONL is whitelisted into the shared event schema; unknown fields such as cookies, passwords, Authorization, API keys and secrets are discarded. Provide a pre-hashed pseudonymous `session_hash` if session grouping is needed.

## Detection and evaluation

Events are grouped by source IP and, when provided, session hash into 1-minute and 5-minute windows. The deterministic baseline has named rules and evidence. Jev receives only structured aggregate features; raw paths, user-agent strings and referers are not sent. Hybrid scoring retains an uncertainty state for low confidence or rule/model disagreement. It is triage output, not a block decision.

Generate a fixed-seed dataset (10,000+ events), then run a held-out evaluation:

```sh
.venv/bin/security-engine generate-dataset --out datasets/generated --entities 1200 --seed 20261001
.venv/bin/security-engine benchmark --data datasets/generated --reports reports --provider local_jev --model nli-deberta-large --sample-limit 120
```

The local model evaluation samples up to the requested number from the test partition, stratified by category, because single-window model inference can be slow. Reports include sample count and synthetic-data caveats. Thresholds are config defaults and are not fit on the test partition. Never interpret these synthetic metrics as production effectiveness.

## Configuration

Environment variables: `SDE_DATABASE`, `SDE_DECISION_PROVIDER` (`mock` or `local_jev`), `LOCAL_JEV_BASE_URL`, `LOCAL_JEV_MODEL`, `SDE_DECISION_TIMEOUT`, `SDE_MODE` (`hybrid`, `rules_only`, `jev_only`), `SDE_ALERT_THRESHOLD`, `SDE_HIGH_RISK_THRESHOLD`, `SDE_LOW_CONFIDENCE_THRESHOLD`.

## Deployment

- macOS Apple Silicon: `scripts/install_macos.sh`, then start local-jev and run the engine natively.
- Linux: `docker compose up --build`; the engine connects to a separately hosted local-jev URL via `LOCAL_JEV_BASE_URL`. Docker on macOS is not assumed to provide Apple GPU acceleration.

## Safety and privacy

No automated enforcement. No external target activity is performed. See [SECURITY.md](SECURITY.md), [PRIVACY.md](PRIVACY.md), and [THREAT_MODEL.md](THREAT_MODEL.md). Events and assessments are local SQLite records; configure retention and file-system access for your environment.

## Project state

This is v0.1 and an engineering prototype. Authentication, multi-tenant access control, enterprise retention controls, advanced log rotation support and production calibration remain outside the first release. Actual benchmark results and limitations are in [reports/BENCHMARK.md](reports/BENCHMARK.md). Release steps are in [RELEASE_COMMANDS.md](RELEASE_COMMANDS.md).
