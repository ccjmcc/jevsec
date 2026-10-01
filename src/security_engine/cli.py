from __future__ import annotations

import asyncio
import os
import platform
import socket
import sys
import time
from pathlib import Path

import httpx
import typer

from .benchmark import render_report, run_benchmark
from .aggregation import active_window_keys
from .config import settings
from .dataset import generate_dataset
from .decision import LocalJevProvider, MockProvider
from .engine import analyze
from .parser import parse_line
from .storage import Store

app = typer.Typer(no_args_is_help=True, help="Self-hosted security behavior detection and triage")

def _provider():
    return LocalJevProvider(settings.local_jev_base_url, settings.local_jev_model, settings.decision_timeout) if settings.decision_provider == "local_jev" else MockProvider()

@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Run the API and dashboard."""
    import uvicorn
    uvicorn.run("security_engine.api:app", host=host, port=port, reload=False)

@app.command()
def ingest(path: Path = typer.Argument(..., exists=True, readable=True), format: str = typer.Option("auto", "--format", help="auto, nginx or jsonl"),
           follow: bool = typer.Option(False, "--follow", "-f"), mode: str = typer.Option("hybrid", help="hybrid, rules_only, jev_only")):
    """Import a log once or tail it as new lines are appended. Parser errors are counted and skipped."""
    store = Store(settings.database)
    good = bad = assessments = 0
    offset = 0
    parsed = []
    async def process(lines: list[str]):
        nonlocal good, bad, assessments, parsed
        batch = []
        for line in lines:
            try:
                batch.append(parse_line(line, format))
            except Exception as exc:
                bad += 1
                typer.echo(f"parser_error line={good + bad}: {exc}", err=True)
        if not batch:
            return
        known_sources = store.source_ips()
        active = active_window_keys(batch)
        store.add_events(batch)
        good += len(batch)
        parsed.extend(batch)
        five_minute_starts = [start for _, _, window, start in active if window == "5m"]
        start = min(five_minute_starts) if five_minute_starts else min(e.timestamp for e in batch)
        source = store.recent_events(start, {e.source_ip for e in batch}, {e.session_hash for e in batch if e.session_hash})
        results = await analyze(source, _provider(), mode, known_sources=known_sources, active_windows=active)
        for item in results: store.add_assessment(item)
        assessments += len(results)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
        offset = sum(len(x.encode("utf-8", errors="replace")) for x in lines)
        asyncio.run(process(lines))
        if follow:
            pending = []
            last_flush = time.monotonic()
            while True:
                line = f.readline()
                if line:
                    pending.append(line)
                    offset += len(line.encode("utf-8", errors="replace"))
                elif pending and time.monotonic() - last_flush >= .5:
                    asyncio.run(process(pending))
                    pending = []
                    last_flush = time.monotonic()
                else:
                    time.sleep(.25)
    typer.echo(f"ingest_complete events={good} parser_errors={bad} assessments={assessments} bytes_read={offset}")

@app.command("generate-dataset")
def generate(out: Path = typer.Option(Path("datasets/generated"), "--out"), entities: int = typer.Option(1200), seed: int = typer.Option(20261001)):
    event_path, labels_path = generate_dataset(out, entities, seed)
    typer.echo(f"generated events={event_path} labels={labels_path} entities={sum(1 for _ in labels_path.open())-1}")

@app.command()
def benchmark(data: Path = typer.Option(Path("datasets/generated"), "--data"), reports: Path = typer.Option(Path("reports"), "--reports"),
              provider: str = typer.Option("local_jev", help="local_jev or mock; mock is explicitly not an ML benchmark"),
              model: str = typer.Option(settings.local_jev_model), sample_limit: int = typer.Option(120)):
    """Run fixed held-out rules and provider comparisons; writes CSV, JSON and Markdown."""
    async def run():
        meta = await run_benchmark(data, reports, provider, model, settings.local_jev_base_url, sample_limit)
        render_report(meta, reports / "BENCHMARK.md")
        return meta
    meta = asyncio.run(run())
    typer.echo(f"benchmark complete provider={meta['provider']} model={meta['model']} inferences={meta['model_inferences']} report={reports / 'BENCHMARK.md'}")

@app.command()
def doctor():
    """Check runtime, database, ports, Jev health and model inventory."""
    print(f"System: {platform.platform()}\nArchitecture: {platform.machine()}\nPython: {sys.version.split()[0]}")
    store = Store(settings.database)
    print(f"Database: {store.path.resolve()} (events={store.stats()['total_events']})")
    for port in (8000, 8765):
        sock = socket.socket(); sock.settimeout(.3)
        result = sock.connect_ex(("127.0.0.1", port)) == 0
        sock.close()
        print(f"Port {port}: {'in use' if result else 'available'}")
    try:
        import urllib.request
        with urllib.request.urlopen(settings.local_jev_base_url + "/healthz", timeout=2) as r:
            print(f"Jev connectivity: {r.status} {r.read().decode()[:300]}")
        with urllib.request.urlopen(settings.local_jev_base_url + "/v1/models", timeout=3) as r:
            print(f"Available models: {r.read().decode()[:1000]}")
    except Exception as exc:
        print(f"Jev connectivity: unavailable ({exc})")
    print(f"Configuration: provider={settings.decision_provider}, model={settings.local_jev_model}, mode={settings.mode}")

if __name__ == "__main__":
    app()
