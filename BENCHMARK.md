# Benchmark entry point

The reproducible synthetic evaluation and the M5/local-jev measurements are in [reports/BENCHMARK.md](reports/BENCHMARK.md). Per-model held-out metrics are in [reports/local_jev_benchmark.md](reports/local_jev_benchmark.md), with machine-readable results in [reports/local_jev_benchmark.csv](reports/local_jev_benchmark.csv).

Run `./.venv/bin/security-engine generate-dataset --out datasets/generated --entities 1200 --seed 20261001` followed by `./.venv/bin/security-engine benchmark --data datasets/generated --reports reports/local_jev/<model> --provider local_jev --model <model> --sample-limit 70`. The split is entity-disjoint; config thresholds are held fixed and no test labels are used for threshold tuning.
