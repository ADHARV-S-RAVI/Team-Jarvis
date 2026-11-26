# Q-SHIELD — Benchmark Methodology

## 1. Measurement Design (`scripts/benchmark.py`)
- **Timer:** `time.perf_counter_ns()` (nanosecond monotonic clock, converted to milliseconds).
- **Deterministic Seed:** `SEED = 42`.
- **Warm-ups & Repeated Samples:** Each operation runs explicit warm-up iterations (`1`–`5`) before collecting `5`–`100` timed samples.
- **Error Accounting:** Failed samples are counted in `errors` and recorded in `reports/benchmarks/raw_samples.csv` with `status=err:<Exception>` — never silently excluded.

## 2. Statistical Formulas
- **Mean:** Arithmetic mean of successful sample durations (ms).
- **Percentiles (`p50`, `p95`, `p99`):** Nearest-rank method `idx = min(N - 1, max(0, ceil(p * N) - 1))` on sorted sample durations.
- **Standard Deviation:** Sample standard deviation (`statistics.stdev`).
- **Throughput (`ops/s`):** `len(success_samples) / (sum(durations_ms) / 1000.0)`.

## 3. Environment & Resource Measurement
- **OS / Python:** Windows 11 (`Windows-11-10.0.26200-SP0`), Python `3.12.3`, 4 CPU cores.
- **CPU & Peak RAM:** Measured via `psutil.Process()` (`cpu_times().user`, `cpu_times().system`, `memory_info().rss` in MB). Latest run: `4.703s` user / `2.531s` sys, `118.69 MB` RSS, `15.15 s` total suite duration.

## 4. Simulated-Node Measurement Limitations
- `node_revocation_convergence_{3,5,7}nodes` benchmarks measure **in-process simulated nodes** backed by SQLite, not physical network RTT across separate hosts.
- `ML-DSA` is **NOT IMPLEMENTED** and is omitted from measurements.

## 5. Evidence Files
- [reports/benchmarks/latest.json](../../reports/benchmarks/latest.json)
- [reports/benchmarks/raw_samples.csv](../../reports/benchmarks/raw_samples.csv)
- [reports/benchmarks/summary.md](../../reports/benchmarks/summary.md)
- [docs/STAGE11_INTEGRATION_BENCHMARKS.md](STAGE11_INTEGRATION_BENCHMARKS.md)
