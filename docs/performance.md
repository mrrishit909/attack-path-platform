# Performance

Docker stack (one uvicorn process, one worker, Postgres 16) holding the full synthetic estate: 8,675 assets, 4,453 identities,
23,737 relationships, 6,915 open findings. Closed loop, 8 seconds per level. Reproduce with `make demo && make load-test`.

## Reads: summary, attack paths, remediation backlog (in rotation)

Hardware: arm64, 12 cores, Darwin (client and server on the same machine)

| Concurrency | Requests | Throughput | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|
| 1 | 2706 | 338.2 req/s | 2.8 ms | 3.9 ms | 4.9 ms | 0.00% |
| 8 | 3945 | 492.5 req/s | 15.3 ms | 21.0 ms | 24.2 ms | 0.00% |
| 32 | 2654 | 329.7 req/s | 69.3 ms | 86.9 ms | 98.4 ms | 0.00% |

Target: p95 under 750 ms for interactive reads. Met with a wide margin, because paths are computed once per snapshot by the sync job
and reads only fetch stored rows.

## Simulation: `POST /v1/simulations` (optimizer chooses two fixes estate-wide, then re-searches the graph)

| Concurrency | Requests | Throughput | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|
| 1 | 30 | 3.7 req/s | 263.8 ms | 340.7 ms | 341.3 ms | 0.00% |
| 2 | 30 | 3.6 req/s | 542.6 ms | 606.6 ms | 607.9 ms | 0.00% |
| 8 | 33 | 3.3 req/s | 2344.4 ms | 2999.8 ms | 3054.2 ms | 0.00% |

This is the saturation case. One simulation is about a quarter of a second of pure Python and solver time, and the API is a single
process, so requests queue: 8 concurrent analysts wait about 3 seconds each. Nothing is dropped. The fix is known and not built:
run simulations on the worker pool (the job queue already exists) or add API processes.

## Sync job (from the job result)

Collect + normalize 177 ms, write + reload 853 ms, search + optimize 183 ms for the whole estate.
A second sync of an unchanged estate updates rows in place: same counts, no duplicates (`test_resync_is_idempotent`).
