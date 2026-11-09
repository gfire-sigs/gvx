# Cross-Platform Benchmark Results

This branch records automated cross-platform `TestE2EMicroBench` latency and host CPU utilization results.

## Latest Summary by Platform and Backend

| Target | Backend | Commit | `host_new` | `getpid` | `open_close` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `darwin/arm64` | `hvf` | `ce792c97` | 11.39 ms | 1.3 us (206%) | 5.2 us (257%) | 15.1 us (401%) | 25.9 us (566%) | 940.2 us (293%) | 232.0 us (323%) | 0.3% CPU |

## Historical Trend (Last 10 Runs per Target)

### `darwin/arm64` (`hvf`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T15:32:50Z` | `ce792c97` | 1.3 us (206%) | 15.1 us (401%) | 25.9 us (566%) | 940.2 us (293%) | 232.0 us (323%) | 0.3% CPU | 0 |

