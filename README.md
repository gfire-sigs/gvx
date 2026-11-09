# Cross-Platform Benchmark Results

This branch records automated cross-platform `TestE2EMicroBench` latency and host CPU utilization results.

## Latest Summary by Platform and Backend

| Target | Backend | Commit | `host_new` | `getpid` | `open_close` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `darwin/arm64` | `hvf` | `ce792c97` | 11.39 ms | 1.3 us (206%) | 5.2 us (257%) | 15.1 us (401%) | 25.9 us (566%) | 940.2 us (293%) | 232.0 us (323%) | 0.3% CPU |
| `linux/amd64` | `systrap` | `ff237f9c` | 2.44 ms | 4.1 us (105%) | 14.5 us (115%) | 28.1 us (120%) | 9.6 us (113%) | 3.40 ms (188%) | 602.9 us (129%) | 0.3% CPU |
| `linux/arm64` | `systrap` | `ff237f9c` | 2.40 ms | 3.1 us (102%) | 10.5 us (110%) | 16.7 us (111%) | 6.7 us (105%) | 1.80 ms (184%) | 641.1 us (116%) | 0.2% CPU |
| `windows/amd64` | `systrap` | `ff237f9c` | 60.52 ms | 790 ns (100%) | 6.4 us (105%) | 68.4 us (98%) | 68.2 us (97%) | 3.82 ms (151%) | 2.07 ms (115%) | 2.5% CPU |
| `windows/amd64` | `whpx` | `ff237f9c` | 19.48 ms | 30.9 us (106%) | 71.3 us (148%) | 150.0 us (207%) | 136.9 us (224%) | 1.11 ms (271%) | 2.52 ms (131%) | 0.0% CPU |
| `windows/arm64` | `systrap` | `ff237f9c` | 82.56 ms | 932 ns (97%) | 5.3 us (118%) | 33.3 us (115%) | 26.8 us (136%) | 1.94 ms (128%) | 1.29 ms (85%) | 2.3% CPU |

## Historical Trend (Last 10 Runs per Target)

### `darwin/arm64` (`hvf`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T15:32:50Z` | `ce792c97` | 1.3 us (206%) | 15.1 us (401%) | 25.9 us (566%) | 940.2 us (293%) | 232.0 us (323%) | 0.3% CPU | 0 |

### `linux/amd64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 4.1 us (105%) | 28.1 us (120%) | 9.6 us (113%) | 3.40 ms (188%) | 602.9 us (129%) | 0.3% CPU | 0 |

### `linux/arm64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 3.1 us (102%) | 16.7 us (111%) | 6.7 us (105%) | 1.80 ms (184%) | 641.1 us (116%) | 0.2% CPU | 0 |

### `windows/amd64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 790 ns (100%) | 68.4 us (98%) | 68.2 us (97%) | 3.82 ms (151%) | 2.07 ms (115%) | 2.5% CPU | 0 |

### `windows/amd64` (`whpx`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 30.9 us (106%) | 150.0 us (207%) | 136.9 us (224%) | 1.11 ms (271%) | 2.52 ms (131%) | 0.0% CPU | 0 |

### `windows/arm64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 932 ns (97%) | 33.3 us (115%) | 26.8 us (136%) | 1.94 ms (128%) | 1.29 ms (85%) | 2.3% CPU | 0 |

