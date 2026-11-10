# Cross-Platform Benchmark Results

This branch records automated cross-platform `TestE2EMicroBench` latency and host CPU utilization results.

## Latest Summary by Platform and Backend

| Target | Backend | Commit | `host_new` | `getpid` | `open_close` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `darwin/arm64` | `hvf` | `ce792c97` | 11.39 ms | 1.3 us (206%) | 5.2 us (257%) | 15.1 us (401%) | 25.9 us (566%) | 940.2 us (293%) | 232.0 us (323%) | 0.3% CPU |
| `linux/amd64` | `systrap` | `aa721377` | 2.53 ms | 4.1 us (104%) | 14.1 us (114%) | 24.6 us (110%) | 8.0 us (108%) | 1.99 ms (187%) | 527.1 us (128%) | 0.2% CPU |
| `linux/arm64` | `systrap` | `aa721377` | 2.84 ms | 3.1 us (102%) | 10.7 us (109%) | 17.0 us (111%) | 6.5 us (106%) | 1.99 ms (180%) | 706.5 us (117%) | 0.3% CPU |
| `windows/amd64` | `systrap` | `aa721377` | 63.72 ms | 530 ns (86%) | 5.2 us (115%) | 78.4 us (120%) | 65.1 us (115%) | 8.64 ms (89%) | 7.12 ms (64%) | 3.1% CPU |
| `windows/amd64` | `whpx` | `aa721377` | 14.95 ms | 16.2 us (99%) | 44.4 us (149%) | 156.8 us (193%) | 142.5 us (200%) | 755.8 us (266%) | 1.67 ms (157%) | 0.8% CPU |
| `windows/arm64` | `systrap` | `aa721377` | 98.14 ms | 907 ns (94%) | 5.6 us (96%) | 29.6 us (114%) | 26.9 us (108%) | 12.41 ms (29%) | 16.18 ms (16%) | 0.0% CPU |

## Historical Trend (Last 10 Runs per Target)

### `darwin/arm64` (`hvf`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-09T15:32:50Z` | `ce792c97` | 1.3 us (206%) | 15.1 us (401%) | 25.9 us (566%) | 940.2 us (293%) | 232.0 us (323%) | 0.3% CPU | 0 |

### `linux/amd64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-10T01:45:08Z` | `aa721377` | 4.1 us (104%) | 24.6 us (110%) | 8.0 us (108%) | 1.99 ms (187%) | 527.1 us (128%) | 0.2% CPU | 0 |
| `2026-11-09T17:02:10Z` | `153b900b` | 2.9 us (102%) | 14.9 us (112%) | 4.8 us (106%) | 1.81 ms (169%) | 304.0 us (123%) | 0.2% CPU | 0 |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 4.1 us (105%) | 28.1 us (120%) | 9.6 us (113%) | 3.40 ms (188%) | 602.9 us (129%) | 0.3% CPU | 0 |

### `linux/arm64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-10T01:45:08Z` | `aa721377` | 3.1 us (102%) | 17.0 us (111%) | 6.5 us (106%) | 1.99 ms (180%) | 706.5 us (117%) | 0.3% CPU | 0 |
| `2026-11-09T17:02:10Z` | `153b900b` | 3.1 us (102%) | 17.4 us (110%) | 6.9 us (106%) | 1.99 ms (180%) | 722.0 us (116%) | 0.2% CPU | 0 |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 3.1 us (102%) | 16.7 us (111%) | 6.7 us (105%) | 1.80 ms (184%) | 641.1 us (116%) | 0.2% CPU | 0 |

### `windows/amd64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-10T01:45:08Z` | `aa721377` | 530 ns (86%) | 78.4 us (120%) | 65.1 us (115%) | 8.64 ms (89%) | 7.12 ms (64%) | 3.1% CPU | 0 |
| `2026-11-09T17:02:10Z` | `153b900b` | 535 ns (95%) | 81.2 us (116%) | 68.9 us (118%) | 10.87 ms (73%) | 9.61 ms (47%) | 3.9% CPU | 0 |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 790 ns (100%) | 68.4 us (98%) | 68.2 us (97%) | 3.82 ms (151%) | 2.07 ms (115%) | 2.5% CPU | 0 |

### `windows/amd64` (`whpx`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-10T01:45:08Z` | `aa721377` | 16.2 us (99%) | 156.8 us (193%) | 142.5 us (200%) | 755.8 us (266%) | 1.67 ms (157%) | 0.8% CPU | 0 |
| `2026-11-09T17:02:10Z` | `153b900b` | 16.6 us (109%) | 158.8 us (165%) | 147.5 us (198%) | 915.1 us (249%) | 1.69 ms (140%) | 0.0% CPU | 0 |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 30.9 us (106%) | 150.0 us (207%) | 136.9 us (224%) | 1.11 ms (271%) | 2.52 ms (131%) | 0.0% CPU | 0 |

### `windows/arm64` (`systrap`)

| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2026-11-10T01:45:08Z` | `aa721377` | 907 ns (94%) | 29.6 us (114%) | 26.9 us (108%) | 12.41 ms (29%) | 16.18 ms (16%) | 0.0% CPU | 0 |
| `2026-11-09T17:02:10Z` | `153b900b` | 866 ns (97%) | 30.4 us (126%) | 28.3 us (111%) | 16.44 ms (24%) | 15.00 ms (18%) | 1.6% CPU | 0 |
| `2026-11-09T16:09:12Z` | `ff237f9c` | 932 ns (97%) | 33.3 us (115%) | 26.8 us (136%) | 1.94 ms (128%) | 1.29 ms (85%) | 2.3% CPU | 0 |

