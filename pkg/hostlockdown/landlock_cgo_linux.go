// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && cgo

package hostlockdown

/*
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#endif

#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif

#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif

static pthread_mutex_t gvx_ll_mu = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int gvx_ll_ruleset_fd;
static _Atomic int gvx_ll_target_tid;
static _Atomic int gvx_ll_done;
static _Atomic int gvx_ll_errno;

static void gvx_ll_handler(int sig) {
	(void)sig;
	int saved_errno = errno;
	int tid = (int)syscall(SYS_gettid);
	if (tid != atomic_load_explicit(&gvx_ll_target_tid, memory_order_acquire)) {
		errno = saved_errno;
		return;
	}
	int fd = atomic_load_explicit(&gvx_ll_ruleset_fd, memory_order_acquire);
	int err = 0;
	if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
		err = errno != 0 ? errno : EINVAL;
	} else if (syscall(SYS_landlock_restrict_self, fd, 0UL) != 0) {
		err = errno != 0 ? errno : EINVAL;
	}
	atomic_store_explicit(&gvx_ll_errno, err, memory_order_release);
	atomic_store_explicit(&gvx_ll_done, 1, memory_order_release);
	(void)syscall(SYS_futex, &gvx_ll_done, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
	errno = saved_errno;
}

// gvx_landlock_pick_signal selects the lowest available real-time signal in
// [SIGRTMIN, SIGRTMAX]. This range avoids NPTL internal signals below SIGRTMIN
// and Go SIGURG. Scanning from SIGRTMIN selects signal 34 on glibc, which Go
// marks _SigUnblock. On musl it selects signal 35, which the Go caller unblocks
// through signal.Notify.
static int gvx_landlock_pick_signal(void) {
	int rtmin = SIGRTMIN;
	int rtmax = SIGRTMAX;
	for (int s = rtmin; s <= rtmax; s++) {
		struct sigaction old_sa;
		memset(&old_sa, 0, sizeof(old_sa));
		if (sigaction(s, NULL, &old_sa) != 0) {
			continue;
		}
		if (old_sa.sa_handler == SIG_DFL && (old_sa.sa_flags & SA_SIGINFO) == 0) {
			return s;
		}
	}
	for (int s = rtmin; s <= rtmax; s++) {
		struct sigaction old_sa;
		memset(&old_sa, 0, sizeof(old_sa));
		if (sigaction(s, NULL, &old_sa) != 0) {
			continue;
		}
		if (old_sa.sa_handler != SIG_IGN) {
			return s;
		}
	}
	return -1;
}

static int gvx_ll_restrict_tid(int pid, int tid, int sig) {
	atomic_store_explicit(&gvx_ll_errno, 0, memory_order_relaxed);
	atomic_store_explicit(&gvx_ll_done, 0, memory_order_relaxed);
	atomic_store_explicit(&gvx_ll_target_tid, tid, memory_order_seq_cst);

	if (syscall(SYS_tgkill, pid, tid, sig) != 0) {
		int err = errno;
		atomic_store_explicit(&gvx_ll_target_tid, 0, memory_order_release);
		if (err == ESRCH) {
			return 0;
		}
		return err != 0 ? err : EINVAL;
	}

	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 10 * 1000 * 1000;
	for (int i = 0; i < 500; i++) {
		if (atomic_load_explicit(&gvx_ll_done, memory_order_acquire) != 0) {
			atomic_store_explicit(&gvx_ll_target_tid, 0, memory_order_release);
			return atomic_load_explicit(&gvx_ll_errno, memory_order_acquire);
		}
		(void)syscall(SYS_futex, &gvx_ll_done, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts, NULL, 0);
		if (atomic_load_explicit(&gvx_ll_done, memory_order_acquire) != 0) {
			atomic_store_explicit(&gvx_ll_target_tid, 0, memory_order_release);
			return atomic_load_explicit(&gvx_ll_errno, memory_order_acquire);
		}
		if (syscall(SYS_tgkill, pid, tid, 0) != 0 && errno == ESRCH) {
			atomic_store_explicit(&gvx_ll_target_tid, 0, memory_order_release);
			return 0;
		}
	}

	atomic_store_explicit(&gvx_ll_target_tid, 0, memory_order_release);
	return ETIMEDOUT;
}

static int gvx_ll_seen_contains(const int *seen, size_t len, int tid) {
	for (size_t i = 0; i < len; i++) {
		if (seen[i] == tid) {
			return 1;
		}
	}
	return 0;
}

static int gvx_ll_seen_add(int **seen, size_t *len, size_t *cap, int tid) {
	if (*len == *cap) {
		size_t next_cap = (*cap == 0) ? 64 : (*cap * 2);
		int *next = (int *)realloc(*seen, next_cap * sizeof(int));
		if (next == NULL) {
			return ENOMEM;
		}
		*seen = next;
		*cap = next_cap;
	}
	(*seen)[*len] = tid;
	(*len)++;
	return 0;
}

static int gvx_landlock_restrict_all(int ruleset_fd, int sig) {
	if (sig < SIGRTMIN || sig > SIGRTMAX) {
		return EBUSY;
	}
	pthread_mutex_lock(&gvx_ll_mu);

	// Open /proc/self/task before restricting the calling thread so Landlock
	// does not block the directory open. rewinddir and readdir operate on the
	// open descriptor without reopening paths.
	DIR *dir = opendir("/proc/self/task");
	if (dir == NULL) {
		int err = errno != 0 ? errno : ENOENT;
		pthread_mutex_unlock(&gvx_ll_mu);
		return err;
	}

	struct sigaction old_sa;
	memset(&old_sa, 0, sizeof(old_sa));
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = gvx_ll_handler;
	sa.sa_flags = SA_ONSTACK | SA_RESTART;
	sigfillset(&sa.sa_mask);
	if (sigaction(sig, &sa, &old_sa) != 0) {
		int err = errno != 0 ? errno : EINVAL;
		closedir(dir);
		pthread_mutex_unlock(&gvx_ll_mu);
		return err;
	}

	atomic_store_explicit(&gvx_ll_ruleset_fd, ruleset_fd, memory_order_release);
	atomic_store_explicit(&gvx_ll_target_tid, 0, memory_order_release);
	atomic_store_explicit(&gvx_ll_done, 0, memory_order_release);
	atomic_store_explicit(&gvx_ll_errno, 0, memory_order_release);

	int *seen = NULL;
	size_t seen_len = 0;
	size_t seen_cap = 0;
	int pid = (int)getpid();
	int self_tid = (int)syscall(SYS_gettid);
	int result = 0;

	if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) != 0) {
		result = errno != 0 ? errno : EINVAL;
	} else if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0UL) != 0) {
		result = errno != 0 ? errno : EINVAL;
	} else {
		result = gvx_ll_seen_add(&seen, &seen_len, &seen_cap, self_tid);
	}

	int clean_passes = 0;
	while (result == 0 && clean_passes < 2) {
		rewinddir(dir);
		int new_in_pass = 0;
		for (;;) {
			errno = 0;
			struct dirent *ent = readdir(dir);
			if (ent == NULL) {
				if (errno != 0) {
					result = errno;
				}
				break;
			}
			if (ent->d_name[0] < '1' || ent->d_name[0] > '9') {
				continue;
			}
			char *end = NULL;
			long parsed = strtol(ent->d_name, &end, 10);
			if (end == NULL || *end != '\0' || parsed <= 0 || parsed > 0x7fffffffL) {
				continue;
			}
			int tid = (int)parsed;
			if (gvx_ll_seen_contains(seen, seen_len, tid)) {
				continue;
			}
			int err = gvx_ll_restrict_tid(pid, tid, sig);
			if (err != 0) {
				result = err;
				break;
			}
			err = gvx_ll_seen_add(&seen, &seen_len, &seen_cap, tid);
			if (err != 0) {
				result = err;
				break;
			}
			new_in_pass++;
		}
		if (result != 0) {
			break;
		}
		if (new_in_pass == 0) {
			clean_passes++;
		} else {
			clean_passes = 0;
		}
	}

	if (result == ETIMEDOUT && old_sa.sa_handler == SIG_DFL && (old_sa.sa_flags & SA_SIGINFO) == 0) {
		struct sigaction ign;
		memset(&ign, 0, sizeof(ign));
		ign.sa_handler = SIG_IGN;
		sigemptyset(&ign.sa_mask);
		(void)sigaction(sig, &ign, NULL);
	} else {
		(void)sigaction(sig, &old_sa, NULL);
	}

	free(seen);
	closedir(dir);
	pthread_mutex_unlock(&gvx_ll_mu);
	return result;
}
*/
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
)

var cgoLandlockMu sync.Mutex

// restrictCgoThreadsLandlock applies rulesetFD to every task in /proc/self/task
// using a real-time signal handler when cgo disables AllThreadsSyscall.
func restrictCgoThreadsLandlock(rulesetFD int) error {
	cgoLandlockMu.Lock()
	defer cgoLandlockMu.Unlock()

	sig := int(C.gvx_landlock_pick_signal())
	if sig < 0 {
		return fmt.Errorf("hostlockdown: restrict cgo threads with Landlock: %w", syscall.EBUSY)
	}
	// Signals above 34 lack _SigUnblock in the Go runtime signal table, so
	// ensureSigM keeps them blocked until signal.Notify enables the signal.
	if sig > 34 {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.Signal(sig))
		defer signal.Stop(sigCh)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if rc := C.gvx_landlock_restrict_all(C.int(rulesetFD), C.int(sig)); rc != 0 {
		return fmt.Errorf("hostlockdown: restrict cgo threads with Landlock: %w", syscall.Errno(rc))
	}
	return nil
}
