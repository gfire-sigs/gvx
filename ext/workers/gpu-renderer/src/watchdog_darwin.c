/*
 * Copyright 2026 The gVisor Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "renderer.h"

#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static uint64_t g_watchdog_limit = 0;
static atomic_bool g_watchdog_armed = false;

int watchdog_sample_footprint(uint64_t *out_bytes)
{
	task_vm_info_data_t info;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	kern_return_t kr = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count);
	if (kr != KERN_SUCCESS || count < TASK_VM_INFO_REV1_COUNT) {
		return EIO;
	}
	*out_bytes = (uint64_t)info.phys_footprint;
	return 0;
}

void watchdog_arm(void)
{
	atomic_store_explicit(&g_watchdog_armed, true, memory_order_release);
}

static void *watchdog_thread(void *arg)
{
	(void)arg;
	const struct timespec period = {
		.tv_sec = GVX_GPU_WATCHDOG_PERIOD_MILLIS / 1000u,
		.tv_nsec = (long)(GVX_GPU_WATCHDOG_PERIOD_MILLIS % 1000u) * 1000000L,
	};

	for (;;) {
		struct timespec rem = period;
		while (nanosleep(&rem, &rem) != 0 && errno == EINTR) {
		}

		if (!atomic_load_explicit(&g_watchdog_armed, memory_order_acquire)) {
			continue;
		}

		uint64_t footprint = 0;
		if (watchdog_sample_footprint(&footprint) != 0) {
			continue;
		}
		if (footprint > g_watchdog_limit) {
			char msg[160];
			int n = snprintf(
			    msg, sizeof(msg),
			    "gvx-gpu-renderer: memory footprint %" PRIu64
			    " bytes exceeds %" PRIu64 " bytes\n",
			    footprint, g_watchdog_limit);
			if (n > 0) {
				size_t len = (size_t)n < sizeof(msg) ? (size_t)n : sizeof(msg) - 1;
				ssize_t ignored = write(STDERR_FILENO, msg, len);
				(void)ignored;
			}
			/* Avoid exit() so driver atexit handlers do not run concurrently. */
			_exit(GVX_GPU_EXIT_MEMORY_LIMIT);
		}
	}
	return NULL;
}

int watchdog_start(uint64_t limit_bytes)
{
	if (limit_bytes == 0) {
		return 0;
	}

	/* Take one sample before starting the thread so start fails fast if blocked. */
	uint64_t initial = 0;
	int err = watchdog_sample_footprint(&initial);
	if (err != 0) {
		return err;
	}

	g_watchdog_limit = limit_bytes;
	atomic_store_explicit(&g_watchdog_armed, false, memory_order_relaxed);

	pthread_attr_t attr;
	err = pthread_attr_init(&attr);
	if (err != 0) {
		return err;
	}
	err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err != 0) {
		(void)pthread_attr_destroy(&attr);
		return err;
	}

	pthread_t tid;
	err = pthread_create(&tid, &attr, watchdog_thread, NULL);
	(void)pthread_attr_destroy(&attr);
	return err;
}
