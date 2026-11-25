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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Records that fork() failed with EPERM under Seatbelt before confine_apply()
 * lowered RLIMIT_NPROC to 0. Once RLIMIT_NPROC is 0, XNU enforces the rlimit
 * before the Seatbelt MAC hook and returns EAGAIN instead of EPERM.
 */
static _Atomic bool g_seatbelt_fork_eperm_verified = false;

uint8_t confine_check_fork(char *detail, size_t detail_len)
{
	errno = 0;
	pid_t pid = fork();
	if (pid == 0) {
		_exit(0);
	}
	if (pid > 0) {
		while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
		}
		snprintf(detail, detail_len, "fork succeeded");
		return GVX_GPU_CONFINE_ALLOWED;
	}
	int err = errno;
	if (err == EPERM) {
		atomic_store_explicit(&g_seatbelt_fork_eperm_verified, true, memory_order_release);
		return GVX_GPU_CONFINE_DENIED;
	}
	if (err == EAGAIN &&
	    atomic_load_explicit(&g_seatbelt_fork_eperm_verified, memory_order_acquire)) {
		struct rlimit nproc;
		if (getrlimit(RLIMIT_NPROC, &nproc) == 0 &&
		    nproc.rlim_cur == 0 && nproc.rlim_max == 0) {
			return GVX_GPU_CONFINE_DENIED;
		}
	}
	snprintf(detail, detail_len, "unexpected fork errno %d (%s)", err, strerror(err));
	return GVX_GPU_CONFINE_UNEXPECTED;
}

uint8_t confine_check_exec(char *detail, size_t detail_len)
{
	/* Invoke /usr/bin/false so an allowed exec exits non-zero rather than 0. */
	(void)execl("/usr/bin/false", "false", (char *)NULL);
	if (errno == EPERM || errno == EACCES) {
		return GVX_GPU_CONFINE_DENIED;
	}
	snprintf(detail, detail_len, "unexpected exec errno %d (%s)", errno, strerror(errno));
	return GVX_GPU_CONFINE_UNEXPECTED;
}

uint8_t confine_check_read(char *detail, size_t detail_len)
{
	int fd = open("/etc/passwd", O_RDONLY);
	if (fd >= 0) {
		(void)close(fd);
		snprintf(detail, detail_len, "open /etc/passwd succeeded");
		return GVX_GPU_CONFINE_ALLOWED;
	}
	if (errno == EPERM || errno == EACCES) {
		return GVX_GPU_CONFINE_DENIED;
	}
	snprintf(detail, detail_len, "unexpected errno %d (%s)", errno, strerror(errno));
	return GVX_GPU_CONFINE_UNEXPECTED;
}

uint8_t confine_check_create(char *detail, size_t detail_len)
{
	char path[128];
	snprintf(path, sizeof(path), "/private/tmp/gvx-gpu-selftest-%d", (int)getpid());
	int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd >= 0) {
		(void)close(fd);
		(void)unlink(path);
		snprintf(detail, detail_len, "create %s succeeded", path);
		return GVX_GPU_CONFINE_ALLOWED;
	}
	if (errno == EPERM || errno == EACCES) {
		return GVX_GPU_CONFINE_DENIED;
	}
	snprintf(detail, detail_len, "unexpected errno %d (%s)", errno, strerror(errno));
	return GVX_GPU_CONFINE_UNEXPECTED;
}

uint8_t confine_check_connect(char *detail, size_t detail_len)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		if (errno == EPERM || errno == EACCES) {
			return GVX_GPU_CONFINE_DENIED;
		}
		snprintf(detail, detail_len, "unexpected socket errno %d (%s)", errno, strerror(errno));
		return GVX_GPU_CONFINE_UNEXPECTED;
	}

	int flags = fcntl(s, F_GETFL);
	if (flags >= 0) {
		(void)fcntl(s, F_SETFL, flags | O_NONBLOCK);
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(9);
	(void)inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

	int rc = connect(s, (const struct sockaddr *)&sa, sizeof(sa));
	int err = errno;
	(void)close(s);

	if (rc < 0 && (err == EPERM || err == EACCES)) {
		return GVX_GPU_CONFINE_DENIED;
	}
	if (rc == 0 || err == EINPROGRESS || err == ECONNREFUSED) {
		snprintf(detail, detail_len, "connect to 127.0.0.1:9 was allowed");
		return GVX_GPU_CONFINE_ALLOWED;
	}
	snprintf(detail, detail_len, "unexpected connect errno %d (%s)", err, strerror(err));
	return GVX_GPU_CONFINE_UNEXPECTED;
}
