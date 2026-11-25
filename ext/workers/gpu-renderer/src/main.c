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
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include "virglrenderer.h"

#define RENDERER_MAX_LOG_BYTES 512

static enum virgl_log_level_flags g_min_virgl_log_level = VIRGL_LOG_LEVEL_WARNING;

static void init_virgl_log_level(void)
{
	const char *env = getenv("VIRGL_LOG_LEVEL");
	if (env == NULL || env[0] == '\0') {
		return;
	}
	if (strcmp(env, "debug") == 0) {
		g_min_virgl_log_level = VIRGL_LOG_LEVEL_DEBUG;
	} else if (strcmp(env, "info") == 0) {
		g_min_virgl_log_level = VIRGL_LOG_LEVEL_INFO;
	} else if (strcmp(env, "warning") == 0) {
		g_min_virgl_log_level = VIRGL_LOG_LEVEL_WARNING;
	} else if (strcmp(env, "error") == 0) {
		g_min_virgl_log_level = VIRGL_LOG_LEVEL_ERROR;
	} else if (strcmp(env, "silent") == 0) {
		g_min_virgl_log_level = VIRGL_LOG_LEVEL_SILENT;
	}
}

static void renderer_virgl_log(enum virgl_log_level_flags log_level,
                               const char *message,
                               void *user_data)
{
	(void)user_data;
	if (message == NULL || log_level < g_min_virgl_log_level) {
		return;
	}

	size_t len = strlen(message);
	while (len > 0 && (message[len - 1] == '\n' || message[len - 1] == '\r')) {
		len--;
	}
	if (len > RENDERER_MAX_LOG_BYTES) {
		len = RENDERER_MAX_LOG_BYTES;
	}

	char clean[RENDERER_MAX_LOG_BYTES + 1];
	for (size_t i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)message[i];
		clean[i] = (ch >= ' ' && ch <= '~') ? (char)ch : '?';
	}
	clean[len] = '\0';

	fprintf(stderr, "gvx-gpu-renderer: virgl: %s\n", clean);
}

static int print_usage(void)
{
	fprintf(stderr,
	        "gvx-gpu-renderer: usage: gvx-gpu-renderer [--mode=venus|virgl] [--selftest | --memory-limit=N]\n");
	return GVX_GPU_EXIT_USAGE;
}

static bool parse_macos_version(const char *s, long *major_out, long *minor_out, long *patch_out)
{
	if (s == NULL || s[0] < '0' || s[0] > '9') {
		return false;
	}
	char *end = NULL;
	errno = 0;
	long major = strtol(s, &end, 10);
	if (errno != 0 || end == s || (*end != '.' && *end != '\0') || major <= 0) {
		return false;
	}
	long minor = 0;
	long patch = 0;
	if (*end == '.') {
		const char *minor_start = end + 1;
		if (minor_start[0] < '0' || minor_start[0] > '9') {
			return false;
		}
		char *end2 = NULL;
		errno = 0;
		minor = strtol(minor_start, &end2, 10);
		if (errno != 0 || end2 == minor_start || (*end2 != '.' && *end2 != '\0') || minor < 0) {
			return false;
		}
		if (*end2 == '.') {
			const char *patch_start = end2 + 1;
			if (patch_start[0] < '0' || patch_start[0] > '9') {
				return false;
			}
			char *end3 = NULL;
			errno = 0;
			patch = strtol(patch_start, &end3, 10);
			if (errno != 0 || end3 == patch_start || (*end3 != '.' && *end3 != '\0') || patch < 0) {
				return false;
			}
		}
	}
	*major_out = major;
	*minor_out = minor;
	*patch_out = patch;
	return true;
}

static int check_macos_version(void)
{
	long min_major = 0;
	long min_minor = 0;
	long min_patch = 0;
	if (!parse_macos_version(GVX_RENDERER_MIN_MACOS, &min_major, &min_minor, &min_patch)) {
		fprintf(stderr, "gvx-gpu-renderer: unparsable minimum macOS version: %s\n",
		        GVX_RENDERER_MIN_MACOS);
		return -1;
	}

	char ver[64];
	size_t len = sizeof(ver);
	if (sysctlbyname("kern.osproductversion", ver, &len, NULL, 0) != 0 || len == 0) {
		fprintf(stderr, "gvx-gpu-renderer: sysctlbyname(kern.osproductversion): %s\n",
		        strerror(errno));
		return -1;
	}
	ver[sizeof(ver) - 1] = '\0';

	long host_major = 0;
	long host_minor = 0;
	long host_patch = 0;
	if (!parse_macos_version(ver, &host_major, &host_minor, &host_patch)) {
		fprintf(stderr, "gvx-gpu-renderer: unparsable macOS version: %s\n", ver);
		return -1;
	}
	bool too_old = host_major < min_major ||
	               (host_major == min_major && host_minor < min_minor) ||
	               (host_major == min_major && host_minor == min_minor && host_patch < min_patch);
	if (too_old) {
		fprintf(stderr,
		        "gvx-gpu-renderer: this bundle needs macOS %s or later (its KosmicKrisp driver was built for it); this host runs macOS %s\n",
		        GVX_RENDERER_MIN_MACOS, ver);
		return -1;
	}
	return 0;
}

static bool parse_u64_decimal(const char *s, uint64_t *out)
{
	if (s == NULL || s[0] == '\0') {
		return false;
	}
	uint64_t val = 0;
	for (size_t i = 0; s[i] != '\0'; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c < '0' || c > '9') {
			return false;
		}
		uint64_t digit = (uint64_t)(c - '0');
		if (val > (UINT64_MAX - digit) / 10u) {
			return false;
		}
		val = val * 10u + digit;
	}
	*out = val;
	return true;
}

int main(int argc, char **argv)
{
	(void)signal(SIGPIPE, SIG_IGN);
	(void)setvbuf(stderr, NULL, _IOLBF, 0);
	init_virgl_log_level();

	bool selftest = false;
	bool stall_fences = false;
	bool seen_mode = false;
	bool seen_memory_limit = false;
	bool seen_test_watchdog = false;
	uint32_t mode = GVX_GPU_MODE_VENUS;
	uint64_t memory_limit = 0;
	uint64_t test_watchdog_bytes = 0;

	const char *test_mode = getenv(GVX_GPU_ENV_TEST_MODE);
	const bool allow_test_args = (test_mode != NULL && strcmp(test_mode, "1") == 0);
	const size_t mode_prefix_len = strlen(GVX_GPU_ARG_MODE);
	const size_t mem_limit_prefix_len = strlen(GVX_GPU_ARG_MEMORY_LIMIT);
	const size_t test_wd_prefix_len = strlen(GVX_GPU_ARG_TEST_WATCHDOG_BYTES);

	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (strcmp(arg, GVX_GPU_ARG_SELFTEST) == 0) {
			if (selftest) {
				return print_usage();
			}
			selftest = true;
		} else if (strncmp(arg, GVX_GPU_ARG_MODE, mode_prefix_len) == 0) {
			if (seen_mode) {
				return print_usage();
			}
			const char *val = arg + mode_prefix_len;
			if (strcmp(val, GVX_GPU_MODE_NAME_VENUS) == 0) {
				mode = GVX_GPU_MODE_VENUS;
			} else if (strcmp(val, GVX_GPU_MODE_NAME_VIRGL) == 0) {
				mode = GVX_GPU_MODE_VIRGL;
			} else {
				return print_usage();
			}
			seen_mode = true;
		} else if (strcmp(arg, GVX_GPU_ARG_STALL_FENCES) == 0) {
			if (!allow_test_args || stall_fences) {
				return print_usage();
			}
			stall_fences = true;
		} else if (strncmp(arg, GVX_GPU_ARG_MEMORY_LIMIT, mem_limit_prefix_len) == 0) {
			if (seen_memory_limit ||
			    !parse_u64_decimal(arg + mem_limit_prefix_len, &memory_limit)) {
				return print_usage();
			}
			seen_memory_limit = true;
		} else if (strncmp(arg, GVX_GPU_ARG_TEST_WATCHDOG_BYTES, test_wd_prefix_len) == 0) {
			if (!allow_test_args ||
			    seen_test_watchdog ||
			    !parse_u64_decimal(arg + test_wd_prefix_len, &test_watchdog_bytes)) {
				return print_usage();
			}
			seen_test_watchdog = true;
		} else {
			return print_usage();
		}
	}
	if (selftest && argc != (seen_mode ? 3 : 2)) {
		return print_usage();
	}

	if (!selftest) {
		struct stat st;
		if (fstat(GVX_GPU_SOCKET_FD, &st) != 0 || !S_ISSOCK(st.st_mode)) {
			fprintf(stderr, "gvx-gpu-renderer: descriptor %d is not a socket\n",
			        GVX_GPU_SOCKET_FD);
			return GVX_GPU_EXIT_USAGE;
		}
		int sock_type = 0;
		socklen_t sock_type_len = sizeof(sock_type);
		if (getsockopt(GVX_GPU_SOCKET_FD, SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len) != 0 ||
		    sock_type != SOCK_STREAM) {
			fprintf(stderr, "gvx-gpu-renderer: descriptor %d is not a stream socket\n",
			        GVX_GPU_SOCKET_FD);
			return GVX_GPU_EXIT_USAGE;
		}
		int fl = fcntl(GVX_GPU_SOCKET_FD, F_GETFL);
		if (fl < 0 ||
		    ((fl & O_NONBLOCK) != 0 &&
		     fcntl(GVX_GPU_SOCKET_FD, F_SETFL, fl & ~O_NONBLOCK) != 0)) {
			fprintf(stderr,
			        "gvx-gpu-renderer: failed to configure blocking socket %d: %s\n",
			        GVX_GPU_SOCKET_FD, strerror(errno));
			return GVX_GPU_EXIT_INIT;
		}
	}

	virgl_set_log_callback(renderer_virgl_log, NULL, NULL);

	if (mode == GVX_GPU_MODE_VENUS && check_macos_version() != 0) {
		return GVX_GPU_EXIT_INIT;
	}

	struct bundle b;
	if (bundle_locate(&b) != 0) {
		return GVX_GPU_EXIT_INIT;
	}
	if (mode == GVX_GPU_MODE_VENUS && bundle_load_vulkan(&b) != 0) {
		return GVX_GPU_EXIT_INIT;
	}

	char err[256];
	if (mode == GVX_GPU_MODE_VIRGL) {
		err[0] = '\0';
		if (gl_cgl_init(err, sizeof(err)) != 0) {
			fprintf(stderr, "gvx-gpu-renderer: OpenGL probe failed: %s\n", err);
			return GVX_GPU_EXIT_INIT;
		}
	}

	/* virgl_renderer_init must run before Seatbelt confinement. */
	int ret = virgl_renderer_init(server_cookie(), renderer_virgl_flags(mode), server_callbacks());
	if (ret != 0) {
		fprintf(stderr, "gvx-gpu-renderer: virgl_renderer_init failed: %d\n", ret);
		return GVX_GPU_EXIT_INIT;
	}

	err[0] = '\0';
	if (server_init_capsets(mode, err, sizeof(err)) != 0) {
		fprintf(stderr, "gvx-gpu-renderer: capset init failed: %s\n", err);
		return GVX_GPU_EXIT_INIT;
	}

	err[0] = '\0';
	if (confine_apply(b.lib_dir, err, sizeof(err)) != 0) {
		fprintf(stderr, "gvx-gpu-renderer: confinement failed: %s\n", err);
		return GVX_GPU_EXIT_CONFINE;
	}

	if (selftest) {
		return selftest_run(&b, mode);
	}

	uint64_t watchdog_limit = 0;
	if (seen_test_watchdog) {
		watchdog_limit = test_watchdog_bytes;
	} else if (seen_memory_limit) {
		if (memory_limit > UINT64_MAX - GVX_GPU_WATCHDOG_HEADROOM_BYTES) {
			watchdog_limit = UINT64_MAX;
		} else {
			watchdog_limit = memory_limit + GVX_GPU_WATCHDOG_HEADROOM_BYTES;
		}
	}
	int werr = watchdog_start(watchdog_limit);
	if (werr != 0) {
		fprintf(stderr, "gvx-gpu-renderer: watchdog start failed: %s\n", strerror(werr));
		return GVX_GPU_EXIT_CONFINE;
	}

	if (mode == GVX_GPU_MODE_VENUS) {
		err[0] = '\0';
		if (vk_probe_device(&b, err, sizeof(err)) != 0) {
			fprintf(stderr, "gvx-gpu-renderer: Vulkan probe failed: %s\n", err);
			return GVX_GPU_EXIT_INIT;
		}
	}

	return server_run(GVX_GPU_SOCKET_FD, mode, stall_fences, allow_test_args);
}
