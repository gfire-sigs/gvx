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
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <unistd.h>

/* Private macOS Seatbelt entry points in libSystem. */
int sandbox_init_with_parameters(const char *profile,
                                 uint64_t flags,
                                 const char *const parameters[],
                                 char **errorbuf);
void sandbox_free_error(char *errorbuf);

/*
 * Seatbelt profile for the confined GPU renderer.
 *
 * Known residue: POSIX shm names exist in the global namespace between
 * shm_open(O_CREAT | O_EXCL, 0600) and shm_unlink. The /gvx-r- names exist
 * only between shm_open and shm_unlink of one RES_CREATE. The names are
 * random and owner-only. Broad file-read-metadata stays enabled because
 * narrowing it crashed MoltenVK during host measurements.
 */
static const char renderer_seatbelt_profile[] =
    "(version 1)\n"
    "(deny default)\n"
    "(allow iokit-open\n"
    "  (iokit-connection \"IOAccelerator\")\n"
    "  (iokit-user-client-class \"IOSurfaceRootUserClient\"))\n"
    "(allow mach-lookup (xpc-service-name \"com.apple.MTLCompilerService\"))\n"
    "(allow file-read*\n"
    "  (subpath \"/System/Library\")\n"
    "  (subpath \"/Library/GPUBundles\")\n"
    "  (subpath \"/usr/lib\")\n"
    "  (subpath \"/private/var/db/dyld\")\n"
    "  (subpath (param \"BUNDLE_DIR\")))\n"
    "(allow file-read-metadata)\n"
    "(allow ipc-posix-shm-read* ipc-posix-shm-write-create ipc-posix-shm-write-data ipc-posix-shm-write-unlink\n"
    "  (ipc-posix-name-prefix \"/vkr-\")\n"
    "  (ipc-posix-name-prefix \"/proxy-\")\n"
    "  (ipc-posix-name-prefix \"/gvx-r-\"))\n"
    "(allow sysctl-read)\n"
    "(deny process-fork)\n"
    "(deny process-exec*)\n";

/*
 * Raises the soft RLIMIT_NOFILE to min(hard limit, kern.maxfilesperproc).
 * Go restores the launchd soft limit (256) for child processes, while
 * virglrenderer keeps about one descriptor per live mappable blob.
 */
static int raise_nofile_limit(char *err, size_t err_len)
{
	struct rlimit nofile;
	if (getrlimit(RLIMIT_NOFILE, &nofile) != 0) {
		snprintf(err, err_len, "getrlimit(RLIMIT_NOFILE): %s", strerror(errno));
		return -1;
	}

	int maxfiles = 0;
	size_t maxfiles_len = sizeof(maxfiles);
	if (sysctlbyname("kern.maxfilesperproc", &maxfiles, &maxfiles_len, NULL, 0) != 0) {
		snprintf(err, err_len, "sysctlbyname(kern.maxfilesperproc): %s", strerror(errno));
		return -1;
	}
	if (maxfiles_len != sizeof(maxfiles) || maxfiles <= 0) {
		snprintf(err, err_len, "invalid kern.maxfilesperproc: %d", maxfiles);
		return -1;
	}

	/* Never pass RLIM_INFINITY as rlim_cur: macOS rejects it for RLIMIT_NOFILE. */
	rlim_t target = (rlim_t)maxfiles;
	if (nofile.rlim_max != RLIM_INFINITY && nofile.rlim_max < target) {
		target = nofile.rlim_max;
	}
	if (nofile.rlim_cur < target) {
		nofile.rlim_cur = target;
		if (setrlimit(RLIMIT_NOFILE, &nofile) != 0) {
			snprintf(err, err_len, "setrlimit(RLIMIT_NOFILE, %llu): %s",
			         (unsigned long long)target, strerror(errno));
			return -1;
		}
	}
	return 0;
}

int confine_apply(const char *bundle_dir, char *err, size_t err_len)
{
	if (raise_nofile_limit(err, err_len) != 0) {
		return -1;
	}

	const struct rlimit zero = { 0, 0 };

	if (setrlimit(RLIMIT_CORE, &zero) != 0) {
		snprintf(err, err_len, "setrlimit(RLIMIT_CORE): %s", strerror(errno));
		return -1;
	}

	/*
	 * Resolve the per-user cache directory while Mach lookups still work.
	 * Metal finds its shader cache through confstr(_CS_DARWIN_USER_CACHE_DIR),
	 * which asks dirhelper over XPC, and the profile denies that lookup.
	 * libsystem keeps the resolved path for the process, so Metal does not
	 * repeat the slow denied lookup for each shader library after confinement.
	 * The renderer gets no file access from this call.
	 */
	char cache_dir[PATH_MAX];
	errno = 0;
	if (confstr(_CS_DARWIN_USER_CACHE_DIR, cache_dir, sizeof(cache_dir)) == 0) {
		fprintf(stderr,
		        "gvx-gpu-renderer: no user cache directory (%s); Metal shader compilation will be slow\n",
		        errno != 0 ? strerror(errno) : "not configured");
	}

	const char *const params[] = { "BUNDLE_DIR", bundle_dir, NULL };
	char *sb_err = NULL;
	if (sandbox_init_with_parameters(renderer_seatbelt_profile, 0, params, &sb_err) != 0) {
		snprintf(err, err_len, "%s", sb_err != NULL ? sb_err : "sandbox_init_with_parameters failed");
		if (sb_err != NULL) {
			sandbox_free_error(sb_err);
		}
		return -1;
	}
	if (sb_err != NULL) {
		sandbox_free_error(sb_err);
	}

	/*
	 * Verify that Seatbelt rejects fork() with EPERM before lowering
	 * RLIMIT_NPROC to 0. XNU enforces RLIMIT_NPROC before the Seatbelt MAC
	 * hook, so setting the limit first would return EAGAIN and mask a
	 * missing (deny process-fork) rule.
	 */
	char fork_detail[128];
	fork_detail[0] = '\0';
	if (confine_check_fork(fork_detail, sizeof(fork_detail)) != GVX_GPU_CONFINE_DENIED) {
		snprintf(err, err_len, "Seatbelt deny process-fork verification failed: %s",
		         fork_detail[0] != '\0' ? fork_detail : "unexpected result");
		return -1;
	}

	if (setrlimit(RLIMIT_NPROC, &zero) != 0) {
		snprintf(err, err_len, "setrlimit(RLIMIT_NPROC): %s", strerror(errno));
		return -1;
	}

	return 0;
}
