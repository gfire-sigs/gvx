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

#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int check_bundle_file(const char *lib_dir, const char *name)
{
	char path[PATH_MAX];
	int n = snprintf(path, sizeof(path), "%s/%s", lib_dir, name);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		fprintf(stderr, "gvx-gpu-renderer: bundle library path exceeds PATH_MAX\n");
		return -1;
	}

	struct stat st;
	if (stat(path, &st) != 0) {
		fprintf(stderr, "gvx-gpu-renderer: %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

int bundle_locate(struct bundle *b)
{
	memset(b, 0, sizeof(*b));

	char raw_exe[PATH_MAX];
	uint32_t raw_size = (uint32_t)sizeof(raw_exe);
	if (_NSGetExecutablePath(raw_exe, &raw_size) != 0) {
		fprintf(stderr, "gvx-gpu-renderer: executable path exceeds PATH_MAX\n");
		return -1;
	}

	char exe[PATH_MAX];
	if (realpath(raw_exe, exe) == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: realpath %s: %s\n", raw_exe, strerror(errno));
		return -1;
	}

	char copy1[PATH_MAX];
	int n = snprintf(copy1, sizeof(copy1), "%s", exe);
	if (n < 0 || (size_t)n >= sizeof(copy1)) {
		fprintf(stderr, "gvx-gpu-renderer: executable path exceeds PATH_MAX\n");
		return -1;
	}
	const char *bin_dir = dirname(copy1);

	char bin_base_copy[PATH_MAX];
	n = snprintf(bin_base_copy, sizeof(bin_base_copy), "%s", bin_dir);
	if (n < 0 || (size_t)n >= sizeof(bin_base_copy)) {
		fprintf(stderr, "gvx-gpu-renderer: bundle directory path exceeds PATH_MAX\n");
		return -1;
	}
	if (strcmp(basename(bin_base_copy), "bin") != 0) {
		fprintf(stderr, "gvx-gpu-renderer: executable directory %s must be named bin\n", bin_dir);
		return -1;
	}

	char copy2[PATH_MAX];
	n = snprintf(copy2, sizeof(copy2), "%s", bin_dir);
	if (n < 0 || (size_t)n >= sizeof(copy2)) {
		fprintf(stderr, "gvx-gpu-renderer: bundle directory path exceeds PATH_MAX\n");
		return -1;
	}
	const char *root = dirname(copy2);

	n = snprintf(b->root, sizeof(b->root), "%s", root);
	if (n < 0 || (size_t)n >= sizeof(b->root)) {
		fprintf(stderr, "gvx-gpu-renderer: bundle root path exceeds PATH_MAX\n");
		return -1;
	}
	if (strcmp(b->root, "/") == 0) {
		fprintf(stderr, "gvx-gpu-renderer: bundle root cannot be filesystem root\n");
		return -1;
	}

	n = snprintf(b->lib_dir, sizeof(b->lib_dir), "%s/lib", b->root);
	if (n < 0 || (size_t)n >= sizeof(b->lib_dir)) {
		fprintf(stderr, "gvx-gpu-renderer: bundle lib path exceeds PATH_MAX\n");
		return -1;
	}

	return 0;
}

int bundle_load_vulkan(struct bundle *b)
{
	if (check_bundle_file(b->lib_dir, "libvulkan_kosmickrisp.dylib") != 0 ||
	    check_bundle_file(b->lib_dir, "libvulkan.dylib") != 0) {
		return -1;
	}

	/*
	 * Load by leaf name so dyld caches the same image that virglrenderer's
	 * vkr_library_load opens after confinement. Keep the handle open for the
	 * process lifetime.
	 */
	void *vulkan = dlopen("libvulkan.dylib", RTLD_NOW | RTLD_LOCAL);
	if (vulkan == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: dlopen libvulkan.dylib: %s\n", dlerror());
		return -1;
	}

	void *sym = dlsym(vulkan, "vkGetInstanceProcAddr");
	if (sym == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: dlsym vkGetInstanceProcAddr: %s\n", dlerror());
		return -1;
	}

	Dl_info info;
	if (dladdr(sym, &info) == 0 || info.dli_fname == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: dladdr vkGetInstanceProcAddr failed\n");
		return -1;
	}

	char resolved[PATH_MAX];
	if (realpath(info.dli_fname, resolved) == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: realpath %s: %s\n", info.dli_fname, strerror(errno));
		return -1;
	}

	char lib_prefix[PATH_MAX];
	int n = snprintf(lib_prefix, sizeof(lib_prefix), "%s/", b->lib_dir);
	if (n < 0 || (size_t)n >= sizeof(lib_prefix)) {
		fprintf(stderr, "gvx-gpu-renderer: bundle lib prefix exceeds PATH_MAX\n");
		return -1;
	}

	if (strncmp(resolved, lib_prefix, (size_t)n) != 0) {
		fprintf(stderr, "gvx-gpu-renderer: libvulkan.dylib resolved to %s, outside %s\n",
		        resolved, b->lib_dir);
		return -1;
	}

	void *icd_sym = dlsym(vulkan, "vk_icdGetInstanceProcAddr");
	if (icd_sym == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: vk_icdGetInstanceProcAddr missing: %s\n", dlerror());
		return -1;
	}
	Dl_info icd_info;
	if (dladdr(icd_sym, &icd_info) == 0 || icd_info.dli_fname == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: dladdr vk_icdGetInstanceProcAddr failed\n");
		return -1;
	}
	char icd_resolved[PATH_MAX];
	if (realpath(icd_info.dli_fname, icd_resolved) == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: realpath %s: %s\n",
		        icd_info.dli_fname, strerror(errno));
		return -1;
	}
	if (strncmp(icd_resolved, lib_prefix, (size_t)n) != 0) {
		fprintf(stderr,
		        "gvx-gpu-renderer: vk_icdGetInstanceProcAddr resolved to %s, outside %s\n",
		        icd_resolved, b->lib_dir);
		return -1;
	}

	b->vulkan = vulkan;
	memcpy(&b->get_instance_proc_addr, &sym, sizeof(b->get_instance_proc_addr));
	return 0;
}
