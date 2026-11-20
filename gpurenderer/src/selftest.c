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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "virglrenderer.h"

static void report_result(const char *name, bool pass, const char *detail, bool *all_ok)
{
	if (pass) {
		printf("PASS %s\n", name);
		return;
	}
	*all_ok = false;
	printf("FAIL %s: %s\n", name, detail);
}

static bool check_virgl_context(char *detail, size_t detail_len)
{
	const uint32_t ctx_id = 1;
	const uint32_t res_id = 1;
	const uint64_t req_size = 12388;
	const uint64_t fence_id = 1;

	bool ctx_created = false;
	bool blob_created = false;
	bool blob_attached = false;
	int blob_fd = -1;
	bool ok = false;

	int ret = virgl_renderer_context_create_with_flags(
	    ctx_id, GVX_GPU_CAPSET_VENUS, 8, "selftest");
	if (ret != 0) {
		snprintf(detail, detail_len, "context_create failed: %d", ret);
		goto cleanup;
	}
	ctx_created = true;

	struct virgl_renderer_resource_create_blob_args args;
	memset(&args, 0, sizeof(args));
	args.res_handle = res_id;
	args.ctx_id = ctx_id;
	args.blob_mem = GVX_GPU_BLOB_MEM_HOST3D;
	args.blob_flags = GVX_GPU_BLOB_FLAG_MAPPABLE;
	args.blob_id = 0;
	args.size = req_size;

	ret = virgl_renderer_resource_create_blob(&args);
	if (ret != 0) {
		snprintf(detail, detail_len, "create_blob failed: %d", ret);
		goto cleanup;
	}
	blob_created = true;

	virgl_renderer_ctx_attach_resource((int)ctx_id, (int)res_id);
	blob_attached = true;

	uint32_t fd_type = 0;
	ret = virgl_renderer_resource_export_blob(res_id, &fd_type, &blob_fd);
	if (ret != 0) {
		snprintf(detail, detail_len, "export_blob failed: %d", ret);
		goto cleanup;
	}
	if (fd_type != VIRGL_RENDERER_BLOB_FD_TYPE_SHM || blob_fd < 0) {
		snprintf(detail, detail_len, "unexpected fd_type=%u fd=%d", fd_type, blob_fd);
		goto cleanup;
	}

	struct stat st;
	if (fstat(blob_fd, &st) != 0) {
		snprintf(detail, detail_len, "fstat: %s", strerror(errno));
		goto cleanup;
	}
	if (st.st_size < 0 ||
	    (uint64_t)st.st_size < req_size ||
	    ((uint64_t)st.st_size % GVX_GPU_HOST_BLOB_ALIGN) != 0) {
		snprintf(detail, detail_len, "bad shm size %lld", (long long)st.st_size);
		goto cleanup;
	}

	ret = virgl_renderer_context_create_fence(ctx_id, 0, 0, fence_id);
	if (ret != 0) {
		snprintf(detail, detail_len, "create_fence failed: %d", ret);
		goto cleanup;
	}

	const struct timespec one_ms = { .tv_sec = 0, .tv_nsec = 1000000L };
	for (int i = 0; i < 1000; i++) {
		virgl_renderer_context_poll(ctx_id);
		if (server_fence_seen(ctx_id, fence_id)) {
			break;
		}
		(void)nanosleep(&one_ms, NULL);
	}
	if (!server_fence_seen(ctx_id, fence_id)) {
		snprintf(detail, detail_len, "fence callback did not arrive");
		goto cleanup;
	}

	ok = true;

cleanup:
	if (blob_attached) {
		virgl_renderer_ctx_detach_resource((int)ctx_id, (int)res_id);
	}
	if (blob_created) {
		virgl_renderer_resource_unref(res_id);
	}
	if (blob_fd >= 0) {
		(void)close(blob_fd);
	}
	if (ctx_created) {
		virgl_renderer_context_destroy(ctx_id);
	}
	return ok;
}

static bool check_watchdog_sample(char *detail, size_t detail_len)
{
	uint64_t footprint = 0;
	int err = watchdog_sample_footprint(&footprint);
	if (err != 0) {
		snprintf(detail, detail_len, "task_info failed: %s", strerror(err));
		return false;
	}
	if (footprint == 0) {
		snprintf(detail, detail_len, "phys_footprint is 0");
		return false;
	}
	return true;
}

#define SELFTEST_MAX_COMPILE_MS 6000ULL

int selftest_run(const struct bundle *b)
{
	bool all_ok = true;
	int stages[VK_STAGE_COUNT];
	uint64_t compile_ms = 0;
	char err[256];
	err[0] = '\0';

	vk_selftest(b, stages, &compile_ms, err, sizeof(err));

	static const char *const stage_names[VK_STAGE_COUNT] = {
		"device",
		"shader",
		"shm-import",
		"gpu-write",
	};
	bool reported_vk_fail = false;
	for (int i = 0; i < VK_STAGE_COUNT; i++) {
		if (stages[i] == 0) {
			report_result(stage_names[i], true, "", &all_ok);
		} else if (!reported_vk_fail) {
			reported_vk_fail = true;
			report_result(stage_names[i], false, err[0] != '\0' ? err : "failed", &all_ok);
		} else {
			report_result(stage_names[i], false, "skipped", &all_ok);
		}
		if (i == VK_STAGE_SHADER) {
			if (stages[VK_STAGE_DEVICE] == 0 && stages[VK_STAGE_SHADER] == 0) {
				char compile_detail[128];
				compile_detail[0] = '\0';
				bool fast_enough = compile_ms <= SELFTEST_MAX_COMPILE_MS;
				if (!fast_enough) {
					snprintf(compile_detail, sizeof(compile_detail),
					         "%llu ms > %llu ms (Metal cannot resolve its cache directory)",
					         (unsigned long long)compile_ms,
					         (unsigned long long)SELFTEST_MAX_COMPILE_MS);
				}
				report_result("compile-time", fast_enough, compile_detail, &all_ok);
			} else {
				report_result("compile-time", false, "skipped", &all_ok);
			}
		}
	}

	char detail[256];

	detail[0] = '\0';
	report_result("virgl-context", check_virgl_context(detail, sizeof(detail)), detail, &all_ok);

	detail[0] = '\0';
	report_result("deny-fork",
	              confine_check_fork(detail, sizeof(detail)) == GVX_GPU_CONFINE_DENIED,
	              detail, &all_ok);

	detail[0] = '\0';
	report_result("deny-exec",
	              confine_check_exec(detail, sizeof(detail)) == GVX_GPU_CONFINE_DENIED,
	              detail, &all_ok);

	detail[0] = '\0';
	report_result("deny-read",
	              confine_check_read(detail, sizeof(detail)) == GVX_GPU_CONFINE_DENIED,
	              detail, &all_ok);

	detail[0] = '\0';
	report_result("deny-create",
	              confine_check_create(detail, sizeof(detail)) == GVX_GPU_CONFINE_DENIED,
	              detail, &all_ok);

	detail[0] = '\0';
	report_result("deny-connect",
	              confine_check_connect(detail, sizeof(detail)) == GVX_GPU_CONFINE_DENIED,
	              detail, &all_ok);

	detail[0] = '\0';
	report_result("watchdog sample", check_watchdog_sample(detail, sizeof(detail)), detail, &all_ok);

	printf("selftest: %s\n", all_ok ? "PASS" : "FAIL");
	return all_ok ? GVX_GPU_EXIT_OK : GVX_GPU_EXIT_SELFTEST;
}
