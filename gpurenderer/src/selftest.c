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
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "virglrenderer.h"
#include "virgl_hw.h"

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

static bool check_virgl_capsets(char *detail, size_t detail_len)
{
	if (server_capset_count() != 2) {
		snprintf(detail, detail_len, "capset count %u, want 2", server_capset_count());
		return false;
	}

	const struct {
		uint32_t want_id;
		uint32_t want_ver;
	} expect[2] = {
		{ GVX_GPU_CAPSET_VIRGL, 1u },
		{ GVX_GPU_CAPSET_VIRGL2, 2u },
	};

	for (uint32_t i = 0; i < 2; i++) {
		uint32_t id = 0;
		uint32_t max_ver = 0;
		const uint8_t *data = NULL;
		uint32_t size = 0;
		if (!server_get_cached_capset(i, &id, &max_ver, &data, &size)) {
			snprintf(detail, detail_len, "capset %u not cached", expect[i].want_id);
			return false;
		}
		if (id != expect[i].want_id || max_ver != expect[i].want_ver) {
			snprintf(detail, detail_len, "capset %u: id=%u max_version=%u, want %u/%u",
			         i, id, max_ver, expect[i].want_id, expect[i].want_ver);
			return false;
		}
		if (size < sizeof(uint32_t) || size > GVX_GPU_MAX_CAPSET_BYTES) {
			snprintf(detail, detail_len, "capset %u: size %u out of range", id, size);
			return false;
		}
		uint32_t first_word = 0;
		memcpy(&first_word, data, sizeof(first_word));
		if (first_word != max_ver) {
			snprintf(detail, detail_len, "capset %u: first word %u, want %u",
			         id, first_word, max_ver);
			return false;
		}
		if (id == GVX_GPU_CAPSET_VIRGL2) {
			const size_t min_v2_size =
			    offsetof(struct virgl_caps_v2, supported_multisample_formats) +
			    sizeof(((struct virgl_caps_v2 *)0)->supported_multisample_formats);
			if (size < min_v2_size) {
				snprintf(detail, detail_len, "capset 2 size %u smaller than %zu",
				         size, min_v2_size);
				return false;
			}
			struct virgl_caps_v2 v2;
			memset(&v2, 0, sizeof(v2));
			size_t copy_len = size < sizeof(v2) ? size : sizeof(v2);
			memcpy(&v2, data, copy_len);
			if (v2.v1.max_samples < 4u) {
				snprintf(detail, detail_len, "capset 2 max_samples=%u, want >= 4",
				         v2.v1.max_samples);
				return false;
			}
			/* Bit 0 is VIRGL_FORMAT_NONE; require at least one real format bit. */
			uint32_t ms_mask = v2.supported_multisample_formats.bitmask[0] & ~1u;
			for (size_t w = 1; w < 16; w++) {
				ms_mask |= v2.supported_multisample_formats.bitmask[w];
			}
			if (ms_mask == 0) {
				snprintf(detail, detail_len,
				         "capset 2 supported_multisample_formats has no pixel formats");
				return false;
			}
		}
	}
	return true;
}

struct virgl_selftest_state {
	bool ctx_created;
	bool res_created;
	uint8_t *view;
	uint64_t host_size;
};

static bool check_virgl_resource(struct virgl_selftest_state *st,
                                 char *detail,
                                 size_t detail_len)
{
	const uint32_t ctx_id = 1;
	const uint32_t res_id = 1;
	const uint32_t buf_bytes = 4096u;
	int res_fd = -1;

	int ret = server_create_context(ctx_id, GVX_GPU_CAPSET_VIRGL2, 8, "selftest");
	if (ret != 0) {
		snprintf(detail, detail_len, "context_create failed: %d", ret);
		return false;
	}
	st->ctx_created = true;

	/* Reject PIPE_BUFFER requests whose width exceeds the limit or backing size. */
	struct gvx_gpu_res_create_request bad_req = {
		.res_id = 99u,
		.target = 0u,      /* PIPE_BUFFER */
		.format = 64u,     /* VIRGL_FORMAT_R8_UNORM */
		.bind = 1u << 4,   /* VIRGL_BIND_VERTEX_BUFFER */
		.width = GVX_GPU_MAX_BLOB_BYTES + 1u,
		.height = 1u,
		.depth = 1u,
		.array_size = 1u,
		.size = buf_bytes,
	};
	int bad_fd = -1;
	uint64_t bad_host_size = 0;
	int32_t bad_status = virgl_res_create(ctx_id, &bad_req, &bad_fd, &bad_host_size);
	if (bad_status != GVX_GPU_STATUS_INVALID) {
		if (bad_fd >= 0) {
			(void)close(bad_fd);
		}
		snprintf(detail, detail_len, "oversized buffer width returned %d, want INVALID",
		         bad_status);
		return false;
	}
	bad_req.width = buf_bytes * 2u;
	bad_status = virgl_res_create(ctx_id, &bad_req, &bad_fd, &bad_host_size);
	if (bad_status != GVX_GPU_STATUS_INVALID) {
		if (bad_fd >= 0) {
			(void)close(bad_fd);
		}
		snprintf(detail, detail_len, "buffer width > size returned %d, want INVALID",
		         bad_status);
		return false;
	}

	struct gvx_gpu_res_create_request req = {
		.res_id = res_id,
		.target = 0u,      /* PIPE_BUFFER */
		.format = 64u,     /* VIRGL_FORMAT_R8_UNORM */
		.bind = 1u << 4,   /* VIRGL_BIND_VERTEX_BUFFER */
		.width = buf_bytes,
		.height = 1u,
		.depth = 1u,
		.array_size = 1u,
		.last_level = 0u,
		.nr_samples = 0u,
		.flags = 0u,
		.reserved = 0u,
		.size = buf_bytes,
	};

	uint64_t host_size = 0;
	int32_t status = virgl_res_create(ctx_id, &req, &res_fd, &host_size);
	if (status != GVX_GPU_STATUS_OK) {
		snprintf(detail, detail_len, "virgl_res_create failed: %d", status);
		return false;
	}
	st->res_created = true;
	st->host_size = host_size;

	if (host_size != GVX_GPU_HOST_BLOB_ALIGN) {
		(void)close(res_fd);
		snprintf(detail, detail_len, "host_size %llu, want %u",
		         (unsigned long long)host_size, GVX_GPU_HOST_BLOB_ALIGN);
		return false;
	}

	struct stat fst;
	if (fstat(res_fd, &fst) != 0) {
		(void)close(res_fd);
		snprintf(detail, detail_len, "fstat: %s", strerror(errno));
		return false;
	}
	if (fst.st_size != (off_t)GVX_GPU_HOST_BLOB_ALIGN) {
		(void)close(res_fd);
		snprintf(detail, detail_len, "fstat size %lld, want %u",
		         (long long)fst.st_size, GVX_GPU_HOST_BLOB_ALIGN);
		return false;
	}

	void *mapped = mmap(NULL, (size_t)host_size, PROT_READ | PROT_WRITE, MAP_SHARED, res_fd, 0);
	(void)close(res_fd);
	if (mapped == MAP_FAILED) {
		snprintf(detail, detail_len, "mmap: %s", strerror(errno));
		return false;
	}
	st->view = (uint8_t *)mapped;

	for (uint32_t i = 0; i < buf_bytes; i++) {
		st->view[i] = (uint8_t)(i * 7u + 3u);
	}

	struct gvx_gpu_transfer_request xfer = {
		.res_id = res_id,
		.direction = GVX_GPU_TRANSFER_TO_HOST,
		.level = 0u,
		.stride = 0u,
		.layer_stride = 0u,
		.box_x = 0u,
		.box_y = 0u,
		.box_z = 0u,
		.box_w = buf_bytes,
		.box_h = 1u,
		.box_d = 1u,
		.reserved = 0u,
		.offset = 0u,
	};
	status = virgl_res_transfer(ctx_id, &xfer);
	if (status != GVX_GPU_STATUS_OK) {
		snprintf(detail, detail_len, "transfer to host failed: %d", status);
		return false;
	}

	memset(st->view, 0, buf_bytes);

	xfer.direction = GVX_GPU_TRANSFER_FROM_HOST;
	status = virgl_res_transfer(ctx_id, &xfer);
	if (status != GVX_GPU_STATUS_OK) {
		snprintf(detail, detail_len, "transfer from host failed: %d", status);
		return false;
	}

	for (uint32_t i = 0; i < buf_bytes; i++) {
		uint8_t want = (uint8_t)(i * 7u + 3u);
		if (st->view[i] != want) {
			snprintf(detail, detail_len, "mismatch at byte %u: got 0x%02x want 0x%02x",
			         i, st->view[i], want);
			return false;
		}
	}

	return true;
}

static bool check_virgl_fence(const struct virgl_selftest_state *st,
                              char *detail,
                              size_t detail_len)
{
	if (!st->ctx_created || !st->res_created || st->view == NULL) {
		snprintf(detail, detail_len, "skipped");
		return false;
	}

	const uint32_t ctx1_id = 1;
	const uint32_t ctx2_id = 2;
	const uint32_t res_id = 1;
	const uint32_t buf_bytes = 4096u;
	const uint64_t fence_id = 1;
	uint64_t empty_cmd = 0;
	bool ctx2_created = false;
	bool ok = false;

	/* Submit on ctx1, create ctx2, then submit, fence, and transfer on ctx1. */
	int ret = virgl_renderer_submit_cmd(&empty_cmd, (int)ctx1_id, 0);
	if (ret != 0) {
		snprintf(detail, detail_len, "first submit_cmd on ctx1 failed: %d", ret);
		goto cleanup;
	}

	ret = server_create_context(ctx2_id, GVX_GPU_CAPSET_VIRGL2, 9, "selftest2");
	if (ret != 0) {
		snprintf(detail, detail_len, "ctx2 create failed: %d", ret);
		goto cleanup;
	}
	ctx2_created = true;

	ret = virgl_renderer_submit_cmd(&empty_cmd, (int)ctx1_id, 0);
	if (ret != 0) {
		snprintf(detail, detail_len, "second submit_cmd on ctx1 failed: %d", ret);
		goto cleanup;
	}

	ret = virgl_renderer_context_create_fence(ctx1_id, 0, 0, fence_id);
	if (ret != 0) {
		snprintf(detail, detail_len, "create_fence failed: %d", ret);
		goto cleanup;
	}

	const struct timespec one_ms = { .tv_sec = 0, .tv_nsec = 1000000L };
	for (int i = 0; i < 1000; i++) {
		virgl_renderer_poll();
		if (server_fence_seen(ctx1_id, fence_id)) {
			break;
		}
		(void)nanosleep(&one_ms, NULL);
	}
	if (!server_fence_seen(ctx1_id, fence_id)) {
		snprintf(detail, detail_len, "fence callback did not arrive");
		goto cleanup;
	}

	for (uint32_t i = 0; i < buf_bytes; i++) {
		st->view[i] = (uint8_t)(i * 11u + 5u);
	}
	struct gvx_gpu_transfer_request xfer = {
		.res_id = res_id,
		.direction = GVX_GPU_TRANSFER_TO_HOST,
		.box_w = buf_bytes,
		.box_h = 1u,
		.box_d = 1u,
	};
	int32_t status = virgl_res_transfer(ctx1_id, &xfer);
	if (status != GVX_GPU_STATUS_OK) {
		snprintf(detail, detail_len, "post-ctx2 transfer to host failed: %d", status);
		goto cleanup;
	}
	memset(st->view, 0, buf_bytes);
	xfer.direction = GVX_GPU_TRANSFER_FROM_HOST;
	status = virgl_res_transfer(ctx1_id, &xfer);
	if (status != GVX_GPU_STATUS_OK) {
		snprintf(detail, detail_len, "post-ctx2 transfer from host failed: %d", status);
		goto cleanup;
	}
	for (uint32_t i = 0; i < buf_bytes; i++) {
		uint8_t want = (uint8_t)(i * 11u + 5u);
		if (st->view[i] != want) {
			snprintf(detail, detail_len,
			         "post-ctx2 mismatch at byte %u: got 0x%02x want 0x%02x",
			         i, st->view[i], want);
			goto cleanup;
		}
	}

	ok = true;

cleanup:
	if (ctx2_created) {
		virgl_renderer_context_destroy(ctx2_id);
	}
	return ok;
}

static void cleanup_virgl_selftest(struct virgl_selftest_state *st)
{
	if (st->res_created) {
		virgl_res_unref(1u, st->ctx_created, 1u);
	}
	if (st->view != NULL) {
		(void)munmap(st->view, (size_t)st->host_size);
		st->view = NULL;
	}
	if (st->ctx_created) {
		virgl_renderer_context_destroy(1u);
	}
}

#define SELFTEST_MAX_COMPILE_MS 6000ULL

int selftest_run(const struct bundle *b, uint32_t mode)
{
	bool all_ok = true;
	char detail[256];

	if (mode == GVX_GPU_MODE_VIRGL) {
		const char *renderer = gl_cgl_renderer();
		printf("INFO opengl renderer=%s\n", renderer);

		bool gl_ok = renderer != NULL && renderer[0] != '\0';
		snprintf(detail, sizeof(detail), "%s", gl_ok ? "" : "no OpenGL renderer");
		report_result("opengl", gl_ok, detail, &all_ok);

		detail[0] = '\0';
		report_result("virgl-capsets",
		              check_virgl_capsets(detail, sizeof(detail)), detail, &all_ok);

		struct virgl_selftest_state vst;
		memset(&vst, 0, sizeof(vst));

		detail[0] = '\0';
		report_result("virgl-resource",
		              check_virgl_resource(&vst, detail, sizeof(detail)), detail, &all_ok);

		detail[0] = '\0';
		report_result("virgl-fence",
		              check_virgl_fence(&vst, detail, sizeof(detail)), detail, &all_ok);

		cleanup_virgl_selftest(&vst);
	} else {
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
				report_result(stage_names[i], false,
				              err[0] != '\0' ? err : "failed", &all_ok);
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

		detail[0] = '\0';
		report_result("virgl-context", check_virgl_context(detail, sizeof(detail)), detail, &all_ok);
	}

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
