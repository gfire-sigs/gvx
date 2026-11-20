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
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virglrenderer.h"

_Static_assert(GVX_GPU_BLOB_MEM_HOST3D == VIRGL_RENDERER_BLOB_MEM_HOST3D,
               "HOST3D blob memory constant must match virglrenderer");
_Static_assert(GVX_GPU_BLOB_FLAG_MAPPABLE == VIRGL_RENDERER_BLOB_FLAG_USE_MAPPABLE,
               "MAPPABLE blob flag must match virglrenderer");
_Static_assert(GVX_GPU_BLOB_FLAG_SHAREABLE == VIRGL_RENDERER_BLOB_FLAG_USE_SHAREABLE,
               "SHAREABLE blob flag must match virglrenderer");
_Static_assert(GVX_GPU_BLOB_FLAG_CROSS_DEVICE == VIRGL_RENDERER_BLOB_FLAG_USE_CROSS_DEVICE,
               "CROSS_DEVICE blob flag must match virglrenderer");
_Static_assert(GVX_GPU_FD_TYPE_SHM == VIRGL_RENDERER_BLOB_FD_TYPE_SHM,
               "SHM fd type constant must match virglrenderer");

#define SERVER_MAX_CONTEXTS 128

const int renderer_virgl_flags =
    VIRGL_RENDERER_VENUS |
    VIRGL_RENDERER_NO_VIRGL |
    VIRGL_RENDERER_RENDER_SERVER |
    VIRGL_RENDERER_THREAD_SYNC |
    VIRGL_RENDERER_USE_EXTERNAL_BLOB;

struct server_context {
	uint32_t id;
	bool lost;
	uint32_t pending_fences;
};

struct server {
	int sock;
	bool stall_fences;
	bool test_ops;
	bool hello_done;
	uint32_t venus_max_version;
	uint32_t venus_max_size;
	struct server_context ctx[SERVER_MAX_CONTEXTS];
	uint8_t *buf;
	size_t buf_cap;
	uint32_t last_fence_ctx;
	uint64_t last_fence_id;
	bool peer_gone;
	bool watchdog_armed;
};

static struct server g_server = { .sock = -1 };

static struct server_context *find_context(struct server *s, uint32_t ctx_id)
{
	if (ctx_id == 0) {
		return NULL;
	}
	for (size_t i = 0; i < SERVER_MAX_CONTEXTS; i++) {
		if (s->ctx[i].id == ctx_id) {
			return &s->ctx[i];
		}
	}
	return NULL;
}

static struct server_context *alloc_context_slot(struct server *s)
{
	for (size_t i = 0; i < SERVER_MAX_CONTEXTS; i++) {
		if (s->ctx[i].id == 0) {
			return &s->ctx[i];
		}
	}
	return NULL;
}

static bool has_pending_fences(const struct server *s)
{
	for (size_t i = 0; i < SERVER_MAX_CONTEXTS; i++) {
		if (s->ctx[i].id != 0 && s->ctx[i].pending_fences > 0) {
			return true;
		}
	}
	return false;
}

static void server_write_fence(void *cookie, uint32_t fence)
{
	(void)cookie;
	(void)fence;
}

static void server_write_context_fence(void *cookie,
                                       uint32_t ctx_id,
                                       uint32_t ring_idx,
                                       uint64_t fence_id)
{
	struct server *s = (struct server *)cookie;
	s->last_fence_ctx = ctx_id;
	s->last_fence_id = fence_id;

	struct server_context *slot = find_context(s, ctx_id);
	if (slot == NULL) {
		return;
	}
	if (slot->pending_fences > 0) {
		slot->pending_fences--;
	}
	if (s->peer_gone) {
		return;
	}

	struct gvx_gpu_header hdr = {
		.magic = GVX_GPU_MAGIC,
		.op = GVX_GPU_OP_FENCE_DONE,
		.flags = GVX_GPU_FLAG_EVENT,
		.seq = 0,
		.ctx_id = ctx_id,
		.payload_len = GVX_GPU_FENCE_DONE_EVENT_SIZE,
		.status = GVX_GPU_STATUS_OK,
	};
	struct gvx_gpu_fence_done_event ev = {
		.ring_idx = ring_idx,
		.reserved = 0,
		.fence_id = fence_id,
	};
	uint8_t ev_buf[GVX_GPU_FENCE_DONE_EVENT_SIZE];
	memcpy(ev_buf, &ev, sizeof(ev_buf));

	if (wire_send(s->sock, &hdr, ev_buf, -1) != 0) {
		s->peer_gone = true;
	}
}

static struct virgl_renderer_callbacks g_callbacks = {
	.version = VIRGL_RENDERER_CALLBACKS_VERSION,
	.write_fence = server_write_fence,
	.write_context_fence = server_write_context_fence,
};

struct virgl_renderer_callbacks *server_callbacks(void)
{
	return &g_callbacks;
}

void *server_cookie(void)
{
	return &g_server;
}

void server_set_venus_caps(uint32_t max_version, uint32_t max_size)
{
	g_server.venus_max_version = max_version;
	g_server.venus_max_size = max_size;
}

bool server_fence_seen(uint32_t ctx_id, uint64_t fence_id)
{
	return g_server.last_fence_ctx == ctx_id && g_server.last_fence_id == fence_id;
}

/*
 * Maps a virglrenderer return value (negative or positive host errno, as its
 * functions mix both) to a closed GVX_GPU_STATUS_* value.
 */
static int32_t status_from_ret(int ret)
{
	if (ret == INT_MIN) {
		return GVX_GPU_STATUS_IO;
	}
	int e = ret < 0 ? -ret : ret;
	switch (e) {
	case ENOMEM:
		return GVX_GPU_STATUS_NO_MEMORY;
	case EINVAL:
		return GVX_GPU_STATUS_INVALID;
	case EEXIST:
		return GVX_GPU_STATUS_EXISTS;
	case ENOSPC:
		return GVX_GPU_STATUS_NO_SPACE;
	case ENOTSUP:
#if EOPNOTSUPP != ENOTSUP
	case EOPNOTSUPP:
#endif
		return GVX_GPU_STATUS_NOT_SUPPORTED;
	default:
		return GVX_GPU_STATUS_IO;
	}
}

static void send_reply(struct server *s,
                       const struct gvx_gpu_header *req,
                       int32_t status,
                       const void *payload,
                       uint32_t payload_len,
                       int send_fd)
{
	if (s->peer_gone) {
		return;
	}
	if (status != GVX_GPU_STATUS_OK) {
		payload = NULL;
		payload_len = 0;
		send_fd = -1;
	}

	struct gvx_gpu_header rep = {
		.magic = GVX_GPU_MAGIC,
		.op = req->op,
		.flags = (uint16_t)(GVX_GPU_FLAG_REPLY | (send_fd >= 0 ? GVX_GPU_FLAG_FD : 0u)),
		.seq = req->seq,
		.ctx_id = req->ctx_id,
		.payload_len = payload_len,
		.status = status,
	};
	if (wire_send(s->sock, &rep, payload, send_fd) != 0) {
		s->peer_gone = true;
	}
}

static void send_ctx_lost(struct server *s, uint32_t ctx_id, uint32_t reason)
{
	if (s->peer_gone) {
		return;
	}
	struct gvx_gpu_header hdr = {
		.magic = GVX_GPU_MAGIC,
		.op = GVX_GPU_OP_CTX_LOST,
		.flags = GVX_GPU_FLAG_EVENT,
		.seq = 0,
		.ctx_id = ctx_id,
		.payload_len = GVX_GPU_CTX_LOST_EVENT_SIZE,
		.status = GVX_GPU_STATUS_OK,
	};
	struct gvx_gpu_ctx_lost_event ev = {
		.reason = reason,
		.reserved = 0,
	};
	uint8_t ev_buf[GVX_GPU_CTX_LOST_EVENT_SIZE];
	memcpy(ev_buf, &ev, sizeof(ev_buf));

	if (wire_send(s->sock, &hdr, ev_buf, -1) != 0) {
		s->peer_gone = true;
	}
}

static int protocol_error(const char *rule)
{
	fprintf(stderr, "gvx-gpu-renderer: protocol error: %s\n", rule);
	return -1;
}

static int validate_header(const struct server *s, const struct gvx_gpu_header *h)
{
	if (h->magic != GVX_GPU_MAGIC) {
		return protocol_error("bad magic");
	}
	if (h->flags != 0) {
		return protocol_error("non-zero request flags");
	}
	if (h->status != 0) {
		return protocol_error("non-zero request status");
	}
	if ((h->op < GVX_GPU_OP_HELLO || h->op > GVX_GPU_OP_SUBMIT) &&
	    h->op != GVX_GPU_OP_TEST_CONFINE) {
		return protocol_error("unknown request op");
	}
	if (h->seq == 0) {
		return protocol_error("zero request seq");
	}
	if (h->op == GVX_GPU_OP_HELLO ||
	    h->op == GVX_GPU_OP_GET_CAPSET ||
	    h->op == GVX_GPU_OP_TEST_CONFINE) {
		if (h->ctx_id != 0) {
			return protocol_error("non-zero ctx_id for global request");
		}
	} else if (h->ctx_id == 0) {
		return protocol_error("zero ctx_id for context request");
	}
	if (h->payload_len > GVX_GPU_MAX_REQUEST_PAYLOAD) {
		return protocol_error("request payload exceeds maximum");
	}
	if (!s->hello_done && h->op != GVX_GPU_OP_HELLO) {
		return protocol_error("first request must be HELLO");
	}
	if (s->hello_done && h->op == GVX_GPU_OP_HELLO) {
		return protocol_error("duplicate HELLO");
	}
	return 0;
}

static int handle_hello(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len != GVX_GPU_HELLO_REQUEST_SIZE) {
		return protocol_error("bad HELLO payload size");
	}

	struct gvx_gpu_hello_request req;
	memcpy(&req, s->buf, sizeof(req));
	if (req.version != GVX_GPU_VERSION) {
		send_reply(s, h, GVX_GPU_STATUS_NOT_SUPPORTED, NULL, 0, -1);
		return 0;
	}

	s->hello_done = true;

	struct gvx_gpu_hello_reply hr;
	memset(&hr, 0, sizeof(hr));
	hr.version = GVX_GPU_VERSION;
	hr.num_capsets = 1;

	static const char build_desc[] =
	    "gvx-gpu-renderer " GVX_RENDERER_VERSION " " GVX_RENDERER_BUILD_INFO;
	size_t copy_len = strlen(build_desc);
	if (copy_len > sizeof(hr.build) - 1) {
		copy_len = sizeof(hr.build) - 1;
	}
	memcpy(hr.build, build_desc, copy_len);

	struct gvx_gpu_capset_info ci = {
		.id = GVX_GPU_CAPSET_VENUS,
		.max_version = s->venus_max_version,
		.max_size = s->venus_max_size,
		.reserved = 0,
	};

	uint8_t out[GVX_GPU_HELLO_REPLY_SIZE + GVX_GPU_CAPSET_INFO_SIZE];
	memcpy(out, &hr, GVX_GPU_HELLO_REPLY_SIZE);
	memcpy(out + GVX_GPU_HELLO_REPLY_SIZE, &ci, GVX_GPU_CAPSET_INFO_SIZE);

	send_reply(s, h, GVX_GPU_STATUS_OK, out, (uint32_t)sizeof(out), -1);
	return 0;
}

static int handle_get_capset(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len != GVX_GPU_GET_CAPSET_REQUEST_SIZE) {
		return protocol_error("bad GET_CAPSET payload size");
	}

	struct gvx_gpu_get_capset_request req;
	memcpy(&req, s->buf, sizeof(req));
	if (req.id != GVX_GPU_CAPSET_VENUS || req.version > s->venus_max_version) {
		send_reply(s, h, GVX_GPU_STATUS_INVALID, NULL, 0, -1);
		return 0;
	}

	uint8_t out[GVX_GPU_MAX_CAPSET_BYTES];
	memset(out, 0, s->venus_max_size);
	virgl_renderer_fill_caps(req.id, req.version, out);

	send_reply(s, h, GVX_GPU_STATUS_OK, out, s->venus_max_size, -1);
	return 0;
}

static int handle_ctx_create(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len < GVX_GPU_CTX_CREATE_REQUEST_SIZE) {
		return protocol_error("short CTX_CREATE payload");
	}

	struct gvx_gpu_ctx_create_request req;
	memcpy(&req, s->buf, sizeof(req));
	if (req.name_len > GVX_GPU_MAX_CONTEXT_NAME_BYTES ||
	    h->payload_len != GVX_GPU_CTX_CREATE_REQUEST_SIZE + req.name_len) {
		return protocol_error("bad CTX_CREATE name length");
	}

	if (req.capset_id != GVX_GPU_CAPSET_VENUS) {
		send_reply(s, h, GVX_GPU_STATUS_INVALID, NULL, 0, -1);
		return 0;
	}
	if (find_context(s, h->ctx_id) != NULL) {
		send_reply(s, h, GVX_GPU_STATUS_EXISTS, NULL, 0, -1);
		return 0;
	}

	struct server_context *slot = alloc_context_slot(s);
	if (slot == NULL) {
		send_reply(s, h, GVX_GPU_STATUS_NO_SPACE, NULL, 0, -1);
		return 0;
	}

	char name[GVX_GPU_MAX_CONTEXT_NAME_BYTES + 1];
	if (req.name_len > 0) {
		memcpy(name, s->buf + GVX_GPU_CTX_CREATE_REQUEST_SIZE, req.name_len);
	}
	name[req.name_len] = '\0';

	int ret = virgl_renderer_context_create_with_flags(
	    h->ctx_id, req.capset_id, req.name_len, name);
	if (ret != 0) {
		send_reply(s, h, status_from_ret(ret), NULL, 0, -1);
		return 0;
	}

	slot->id = h->ctx_id;
	slot->lost = false;
	slot->pending_fences = 0;

	send_reply(s, h, GVX_GPU_STATUS_OK, NULL, 0, -1);
	return 0;
}

static int handle_ctx_destroy(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len != 0) {
		return protocol_error("non-empty CTX_DESTROY payload");
	}

	struct server_context *slot = find_context(s, h->ctx_id);
	if (slot == NULL) {
		send_reply(s, h, GVX_GPU_STATUS_INVALID, NULL, 0, -1);
		return 0;
	}

	virgl_renderer_context_destroy(h->ctx_id);
	slot->id = 0;
	slot->lost = false;
	slot->pending_fences = 0;

	send_reply(s, h, GVX_GPU_STATUS_OK, NULL, 0, -1);
	return 0;
}

static int handle_blob_create(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len != GVX_GPU_BLOB_CREATE_REQUEST_SIZE) {
		return protocol_error("bad BLOB_CREATE payload size");
	}

	struct gvx_gpu_blob_create_request req;
	memcpy(&req, s->buf, sizeof(req));

	struct server_context *slot = find_context(s, h->ctx_id);
	if (slot == NULL) {
		send_reply(s, h, GVX_GPU_STATUS_INVALID, NULL, 0, -1);
		return 0;
	}
	if (slot->lost) {
		send_reply(s, h, GVX_GPU_STATUS_IO, NULL, 0, -1);
		return 0;
	}

	const uint32_t valid_flags = GVX_GPU_BLOB_FLAG_MAPPABLE |
	                             GVX_GPU_BLOB_FLAG_SHAREABLE |
	                             GVX_GPU_BLOB_FLAG_CROSS_DEVICE;
	if (req.res_id == 0 ||
	    req.blob_mem != GVX_GPU_BLOB_MEM_HOST3D ||
	    (req.blob_flags & ~valid_flags) != 0 ||
	    req.size == 0 ||
	    req.size > GVX_GPU_MAX_BLOB_BYTES) {
		send_reply(s, h, GVX_GPU_STATUS_INVALID, NULL, 0, -1);
		return 0;
	}

	struct virgl_renderer_resource_create_blob_args args;
	memset(&args, 0, sizeof(args));
	args.res_handle = req.res_id;
	args.ctx_id = h->ctx_id;
	args.blob_mem = req.blob_mem;
	args.blob_flags = req.blob_flags;
	args.blob_id = req.blob_id;
	args.size = req.size;

	int ret = virgl_renderer_resource_create_blob(&args);
	if (ret != 0) {
		send_reply(s, h, status_from_ret(ret), NULL, 0, -1);
		return 0;
	}

	virgl_renderer_ctx_attach_resource((int)h->ctx_id, (int)req.res_id);

	struct gvx_gpu_blob_create_reply rep;
	memset(&rep, 0, sizeof(rep));
	int blob_fd = -1;

	if ((req.blob_flags & GVX_GPU_BLOB_FLAG_MAPPABLE) != 0) {
		uint32_t fd_type = 0;
		ret = virgl_renderer_resource_export_blob(req.res_id, &fd_type, &blob_fd);
		if (ret != 0) {
			if (blob_fd >= 0) {
				(void)close(blob_fd);
			}
			virgl_renderer_ctx_detach_resource((int)h->ctx_id, (int)req.res_id);
			virgl_renderer_resource_unref(req.res_id);
			send_reply(s, h, status_from_ret(ret), NULL, 0, -1);
			return 0;
		}
		if (fd_type != VIRGL_RENDERER_BLOB_FD_TYPE_SHM || blob_fd < 0) {
			if (blob_fd >= 0) {
				(void)close(blob_fd);
			}
			virgl_renderer_ctx_detach_resource((int)h->ctx_id, (int)req.res_id);
			virgl_renderer_resource_unref(req.res_id);
			send_reply(s, h, GVX_GPU_STATUS_NOT_SUPPORTED, NULL, 0, -1);
			return 0;
		}

		uint32_t map_info = 0;
		if (virgl_renderer_resource_get_map_info(req.res_id, &map_info) != 0) {
			map_info = 0;
		}

		struct stat st;
		if (fstat(blob_fd, &st) != 0 ||
		    st.st_size < 0 ||
		    (uint64_t)st.st_size < req.size ||
		    ((uint64_t)st.st_size % GVX_GPU_HOST_BLOB_ALIGN) != 0) {
			(void)close(blob_fd);
			virgl_renderer_ctx_detach_resource((int)h->ctx_id, (int)req.res_id);
			virgl_renderer_resource_unref(req.res_id);
			send_reply(s, h, GVX_GPU_STATUS_IO, NULL, 0, -1);
			return 0;
		}

		rep.host_size = (uint64_t)st.st_size;
		rep.map_info = map_info;
		rep.fd_type = GVX_GPU_FD_TYPE_SHM;
	}

	uint8_t out[GVX_GPU_BLOB_CREATE_REPLY_SIZE];
	memcpy(out, &rep, sizeof(out));
	send_reply(s, h, GVX_GPU_STATUS_OK, out, (uint32_t)sizeof(out), blob_fd);
	if (blob_fd >= 0) {
		(void)close(blob_fd);
	}
	return 0;
}

static int handle_res_unref(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len != GVX_GPU_RES_UNREF_REQUEST_SIZE) {
		return protocol_error("bad RES_UNREF payload size");
	}

	struct gvx_gpu_res_unref_request req;
	memcpy(&req, s->buf, sizeof(req));

	if (find_context(s, h->ctx_id) != NULL) {
		virgl_renderer_ctx_detach_resource((int)h->ctx_id, (int)req.res_id);
	}
	virgl_renderer_resource_unref(req.res_id);

	send_reply(s, h, GVX_GPU_STATUS_OK, NULL, 0, -1);
	return 0;
}

static int handle_submit(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len < GVX_GPU_SUBMIT_REQUEST_SIZE) {
		return protocol_error("short SUBMIT payload");
	}

	struct gvx_gpu_submit_request req;
	memcpy(&req, s->buf, sizeof(req));
	if ((req.cmd_len % 4u) != 0 ||
	    req.cmd_len > GVX_GPU_MAX_SUBMIT_BYTES ||
	    h->payload_len != GVX_GPU_SUBMIT_REQUEST_SIZE + req.cmd_len) {
		return protocol_error("bad SUBMIT command length");
	}
	if ((req.flags & ~GVX_GPU_SUBMIT_FLAG_FENCE) != 0) {
		return protocol_error("unknown SUBMIT flags");
	}

	const bool has_fence = (req.flags & GVX_GPU_SUBMIT_FLAG_FENCE) != 0;
	if (has_fence && (req.ring_idx >= GVX_GPU_MAX_RINGS || req.fence_id == 0)) {
		return protocol_error("invalid SUBMIT fence parameters");
	}

	struct server_context *slot = find_context(s, h->ctx_id);
	if (slot == NULL) {
		send_reply(s, h, GVX_GPU_STATUS_INVALID, NULL, 0, -1);
		return 0;
	}
	if (slot->lost) {
		send_reply(s, h, GVX_GPU_STATUS_IO, NULL, 0, -1);
		return 0;
	}
	if (has_fence && slot->pending_fences == UINT32_MAX) {
		send_reply(s, h, GVX_GPU_STATUS_NO_SPACE, NULL, 0, -1);
		return 0;
	}

	if (req.cmd_len > 0) {
		/* s->buf is malloc-aligned and GVX_GPU_SUBMIT_REQUEST_SIZE is 24, so cmd is 8-byte aligned. */
		int ret = virgl_renderer_submit_cmd(
		    s->buf + GVX_GPU_SUBMIT_REQUEST_SIZE, (int)h->ctx_id, (int)(req.cmd_len / 4u));
		if (ret != 0) {
			slot->lost = true;
			send_ctx_lost(s, h->ctx_id, GVX_GPU_CTX_LOST_SUBMIT_FAILED);
			send_reply(s, h, GVX_GPU_STATUS_IO, NULL, 0, -1);
			return 0;
		}
	}

	if (has_fence) {
		int ret = virgl_renderer_context_create_fence(
		    h->ctx_id, 0, req.ring_idx, req.fence_id);
		if (ret != 0) {
			slot->lost = true;
			send_ctx_lost(s, h->ctx_id, GVX_GPU_CTX_LOST_FENCE_FAILED);
			send_reply(s, h, GVX_GPU_STATUS_IO, NULL, 0, -1);
			return 0;
		}
		slot->pending_fences++;
	}

	send_reply(s, h, GVX_GPU_STATUS_OK, NULL, 0, -1);
	return 0;
}

static int handle_test_confine(struct server *s, const struct gvx_gpu_header *h)
{
	if (h->payload_len != 0) {
		return protocol_error("non-empty TEST_CONFINE payload");
	}
	if (!s->test_ops) {
		send_reply(s, h, GVX_GPU_STATUS_NOT_SUPPORTED, NULL, 0, -1);
		return 0;
	}

	typedef uint8_t (*confine_check_fn)(char *, size_t);
	static const struct {
		uint8_t index;
		const char *name;
		confine_check_fn fn;
	} checks[GVX_GPU_CONFINE_CHECKS] = {
		{ GVX_GPU_CONFINE_CHECK_FORK, "deny-fork", confine_check_fork },
		{ GVX_GPU_CONFINE_CHECK_EXEC, "deny-exec", confine_check_exec },
		{ GVX_GPU_CONFINE_CHECK_READ, "deny-read", confine_check_read },
		{ GVX_GPU_CONFINE_CHECK_CREATE, "deny-create", confine_check_create },
		{ GVX_GPU_CONFINE_CHECK_CONNECT, "deny-connect", confine_check_connect },
	};

	struct gvx_gpu_test_confine_reply rep;
	memset(&rep, 0, sizeof(rep));
	rep.checks = GVX_GPU_CONFINE_CHECKS;

	for (size_t i = 0; i < GVX_GPU_CONFINE_CHECKS; i++) {
		char detail[256];
		detail[0] = '\0';
		uint8_t res = checks[i].fn(detail, sizeof(detail));
		rep.results[checks[i].index] = res;
		if (res != GVX_GPU_CONFINE_DENIED) {
			fprintf(stderr, "gvx-gpu-renderer: test-confine %s: %s\n",
			        checks[i].name, detail[0] != '\0' ? detail : "failed");
		}
	}

	uint8_t out[GVX_GPU_TEST_CONFINE_REPLY_SIZE];
	memcpy(out, &rep, sizeof(out));
	send_reply(s, h, GVX_GPU_STATUS_OK, out, (uint32_t)sizeof(out), -1);
	return 0;
}

static int dispatch_request(struct server *s, const struct gvx_gpu_header *h)
{
	if (!s->watchdog_armed &&
	    h->op != GVX_GPU_OP_HELLO &&
	    h->op != GVX_GPU_OP_GET_CAPSET) {
		s->watchdog_armed = true;
		watchdog_arm();
	}
	switch (h->op) {
	case GVX_GPU_OP_HELLO:
		return handle_hello(s, h);
	case GVX_GPU_OP_GET_CAPSET:
		return handle_get_capset(s, h);
	case GVX_GPU_OP_CTX_CREATE:
		return handle_ctx_create(s, h);
	case GVX_GPU_OP_CTX_DESTROY:
		return handle_ctx_destroy(s, h);
	case GVX_GPU_OP_BLOB_CREATE:
		return handle_blob_create(s, h);
	case GVX_GPU_OP_RES_UNREF:
		return handle_res_unref(s, h);
	case GVX_GPU_OP_SUBMIT:
		return handle_submit(s, h);
	case GVX_GPU_OP_TEST_CONFINE:
		return handle_test_confine(s, h);
	default:
		return protocol_error("unknown request op");
	}
}

int server_run(int sock, bool stall_fences, bool test_ops)
{
	struct server *s = &g_server;
	s->sock = sock;
	s->stall_fences = stall_fences;
	s->test_ops = test_ops;

	for (;;) {
		if (s->peer_gone) {
			return GVX_GPU_EXIT_OK;
		}

		int timeout = (!s->stall_fences && has_pending_fences(s)) ? 1 : -1;
		struct pollfd pfd = {
			.fd = s->sock,
			.events = POLLIN,
			.revents = 0,
		};

		int pr = poll(&pfd, 1, timeout);
		if (pr < 0) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "gvx-gpu-renderer: poll failed: %s\n", strerror(errno));
			return GVX_GPU_EXIT_OK;
		}

		if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
			uint8_t hdr_buf[GVX_GPU_HEADER_SIZE];
			int rr = wire_read_full(s->sock, hdr_buf, sizeof(hdr_buf));
			if (rr == 0) {
				return GVX_GPU_EXIT_OK;
			}
			if (rr < 0) {
				(void)protocol_error("truncated request header");
				return GVX_GPU_EXIT_PROTOCOL;
			}

			struct gvx_gpu_header h;
			memcpy(&h, hdr_buf, sizeof(h));
			if (validate_header(s, &h) != 0) {
				return GVX_GPU_EXIT_PROTOCOL;
			}

			if (h.payload_len > 0) {
				if (h.payload_len > s->buf_cap) {
					uint8_t *grown = realloc(s->buf, h.payload_len);
					if (grown == NULL) {
						fprintf(stderr, "gvx-gpu-renderer: out of memory allocating %u bytes\n",
						        h.payload_len);
						return GVX_GPU_EXIT_INIT;
					}
					s->buf = grown;
					s->buf_cap = h.payload_len;
				}
				if (wire_read_full(s->sock, s->buf, h.payload_len) != 1) {
					(void)protocol_error("truncated request payload");
					return GVX_GPU_EXIT_PROTOCOL;
				}
			}

			if (dispatch_request(s, &h) != 0) {
				return GVX_GPU_EXIT_PROTOCOL;
			}
			if (s->peer_gone) {
				return GVX_GPU_EXIT_OK;
			}
		}

		if (!s->stall_fences) {
			for (size_t i = 0; i < SERVER_MAX_CONTEXTS; i++) {
				if (s->ctx[i].id != 0 && s->ctx[i].pending_fences > 0) {
					virgl_renderer_context_poll(s->ctx[i].id);
					if (s->peer_gone) {
						return GVX_GPU_EXIT_OK;
					}
				}
			}
		}
	}
}
