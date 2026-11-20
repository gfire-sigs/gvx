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

#ifndef GVX_GPU_RENDERER_H
#define GVX_GPU_RENDERER_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vulkan/vulkan.h>

#include "gvx_gpu_protocol.h"
#include "virglrenderer.h"

/* Real paths of the bundle that holds this executable. */
struct bundle {
	char root[PATH_MAX];    /* <root>/bin/gvx-gpu-renderer */
	char lib_dir[PATH_MAX]; /* <root>/lib */
	void *vulkan;           /* dlopen handle of libvulkan.dylib; never closed */
	PFN_vkGetInstanceProcAddr get_instance_proc_addr;
};

/*
 * Populates b->root and b->lib_dir from the executable real path.
 * Prints one diagnostic line on stderr and returns -1 on failure.
 */
int bundle_locate(struct bundle *b);

/*
 * Verifies bundle Vulkan libraries and loads libvulkan.dylib by leaf name.
 * Requires b->lib_dir from bundle_locate. Prints one diagnostic line on
 * stderr and returns -1 on failure.
 */
int bundle_load_vulkan(struct bundle *b);

/*
 * Applies the renderer Seatbelt profile and resource limits.
 * bundle_dir is the real path of the readable bundle directory.
 * Writes one line to err and returns -1 on failure.
 * The kernel keeps the profile until process exit.
 */
int confine_apply(const char *bundle_dir, char *err, size_t err_len);

/*
 * Creates a VkInstance and VkDevice with VK_EXT_external_memory_host (and
 * VK_KHR_portability_subset when the driver lists it), then destroys both.
 * Returns 0 or -1 with a diagnostic message in err.
 */
int vk_probe_device(const struct bundle *b, char *err, size_t err_len);

/* Self-test result index for each Vulkan stage. */
enum vk_stage {
	VK_STAGE_DEVICE,
	VK_STAGE_SHADER,
	VK_STAGE_SHM_IMPORT,
	VK_STAGE_GPU_WRITE,
	VK_STAGE_COUNT
};

/*
 * Runs the Vulkan self-test sequence: device creation, compute shader
 * compilation, POSIX shm import through VK_EXT_external_memory_host,
 * dispatch, and readback. Writes 0 (pass) or -1 (fail) to result[], and writes
 * the first failure detail to err. Records the device-plus-shader wall time in
 * milliseconds to compile_ms (0 when the device stage fails). Sets every stage
 * after a failed stage to -1.
 */
void vk_selftest(const struct bundle *b,
                 int result[VK_STAGE_COUNT],
                 uint64_t *compile_ms,
                 char *err,
                 size_t err_len);

/*
 * Reads exactly len bytes from fd. Returns 1 on success, 0 on end of file
 * before the first byte, and -1 on a short read or error.
 */
int wire_read_full(int fd, void *buf, size_t len);

/*
 * Writes one message (header followed by payload) to fd. When send_fd >= 0,
 * sendmsg attaches the descriptor through SCM_RIGHTS on the first header
 * byte. Callers must set GVX_GPU_FLAG_FD in h->flags when send_fd >= 0.
 * Returns 0 on success or -1 on write failure.
 */
int wire_send(int fd, const struct gvx_gpu_header *h, const void *payload, int send_fd);

/*
 * Returns the callback table and cookie for virgl_renderer_init. The cookie is
 * the process-lifetime server state.
 */
struct virgl_renderer_callbacks *server_callbacks(void);
void *server_cookie(void);

/*
 * Reads and validates the capsets of mode (venus: 4; virgl: 1 and 2) with
 * virgl_renderer_get_cap_set. In virgl mode it also fills each capset at its
 * max_version into the cache. Rejects max_size 0 or above
 * GVX_GPU_MAX_CAPSET_BYTES and max_version above GVX_GPU_MAX_CAPSET_VERSION.
 * Returns 0, or -1 with a message in err.
 */
int server_init_capsets(uint32_t mode, char *err, size_t err_len);

/* Returns the number of initialized capsets. */
uint32_t server_capset_count(void);

/*
 * Reads cached capset metadata and bytes at index into out parameters.
 * Returns true when index is valid and cached.
 */
bool server_get_cached_capset(uint32_t index,
                              uint32_t *id_out,
                              uint32_t *max_version_out,
                              const uint8_t **data_out,
                              uint32_t *size_out);

/*
 * Maps a virglrenderer return value (negative or positive host errno) to a
 * closed GVX_GPU_STATUS_* value.
 */
int32_t renderer_status_from_ret(int ret);

/*
 * Creates a virglrenderer context. In virgl mode it restores ctx0 after
 * creation so vrend's context tracker matches the thread-local CGL context.
 */
int server_create_context(uint32_t ctx_id,
                          uint32_t capset_id,
                          uint32_t name_len,
                          const char *name);

/* Reports whether the last write_context_fence callback matched (ctx_id, fence_id). */
bool server_fence_seen(uint32_t ctx_id, uint64_t fence_id);

/* Serves protocol requests on sock until end of file. Returns a GVX_GPU_EXIT_* code. */
int server_run(int sock, uint32_t mode, bool stall_fences, bool test_ops);

/* Runs all self-test checks for mode and prints one line per check to stdout. */
int selftest_run(const struct bundle *b, uint32_t mode);

/*
 * Confinement checks shared by --selftest and TEST_CONFINE.
 * Each returns GVX_GPU_CONFINE_DENIED, ALLOWED, or UNEXPECTED and writes a
 * diagnostic string to detail when the result is not DENIED.
 */
uint8_t confine_check_fork(char *detail, size_t detail_len);
uint8_t confine_check_exec(char *detail, size_t detail_len);
uint8_t confine_check_read(char *detail, size_t detail_len);
uint8_t confine_check_create(char *detail, size_t detail_len);
uint8_t confine_check_connect(char *detail, size_t detail_len);

/*
 * Reads the task phys_footprint in bytes into out_bytes.
 * Returns 0 on success or an errno value on failure.
 */
int watchdog_sample_footprint(uint64_t *out_bytes);

/*
 * Starts a detached thread that polls phys_footprint every
 * GVX_GPU_WATCHDOG_PERIOD_MILLIS. Exits with GVX_GPU_EXIT_MEMORY_LIMIT
 * once armed and above limit_bytes. A limit_bytes of 0 starts nothing.
 * Returns 0 on success or an errno value on failure.
 */
int watchdog_start(uint64_t limit_bytes);

/* Arms the memory watchdog after the protocol handshake finishes. */
void watchdog_arm(void);

/*
 * Returns virglrenderer initialization flags for mode.
 * VIRGL_RENDERER_ASYNC_FENCE_CB stays clear so write_context_fence runs on the
 * thread calling poll.
 */
int renderer_virgl_flags(uint32_t mode);

#define GL_CGL_MAX_CONTEXTS 1024u

/*
 * Chooses the CGL pixel format, creates one probe context, and verifies that
 * it is an accelerated OpenGL 4.1 core context. Logs one line:
 * "gvx-gpu-renderer: OpenGL: <GL_RENDERER>, <GL_VERSION>". Leaves no context
 * current. Call once before virgl_renderer_init and before confinement.
 * Returns 0, or -1 with a message in err.
 */
int gl_cgl_init(char *err, size_t err_len);

/* Returns GL_RENDERER of the probe context, or "" before gl_cgl_init. */
const char *gl_cgl_renderer(void);

/* vrend GL callbacks (struct virgl_renderer_callbacks v4). */
virgl_renderer_gl_context gl_cgl_create_context(void *cookie,
                                                int scanout_idx,
                                                struct virgl_renderer_gl_ctx_param *param);
void gl_cgl_destroy_context(void *cookie, virgl_renderer_gl_context ctx);
int gl_cgl_make_current(void *cookie, int scanout_idx, virgl_renderer_gl_context ctx);

/* Returns the number of live contexts that gl_cgl_create_context returned. */
uint32_t gl_cgl_live_contexts(void);

/*
 * Creates a vrend resource with a shared-memory backing and attaches both to
 * ctx_id. Writes the descriptor to fd_out and the aligned size to
 * host_size_out, and returns a GVX_GPU_STATUS_* code.
 */
int32_t virgl_res_create(uint32_t ctx_id,
                         const struct gvx_gpu_res_create_request *req,
                         int *fd_out,
                         uint64_t *host_size_out);

/*
 * Copies synchronously between the attached backing of req->res_id and the
 * vrend resource in ctx_id. Returns a GVX_GPU_STATUS_* code.
 */
int32_t virgl_res_transfer(uint32_t ctx_id,
                           const struct gvx_gpu_transfer_request *req);

/*
 * Detaches the backing and context attachment (when ctx_live is true), unrefs
 * res_id, and unmaps and frees the backing.
 */
void virgl_res_unref(uint32_t ctx_id, bool ctx_live, uint32_t res_id);

#endif /* GVX_GPU_RENDERER_H */
