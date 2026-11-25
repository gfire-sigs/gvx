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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

struct res_backing {
	void *base;
	size_t size;
	struct iovec iov;
};

/*
 * Matches struct virgl_box (six uint32_t fields, cast inside virglrenderer to
 * struct pipe_box of six 32-bit int fields). virglrenderer.h only
 * forward-declares struct virgl_box.
 */
struct gvx_box {
	uint32_t x;
	uint32_t y;
	uint32_t z;
	uint32_t w;
	uint32_t h;
	uint32_t d;
};
_Static_assert(sizeof(struct gvx_box) == 24, "gvx_box size");

static uint64_t round_up_align(uint64_t size, uint64_t align)
{
	return ((size + align - 1u) / align) * align;
}

int32_t virgl_res_create(uint32_t ctx_id,
                         const struct gvx_gpu_res_create_request *req,
                         int *fd_out,
                         uint64_t *host_size_out)
{
	if (req->res_id == 0 ||
	    req->size == 0 ||
	    req->size > GVX_GPU_MAX_BLOB_BYTES) {
		return GVX_GPU_STATUS_INVALID;
	}
	/* PIPE_BUFFER (target 0) has a linear backing; width cannot exceed size. */
	if (req->target == 0u &&
	    (req->width > GVX_GPU_MAX_BLOB_BYTES || (uint64_t)req->width > req->size)) {
		return GVX_GPU_STATUS_INVALID;
	}

	const uint64_t host_size = round_up_align(req->size, GVX_GPU_HOST_BLOB_ALIGN);

	int fd = -1;
	int last_err = 0;
	char name[32];
	for (int attempt = 0; attempt < 8; attempt++) {
		uint64_t rnd = 0;
		arc4random_buf(&rnd, sizeof(rnd));
		snprintf(name, sizeof(name), "/gvx-r-%016llx", (unsigned long long)rnd);
		/* macOS shm_open rejects O_CLOEXEC with EINVAL; set FD_CLOEXEC after open. */
		fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd >= 0) {
			break;
		}
		last_err = errno;
		if (last_err != EEXIST) {
			break;
		}
	}
	if (fd < 0) {
		if (last_err == EACCES || last_err == EPERM) {
			fprintf(stderr, "gvx-gpu-renderer: shm_open(%s): %s\n",
			        name, strerror(last_err));
			return GVX_GPU_STATUS_IO;
		}
		return GVX_GPU_STATUS_NO_MEMORY;
	}
	(void)shm_unlink(name);
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);

	if (ftruncate(fd, (off_t)host_size) != 0) {
		(void)close(fd);
		return GVX_GPU_STATUS_NO_MEMORY;
	}

	void *base = mmap(NULL, (size_t)host_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		(void)close(fd);
		return GVX_GPU_STATUS_NO_MEMORY;
	}

	struct virgl_renderer_resource_create_args args = {
		.handle = req->res_id,
		.target = req->target,
		.format = req->format,
		.bind = req->bind,
		.width = req->width,
		.height = req->height,
		.depth = req->depth,
		.array_size = req->array_size,
		.last_level = req->last_level,
		.nr_samples = req->nr_samples,
		.flags = req->flags,
	};

	/*
	 * Switch to ctx0 so GL allocation errors stay off guest contexts.
	 * Create with no iovec first, then attach: passing iovecs to
	 * virgl_renderer_resource_create bypasses the vrend attach_iov callback.
	 */
	virgl_renderer_force_ctx_0();
	int ret = virgl_renderer_resource_create(&args, NULL, 0);
	if (ret != 0) {
		(void)munmap(base, (size_t)host_size);
		(void)close(fd);
		return renderer_status_from_ret(ret);
	}

	struct res_backing *bk = malloc(sizeof(*bk));
	if (bk == NULL) {
		virgl_renderer_resource_unref(req->res_id);
		(void)munmap(base, (size_t)host_size);
		(void)close(fd);
		return GVX_GPU_STATUS_NO_MEMORY;
	}
	bk->base = base;
	bk->size = (size_t)host_size;
	bk->iov.iov_base = base;
	bk->iov.iov_len = (size_t)host_size;

	ret = virgl_renderer_resource_attach_iov((int)req->res_id, &bk->iov, 1);
	if (ret != 0) {
		free(bk);
		virgl_renderer_resource_unref(req->res_id);
		(void)munmap(base, (size_t)host_size);
		(void)close(fd);
		return GVX_GPU_STATUS_IO;
	}

	virgl_renderer_resource_set_priv(req->res_id, bk);
	virgl_renderer_ctx_attach_resource((int)ctx_id, (int)req->res_id);

	*fd_out = fd;
	*host_size_out = host_size;
	return GVX_GPU_STATUS_OK;
}

int32_t virgl_res_transfer(uint32_t ctx_id,
                           const struct gvx_gpu_transfer_request *req)
{
	if (req->res_id == 0 ||
	    (req->direction != GVX_GPU_TRANSFER_TO_HOST &&
	     req->direction != GVX_GPU_TRANSFER_FROM_HOST)) {
		return GVX_GPU_STATUS_INVALID;
	}

	struct gvx_box box = {
		.x = req->box_x,
		.y = req->box_y,
		.z = req->box_z,
		.w = req->box_w,
		.h = req->box_h,
		.d = req->box_d,
	};

	int ret;
	if (req->direction == GVX_GPU_TRANSFER_TO_HOST) {
		ret = virgl_renderer_transfer_write_iov(
		    req->res_id, ctx_id, (int)req->level, req->stride, req->layer_stride,
		    (struct virgl_box *)&box, req->offset, NULL, 0);
	} else {
		ret = virgl_renderer_transfer_read_iov(
		    req->res_id, ctx_id, req->level, req->stride, req->layer_stride,
		    (struct virgl_box *)&box, req->offset, NULL, 0);
	}
	if (ret != 0) {
		return renderer_status_from_ret(ret);
	}
	return GVX_GPU_STATUS_OK;
}

void virgl_res_unref(uint32_t ctx_id, bool ctx_live, uint32_t res_id)
{
	struct res_backing *bk =
	    (struct res_backing *)virgl_renderer_resource_get_priv(res_id);
	if (bk != NULL) {
		/* Detach before munmap because vrend copies host-memory resources back here. */
		virgl_renderer_resource_detach_iov((int)res_id, NULL, NULL);
	}
	if (ctx_live) {
		virgl_renderer_ctx_detach_resource((int)ctx_id, (int)res_id);
	}
	virgl_renderer_resource_unref(res_id);
	if (bk != NULL) {
		(void)munmap(bk->base, bk->size);
		free(bk);
	}
}
