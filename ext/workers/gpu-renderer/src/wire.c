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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

int wire_read_full(int fd, void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf;
	size_t done = 0;

	while (done < len) {
		ssize_t n = read(fd, p + done, len - done);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return done == 0 ? 0 : -1;
		}
		done += (size_t)n;
	}
	return 1;
}

static int write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = write(fd, buf + done, len - done);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (n == 0) {
			return -1;
		}
		done += (size_t)n;
	}
	return 0;
}

int wire_send(int fd, const struct gvx_gpu_header *h, const void *payload, int send_fd)
{
	const bool want_fd = send_fd >= 0;
	const bool flag_fd = (h->flags & GVX_GPU_FLAG_FD) != 0;
	if (want_fd != flag_fd) {
		fprintf(stderr, "gvx-gpu-renderer: internal error: send_fd and GVX_GPU_FLAG_FD disagree\n");
		abort();
	}

	uint8_t hdr_buf[GVX_GPU_HEADER_SIZE];
	memcpy(hdr_buf, h, sizeof(hdr_buf));

	struct iovec iov[2];
	iov[0].iov_base = hdr_buf;
	iov[0].iov_len = sizeof(hdr_buf);
	int iovcnt = 1;
	if (h->payload_len > 0) {
		/* sendmsg does not mutate iov_base; cast removes const for POSIX struct iovec. */
		iov[1].iov_base = (void *)(uintptr_t)payload;
		iov[1].iov_len = h->payload_len;
		iovcnt = 2;
	}

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = iovcnt;

	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} cmsg_buf;

	if (want_fd) {
		memset(&cmsg_buf, 0, sizeof(cmsg_buf));
		msg.msg_control = cmsg_buf.buf;
		msg.msg_controllen = sizeof(cmsg_buf.buf);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &send_fd, sizeof(int));
	}

	ssize_t n;
	do {
		n = sendmsg(fd, &msg, 0);
	} while (n < 0 && errno == EINTR);
	if (n <= 0) {
		return -1;
	}

	size_t sent = (size_t)n;
	if (sent < sizeof(hdr_buf)) {
		if (write_all(fd, hdr_buf + sent, sizeof(hdr_buf) - sent) != 0) {
			return -1;
		}
		if (h->payload_len > 0) {
			if (write_all(fd, (const uint8_t *)payload, h->payload_len) != 0) {
				return -1;
			}
		}
		return 0;
	}

	size_t payload_sent = sent - sizeof(hdr_buf);
	if (payload_sent < h->payload_len) {
		const uint8_t *p = (const uint8_t *)payload;
		if (write_all(fd, p + payload_sent, h->payload_len - payload_sent) != 0) {
			return -1;
		}
	}
	return 0;
}
