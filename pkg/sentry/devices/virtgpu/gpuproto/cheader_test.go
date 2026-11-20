// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gpuproto_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

func TestGeneratedHeaderIsCurrent(t *testing.T) {
	onDisk, err := os.ReadFile("../../../../../gpurenderer/gvx_gpu_protocol.h")
	if err != nil {
		t.Fatalf("read generated header: %v", err)
	}
	want := gpuproto.CHeader()
	if !bytes.Equal(onDisk, want) {
		t.Fatalf("gpurenderer/gvx_gpu_protocol.h is stale: run go generate ./pkg/sentry/devices/virtgpu/gpuproto")
	}
}

func TestCHeaderCompilesWithCC(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("C compiler not found in PATH: %v", err)
	}

	dir := t.TempDir()
	headerPath := filepath.Join(dir, "gvx_gpu_protocol.h")
	if err := os.WriteFile(headerPath, gpuproto.CHeader(), 0o644); err != nil {
		t.Fatalf("write header: %v", err)
	}

	const mainC = `#include "gvx_gpu_protocol.h"
_Static_assert(GVX_GPU_HEADER_SIZE == sizeof(struct gvx_gpu_header), "header size macro");
_Static_assert(GVX_GPU_HELLO_REQUEST_SIZE == sizeof(struct gvx_gpu_hello_request), "hello_request size macro");
_Static_assert(GVX_GPU_HELLO_REPLY_SIZE == sizeof(struct gvx_gpu_hello_reply), "hello_reply size macro");
_Static_assert(GVX_GPU_CAPSET_INFO_SIZE == sizeof(struct gvx_gpu_capset_info), "capset_info size macro");
_Static_assert(GVX_GPU_GET_CAPSET_REQUEST_SIZE == sizeof(struct gvx_gpu_get_capset_request), "get_capset_request size macro");
_Static_assert(GVX_GPU_CTX_CREATE_REQUEST_SIZE == sizeof(struct gvx_gpu_ctx_create_request), "ctx_create_request size macro");
_Static_assert(GVX_GPU_BLOB_CREATE_REQUEST_SIZE == sizeof(struct gvx_gpu_blob_create_request), "blob_create_request size macro");
_Static_assert(GVX_GPU_BLOB_CREATE_REPLY_SIZE == sizeof(struct gvx_gpu_blob_create_reply), "blob_create_reply size macro");
_Static_assert(GVX_GPU_RES_UNREF_REQUEST_SIZE == sizeof(struct gvx_gpu_res_unref_request), "res_unref_request size macro");
_Static_assert(GVX_GPU_SUBMIT_REQUEST_SIZE == sizeof(struct gvx_gpu_submit_request), "submit_request size macro");
_Static_assert(GVX_GPU_FENCE_DONE_EVENT_SIZE == sizeof(struct gvx_gpu_fence_done_event), "fence_done_event size macro");
_Static_assert(GVX_GPU_CTX_LOST_EVENT_SIZE == sizeof(struct gvx_gpu_ctx_lost_event), "ctx_lost_event size macro");
_Static_assert(GVX_GPU_TEST_CONFINE_REPLY_SIZE == sizeof(struct gvx_gpu_test_confine_reply), "test_confine_reply size macro");
_Static_assert(GVX_GPU_RES_CREATE_REQUEST_SIZE == sizeof(struct gvx_gpu_res_create_request), "res_create_request size macro");
_Static_assert(GVX_GPU_RES_CREATE_REPLY_SIZE == sizeof(struct gvx_gpu_res_create_reply), "res_create_reply size macro");
_Static_assert(GVX_GPU_TRANSFER_REQUEST_SIZE == sizeof(struct gvx_gpu_transfer_request), "transfer_request size macro");
int main(void) {
	struct gvx_gpu_header h = { .magic = GVX_GPU_MAGIC, .status = GVX_GPU_STATUS_INVALID };
	struct gvx_gpu_hello_request hreq = { .version = GVX_GPU_VERSION, .mode = GVX_GPU_MODE_VIRGL };
	struct gvx_gpu_hello_reply hrep = { .version = GVX_GPU_VERSION, .mode = GVX_GPU_MODE_VENUS, .reserved = 0 };
	struct gvx_gpu_res_create_request rreq = { .res_id = 1, .size = 4096 };
	struct gvx_gpu_res_create_reply rrep = { .host_size = GVX_GPU_HOST_BLOB_ALIGN, .fd_type = GVX_GPU_FD_TYPE_SHM };
	struct gvx_gpu_transfer_request treq = { .res_id = 1, .direction = GVX_GPU_TRANSFER_TO_HOST };
	const char *arg = GVX_GPU_ARG_MODE;
	return (int)(h.magic != GVX_GPU_MAGIC) +
	       (int)(hreq.mode != GVX_GPU_MODE_VIRGL) +
	       (int)(hrep.mode != GVX_GPU_MODE_VENUS) +
	       (int)(rreq.res_id != 1) +
	       (int)(rrep.fd_type != GVX_GPU_FD_TYPE_SHM) +
	       (int)(treq.direction != GVX_GPU_TRANSFER_TO_HOST) +
	       (arg[0] != '-');
}
`
	mainPath := filepath.Join(dir, "main.c")
	if err := os.WriteFile(mainPath, []byte(mainC), 0o644); err != nil {
		t.Fatalf("write main.c: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cc, "-std=c11", "-Wall", "-Werror", "-fsyntax-only", "-I"+dir, mainPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cc failed: %v\n%s", err, out)
	}
}

func TestCHeaderHasNewNames(t *testing.T) {
	text := string(gpuproto.CHeader())
	want := []string{
		"#define GVX_GPU_VERSION 2u",
		"#define GVX_GPU_OP_RES_CREATE 11u",
		"#define GVX_GPU_OP_TRANSFER 12u",
		"#define GVX_GPU_CAPSET_VIRGL 1u",
		"#define GVX_GPU_CAPSET_VIRGL2 2u",
		"#define GVX_GPU_TRANSFER_TO_HOST 1u",
		"#define GVX_GPU_TRANSFER_FROM_HOST 2u",
		"#define GVX_GPU_MODE_VENUS 1u",
		"#define GVX_GPU_MODE_VIRGL 2u",
		"#define GVX_GPU_ARG_MODE \"--mode=\"",
		"#define GVX_GPU_MODE_NAME_VENUS \"venus\"",
		"#define GVX_GPU_MODE_NAME_VIRGL \"virgl\"",
		"struct gvx_gpu_res_create_request {",
		"struct gvx_gpu_res_create_reply {",
		"struct gvx_gpu_transfer_request {",
	}
	for _, needle := range want {
		if !strings.Contains(text, needle) {
			t.Errorf("CHeader() missing %q", needle)
		}
	}
}
