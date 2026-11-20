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
int main(void) {
	struct gvx_gpu_header h = { .magic = GVX_GPU_MAGIC, .status = GVX_GPU_STATUS_INVALID };
	const char *arg = GVX_GPU_ARG_SELFTEST;
	return (int)(h.magic != GVX_GPU_MAGIC) + (arg[0] != '-');
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
