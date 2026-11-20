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

package main

import (
	"bufio"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

var probeABIStructs = []struct {
	c string
	v any
}{
	{"drm_version", drmVersion{}},
	{"drm_get_cap", drmGetCap{}},
	{"drm_gem_close", drmGemClose{}},
	{"drm_virtgpu_getparam", virtgpuGetparam{}},
	{"drm_virtgpu_get_caps", virtgpuGetCaps{}},
	{"drm_virtgpu_context_set_param", virtgpuContextSetParam{}},
	{"drm_virtgpu_context_init", virtgpuContextInit{}},
	{"drm_virtgpu_resource_create", virtgpuResourceCreate{}},
	{"drm_virtgpu_resource_info", virtgpuResourceInfo{}},
	{"drm_virtgpu_3d_box", virtgpu3DBox{}},
	{"drm_virtgpu_3d_transfer_to_host", virtgpu3DTransfer{}},
	{"drm_virtgpu_3d_transfer_from_host", virtgpu3DTransfer{}},
	{"drm_virtgpu_3d_wait", virtgpu3DWait{}},
	{"drm_virtgpu_resource_create_blob", virtgpuResourceCreateBlob{}},
	{"drm_virtgpu_map", virtgpuMap{}},
	{"drm_virtgpu_execbuffer", virtgpuExecbuffer{}},
}

func snake(s string) string {
	var b strings.Builder
	r := []rune(s)
	for i, c := range r {
		if unicode.IsUpper(c) && i > 0 && (unicode.IsLower(r[i-1]) || (i+1 < len(r) && unicode.IsLower(r[i+1]))) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

func probeABI(t *testing.T) map[string]uint64 {
	t.Helper()
	m := map[string]uint64{
		"cmd DRM_IOCTL_VERSION":                      uint64(cmdVersion),
		"cmd DRM_IOCTL_GEM_CLOSE":                    uint64(cmdGemClose),
		"cmd DRM_IOCTL_GET_CAP":                      uint64(cmdGetCap),
		"cmd DRM_IOCTL_VIRTGPU_MAP":                  uint64(cmdVirtgpuMap),
		"cmd DRM_IOCTL_VIRTGPU_EXECBUFFER":           uint64(cmdVirtgpuExecbuffer),
		"cmd DRM_IOCTL_VIRTGPU_GETPARAM":             uint64(cmdVirtgpuGetparam),
		"cmd DRM_IOCTL_VIRTGPU_RESOURCE_CREATE":      uint64(cmdVirtgpuResourceCreate),
		"cmd DRM_IOCTL_VIRTGPU_RESOURCE_INFO":        uint64(cmdVirtgpuResourceInfo),
		"cmd DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST":   uint64(cmdVirtgpuTransferFromHost),
		"cmd DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST":     uint64(cmdVirtgpuTransferToHost),
		"cmd DRM_IOCTL_VIRTGPU_WAIT":                 uint64(cmdVirtgpuWait),
		"cmd DRM_IOCTL_VIRTGPU_GET_CAPS":             uint64(cmdVirtgpuGetCaps),
		"cmd DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB": uint64(cmdVirtgpuResourceCreateBlob),
		"cmd DRM_IOCTL_VIRTGPU_CONTEXT_INIT":         uint64(cmdVirtgpuContextInit),

		"const DRM_COMMAND_BASE":                      drmCommandBase,
		"const DRM_CAP_SYNCOBJ":                       drmCapSyncobj,
		"const VIRTGPU_PARAM_3D_FEATURES":             virtgpuParam3DFeatures,
		"const VIRTGPU_PARAM_CAPSET_QUERY_FIX":        virtgpuParamCapsetQueryFix,
		"const VIRTGPU_PARAM_RESOURCE_BLOB":           virtgpuParamResourceBlob,
		"const VIRTGPU_PARAM_HOST_VISIBLE":            virtgpuParamHostVisible,
		"const VIRTGPU_PARAM_CROSS_DEVICE":            virtgpuParamCrossDevice,
		"const VIRTGPU_PARAM_CONTEXT_INIT":            virtgpuParamContextInit,
		"const VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs":    virtgpuParamSupportedCapsetIDs,
		"const VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME":     virtgpuParamExplicitDebugName,
		"const VIRTGPU_DRM_CAPSET_VIRGL":              virtgpuCapsetVirgl,
		"const VIRTGPU_DRM_CAPSET_VIRGL2":             virtgpuCapsetVirgl2,
		"const VIRTGPU_DRM_CAPSET_VENUS":              virtgpuCapsetVenus,
		"const VIRTGPU_WAIT_NOWAIT":                   virtgpuWaitNoWait,
		"const VIRTGPU_BLOB_MEM_HOST3D":               virtgpuBlobMemHost3D,
		"const VIRTGPU_BLOB_FLAG_USE_MAPPABLE":        virtgpuBlobFlagUseMappable,
		"const VIRTGPU_CONTEXT_PARAM_CAPSET_ID":       virtgpuContextParamCapsetID,
		"const VIRTGPU_CONTEXT_PARAM_NUM_RINGS":       virtgpuContextParamNumRings,
		"const VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK": virtgpuContextParamPollRingsMask,
		"const VIRTGPU_EXECBUF_FENCE_FD_OUT":          virtgpuExecbufFenceFDOut,
		"const VIRTGPU_EXECBUF_RING_IDX":              virtgpuExecbufRingIdx,
	}
	for _, s := range probeABIStructs {
		typ := reflect.TypeOf(s.v)
		if bin, mem := binary.Size(s.v), int(typ.Size()); bin != mem {
			t.Errorf("%s: binary.Size %d != unsafe.Sizeof %d", s.c, bin, mem)
		}
		m["sizeof "+s.c] = uint64(typ.Size())
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.Name == "_" {
				continue
			}
			m["offsetof "+s.c+"."+snake(f.Name)] = uint64(f.Offset)
		}
	}
	return m
}

func readABITable(t *testing.T, path string) map[string]uint64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	m := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("%s: malformed line %q", path, line)
		}
		v, err := strconv.ParseUint(fields[2], 0, 64)
		if err != nil {
			t.Fatalf("%s: %q: %v", path, line, err)
		}
		m[fields[0]+" "+fields[1]] = v
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return m
}

func TestGPUProbeABIMatchesClangTables(t *testing.T) {
	got := probeABI(t)
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "pkg", "sentry", "devices", "virtgpu", "testdata", "abi_"+arch+".txt")
			want := readABITable(t, path)
			for k, g := range got {
				w, ok := want[k]
				if !ok {
					t.Errorf("%s: gpuprobe defines it, %s does not", k, path)
					continue
				}
				if g != w {
					t.Errorf("%s = %#x in gpuprobe, %#x from clang", k, g, w)
				}
			}
		})
	}
}
