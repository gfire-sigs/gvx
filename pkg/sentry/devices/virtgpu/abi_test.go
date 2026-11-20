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

package virtgpu

import (
	"bufio"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// abiStructs names the C structure of every ABI struct.
var abiStructs = []struct {
	c string
	v any
}{
	{"drm_version", drmVersion{}},
	{"drm_get_cap", drmGetCap{}},
	{"drm_gem_close", drmGemClose{}},
	{"drm_virtgpu_map", virtgpuMap{}},
	{"drm_virtgpu_execbuffer", virtgpuExecbuffer{}},
	{"drm_virtgpu_getparam", virtgpuGetparam{}},
	{"drm_virtgpu_resource_info", virtgpuResourceInfo{}},
	{"drm_virtgpu_get_caps", virtgpuGetCaps{}},
	{"drm_virtgpu_resource_create_blob", virtgpuResourceCreateBlob{}},
	{"drm_virtgpu_context_set_param", virtgpuContextSetParam{}},
	{"drm_virtgpu_context_init", virtgpuContextInit{}},
}

// snake converts a Go field name to the C field name: NameLen is name_len,
// FenceFD is fence_fd, CapSetID is cap_set_id.
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

// goABI returns every value that the Go side defines, keyed as gen.sh keys the
// clang output.
func goABI(t *testing.T) map[string]uint64 {
	m := map[string]uint64{
		"cmd DRM_IOCTL_VERSION":                      uint64(cmdVersion),
		"cmd DRM_IOCTL_GEM_CLOSE":                    uint64(cmdGemClose),
		"cmd DRM_IOCTL_GET_CAP":                      uint64(cmdGetCap),
		"cmd DRM_IOCTL_VIRTGPU_MAP":                  uint64(cmdVirtgpuMap),
		"cmd DRM_IOCTL_VIRTGPU_EXECBUFFER":           uint64(cmdVirtgpuExecbuffer),
		"cmd DRM_IOCTL_VIRTGPU_GETPARAM":             uint64(cmdVirtgpuGetparam),
		"cmd DRM_IOCTL_VIRTGPU_RESOURCE_INFO":        uint64(cmdVirtgpuResourceInfo),
		"cmd DRM_IOCTL_VIRTGPU_GET_CAPS":             uint64(cmdVirtgpuGetCaps),
		"cmd DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB": uint64(cmdVirtgpuResourceCreateBlob),
		"cmd DRM_IOCTL_VIRTGPU_CONTEXT_INIT":         uint64(cmdVirtgpuContextInit),

		"const DRM_COMMAND_BASE":                      drmCommandBase,
		"const DRM_COMMAND_END":                       drmCommandEnd,
		"const DRM_CAP_DUMB_BUFFER":                   drmCapDumbBuffer,
		"const DRM_CAP_PRIME":                         drmCapPrime,
		"const DRM_CAP_TIMESTAMP_MONOTONIC":           drmCapTimestampMonotonic,
		"const DRM_CAP_SYNCOBJ":                       drmCapSyncobj,
		"const DRM_CAP_SYNCOBJ_TIMELINE":              drmCapSyncobjTimeline,
		"const VIRTGPU_PARAM_3D_FEATURES":             virtgpuParam3DFeatures,
		"const VIRTGPU_PARAM_CAPSET_QUERY_FIX":        virtgpuParamCapsetQueryFix,
		"const VIRTGPU_PARAM_RESOURCE_BLOB":           virtgpuParamResourceBlob,
		"const VIRTGPU_PARAM_HOST_VISIBLE":            virtgpuParamHostVisible,
		"const VIRTGPU_PARAM_CROSS_DEVICE":            virtgpuParamCrossDevice,
		"const VIRTGPU_PARAM_CONTEXT_INIT":            virtgpuParamContextInit,
		"const VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs":    virtgpuParamSupportedCapsetIDs,
		"const VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME":     virtgpuParamExplicitDebugName,
		"const VIRTGPU_EXECBUF_FENCE_FD_IN":           virtgpuExecbufFenceFDIn,
		"const VIRTGPU_EXECBUF_FENCE_FD_OUT":          virtgpuExecbufFenceFDOut,
		"const VIRTGPU_EXECBUF_RING_IDX":              virtgpuExecbufRingIdx,
		"const VIRTGPU_DRM_CAPSET_VENUS":              virtgpuCapsetVenus,
		"const VIRTGPU_BLOB_MEM_GUEST":                virtgpuBlobMemGuest,
		"const VIRTGPU_BLOB_MEM_HOST3D":               virtgpuBlobMemHost3D,
		"const VIRTGPU_BLOB_MEM_HOST3D_GUEST":         virtgpuBlobMemHost3DGuest,
		"const VIRTGPU_BLOB_FLAG_USE_MAPPABLE":        virtgpuBlobFlagUseMappable,
		"const VIRTGPU_BLOB_FLAG_USE_SHAREABLE":       virtgpuBlobFlagUseShareable,
		"const VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE":    virtgpuBlobFlagUseCrossDevice,
		"const VIRTGPU_CONTEXT_PARAM_CAPSET_ID":       virtgpuContextParamCapsetID,
		"const VIRTGPU_CONTEXT_PARAM_NUM_RINGS":       virtgpuContextParamNumRings,
		"const VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK": virtgpuContextParamPollRingsMask,
		"const VIRTGPU_CONTEXT_PARAM_DEBUG_NAME":      virtgpuContextParamDebugName,
	}
	for nr, r := range refusedIoctls {
		m["nr "+r.name] = uint64(nr)
	}
	for _, s := range abiStructs {
		typ := reflect.TypeOf(s.v)
		if bin, mem := binary.Size(s.v), int(typ.Size()); bin != mem {
			t.Errorf("%s: binary.Size %d != unsafe.Sizeof %d (Go adds padding that C does not have)", s.c, bin, mem)
		}
		m["sizeof "+s.c] = uint64(binary.Size(s.v))
		for i := 0; i < typ.NumField(); i++ {
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
	m := map[string]uint64{}
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

func readNonCommentLines(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

func TestABIMatchesClangTables(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			want := readABITable(t, "testdata/abi_"+arch+".txt")
			got := goABI(t)
			for k, w := range want {
				g, ok := got[k]
				if !ok {
					t.Errorf("%s: clang defines it, the Go side does not", k)
					continue
				}
				if g != w {
					t.Errorf("%s = %#x in Go, %#x from clang", k, g, w)
				}
			}
			for k := range got {
				if _, ok := want[k]; !ok {
					t.Errorf("%s: the Go side defines it, the clang table does not (add it to testdata/abi/probe.c)", k)
				}
			}
		})
	}
}

func TestABITableIsCurrent(t *testing.T) {
	libdrmDir := os.Getenv("GVX_LIBDRM_DIR")
	if libdrmDir == "" {
		t.Skip("GVX_LIBDRM_DIR is unset")
	}
	tmpDir := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "testdata/abi/gen.sh", libdrmDir, tmpDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen.sh failed: %v\n%s", err, out)
	}
	for _, arch := range []string{"arm64", "amd64"} {
		checkedIn := readNonCommentLines(t, filepath.Join("testdata", "abi_"+arch+".txt"))
		generated := readNonCommentLines(t, filepath.Join(tmpDir, "abi_"+arch+".txt"))
		if checkedIn != generated {
			t.Errorf("testdata/abi_%s.txt differs from generated output; regenerate with testdata/abi/gen.sh", arch)
		}
	}
}
