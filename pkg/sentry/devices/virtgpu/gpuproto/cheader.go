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

package gpuproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
)

type cConst struct {
	name  string
	value string
}

type cStruct struct {
	name string
	zero any
}

var cConstants = buildCConstants()

var cStructs = []cStruct{
	{"header", Header{}},
	{"hello_request", HelloRequest{}},
	{"hello_reply", HelloReply{}},
	{"capset_info", CapsetInfo{}},
	{"get_capset_request", GetCapsetRequest{}},
	{"ctx_create_request", CtxCreateRequest{}},
	{"blob_create_request", BlobCreateRequest{}},
	{"blob_create_reply", BlobCreateReply{}},
	{"res_unref_request", ResUnrefRequest{}},
	{"submit_request", SubmitRequest{}},
	{"fence_done_event", FenceDoneEvent{}},
	{"ctx_lost_event", CtxLostEvent{}},
	{"test_confine_reply", TestConfineReply{}},
	{"res_create_request", ResCreateRequest{}},
	{"res_create_reply", ResCreateReply{}},
	{"transfer_request", TransferRequest{}},
}

func maxRequestPayloadAll() uint32 {
	var best uint32
	for _, entry := range allOps {
		if entry.op.IsRequest() {
			best = max(best, MaxRequestPayload(entry.op))
		}
	}
	return best
}

func buildCConstants() []cConst {
	var out []cConst
	addGroup := func(items ...cConst) {
		if len(out) > 0 {
			out = append(out, cConst{})
		}
		out = append(out, items...)
	}

	addGroup(
		cConst{"GVX_GPU_MAGIC", fmt.Sprintf("0x%xu", Magic)},
		cConst{"GVX_GPU_VERSION", fmt.Sprintf("%du", Version)},
		cConst{"GVX_GPU_HEADER_SIZE", fmt.Sprintf("%du", HeaderSize)},
		cConst{"GVX_GPU_SOCKET_FD", fmt.Sprintf("%d", SocketFD)},
	)

	addGroup(
		cConst{"GVX_GPU_FLAG_REPLY", fmt.Sprintf("%du", FlagReply)},
		cConst{"GVX_GPU_FLAG_EVENT", fmt.Sprintf("%du", FlagEvent)},
		cConst{"GVX_GPU_FLAG_FD", fmt.Sprintf("%du", FlagFD)},
	)

	ops := make([]cConst, 0, len(allOps))
	for _, entry := range allOps {
		ops = append(ops, cConst{"GVX_GPU_OP_" + entry.name, fmt.Sprintf("%du", entry.op)})
	}
	addGroup(ops...)

	statuses := make([]cConst, 0, len(allStatuses))
	for _, entry := range allStatuses {
		statuses = append(statuses, cConst{"GVX_GPU_STATUS_" + entry.cName, fmt.Sprintf("(%d)", entry.status)})
	}
	addGroup(statuses...)

	addGroup(
		cConst{"GVX_GPU_MAX_CAPSETS", fmt.Sprintf("%du", MaxCapsets)},
		cConst{"GVX_GPU_MAX_CAPSET_VERSION", fmt.Sprintf("%du", MaxCapsetVersion)},
		cConst{"GVX_GPU_MAX_CAPSET_BYTES", fmt.Sprintf("%du", MaxCapsetBytes)},
		cConst{"GVX_GPU_MAX_CONTEXT_NAME_BYTES", fmt.Sprintf("%du", MaxContextNameBytes)},
		cConst{"GVX_GPU_MAX_SUBMIT_BYTES", fmt.Sprintf("%du", MaxSubmitBytes)},
		cConst{"GVX_GPU_MAX_RINGS", fmt.Sprintf("%du", MaxRings)},
		cConst{"GVX_GPU_MAX_BLOB_BYTES", fmt.Sprintf("%du", MaxBlobBytes)},
		cConst{"GVX_GPU_HOST_BLOB_ALIGN", fmt.Sprintf("%du", HostBlobAlign)},
		cConst{"GVX_GPU_MAX_REPLY_PAYLOAD", fmt.Sprintf("%du", MaxReplyPayload)},
		cConst{"GVX_GPU_MAX_REQUEST_PAYLOAD", fmt.Sprintf("%du", maxRequestPayloadAll())},
	)

	addGroup(
		cConst{"GVX_GPU_CAPSET_VIRGL", fmt.Sprintf("%du", CapsetVirgl)},
		cConst{"GVX_GPU_CAPSET_VIRGL2", fmt.Sprintf("%du", CapsetVirgl2)},
		cConst{"GVX_GPU_CAPSET_VENUS", fmt.Sprintf("%du", CapsetVenus)},
		cConst{"GVX_GPU_BLOB_MEM_HOST3D", fmt.Sprintf("%du", BlobMemHost3D)},
		cConst{"GVX_GPU_BLOB_FLAG_MAPPABLE", fmt.Sprintf("%du", BlobFlagMappable)},
		cConst{"GVX_GPU_BLOB_FLAG_SHAREABLE", fmt.Sprintf("%du", BlobFlagShareable)},
		cConst{"GVX_GPU_BLOB_FLAG_CROSS_DEVICE", fmt.Sprintf("%du", BlobFlagCrossDevice)},
		cConst{"GVX_GPU_FD_TYPE_SHM", fmt.Sprintf("%du", FDTypeShm)},
		cConst{"GVX_GPU_SUBMIT_FLAG_FENCE", fmt.Sprintf("%du", SubmitFlagFence)},
		cConst{"GVX_GPU_TRANSFER_TO_HOST", fmt.Sprintf("%du", TransferToHost)},
		cConst{"GVX_GPU_TRANSFER_FROM_HOST", fmt.Sprintf("%du", TransferFromHost)},
	)

	addGroup(
		cConst{"GVX_GPU_MODE_VENUS", fmt.Sprintf("%du", ModeVenus)},
		cConst{"GVX_GPU_MODE_VIRGL", fmt.Sprintf("%du", ModeVirgl)},
	)

	addGroup(
		cConst{"GVX_GPU_CTX_LOST_SUBMIT_FAILED", fmt.Sprintf("%du", CtxLostSubmitFailed)},
		cConst{"GVX_GPU_CTX_LOST_FENCE_FAILED", fmt.Sprintf("%du", CtxLostFenceFailed)},
	)

	addGroup(
		cConst{"GVX_GPU_CONFINE_CHECK_FORK", fmt.Sprintf("%du", ConfineCheckFork)},
		cConst{"GVX_GPU_CONFINE_CHECK_EXEC", fmt.Sprintf("%du", ConfineCheckExec)},
		cConst{"GVX_GPU_CONFINE_CHECK_READ", fmt.Sprintf("%du", ConfineCheckRead)},
		cConst{"GVX_GPU_CONFINE_CHECK_CREATE", fmt.Sprintf("%du", ConfineCheckCreate)},
		cConst{"GVX_GPU_CONFINE_CHECK_CONNECT", fmt.Sprintf("%du", ConfineCheckConnect)},
		cConst{"GVX_GPU_CONFINE_CHECKS", fmt.Sprintf("%du", ConfineChecks)},
		cConst{"GVX_GPU_CONFINE_NOT_RUN", fmt.Sprintf("%du", ConfineNotRun)},
		cConst{"GVX_GPU_CONFINE_DENIED", fmt.Sprintf("%du", ConfineDenied)},
		cConst{"GVX_GPU_CONFINE_ALLOWED", fmt.Sprintf("%du", ConfineAllowed)},
		cConst{"GVX_GPU_CONFINE_UNEXPECTED", fmt.Sprintf("%du", ConfineUnexpected)},
	)

	addGroup(
		cConst{"GVX_GPU_EXIT_OK", fmt.Sprintf("%d", ExitOK)},
		cConst{"GVX_GPU_EXIT_USAGE", fmt.Sprintf("%d", ExitUsage)},
		cConst{"GVX_GPU_EXIT_INIT", fmt.Sprintf("%d", ExitInit)},
		cConst{"GVX_GPU_EXIT_CONFINE", fmt.Sprintf("%d", ExitConfine)},
		cConst{"GVX_GPU_EXIT_PROTOCOL", fmt.Sprintf("%d", ExitProtocol)},
		cConst{"GVX_GPU_EXIT_SELFTEST", fmt.Sprintf("%d", ExitSelftest)},
		cConst{"GVX_GPU_EXIT_MEMORY_LIMIT", fmt.Sprintf("%d", ExitMemoryLimit)},
	)

	addGroup(
		cConst{"GVX_GPU_ARG_SELFTEST", fmt.Sprintf("%q", ArgSelftest)},
		cConst{"GVX_GPU_ARG_STALL_FENCES", fmt.Sprintf("%q", ArgStallFences)},
		cConst{"GVX_GPU_ARG_MEMORY_LIMIT", fmt.Sprintf("%q", ArgMemoryLimit)},
		cConst{"GVX_GPU_ARG_TEST_WATCHDOG_BYTES", fmt.Sprintf("%q", ArgTestWatchdogBytes)},
		cConst{"GVX_GPU_ARG_MODE", fmt.Sprintf("%q", ArgMode)},
		cConst{"GVX_GPU_MODE_NAME_VENUS", fmt.Sprintf("%q", ModeNameVenus)},
		cConst{"GVX_GPU_MODE_NAME_VIRGL", fmt.Sprintf("%q", ModeNameVirgl)},
		cConst{"GVX_GPU_ENV_TEST_MODE", fmt.Sprintf("%q", EnvTestMode)},
		cConst{"GVX_GPU_WATCHDOG_HEADROOM_BYTES", fmt.Sprintf("%dull", WatchdogHeadroomBytes)},
		cConst{"GVX_GPU_WATCHDOG_PERIOD_MILLIS", fmt.Sprintf("%du", WatchdogPeriodMillis)},
	)

	return out
}

// CHeader returns the text of gpurenderer/gvx_gpu_protocol.h. The output
// depends only on the constants and struct types of this package.
func CHeader() []byte {
	var buf bytes.Buffer
	buf.WriteString("/* Code generated by \"go generate ./pkg/sentry/devices/virtgpu/gpuproto\". DO NOT EDIT. */\n\n")
	buf.WriteString("/*\n")
	buf.WriteString(" * Protocol between the gvx Sentry and gvx-gpu-renderer. The Go package\n")
	buf.WriteString(" * pkg/sentry/devices/virtgpu/gpuproto is the source of every value here.\n")
	buf.WriteString(" */\n\n")
	buf.WriteString("#ifndef GVX_GPU_PROTOCOL_H\n")
	buf.WriteString("#define GVX_GPU_PROTOCOL_H\n\n")
	buf.WriteString("#include <stddef.h>\n")
	buf.WriteString("#include <stdint.h>\n\n")
	buf.WriteString("_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, \"the protocol is little-endian\");\n\n")

	for _, c := range cConstants {
		if c.name == "" {
			buf.WriteByte('\n')
			continue
		}
		fmt.Fprintf(&buf, "#define %s %s\n", c.name, c.value)
	}

	for _, s := range cStructs {
		buf.WriteByte('\n')
		writeCStruct(&buf, s)
	}

	buf.WriteString("\n#endif /* GVX_GPU_PROTOCOL_H */\n")
	return buf.Bytes()
}

func writeCStruct(buf *bytes.Buffer, s cStruct) {
	t := reflect.TypeOf(s.zero)
	if t == nil || t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("gpuproto: %q is not a struct", s.name))
	}
	wireSize := binary.Size(s.zero)
	if wireSize < 0 || uintptr(wireSize) != t.Size() {
		panic(fmt.Sprintf("gpuproto: struct %s has padding (wire=%d, go=%d)", s.name, wireSize, t.Size()))
	}

	cName := "gvx_gpu_" + s.name
	if s.name == "header" {
		if wireSize != HeaderSize {
			panic(fmt.Sprintf("gpuproto: HeaderSize %d disagrees with Header wire size %d", HeaderSize, wireSize))
		}
	} else {
		fmt.Fprintf(buf, "#define GVX_GPU_%s_SIZE %du\n", strings.ToUpper(s.name), wireSize)
	}
	fmt.Fprintf(buf, "struct %s {\n", cName)

	type fieldAssert struct {
		name   string
		offset uintptr
	}
	asserts := make([]fieldAssert, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("c")
		if tag == "" {
			panic(fmt.Sprintf("gpuproto: %s.%s lacks a c struct tag", t.Name(), f.Name))
		}
		fmt.Fprintf(buf, "\t%s;\n", cFieldDecl(f.Type, tag))
		asserts = append(asserts, fieldAssert{name: tag, offset: f.Offset})
	}
	buf.WriteString("};\n")

	fmt.Fprintf(buf, "_Static_assert(sizeof(struct %s) == %d, \"%s size\");\n", cName, wireSize, cName)
	for _, a := range asserts {
		fmt.Fprintf(buf, "_Static_assert(offsetof(struct %s, %s) == %d, \"%s.%s offset\");\n", cName, a.name, a.offset, cName, a.name)
	}
}

func cFieldDecl(t reflect.Type, name string) string {
	switch t.Kind() {
	case reflect.Uint16:
		return "uint16_t " + name
	case reflect.Uint32:
		return "uint32_t " + name
	case reflect.Uint64:
		return "uint64_t " + name
	case reflect.Int32:
		return "int32_t " + name
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return fmt.Sprintf("uint8_t %s[%d]", name, t.Len())
		}
	}
	panic(fmt.Sprintf("gpuproto: unsupported C field type %s for %q", t, name))
}
