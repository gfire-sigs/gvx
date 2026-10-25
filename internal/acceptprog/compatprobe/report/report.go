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

// Package report defines the structured JSON schema emitted by the guest
// compatibility, system fingerprint, and performance benchmark suite.
package report

// GoldenDigests maps each deterministic compatibility probe name to the
// canonical digest produced on the Linux golden standard (linux/amd64 and
// linux/arm64). Every backend on Windows, macOS, and Linux must produce these
// exact digests.
var GoldenDigests = map[string]string{
	"abi_auxv_procfs":           "auxv:ok:proc:exe+maps+fd+stat+cpuinfo:rng:32b",
	"cpu_dual_tls_wine64_teb":   "teb:self=ok:peb=ok:tls0=0xcafe1234dead5678:tls1=0x102a:svc=ok:fault=ok:sig=ok",
	"cpu_simd_fp_preservation":  "simd:128bit:lanes=ok:svc=ok:fault=ok:xor=0xa5a5a5a55a5a5a5a",
	"wine64_pe32plus_execution": "pe32+:magic=0x20b:base=0x140000000:ret=0x140001379:tls2=0x77696e6536346f6b:data=0x57494e45",
	"wine64_pe_mmap_layout":     "mmap:pe_fixed=0x140000000:low32=ok:mremap=ok",
	"wine64_wineserver_ipc":     "ipc:memfd=ok:scm_rights=ok:shared_coh=0x57535256:preadv=ok",
	"wine64_ntdll_sync_signal":  "sync:futex_bitset=0xdeadbeef:guard_page_segv=recovered:val=0x42424242",
	"mm_jit_wx_transition":      "jit:v1=121:v2=277:wx_transition=ok",
	"mm_fork_cow_shared":        "cow:private_parent=0x1111222233334444:shared_parent=0x9999888877776666:status=0",
	"vfs_posix_torture":         "vfs:tmpfs=ok:workspace=ok:volume=ok:rename_open=ok:unlink_open=ok:links=ok:preadv=ok",
	"net_epoll_loopback":        "net:epoll_tcp_udp=ok:sha256=aa6357af44d6eba0ef8446b591c37041520daafc9bb4b7a8be6c14e01fc1ab24",
}

// Report is the top-level JSON document emitted by compatprobe.
type Report struct {
	SchemaVersion int               `json:"schema_version"`
	Fingerprint   SystemFingerprint `json:"fingerprint"`
	Probes        []ProbeResult     `json:"probes"`
	Benchmarks    []BenchResult     `json:"benchmarks"`
	TotalNs       int64             `json:"total_ns"`
	AllPassed     bool              `json:"all_passed"`
}

// SystemFingerprint captures the guest-visible hardware, kernel, and address
// space identity of the sandbox.
type SystemFingerprint struct {
	Arch          string              `json:"arch"`
	Sysname       string              `json:"sysname"`
	Release       string              `json:"release"`
	Version       string              `json:"version"`
	Machine       string              `json:"machine"`
	PageSize      int                 `json:"page_size"`
	NumCPU        int                 `json:"num_cpu"`
	PID           int                 `json:"pid"`
	UID           int                 `json:"uid"`
	GID           int                 `json:"gid"`
	Auxv          AuxvSummary         `json:"auxv"`
	CPU           CPUFingerprint      `json:"cpu"`
	AddressSpace  AddressSpaceSummary `json:"address_space"`
	CPUInfoFields map[string]string   `json:"cpuinfo_fields"`
}

// AuxvSummary holds the key auxiliary vector entries passed by the loader.
type AuxvSummary struct {
	PageSize    uint64 `json:"at_pagesz"`
	HWCap       string `json:"at_hwcap"`
	HWCap2      string `json:"at_hwcap2"`
	Phdr        string `json:"at_phdr"`
	Entry       string `json:"at_entry"`
	SysinfoEhdr string `json:"at_sysinfo_ehdr"`
}

// CPUFingerprint holds architecture-specific register and feature state
// queried directly from user mode.
type CPUFingerprint struct {
	Vendor        string `json:"vendor,omitempty"`
	Brand         string `json:"brand,omitempty"`
	MaxLeaf       uint32 `json:"max_leaf,omitempty"`
	Leaf1ECX      string `json:"leaf1_ecx,omitempty"`
	Leaf1EDX      string `json:"leaf1_edx,omitempty"`
	Leaf7EBX      string `json:"leaf7_ebx,omitempty"`
	Leaf7ECX      string `json:"leaf7_ecx,omitempty"`
	FSBase        string `json:"fs_base,omitempty"`
	GSBase        string `json:"gs_base,omitempty"`
	MIDREL1       string `json:"midr_el1,omitempty"`
	IDAA64PFR0EL1 string `json:"id_aa64pfr0_el1,omitempty"`
	IDAA64ISAR0   string `json:"id_aa64isar0_el1,omitempty"`
	IDAA64MMFR0   string `json:"id_aa64mmfr0_el1,omitempty"`
	CTREL0        string `json:"ctr_el0,omitempty"`
	DCZIDEL0      string `json:"dczid_el0,omitempty"`
	CNTVCTEL0     string `json:"cntvct_el0,omitempty"`
	TPIDREL0      string `json:"tpidr_el0,omitempty"`
	X18           string `json:"x18,omitempty"`
}

// AddressSpaceSummary summarizes /proc/self/maps inside the guest.
type AddressSpaceSummary struct {
	RegionCount int    `json:"region_count"`
	FirstStart  string `json:"first_start"`
	LastEnd     string `json:"last_end"`
	ExecStart   string `json:"exec_start"`
	StackStart  string `json:"stack_start"`
	VDSOStart   string `json:"vdso_start"`
}

// ProbeResult records the outcome, traceability digest, and latency of one
// compatibility probe.
type ProbeResult struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Passed     bool   `json:"passed"`
	Digest     string `json:"digest"`
	Detail     string `json:"detail"`
	DurationNs int64  `json:"duration_ns"`
}

// BenchResult records the throughput and latency of one micro-benchmark.
type BenchResult struct {
	Name       string  `json:"name"`
	Iterations int     `json:"iterations"`
	TotalNs    int64   `json:"total_ns"`
	NsPerOp    float64 `json:"ns_per_op"`
	OpsPerSec  float64 `json:"ops_per_sec"`
}
