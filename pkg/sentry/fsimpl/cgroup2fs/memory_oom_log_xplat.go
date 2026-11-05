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

package cgroup2fs

import (
	"path"
	"slices"

	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

// The OOM killer of Linux writes a report to the kernel log for each kill. The
// kubelet reads it from /dev/kmsg through the OOM parser of cAdvisor, which
// looks for the three lines that this file writes, in this order. The text and
// the levels follow mm/oom_kill.c (dump_header, dump_oom_summary, and
// __oom_kill_process). The Sentry does not split the resident set of a process
// into anonymous, file, and shared pages, so it reports the whole set as
// anon-rss. It has no page tables to count, and it reports pgtables as zero.

// orderVictims returns victims with selected first. The selected victim gets
// the first line "Killed process", as in oom_kill_process.
func orderVictims(victims []oomCandidate, selected oomCandidate) []oomCandidate {
	out := slices.Clone(victims)
	slices.SortStableFunc(out, func(a, b oomCandidate) int {
		switch {
		case a.group == selected.group && b.group != selected.group:
			return -1
		case a.group != selected.group && b.group == selected.group:
			return 1
		}
		return 0
	})
	return out
}

// oomCpusetName returns the name that Linux prints after "cpuset=": the last
// element of the cgroup path, or "/" for the root cgroup.
func oomCpusetName(cgroupPath string) string {
	if cgroupPath == "/" || cgroupPath == "" {
		return "/"
	}
	return path.Base(cgroupPath)
}

// logOOMContext writes the lines that come before the first kill: the process
// that invoked the OOM killer, and the one-line summary. limited is the path of
// the cgroup that passed its limit. The Sentry has no task that triggered the
// charge, so the report names the victim as the invoker.
func logOOMContext(klog *kernel.KernelLog, limited string, v oomCandidate) {
	klog.Printkf(kernel.LogWarning, "%s invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=%d", v.comm, v.adj)
	klog.Printkf(kernel.LogInfo,
		"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=%s,mems_allowed=0,oom_memcg=%s,task_memcg=%s,task=%s,pid=%d,uid=%d",
		oomCpusetName(v.cgroup), limited, v.cgroup, v.comm, v.id, v.uid)
}

// logOOMKill writes the line for one killed process.
func logOOMKill(klog *kernel.KernelLog, v oomCandidate) {
	klog.Printkf(kernel.LogErr,
		"Memory cgroup out of memory: Killed process %d (%s) total-vm:%dkB, anon-rss:%dkB, file-rss:0kB, shmem-rss:0kB, UID:%d pgtables:0kB oom_score_adj:%d",
		v.id, v.comm, v.vm>>10, v.rss>>10, v.uid, v.adj)
}

// logOOMGroup writes the line that announces the kill of every process of a
// cgroup with memory.oom.group.
func logOOMGroup(klog *kernel.KernelLog, groupPath string) {
	klog.Printkf(kernel.LogInfo, "Tasks in %s are going to be killed due to memory.oom.group set", groupPath)
}
