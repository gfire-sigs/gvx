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
	"regexp"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

// The expressions of utils/oomparser of cAdvisor, which the kubelet uses to
// find an OOM kill in /dev/kmsg.
const (
	cadvisorFirstLine = "invoked oom-killer:"
	cadvisorContainer = `oom-kill:constraint=(.*),nodemask=(.*),cpuset=(.*),mems_allowed=(.*),oom_memcg=(.*),task_memcg=(.*),task=(.*),pid=(.*),uid=(.*)`
	cadvisorLastLine  = `Killed process ([0-9]+) \((.+)\)`
)

func logTexts(l *kernel.KernelLog) (texts []string, levels []uint8) {
	for seq := uint64(0); ; {
		rec, ok := l.Lookup(seq)
		if !ok {
			return texts, levels
		}
		texts = append(texts, rec.Text)
		levels = append(levels, rec.Level)
		seq = rec.Seq + 1
	}
}

func newOOMLog() *kernel.KernelLog {
	return kernel.NewKernelLog(kernel.KernelLogDefaultBufLen, func() time.Duration { return time.Second })
}

func TestOOMKillWritesTheThreeLinesThatCAdvisorParses(t *testing.T) {
	klog := newOOMLog()
	victim := oomCandidate{
		id: 4321, comm: "stress", uid: 1000, adj: 999,
		vm: 300 << 20, rss: 100 << 20,
		cgroup: "/kubepods/burstable/pod1/ctr",
	}
	logOOMContext(klog, "/kubepods/burstable/pod1", victim)
	logOOMKill(klog, victim)

	texts, levels := logTexts(klog)
	want := []string{
		"stress invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=999",
		"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=ctr,mems_allowed=0,oom_memcg=/kubepods/burstable/pod1,task_memcg=/kubepods/burstable/pod1/ctr,task=stress,pid=4321,uid=1000",
		"Memory cgroup out of memory: Killed process 4321 (stress) total-vm:307200kB, anon-rss:102400kB, file-rss:0kB, shmem-rss:0kB, UID:1000 pgtables:0kB oom_score_adj:999",
	}
	if len(texts) != len(want) {
		t.Fatalf("lines = %q, want %d lines", texts, len(want))
	}
	for i := range want {
		if texts[i] != want[i] {
			t.Errorf("line %d =\n%q\nwant\n%q", i, texts[i], want[i])
		}
	}
	if wantLevels := []uint8{kernel.LogWarning, kernel.LogInfo, kernel.LogErr}; string(levels) != string(wantLevels) {
		t.Errorf("levels = %v, want warning, info, err of mm/oom_kill.c: %v", levels, wantLevels)
	}

	if !regexp.MustCompile(cadvisorFirstLine).MatchString(texts[0]) {
		t.Errorf("cAdvisor first line expression does not match %q", texts[0])
	}
	m := regexp.MustCompile(cadvisorContainer).FindStringSubmatch(texts[1])
	if m == nil || m[5] != "/kubepods/burstable/pod1" || m[6] != "/kubepods/burstable/pod1/ctr" || m[7] != "stress" || m[8] != "4321" || m[9] != "1000" {
		t.Errorf("cAdvisor container expression gives %q for %q", m, texts[1])
	}
	m = regexp.MustCompile(cadvisorLastLine).FindStringSubmatch(texts[2])
	if m == nil || m[1] != "4321" || m[2] != "stress" {
		t.Errorf("cAdvisor last line expression gives %q for %q", m, texts[2])
	}
}

func TestOOMCpusetNameIsTheLastElementOfThePath(t *testing.T) {
	for path, want := range map[string]string{"/": "/", "": "/", "/a": "a", "/a/b/c": "c"} {
		if got := oomCpusetName(path); got != want {
			t.Errorf("oomCpusetName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestOrderVictimsPutsTheSelectedVictimFirstAndKeepsTheRest(t *testing.T) {
	g := [3]*kernel.ThreadGroup{new(kernel.ThreadGroup), new(kernel.ThreadGroup), new(kernel.ThreadGroup)}
	victims := []oomCandidate{{group: g[0], id: 1}, {group: g[1], id: 2}, {group: g[2], id: 3}}
	got := orderVictims(victims, victims[2])
	if len(got) != 3 || got[0].id != 3 || got[1].id != 1 || got[2].id != 2 {
		t.Errorf("order = %v, want 3, 1, 2", []kernel.ThreadID{got[0].id, got[1].id, got[2].id})
	}
	if victims[0].id != 1 || victims[2].id != 3 {
		t.Errorf("orderVictims changed its input")
	}
}

func TestOOMGroupLineNamesTheGroupCgroup(t *testing.T) {
	klog := newOOMLog()
	logOOMGroup(klog, "/kubepods/pod1/ctr")
	texts, levels := logTexts(klog)
	if len(texts) != 1 || texts[0] != "Tasks in /kubepods/pod1/ctr are going to be killed due to memory.oom.group set" || levels[0] != kernel.LogInfo {
		t.Errorf("lines = %q, levels %v", texts, levels)
	}
}
