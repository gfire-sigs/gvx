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

package kernel

import "testing"

func TestIdleTaskActivityChan(t *testing.T) {
	var k Kernel
	k.taskActivityCh = make(chan struct{})
	k.cpuClockTickerRunning = true
	k.timekeeper = &Timekeeper{}

	ch, idle := k.IdleTaskActivityChan()
	if !idle || ch == nil {
		t.Fatalf("IdleTaskActivityChan on idle kernel = (%v, %t), want non-nil channel and idle=true", ch, idle)
	}
	select {
	case <-ch:
		t.Fatal("activity channel is closed before any task runs")
	default:
	}

	k.incRunningTasks()
	select {
	case <-ch:
	default:
		t.Fatal("incRunningTasks did not close the prior activity channel")
	}

	if activeCh, stillIdle := k.IdleTaskActivityChan(); stillIdle || activeCh != nil {
		t.Fatalf("IdleTaskActivityChan with running task = (%v, %t), want (nil, false)", activeCh, stillIdle)
	}

	k.decRunningTasks()
	nextCh, idleAgain := k.IdleTaskActivityChan()
	if !idleAgain || nextCh == nil {
		t.Fatalf("IdleTaskActivityChan after decRunningTasks = (%v, %t), want non-nil channel and idle=true", nextCh, idleAgain)
	}
	select {
	case <-nextCh:
		t.Fatal("replacement activity channel is already closed")
	default:
	}
}
