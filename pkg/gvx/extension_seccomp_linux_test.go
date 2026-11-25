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

//go:build linux

package gvx

import (
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/seccomp"
)

func TestExtensionSeccompRulesPinRecvMsgAndForbidSendMsg(t *testing.T) {
	rules := extensionSeccompRules([]int{7, 11})
	if !rules.Has(unix.SYS_RECVMSG) {
		t.Fatal("extensionSeccompRules must allow SYS_RECVMSG for reserved FDs")
	}
	if rules.Has(unix.SYS_SENDMSG) {
		t.Fatal("extensionSeccompRules must never allow SYS_SENDMSG")
	}

	got := rules.Get(unix.SYS_RECVMSG)
	want := seccomp.Or{
		seccomp.PerArg{seccomp.EqualTo(7)},
		seccomp.PerArg{seccomp.EqualTo(11)},
	}
	if got.String() != want.String() {
		t.Fatalf("SYS_RECVMSG rule = %s, want %s", got, want)
	}
}
