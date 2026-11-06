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

// ptraceUserModifiedGS notifies the address space of target that a ptrace
// request changed the GS base of target. oldGS is the GS base before the
// request.
//
// A change of the GS base with ptrace has the same effect as the call
// arch_prctl(ARCH_SET_GS) of the thread: the address space can hold syscall
// patches that use GS, and the new value can invalidate them. The target is
// in a ptrace stop, so no thread of it runs patched code during the call. The
// target is the context, because the patches are in the address space of the
// target and not in the address space of t.
func (t *Task) ptraceUserModifiedGS(target *Task, oldGS uintptr) error {
	if target.Arch().GS() == oldGS {
		return nil
	}
	return target.MemoryManager().UserModifiedGS(target)
}
