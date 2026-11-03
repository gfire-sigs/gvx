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

package systrap

import "testing"

// The cgroup2 filesystem finds this method by an interface assertion, so a
// rename would turn the memory.max enforcer on for this engine again.
func TestPlatformDeclaresThatItCannotCountCgroupMemory(t *testing.T) {
	var p any = &Platform{}
	counter, ok := p.(interface{ CountsCgroupMemory() bool })
	if !ok {
		t.Fatal("Platform lacks CountsCgroupMemory() bool")
	}
	if counter.CountsCgroupMemory() {
		t.Error("CountsCgroupMemory() = true, want false")
	}
}
