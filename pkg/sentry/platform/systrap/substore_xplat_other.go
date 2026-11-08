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

//go:build linux && !arm64

package systrap

// emulateGuestStore reports that the engine cannot run a guest store for the
// thread. Only an arm64 host has an emulator. An amd64 host has 4 KB pages and
// uses the sub-block layer in tests only.
func emulateGuestStore(insn uint32, env storeEnv) bool {
	return false
}
