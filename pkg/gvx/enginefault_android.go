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

package gvx

import "strings"

// engineFaultNote returns a note for the cause of an engine fault. Android
// kills child processes of apps above 32 in total, and a killed stub process
// of the systrap engine ends the guest with "subprocess died".
func engineFaultNote(cause string) string {
	if !strings.Contains(cause, "subprocess died") {
		return ""
	}
	return "; Android may have stopped a child process of the app, because it allows 32 child processes for all apps (docs/cli.md section 12)"
}
