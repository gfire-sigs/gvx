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

//go:build darwin && arm64

package systrap

import "os"

// ZoneEnv names the optional environment variable that overrides zone mode.
// Zone mode is enabled automatically when the host address range can hold the
// biased 4GB zone; setting ZoneEnv to "0" disables it.
const ZoneEnv = "GVX_SYSTRAP_FIXED_IMAGES"

// zoneModeDisabled reports whether the environment explicitly disables zone mode.
func zoneModeDisabled() bool { return os.Getenv(ZoneEnv) == "0" }
