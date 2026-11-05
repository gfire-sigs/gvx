// Copyright 2018 The gVisor Authors.
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

import "z.gfire.dev/gvx/pkg/sync"

// syslog holds the kernel log of one kernel. KernelLog in kmsg_xplat.go creates
// the log and gives access to it.
//
// +stateify savable
type syslog struct {
	mu sync.Mutex `state:"nosave"`

	// bufLen is the ring size that the log gets at its creation. Zero selects
	// KernelLogDefaultBufLen.
	bufLen int `state:"nosave"`

	// log is nil until the first use.
	log *KernelLog `state:"nosave"`
}
