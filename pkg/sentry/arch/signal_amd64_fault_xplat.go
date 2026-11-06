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

//go:build amd64

package arch

import "z.gfire.dev/gvx/pkg/hostarch"

// SetFaultAccess records the access of a user fault that became a signal. The
// amd64 signal frame has no record of it, because the handler reads the error
// code from the signal context. The method exists so that shared code can call
// it on every architecture.
func (c *Context64) SetFaultAccess(hostarch.AccessType) {}
