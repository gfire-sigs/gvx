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

//go:build !linux && !darwin

package control

import "net"

// SendFDs reports CodeUnsupported on hosts without SCM_RIGHTS support.
func SendFDs(net.Conn, []int) error {
	return NewError(CodeUnsupported, "file descriptor passing is unsupported on this host OS")
}

// RecvFDs reports CodeUnsupported on hosts without SCM_RIGHTS support.
func RecvFDs(net.Conn, int) ([]int, error) {
	return nil, NewError(CodeUnsupported, "file descriptor passing is unsupported on this host OS")
}
