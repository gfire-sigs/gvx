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

//go:build !linux && !darwin && !windows

package oci

import (
	"errors"
	"os"
)

// No terminal support exists on this host OS. Standard input then reads as a
// pipe, and a password comes from one line of input.
func isTerminalFile(*os.File) bool { return false }

func readPasswordFile(*os.File) (string, error) {
	return "", errors.New("oci: reading a password from a terminal is not supported on this OS")
}
