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

package platform

import "z.gfire.dev/gvx/internal/xsys/unix"

// Unwrap returns the underlying error so errors.Is and errors.As inspect
// wrapped causes inside ContextError.
func (e *ContextError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewContextError wraps err in a ContextError carrying errno so kernel callers
// translate platform failures without panicking.
func NewContextError(err error, errno unix.Errno) *ContextError {
	if err == nil {
		return nil
	}
	return &ContextError{
		Err:   err,
		Errno: errno,
	}
}

// NewIOContextError wraps err in a ContextError with unix.EIO.
func NewIOContextError(err error) *ContextError {
	return NewContextError(err, unix.EIO)
}
