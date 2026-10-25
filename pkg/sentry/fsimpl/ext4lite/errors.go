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

package ext4lite

import (
	"errors"
	"fmt"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
)

// hostError translates an error of the host file into a Linux error. A full
// host volume becomes ENOSPC. Every other failure becomes EIO, and the text of
// the host error stays in the chain for logs.
func hostError(err error) error {
	if err == nil {
		return nil
	}
	var le *linuxerrWrap
	if errors.As(err, &le) {
		return err
	}
	switch {
	case chunkcache.IsHostDiskFull(err):
		return &linuxerrWrap{host: err, errno: linuxerr.ENOSPC}
	default:
		return &linuxerrWrap{host: err, errno: linuxerr.EIO}
	}
}

// linuxerrWrap pairs a Linux error with the host error that caused it.
type linuxerrWrap struct {
	host  error
	errno error
}

func (e *linuxerrWrap) Error() string { return fmt.Sprintf("%v (host: %v)", e.errno, e.host) }

// Unwrap returns both errors, so errors.Is finds the Linux error and the host
// error.
func (e *linuxerrWrap) Unwrap() []error { return []error{e.errno, e.host} }
