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

	gverrors "z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// toLinuxErr converts an error of the engine or of the host file into the plain
// linuxerr value that a vfs interface method returns. The first Linux error in
// the chain wins. A wait for held space becomes ENOSPC, and an error without a
// Linux error becomes EIO, so no host detail reaches the guest.
func toLinuxErr(err error) error {
	if err == nil {
		return nil
	}
	var le *gverrors.Error
	if errors.As(err, &le) {
		return le
	}
	if errors.Is(err, errSpaceHeld) {
		return linuxerr.ENOSPC
	}
	return linuxerr.EIO
}
