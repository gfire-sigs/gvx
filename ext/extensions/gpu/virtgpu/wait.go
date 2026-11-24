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

package virtgpu

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// wait serves DRM_IOCTL_VIRTGPU_WAIT.
func (fd *renderFD) wait(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpu3DWait
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	f, ok := fd.gem.lookupFence(req.Handle)
	fd.gemMu.Unlock()
	if !ok {
		return linuxerr.ENOENT
	}
	if f == nil || f.signaled.Load() {
		return nil
	}
	if req.Flags&virtgpuWaitNoWait != 0 {
		return linuxerr.EBUSY
	}

	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	f.queue.EventRegister(&e)
	defer f.queue.EventUnregister(&e)
	if f.signaled.Load() {
		return nil
	}
	if _, err := ctx.BlockWithTimeout(ch, true, fd.dev.limits.WaitTimeout); err != nil {
		if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
			return linuxerr.EBUSY
		}
		return linuxerr.ERESTARTSYS
	}
	return nil
}
