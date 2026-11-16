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

package devpts

import (
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/fsutilx"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// vtimeUnit is the 0.1-second step of termios c_cc[VTIME].
const vtimeUnit = 100 * time.Millisecond

// replicaReadEvents lists the waiter events that wake a blocking replica read.
const replicaReadEvents = waiter.ReadableEvents | waiter.EventHUp | waiter.EventErr

// supportedReplicaReadFlags lists the preadv2 flags accepted by replica reads.
const supportedReplicaReadFlags = uint32(linux.RWF_HIPRI | linux.RWF_DSYNC | linux.RWF_SYNC | fsutilx.RWFNoWait)

// finishReplicaTermios wakes blocked replica readers when a replica TCSETS ioctl succeeds.
func (rfd *replicaFileDescription) finishReplicaTermios(ret uintptr, err error) (uintptr, error) {
	if err == nil {
		rfd.inode.t.ld.replicaWaiter.Notify(waiter.ReadableEvents)
	}
	return ret, err
}

// readReplica serves a replica read using the active canonical or POSIX VMIN and VTIME mode.
func (rfd *replicaFileDescription) readReplica(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if opts.Flags&^supportedReplicaReadFlags != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}
	origCount := dst.NumBytes()
	if origCount == 0 {
		return 0, nil
	}

	ld := rfd.inode.t.ld
	statusNonblock := rfd.vfsfd.StatusFlags()&linux.O_NONBLOCK != 0
	nowait := opts.Flags&fsutilx.RWFNoWait != 0

	n, canon, vmin, vtime, err := ld.readInputOnce(ctx, dst)
	if canon {
		if err == nil {
			return n, nil
		}
		if !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			return 0, err
		}
		if !rfd.inode.Valid(ctx, nil, "") {
			return 0, nil
		}
		if nowait {
			return 0, linuxerr.EAGAIN
		}
		return 0, linuxerr.ErrWouldBlock
	}

	if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		return 0, err
	}

	// POSIX non-canonical Case D (VMIN == 0, VTIME == 0) polls without blocking.
	if vmin == 0 && vtime == 0 {
		return n, nil
	}

	target := nonCanonTarget(vmin, origCount)
	if n >= target {
		return n, nil
	}
	if nowait {
		if n > 0 {
			return n, nil
		}
		if !rfd.inode.Valid(ctx, nil, "") {
			return 0, nil
		}
		return 0, linuxerr.EAGAIN
	}
	if statusNonblock {
		if n > 0 {
			return n, nil
		}
		if !rfd.inode.Valid(ctx, nil, "") {
			return 0, nil
		}
		return 0, linuxerr.ErrWouldBlock
	}
	if !rfd.inode.Valid(ctx, nil, "") {
		return n, nil
	}

	return rfd.readNonCanonSlow(ctx, dst.DropFirst(int(n)), origCount, n, vmin, vtime)
}

// nonCanonTarget returns the byte count that completes a non-canonical read.
func nonCanonTarget(vmin uint8, reqBytes int64) int64 {
	if vmin == 0 {
		return 1
	}
	return min(int64(vmin), reqBytes, nonCanonMaxBytes)
}

// readNonCanonSlow waits for additional bytes or VTIME expiration in Cases A, B, and C.
func (rfd *replicaFileDescription) readNonCanonSlow(ctx context.Context, dst usermem.IOSequence, origCount, total int64, vmin, vtime uint8) (int64, error) {
	ld := rfd.inode.t.ld
	haveTimeout := false
	var remaining time.Duration
	if vmin == 0 && vtime > 0 {
		haveTimeout = true
		remaining = time.Duration(vtime) * vtimeUnit
	} else if total > 0 && vtime > 0 {
		haveTimeout = true
		remaining = time.Duration(vtime) * vtimeUnit
	}

	w, ch := waiter.NewChannelEntry(replicaReadEvents)
	ld.replicaWaiter.EventRegister(&w)
	defer ld.replicaWaiter.EventUnregister(&w)

	for {
		n, canon, curMin, curTime, err := ld.readInputOnce(ctx, dst)
		if n > 0 {
			total += n
			dst = dst.DropFirst(int(n))
			if canon || (curMin == 0 && curTime == 0) {
				return total, nil
			}
			if total >= nonCanonTarget(curMin, origCount) || dst.NumBytes() == 0 {
				return total, nil
			}
			if curTime > 0 {
				haveTimeout = true
				remaining = time.Duration(curTime) * vtimeUnit
			} else {
				haveTimeout = false
			}
			continue
		}
		if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			if total > 0 {
				return total, nil
			}
			return 0, err
		}
		if !rfd.inode.Valid(ctx, nil, "") {
			return total, nil
		}
		if canon {
			if total > 0 {
				return total, nil
			}
			return 0, linuxerr.ErrWouldBlock
		}
		if curMin == 0 {
			if total > 0 || curTime == 0 {
				return total, nil
			}
			if !haveTimeout {
				haveTimeout = true
				remaining = time.Duration(curTime) * vtimeUnit
			}
		} else {
			if total >= nonCanonTarget(curMin, origCount) {
				return total, nil
			}
			if curTime == 0 || total == 0 {
				haveTimeout = false
			} else if !haveTimeout {
				haveTimeout = true
				remaining = time.Duration(curTime) * vtimeUnit
			}
		}
		if haveTimeout && remaining <= 0 {
			return total, nil
		}

		rem, berr := ctx.BlockWithTimeout(ch, haveTimeout, remaining)
		if berr != nil {
			if haveTimeout && !linuxerr.Equals(linuxerr.ErrInterrupted, berr) && (linuxerr.Equals(linuxerr.ETIMEDOUT, berr) || rem == 0) {
				n, _, _, _, rerr := ld.readInputOnce(ctx, dst)
				if n > 0 {
					total += n
					return total, nil
				}
				if rerr != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, rerr) && total == 0 {
					return 0, rerr
				}
				return total, nil
			}
			if total > 0 {
				return total, nil
			}
			if linuxerr.Equals(linuxerr.ErrInterrupted, berr) {
				return 0, berr
			}
			return 0, linuxerr.ErrInterrupted
		}
		remaining = rem
	}
}

// readInputOnce reads the input queue and snapshots ICANON, VMIN, and VTIME together.
//
// +checklocksexclude:l.termiosMu
// +checklocksexclude:l.inQueue.mu
// +checklocksexclude:l.outQueue.mu
// +checklocksexclude:l.masterWaiter.mu
// +checklocksexclude:l.replicaWaiter.mu
func (l *lineDiscipline) readInputOnce(ctx context.Context, dst usermem.IOSequence) (int64, bool, uint8, uint8, error) {
	l.termiosMu.RLock()
	n, pushed, notifyEcho, err := l.inQueue.read(ctx, dst, l, false /* packet */)
	canon := l.termios.LEnabled(linux.ICANON)
	vmin := l.termios.ControlCharacters[linux.VMIN]
	vtime := l.termios.ControlCharacters[linux.VTIME]
	l.termiosMu.RUnlock()
	if err != nil {
		return 0, canon, vmin, vtime, err
	}
	if n > 0 {
		if notifyEcho {
			l.masterWaiter.Notify(waiter.ReadableEvents | waiter.WritableEvents)
		} else {
			l.masterWaiter.Notify(waiter.WritableEvents)
		}
		if pushed {
			l.replicaWaiter.Notify(waiter.ReadableEvents)
		}
		return n, canon, vmin, vtime, nil
	}
	if notifyEcho {
		l.masterWaiter.Notify(waiter.ReadableEvents)
	}
	if !pushed && canon {
		return 0, canon, vmin, vtime, nil
	}
	return 0, canon, vmin, vtime, linuxerr.ErrWouldBlock
}
