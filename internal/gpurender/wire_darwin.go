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

//go:build darwin

package gpurender

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

// maxControlFDs sizes Client.readOOB above XNU's per-sendmsg SCM_RIGHTS cap
// (254 descriptors) so XNU never truncates externalized descriptor numbers out
// of the control buffer.
const maxControlFDs = 512

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// extractAndCloexecFDs parses control messages in oob, marks every received
// SCM_RIGHTS descriptor close-on-exec while the caller holds ForkLock.RLock,
// and appends those descriptors to dst. On a truncated SCM_RIGHTS header
// (MSG_CTRUNC), it still recovers every complete 4-byte descriptor from the
// truncated tail so the caller closes them all.
func extractAndCloexecFDs(oob []byte, dst []int) ([]int, error) {
	var parseErr error
	rem := oob
	hdrSize := unix.CmsgLen(0)
	for len(rem) >= hdrSize {
		hdr, data, next, err := unix.ParseOneSocketControlMessage(rem)
		if err != nil {
			hLen := binary.LittleEndian.Uint32(rem[0:4])
			hLevel := int32(binary.LittleEndian.Uint32(rem[4:8]))
			hType := int32(binary.LittleEndian.Uint32(rem[8:12]))
			if hLen >= uint32(hdrSize) && hLevel == unix.SOL_SOCKET && hType == unix.SCM_RIGHTS {
				tail := rem[hdrSize:]
				for i := 0; i+4 <= len(tail); i += 4 {
					f := int(int32(binary.LittleEndian.Uint32(tail[i : i+4])))
					unix.CloseOnExec(f)
					dst = append(dst, f)
				}
			}
			if parseErr == nil {
				parseErr = err
			}
			break
		}
		if hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SCM_RIGHTS {
			for i := 0; i+4 <= len(data); i += 4 {
				f := int(int32(binary.LittleEndian.Uint32(data[i : i+4])))
				unix.CloseOnExec(f)
				dst = append(dst, f)
			}
			if len(data)%4 != 0 && parseErr == nil {
				parseErr = unix.EINVAL
			}
		} else if parseErr == nil {
			parseErr = fmt.Errorf("unexpected control message level=%d type=%d", hdr.Level, hdr.Type)
		}
		rem = next
	}
	if len(rem) > 0 && parseErr == nil {
		parseErr = unix.EINVAL
	}
	return dst, parseErr
}

// readHeader reads exactly HeaderSize bytes with recvmsg and returns any
// descriptor that arrived with byte 0 of the header.
func (c *Client) readHeader(buf *[gpuproto.HeaderSize]byte, deadlineArmed *bool) (*fd.HostHandle, error) {
	return c.readExact(buf[:], true, deadlineArmed)
}

// readPayload reads exactly len(buf) payload bytes with recvmsg and rejects
// any attached descriptor as a protocol error.
func (c *Client) readPayload(buf []byte, deadlineArmed *bool) error {
	h, err := c.readExact(buf, false, deadlineArmed)
	closeHandle(h)
	return err
}

// readExact fills buf through recvmsg with a control buffer so XNU cannot
// silently externalize smuggled SCM_RIGHTS descriptors through plain read(2).
// When allowFirstFD is true, at most one descriptor may arrive with byte 0;
// every unexpected descriptor is closed and fails the read. Once any byte of
// the frame has arrived, readExact arms a read deadline of RequestTimeout.
func (c *Client) readExact(buf []byte, allowFirstFD bool, deadlineArmed *bool) (*fd.HostHandle, error) {
	if len(c.readOOB) == 0 {
		c.readOOB = make([]byte, unix.CmsgSpace(maxControlFDs*4))
	}
	oob := c.readOOB
	receivedFD := -1
	got := 0
	var chunkFDs []int

	closeAll := func() {
		if receivedFD >= 0 {
			_ = unix.Close(receivedFD)
			receivedFD = -1
		}
		for _, f := range chunkFDs {
			_ = unix.Close(f)
		}
		chunkFDs = chunkFDs[:0]
	}

	timeout := c.opts.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	armDeadline := func() error {
		if *deadlineArmed {
			return nil
		}
		if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		*deadlineArmed = true
		return nil
	}

	if !allowFirstFD {
		if err := armDeadline(); err != nil {
			return nil, err
		}
	}

	for got < len(buf) {
		if got > 0 {
			if err := armDeadline(); err != nil {
				closeAll()
				return nil, err
			}
		}

		var (
			n, oobn, rflags int
			rerr, perr      error
		)
		chunkFDs = chunkFDs[:0]
		err := c.raw.Read(func(fdnum uintptr) bool {
			// Without ForkLock, a concurrent exec can inherit a received
			// descriptor before CloseOnExec marks it close-on-exec.
			syscall.ForkLock.RLock()
			n, oobn, rflags, _, rerr = unix.Recvmsg(int(fdnum), buf[got:], oob, unix.MSG_DONTWAIT)
			if rerr == nil && oobn > 0 {
				chunkFDs, perr = extractAndCloexecFDs(oob[:oobn], chunkFDs[:0])
			}
			syscall.ForkLock.RUnlock()
			return rerr != unix.EAGAIN && rerr != unix.EWOULDBLOCK
		})
		if err != nil {
			closeAll()
			if isTimeoutErr(err) {
				return nil, fmt.Errorf("%w: incomplete frame within %s", ErrRendererHung, timeout)
			}
			return nil, err
		}
		if rerr == unix.EINTR {
			for _, f := range chunkFDs {
				_ = unix.Close(f)
			}
			continue
		}
		if rerr != nil {
			closeAll()
			return nil, rerr
		}
		if rflags&unix.MSG_CTRUNC != 0 {
			closeAll()
			return nil, errors.New("protocol error: truncated control message")
		}
		if perr != nil {
			closeAll()
			return nil, fmt.Errorf("protocol error: parse control message: %w", perr)
		}
		if len(chunkFDs) > 0 {
			if !allowFirstFD {
				closeAll()
				return nil, errors.New("protocol error: unexpected descriptor attached to payload")
			}
			if got != 0 {
				closeAll()
				return nil, errors.New("protocol error: descriptor arrived after byte 0 of header")
			}
			if len(chunkFDs) > 1 || receivedFD >= 0 {
				closeAll()
				return nil, fmt.Errorf("protocol error: received %d descriptors, want at most 1", len(chunkFDs))
			}
			receivedFD = chunkFDs[0]
			chunkFDs = chunkFDs[:0]
		}
		if n == 0 {
			closeAll()
			if !allowFirstFD || got > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, io.EOF
		}
		got += n
	}

	if receivedFD < 0 {
		return nil, nil
	}
	h, err := fd.NewHostHandle(receivedFD)
	if err != nil {
		_ = unix.Close(receivedFD)
		return nil, err
	}
	return h, nil
}

// acquireWriteSem acquires the single-writer token. When ctx is not nil,
// cancellation wakes the waiter before the call enters c.pending.
func (c *Client) acquireWriteSem(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case c.writeSem <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return c.lostErr()
		}
	}
	select {
	case c.writeSem <- struct{}{}:
		return nil
	case <-c.done:
		return c.lostErr()
	}
}

// writeFrameLocked writes the whole frame while the caller holds writeSem.
// A write error or timeout loses the renderer.
func (c *Client) writeFrameLocked(op gpuproto.Op, frame net.Buffers, timeout time.Duration) error {
	if err := c.lostErr(); err != nil {
		return err
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		c.lose(fmt.Errorf("write %s deadline: %w", op, err), true)
		return c.lostErr()
	}
	if _, err := frame.WriteTo(c.conn); err != nil {
		if isTimeoutErr(err) {
			c.lose(fmt.Errorf("%w: write of %s did not finish within %s", ErrRendererHung, op, timeout), true)
		} else {
			fallback := fmt.Errorf("write %s: %w", op, err)
			cause, kill := fallback, true
			if isPeerCloseErr(err) {
				cause, kill = c.peerExitCause(fallback)
			}
			c.lose(cause, kill)
		}
		return c.lostErr()
	}
	return nil
}
