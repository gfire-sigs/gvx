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

package linux

import (
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/waiter"
)

// The commands of syslog(2), from include/linux/syslog.h.
const (
	_SYSLOG_ACTION_CLOSE         = 0
	_SYSLOG_ACTION_OPEN          = 1
	_SYSLOG_ACTION_READ          = 2
	_SYSLOG_ACTION_READ_ALL      = 3
	_SYSLOG_ACTION_READ_CLEAR    = 4
	_SYSLOG_ACTION_CLEAR         = 5
	_SYSLOG_ACTION_CONSOLE_OFF   = 6
	_SYSLOG_ACTION_CONSOLE_ON    = 7
	_SYSLOG_ACTION_CONSOLE_LEVEL = 8
	_SYSLOG_ACTION_SIZE_UNREAD   = 9
	_SYSLOG_ACTION_SIZE_BUFFER   = 10
)

// Syslog implements Linux syscall syslog(2) on the kernel log ring. It follows
// do_syslog of kernel/printk/printk.c. The text of a record has the form
// "<prio>[ sec.usec] text\n".
func Syslog(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	command := args[0].Int()
	buf := args[1].Pointer()
	size := int(args[2].Int())
	klog := t.Kernel().KernelLog()

	// With kernel.dmesg_restrict at 0, READ_ALL and SIZE_BUFFER need no
	// capability. Every other command needs CAP_SYSLOG, and every command
	// needs it when kernel.dmesg_restrict is 1.
	restricted := klog.DmesgRestrict() || (command != _SYSLOG_ACTION_READ_ALL && command != _SYSLOG_ACTION_SIZE_BUFFER)
	if restricted && !kernel.CanReadKernelLog(t.Credentials(), t.Kernel()) {
		return 0, nil, linuxerr.EPERM
	}

	switch command {
	case _SYSLOG_ACTION_CLOSE, _SYSLOG_ACTION_OPEN:
		return 0, nil, nil
	case _SYSLOG_ACTION_READ:
		if buf == 0 || size < 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if size == 0 {
			return 0, nil, nil
		}
		return syslogRead(t, klog, buf, size)
	case _SYSLOG_ACTION_READ_ALL, _SYSLOG_ACTION_READ_CLEAR:
		if buf == 0 || size < 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if size == 0 {
			return 0, nil, nil
		}
		n, err := t.CopyOutBytes(buf, klog.ReadAll(size, command == _SYSLOG_ACTION_READ_CLEAR))
		return uintptr(n), nil, err
	case _SYSLOG_ACTION_CLEAR:
		klog.Clear()
		return 0, nil, nil
	case _SYSLOG_ACTION_CONSOLE_OFF:
		klog.ConsoleOff()
		return 0, nil, nil
	case _SYSLOG_ACTION_CONSOLE_ON:
		klog.ConsoleOn()
		return 0, nil, nil
	case _SYSLOG_ACTION_CONSOLE_LEVEL:
		if !klog.SetConsoleLevel(size) {
			return 0, nil, linuxerr.EINVAL
		}
		return 0, nil, nil
	case _SYSLOG_ACTION_SIZE_UNREAD:
		return uintptr(klog.UnreadSize()), nil, nil
	case _SYSLOG_ACTION_SIZE_BUFFER:
		return uintptr(klog.BufLen()), nil, nil
	default:
		return 0, nil, linuxerr.EINVAL
	}
}

// syslogRead implements SYSLOG_ACTION_READ. It waits until the log has an
// unread record, and an interrupt ends the wait.
func syslogRead(t *kernel.Task, klog *kernel.KernelLog, buf hostarch.Addr, size int) (uintptr, *kernel.SyscallControl, error) {
	w, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := klog.EventRegister(&w); err != nil {
		return 0, nil, err
	}
	defer klog.EventUnregister(&w)
	for {
		if data := klog.Read(size); len(data) > 0 {
			n, err := t.CopyOutBytes(buf, data)
			return uintptr(n), nil, err
		}
		if err := t.Block(ch); err != nil {
			return 0, nil, linuxerr.ConvertIntr(err, linuxerr.ERESTARTSYS)
		}
	}
}
