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

package proc

import (
	"bytes"
	"math"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The files kernel/dmesg_restrict, kernel/printk_devkmsg, and kernel/printk
// show and set values of the kernel log of the kernel. /dev/kmsg and syslog(2)
// read these values.

// kmsgSysctlKind selects the file that a kmsgSysctl serves.
//
// +stateify savable
type kmsgSysctlKind int

const (
	// kmsgDmesgRestrict is kernel/dmesg_restrict, 0 or 1.
	kmsgDmesgRestrict kmsgSysctlKind = iota
	// kmsgPrintkDevkmsg is kernel/printk_devkmsg: on, off, or ratelimit.
	kmsgPrintkDevkmsg
	// kmsgPrintk is kernel/printk: console_loglevel, default_message_loglevel,
	// minimum_console_loglevel, and default_console_loglevel.
	kmsgPrintk
)

// kmsgSysctl implements vfs.WritableDynamicBytesSource for the sysctl files of
// the kernel log.
//
// +stateify savable
type kmsgSysctl struct {
	kernfs.DynamicBytesFile

	kind kmsgSysctlKind
}

var _ vfs.WritableDynamicBytesSource = (*kmsgSysctl)(nil)

// kmsgSysctlFiles returns the sysctl files of the kernel log by name.
func (fs *filesystem) kmsgSysctlFiles(ctx context.Context, root *auth.Credentials) map[string]kernfs.Inode {
	return map[string]kernfs.Inode{
		"dmesg_restrict": fs.newInode(ctx, root, 0644, &kmsgSysctl{kind: kmsgDmesgRestrict}),
		"printk_devkmsg": fs.newInode(ctx, root, 0644, &kmsgSysctl{kind: kmsgPrintkDevkmsg}),
		"printk":         fs.newInode(ctx, root, 0644, &kmsgSysctl{kind: kmsgPrintk}),
	}
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *kmsgSysctl) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return linuxerr.ENOENT
	}
	klog := k.KernelLog()
	switch f.kind {
	case kmsgDmesgRestrict:
		if klog.DmesgRestrict() {
			buf.WriteString("1\n")
		} else {
			buf.WriteString("0\n")
		}
	case kmsgPrintkDevkmsg:
		buf.WriteString(klog.DevkmsgMode().String())
		buf.WriteByte('\n')
	case kmsgPrintk:
		levels := klog.Levels()
		buf.WriteString(strconv.Itoa(levels[0]))
		for _, level := range levels[1:] {
			buf.WriteByte('\t')
			buf.WriteString(strconv.Itoa(level))
		}
		buf.WriteByte('\n')
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write. A write to
// dmesg_restrict needs CAP_SYS_ADMIN, as proc_dointvec_minmax_sysadmin does in
// Linux. A value outside the range of the file fails with EINVAL.
func (f *kmsgSysctl) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return 0, linuxerr.ENOENT
	}
	text, n, err := readSysctlText(ctx, src)
	if err != nil || n == 0 {
		return 0, err
	}
	klog := k.KernelLog()
	sysctlWriteMu.Lock()
	defer sysctlWriteMu.Unlock()
	switch f.kind {
	case kmsgDmesgRestrict:
		creds := auth.CredentialsFromContext(ctx)
		rootNS := k.RootUserNamespace()
		if rootNS == nil {
			rootNS = creds.UserNamespace
		}
		if !creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, rootNS) {
			return 0, linuxerr.EPERM
		}
		cur := "0"
		if klog.DmesgRestrict() {
			cur = "1"
		}
		val, err := intVecParser(1, 0, 1, nil)(text, cur)
		if err != nil {
			return 0, err
		}
		klog.SetDmesgRestrict(val == "1")
	case kmsgPrintkDevkmsg:
		line, _, _ := strings.Cut(text, "\n")
		mode, ok := kernel.ParseDevkmsgMode(line)
		if !ok {
			return 0, linuxerr.EINVAL
		}
		klog.SetDevkmsgMode(mode)
	case kmsgPrintk:
		cur := klog.Levels()
		curText := strings.Join([]string{strconv.Itoa(cur[0]), strconv.Itoa(cur[1]), strconv.Itoa(cur[2]), strconv.Itoa(cur[3])}, "\t")
		val, err := intVecParser(4, math.MinInt32, math.MaxInt32, nil)(text, curText)
		if err != nil {
			return 0, err
		}
		var levels [4]int
		for i, field := range strings.Fields(val) {
			levels[i], _ = strconv.Atoi(field)
		}
		klog.SetLevels(levels)
	}
	return n, nil
}
