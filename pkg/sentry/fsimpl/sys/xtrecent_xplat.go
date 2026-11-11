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

package sys

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// /sys/module/xt_recent/parameters holds the module parameters ip_list_tot and
// ip_pkt_list_tot of the iptables recent match. Linux reads them when it loads
// the module and creates the files with mode 0400. The write of a read-only
// parameter fails with EINVAL, because the file has no write operation.
//
// gvx has no module load, so the files take a write while no recent list
// exists. That write acts as a module load with new options. A write while any
// network namespace of the kernel has a recent list fails with EINVAL, as the
// write to a loaded module does.

// xtRecentParamKind selects one parameter of /sys/module/xt_recent/parameters.
//
// +stateify savable
type xtRecentParamKind int

const (
	xtRecentListTot xtRecentParamKind = iota
	xtRecentPktListTot
)

// xtRecentParam is one of the files in /sys/module/xt_recent/parameters.
//
// +stateify savable
type xtRecentParam struct {
	kernfs.DynamicBytesFile

	kind xtRecentParamKind
}

var _ vfs.WritableDynamicBytesSource = (*xtRecentParam)(nil)

func (f *xtRecentParam) get(mod *netfilter.RecentModule) uint32 {
	switch f.kind {
	case xtRecentListTot:
		return mod.ListTot()
	case xtRecentPktListTot:
		return mod.PktListTot()
	default:
		return 0
	}
}

func (f *xtRecentParam) set(mod *netfilter.RecentModule, v uint32) error {
	switch f.kind {
	case xtRecentListTot:
		return mod.SetListTot(v)
	case xtRecentPktListTot:
		return mod.SetPktListTot(v)
	default:
		return linuxerr.EINVAL
	}
}

// recentModule returns the module parameters of the kernel of the caller. It
// returns nil when the kernel has no network stack.
func recentModule(ctx context.Context) *netfilter.RecentModule {
	var inetSt inet.Stack
	if k := kernel.KernelFromContext(ctx); k != nil {
		if ns := k.RootNetworkNamespace(); ns != nil {
			inetSt = ns.Stack()
		}
	}
	if inetSt == nil {
		inetSt = inet.StackFromContext(ctx)
	}
	st, ok := inetSt.(*netstack.Stack)
	if !ok || st.Stack == nil {
		return nil
	}
	return netfilter.RecentModuleOf(st.Stack)
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *xtRecentParam) Generate(ctx context.Context, buf *bytes.Buffer) error {
	mod := recentModule(ctx)
	if mod == nil {
		mod = new(netfilter.RecentModule)
	}
	fmt.Fprintf(buf, "%d\n", f.get(mod))
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *xtRecentParam) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	if src.NumBytes() == 0 {
		return 0, nil
	}
	src = src.TakeFirst(int(hostarch.PageSize) - 1)
	buf := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	v, err := parseModuleUint(string(buf))
	if err != nil {
		return 0, err
	}
	mod := recentModule(ctx)
	if mod == nil {
		return 0, linuxerr.ENOENT
	}
	if err := f.set(mod, v); err != nil {
		if errors.Is(err, netfilter.ErrRecentModuleBusy) || errors.Is(err, netfilter.ErrRecentParam) {
			return 0, linuxerr.EINVAL
		}
		return 0, err
	}
	return int64(len(buf)), nil
}

// parseModuleUint reads an unsigned 32-bit value as kstrtouint does with base
// 0: a decimal number, a number with the prefix 0x, or an octal number with the
// prefix 0. It accepts one trailing newline. A value that does not fit gives
// ERANGE, and any other malformed text gives EINVAL.
func parseModuleUint(text string) (uint32, error) {
	text = strings.TrimSuffix(text, "\n")
	base, digits := 10, text
	switch {
	case strings.HasPrefix(text, "0x"), strings.HasPrefix(text, "0X"):
		base, digits = 16, text[2:]
	case len(text) > 1 && text[0] == '0':
		base, digits = 8, text[1:]
	}
	if digits == "" || strings.ContainsAny(digits, "+-_ ") {
		return 0, linuxerr.EINVAL
	}
	v, err := strconv.ParseUint(digits, base, 64)
	switch {
	case errors.Is(err, strconv.ErrRange):
		return 0, linuxerr.ERANGE
	case err != nil:
		return 0, linuxerr.EINVAL
	case v > math.MaxUint32:
		return 0, linuxerr.ERANGE
	}
	return uint32(v), nil
}

// newXtRecentDir returns /sys/module/xt_recent.
func (fs *filesystem) newXtRecentDir(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	param := func(kind xtRecentParamKind) kernfs.Inode {
		f := &xtRecentParam{kind: kind}
		f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), f, 0400)
		return f
	}
	return fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"parameters": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"ip_list_tot":     param(xtRecentListTot),
			"ip_pkt_list_tot": param(xtRecentPktListTot),
		}),
	})
}
