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
	"fmt"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// maxSetsFile is /sys/module/ip_set/parameters/max_sets. A network namespace
// that starts after a write gets a table of this many sets, and the table grows
// when it fills up, as on Linux.
type maxSetsFile struct {
	kernfs.DynamicBytesFile
}

var _ vfs.WritableDynamicBytesSource = (*maxSetsFile)(nil)

// module returns the parameters of ip_set for the kernel of the reader.
func (f *maxSetsFile) module(ctx context.Context) *ipset.Module {
	return ipset.ModuleFor(kernel.KernelFromContext(ctx))
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *maxSetsFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", f.module(ctx).MaxSets())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write. Like Linux, it needs a
// non-negative 32-bit number.
func (f *maxSetsFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
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
	v, err := strconv.ParseInt(strings.TrimSpace(string(buf)), 10, 32)
	if err != nil || v < 0 {
		return 0, linuxerr.EINVAL
	}
	f.module(ctx).SetMaxSets(int32(v))
	return int64(len(buf)), nil
}

// newIPSetModuleDir returns /sys/module/ip_set. It holds the parameter
// max_sets of the kernel module of the IP sets.
func (fs *filesystem) newIPSetModuleDir(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	maxSets := &maxSetsFile{}
	maxSets.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), maxSets, 0600)
	return fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
		"parameters": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"max_sets": maxSets,
		}),
	})
}
