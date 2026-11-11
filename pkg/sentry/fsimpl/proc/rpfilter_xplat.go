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
	"fmt"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The files net/ipv4/conf/{all,default}/rp_filter belong to the network
// namespace of the reader, and net/ipv4/conf/<link>/rp_filter belongs to one
// link. Each holds one integer, as the proc_dointvec handler of Linux does. See
// netstack.Stack.EffectiveRPFilter for the rules that combine the values.

// rpFilterStack is a network stack that keeps the rp_filter values of its
// namespace. See socket/netstack/rpfilter_xplat.go.
type rpFilterStack interface {
	RPFilterAll() int32
	SetRPFilterAll(int32)
	RPFilterDefault() int32
	SetRPFilterDefault(int32)
}

// linkRPFilterStack is a network stack that keeps one rp_filter value for each
// link.
type linkRPFilterStack interface {
	LinkRPFilter(id int32) (int32, error)
	SetLinkRPFilter(id int32, v int32) error
}

// parseRPFilter reads the integer of a write. The write must start at offset 0.
func parseRPFilter(ctx context.Context, src usermem.IOSequence, offset int64) (v int32, n int64, err error) {
	if offset != 0 {
		return 0, 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err = ParseInt32Vec(ctx, src, buf)
	return buf[0], n, err
}

// nsRPFilter is conf/all/rp_filter or conf/default/rp_filter.
//
// +stateify savable
type nsRPFilter struct {
	kernfs.DynamicBytesFile

	// stack is the stack of the root network namespace. It serves a caller that
	// has no network namespace of its own.
	stack inet.Stack
	// isDefault selects conf/default/rp_filter.
	isDefault bool
}

var _ vfs.WritableDynamicBytesSource = (*nsRPFilter)(nil)

func (f *nsRPFilter) rpStack(ctx context.Context) (rpFilterStack, error) {
	s, ok := sysctlStack(ctx, f.stack).(rpFilterStack)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return s, nil
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *nsRPFilter) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, err := f.rpStack(ctx)
	if err != nil {
		return err
	}
	v := s.RPFilterAll()
	if f.isDefault {
		v = s.RPFilterDefault()
	}
	fmt.Fprintf(buf, "%d\n", v)
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *nsRPFilter) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	v, n, err := parseRPFilter(ctx, src, offset)
	if err != nil || n == 0 {
		return 0, err
	}
	s, err := f.rpStack(ctx)
	if err != nil {
		return 0, err
	}
	if f.isDefault {
		s.SetRPFilterDefault(v)
	} else {
		s.SetRPFilterAll(v)
	}
	return n, nil
}

// linkRPFilter is conf/<link>/rp_filter.
//
// +stateify savable
type linkRPFilter struct {
	kernfs.DynamicBytesFile

	stack inet.Stack
	// id is the index of the link. Immutable.
	id int32
}

var _ vfs.WritableDynamicBytesSource = (*linkRPFilter)(nil)

func (f *linkRPFilter) linkStack() (linkRPFilterStack, error) {
	s, ok := f.stack.(linkRPFilterStack)
	if !ok {
		return nil, linuxerr.EOPNOTSUPP
	}
	return s, nil
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *linkRPFilter) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, err := f.linkStack()
	if err != nil {
		return err
	}
	v, err := s.LinkRPFilter(f.id)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "%d\n", v)
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *linkRPFilter) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	v, n, err := parseRPFilter(ctx, src, offset)
	if err != nil || n == 0 {
		return 0, err
	}
	s, err := f.linkStack()
	if err != nil {
		return 0, err
	}
	if err := s.SetLinkRPFilter(f.id, v); err != nil {
		return 0, err
	}
	return n, nil
}
