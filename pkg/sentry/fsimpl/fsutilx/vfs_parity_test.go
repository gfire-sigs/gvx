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

package fsutilx

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// TestVFSOptionStructParity fails whenever an upstream gVisor sync adds,
// removes, or retypes an exported field on a VFS option struct.
//
// Custom gvx filesystems (hostfs, ext4lite, rpcfs, and erofs xattr hooks)
// implement vfs.FilesystemImpl without sharing tmpfs/memxattr internals.
// A new option field such as GetXattrOptions.RawCapability compiles without
// errors yet silently drifts if custom drivers ignore it. When this test
// fails after a sync, audit fsutilx, hostfs, ext4lite, rpcfs, and
// pkg/sentry/fsimpl/erofs/xattr_xplat.go for the changed field before
// updating the expected snapshot below.
func TestVFSOptionStructParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		sample any
		fields []string
	}{
		{
			name:   "GetDentryOptions",
			sample: vfs.GetDentryOptions{},
			fields: []string{
				"CheckSearchable:bool",
			},
		},
		{
			name:   "MkdirOptions",
			sample: vfs.MkdirOptions{},
			fields: []string{
				"Mode:linux.FileMode",
				"ForSyntheticMountpoint:bool",
			},
		},
		{
			name:   "MknodOptions",
			sample: vfs.MknodOptions{},
			fields: []string{
				"Mode:linux.FileMode",
				"DevMajor:uint32",
				"DevMinor:uint32",
				"Endpoint:transport.BoundEndpoint",
			},
		},
		{
			name:   "MountFlags",
			sample: vfs.MountFlags{},
			fields: []string{
				"NoExec:bool",
				"NoATime:bool",
				"NoDev:bool",
				"NoSUID:bool",
			},
		},
		{
			name:   "MountOptions",
			sample: vfs.MountOptions{},
			fields: []string{
				"Flags:vfs.MountFlags",
				"ReadOnly:bool",
				"GetFilesystemOptions:vfs.GetFilesystemOptions",
				"Locked:bool",
			},
		},
		{
			name:   "OpenOptions",
			sample: vfs.OpenOptions{},
			fields: []string{
				"Flags:uint32",
				"Mode:linux.FileMode",
				"FileExec:bool",
			},
		},
		{
			name:   "ReadOptions",
			sample: vfs.ReadOptions{},
			fields: []string{
				"Flags:uint32",
			},
		},
		{
			name:   "RenameOptions",
			sample: vfs.RenameOptions{},
			fields: []string{
				"Flags:uint32",
				"MustBeDir:bool",
			},
		},
		{
			name:   "SetStatOptions",
			sample: vfs.SetStatOptions{},
			fields: []string{
				"Stat:linux.Statx",
				"NeedWritePerm:bool",
				"ClearPrivs:bool",
			},
		},
		{
			name:   "BoundEndpointOptions",
			sample: vfs.BoundEndpointOptions{},
			fields: []string{
				"Addr:string",
			},
		},
		{
			name:   "GetXattrOptions",
			sample: vfs.GetXattrOptions{},
			fields: []string{
				"Name:string",
				"Size:uint64",
				"RawCapability:bool",
			},
		},
		{
			name:   "SetXattrOptions",
			sample: vfs.SetXattrOptions{},
			fields: []string{
				"Name:string",
				"Value:string",
				"Flags:uint32",
			},
		},
		{
			name:   "StatOptions",
			sample: vfs.StatOptions{},
			fields: []string{
				"Mask:uint32",
				"Sync:uint32",
			},
		},
		{
			name:   "UmountOptions",
			sample: vfs.UmountOptions{},
			fields: []string{
				"Flags:uint32",
			},
		},
		{
			name:   "WriteOptions",
			sample: vfs.WriteOptions{},
			fields: []string{
				"Flags:uint32",
			},
		},
		{
			name:   "GetFilesystemOptions",
			sample: vfs.GetFilesystemOptions{},
			fields: []string{
				"InternalMount:bool",
				"Data:string",
				"InternalData:interface {}",
			},
		},
		{
			name:   "FileDescriptionOptions",
			sample: vfs.FileDescriptionOptions{},
			fields: []string{
				"AllowDirectIO:bool",
				"DenyPRead:bool",
				"DenyPWrite:bool",
				"UseDentryMetadata:bool",
				"DenySpliceIn:bool",
				"SpecialFile:bool",
			},
		},
		{
			name:   "SyncOptions",
			sample: vfs.SyncOptions{},
			fields: []string{
				"DataOnly:bool",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			typ := reflect.TypeOf(tc.sample)
			var got []string
			for i := range typ.NumField() {
				f := typ.Field(i)
				if !f.IsExported() {
					continue
				}
				got = append(got, fmt.Sprintf("%s:%s", f.Name, f.Type.String()))
			}
			if !slices.Equal(got, tc.fields) {
				t.Fatalf("vfs.%s exported fields changed:\n  got:  %v\n  want: %v\nAudit fsutilx, hostfs, ext4lite, rpcfs, and erofs/xattr_xplat.go for the changed field before updating this snapshot.",
					tc.name, got, tc.fields)
			}
		})
	}
}
