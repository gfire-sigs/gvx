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

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// /sys/block, /sys/class/block, and /sys/dev/block list the disks of the
// sandbox (package blockdev). cAdvisor reads /sys/block/<disk>/{dev,size,stat}
// to learn the number, the size, and the counters of each disk. The three
// directories list the disks on every read, because an ext4lite volume becomes
// a disk when a mount starts and stops being one when the mount ends. On Linux
// the entries of /sys/class/block and /sys/dev/block are links to
// /sys/block. Here each entry is a directory with the same files.

// blockDirKey names a disk in one of the three directories.
//
// +stateify savable
type blockDirKey int

const (
	byDiskName blockDirKey = iota
	byDiskNumber
)

func (k blockDirKey) format(d *blockdev.Device) string {
	switch k {
	case byDiskName:
		return d.Name
	case byDiskNumber:
		return fmt.Sprintf("%d:%d", d.Major, d.Minor)
	default:
		return ""
	}
}

// blockDisks returns the disks of the kernel of the reader.
func blockDisks(ctx context.Context) *blockdev.Registry {
	return blockdev.Of(kernel.KernelFromContext(ctx).VFS())
}

// blockListDir is a directory with one subdirectory for each disk.
//
// +stateify savable
type blockListDir struct {
	dir

	fs    *filesystem
	creds *auth.Credentials
	key   blockDirKey
}

var _ kernfs.Inode = (*blockListDir)(nil)

func (fs *filesystem) newBlockListDir(ctx context.Context, creds *auth.Credentials, key blockDirKey) kernfs.Inode {
	d := &blockListDir{fs: fs, creds: creds, key: key}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	return d
}

// Lookup implements kernfs.Inode.Lookup.
func (d *blockListDir) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	registry := blockDisks(ctx)
	for _, disk := range registry.Devices() {
		if d.key.format(disk) == name {
			return d.fs.newDiskDir(ctx, d.creds, registry, disk), nil
		}
	}
	return nil, linuxerr.ENOENT
}

// IterDirents implements kernfs.inodeDirectory.IterDirents.
func (d *blockListDir) IterDirents(ctx context.Context, mnt *vfs.Mount, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	disks := blockDisks(ctx).Devices()
	base := offset - relOffset
	for i := int(relOffset); i < len(disks); i++ {
		dirent := vfs.Dirent{
			Name:    d.key.format(disks[i]),
			Type:    linux.DT_DIR,
			Ino:     d.fs.NextIno(),
			NextOff: base + int64(i) + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return base + int64(i), err
		}
	}
	return base + int64(len(disks)), nil
}

// diskDir is the directory of one disk. The dentry stays valid while the disk
// exists.
//
// +stateify savable
type diskDir struct {
	dir

	diskName string
	major    uint32
	minor    uint32
	registry *blockdev.Registry `state:"nosave"`
	disk     *blockdev.Device   `state:"nosave"`
}

var _ kernfs.Inode = (*diskDir)(nil)

// Valid implements kernfs.Inode.Valid.
func (d *diskDir) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	if d.registry != nil && d.disk != nil {
		return d.registry.Find(d.disk.Name) == d.disk
	}
	got := blockDisks(ctx).Find(d.diskName)
	return got != nil && got.Major == d.major && got.Minor == d.minor
}

// diskFileKind selects how diskFile generates its line.
//
// +stateify savable
type diskFileKind int

const (
	diskFileConstant diskFileKind = iota
	diskFileSize
	diskFileStat
)

// diskFile is a file of a disk directory.
//
// +stateify savable
type diskFile struct {
	kernfs.DynamicBytesFile

	kind     diskFileKind
	diskName string
	constant string
}

var _ vfs.DynamicBytesSource = (*diskFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *diskFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	switch f.kind {
	case diskFileConstant:
		buf.WriteString(f.constant)
		buf.WriteByte('\n')
		return nil
	case diskFileSize:
		disk := blockDisks(ctx).Find(f.diskName)
		if disk == nil {
			return linuxerr.ENOENT
		}
		fmt.Fprintf(buf, "%d\n", disk.Sectors())
		return nil
	case diskFileStat:
		disk := blockDisks(ctx).Find(f.diskName)
		if disk == nil {
			return linuxerr.ENOENT
		}
		writeDiskStat(buf, disk.Stats.Snapshot())
		return nil
	default:
		return linuxerr.EINVAL
	}
}

func (fs *filesystem) newDiskFile(ctx context.Context, creds *auth.Credentials, kind diskFileKind, diskName, constant string) kernfs.Inode {
	f := &diskFile{kind: kind, diskName: diskName, constant: constant}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), f, 0444)
	return f
}

// constantDiskFile returns a file that always holds the line value.
func (fs *filesystem) constantDiskFile(ctx context.Context, creds *auth.Credentials, value string) kernfs.Inode {
	return fs.newDiskFile(ctx, creds, diskFileConstant, "", value)
}

// writeDiskStat writes the 17 fields of /sys/block/<disk>/stat, each padded to
// 8 characters, as Linux does.
func writeDiskStat(buf *bytes.Buffer, s blockdev.Snapshot) {
	for i, v := range s.Fields() {
		if i > 0 {
			buf.WriteByte(' ')
		}
		fmt.Fprintf(buf, "%8d", v)
	}
	buf.WriteByte('\n')
}

func (fs *filesystem) newDiskDir(ctx context.Context, creds *auth.Credentials, registry *blockdev.Registry, disk *blockdev.Device) kernfs.Inode {
	readOnly := "0"
	if disk.ReadOnly {
		readOnly = "1"
	}
	sectorSize := strconv.Itoa(blockdev.SectorSize)
	contents := map[string]kernfs.Inode{
		"dev":  fs.constantDiskFile(ctx, creds, fmt.Sprintf("%d:%d", disk.Major, disk.Minor)),
		"size": fs.newDiskFile(ctx, creds, diskFileSize, disk.Name, ""),
		// The line has the 17 fields of Linux 5.5 and later, each padded to 8 characters.
		"stat":             fs.newDiskFile(ctx, creds, diskFileStat, disk.Name, ""),
		"ro":               fs.constantDiskFile(ctx, creds, readOnly),
		"removable":        fs.constantDiskFile(ctx, creds, "0"),
		"hidden":           fs.constantDiskFile(ctx, creds, "0"),
		"alignment_offset": fs.constantDiskFile(ctx, creds, "0"),
		"queue": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"scheduler":           fs.constantDiskFile(ctx, creds, "[none]"),
			"rotational":          fs.constantDiskFile(ctx, creds, "0"),
			"logical_block_size":  fs.constantDiskFile(ctx, creds, sectorSize),
			"physical_block_size": fs.constantDiskFile(ctx, creds, sectorSize),
			"hw_sector_size":      fs.constantDiskFile(ctx, creds, sectorSize),
		}),
	}
	d := &diskDir{
		diskName: disk.Name,
		major:    disk.Major,
		minor:    disk.Minor,
		registry: registry,
		disk:     disk,
	}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	d.IncLinks(d.OrderedChildren.Populate(contents))
	return d
}
