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
	"net"
	"slices"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// /sys/class/net has one directory for each link of the network namespace of
// the reader, as on Linux. cAdvisor and the kubelet read the address, the MTU,
// the operational state, and the counters of each link. The directory lists
// the links of the reader on every read, because processes in several network
// namespaces share one sysfs.

// netClassDir is /sys/class/net.
type netClassDir struct {
	dir

	fs    *filesystem
	creds *auth.Credentials
}

var _ kernfs.Inode = (*netClassDir)(nil)

func (fs *filesystem) newNetClassDir(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	d := &netClassDir{fs: fs, creds: creds}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	return d
}

// readerNetNamespace returns the network namespace of the reader.
func readerNetNamespace(ctx context.Context) *inet.Namespace {
	if t := kernel.TaskFromContext(ctx); t != nil {
		return t.NetworkNamespace()
	}
	if k := kernel.KernelFromContext(ctx); k != nil {
		return k.RootNetworkNamespace()
	}
	return nil
}

// readerLinks returns the links of the network namespace of the reader by
// index. A namespace without a stack has no links.
func readerLinks(ctx context.Context) (inet.Stack, map[int32]inet.Interface) {
	ns := readerNetNamespace(ctx)
	if ns == nil || ns.Stack() == nil {
		return nil, nil
	}
	return ns.Stack(), ns.Stack().Interfaces()
}

// findLink returns the index and the description of the link with name in the
// network namespace of the reader.
func findLink(ctx context.Context, name string) (inet.Stack, int32, inet.Interface, bool) {
	st, links := readerLinks(ctx)
	for id, nic := range links {
		if nic.Name == name {
			return st, id, nic, true
		}
	}
	return nil, 0, inet.Interface{}, false
}

// Lookup implements kernfs.Inode.Lookup.
func (d *netClassDir) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	if _, _, _, ok := findLink(ctx, name); !ok {
		return nil, linuxerr.ENOENT
	}
	return d.fs.newNetLinkDir(ctx, d.creds, name), nil
}

// IterDirents implements kernfs.inodeDirectory.IterDirents.
func (d *netClassDir) IterDirents(ctx context.Context, mnt *vfs.Mount, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	_, links := readerLinks(ctx)
	ids := make([]int32, 0, len(links))
	for id := range links {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	base := offset - relOffset
	for i := int(relOffset); i < len(ids); i++ {
		dirent := vfs.Dirent{
			Name:    links[ids[i]].Name,
			Type:    linux.DT_DIR,
			Ino:     d.fs.NextIno(),
			NextOff: base + int64(i) + 1,
		}
		if err := cb.Handle(dirent); err != nil {
			return base + int64(i), err
		}
	}
	return base + int64(len(ids)), nil
}

// netLinkDir is /sys/class/net/<link>. The dentry stays valid for the readers
// whose network namespace has a link with the same name.
type netLinkDir struct {
	dir

	link string
}

var _ kernfs.Inode = (*netLinkDir)(nil)

// Valid implements kernfs.Inode.Valid.
func (d *netLinkDir) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	_, _, _, ok := findLink(ctx, d.link)
	return ok
}

// netLinkFile is a file of a link directory. gen writes the content for the
// link of the reader that has the name of the file's directory.
type netLinkFile struct {
	kernfs.DynamicBytesFile

	link string
	gen  func(buf *bytes.Buffer, id int32, nic inet.Interface, dev inet.StatDev)
}

var _ vfs.DynamicBytesSource = (*netLinkFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *netLinkFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	st, id, nic, ok := findLink(ctx, f.link)
	if !ok {
		return linuxerr.ENOENT
	}
	var dev inet.StatDev
	// A link without counters reads as zero.
	_ = st.Statistics(&dev, nic.Name)
	f.gen(buf, id, nic, dev)
	return nil
}

func (fs *filesystem) newNetLinkFile(ctx context.Context, creds *auth.Credentials, link string, gen func(buf *bytes.Buffer, id int32, nic inet.Interface, dev inet.StatDev)) kernfs.Inode {
	f := &netLinkFile{link: link, gen: gen}
	f.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), f, 0444)
	return f
}

// Positions of the counters in inet.StatDev, which follows /proc/net/dev.
const (
	devRxBytes, devRxPackets, devRxErrors, devRxDropped = 0, 1, 2, 3
	devTxBytes, devTxPackets, devTxErrors, devTxDropped = 8, 9, 10, 11
)

// linkStatistics lists the counters of /sys/class/net/<link>/statistics.
var linkStatistics = []struct {
	name  string
	index int
}{
	{"rx_bytes", devRxBytes}, {"tx_bytes", devTxBytes},
	{"rx_packets", devRxPackets}, {"tx_packets", devTxPackets},
	{"rx_errors", devRxErrors}, {"tx_errors", devTxErrors},
	{"rx_dropped", devRxDropped}, {"tx_dropped", devTxDropped},
}

// linkOperState returns the content of operstate. Linux reports the loopback
// link as unknown.
func linkOperState(nic inet.Interface) string {
	if nic.DeviceType == linux.ARPHRD_LOOPBACK {
		return "unknown"
	}
	// A link kind with its own rule, such as wireguard, shares it with the
	// netlink attribute IFLA_OPERSTATE.
	if name, ok := netstack.LinkOperStateName(nic.Kind, nic.Flags); ok {
		return name
	}
	if nic.Flags&linux.IFF_UP != 0 && nic.Flags&linux.IFF_RUNNING != 0 {
		return "up"
	}
	return "down"
}

func (fs *filesystem) newNetLinkDir(ctx context.Context, creds *auth.Credentials, link string) kernfs.Inode {
	stats := make(map[string]kernfs.Inode, len(linkStatistics))
	for _, c := range linkStatistics {
		index := c.index
		stats[c.name] = fs.newNetLinkFile(ctx, creds, link, func(buf *bytes.Buffer, _ int32, _ inet.Interface, dev inet.StatDev) {
			fmt.Fprintf(buf, "%d\n", dev[index])
		})
	}
	contents := map[string]kernfs.Inode{
		"address": fs.newNetLinkFile(ctx, creds, link, func(buf *bytes.Buffer, _ int32, nic inet.Interface, _ inet.StatDev) {
			addr := net.HardwareAddr(nic.Addr)
			if len(addr) == 0 {
				if netstack.LinkHasNoLinkLayer(nic.Kind) {
					// A link without a link layer has an empty address.
					fmt.Fprintf(buf, "\n")
					return
				}
				addr = make(net.HardwareAddr, 6)
			}
			fmt.Fprintf(buf, "%s\n", addr)
		}),
		"mtu": fs.newNetLinkFile(ctx, creds, link, func(buf *bytes.Buffer, _ int32, nic inet.Interface, _ inet.StatDev) {
			fmt.Fprintf(buf, "%d\n", nic.MTU)
		}),
		"operstate": fs.newNetLinkFile(ctx, creds, link, func(buf *bytes.Buffer, _ int32, nic inet.Interface, _ inet.StatDev) {
			fmt.Fprintf(buf, "%s\n", linkOperState(nic))
		}),
		"ifindex": fs.newNetLinkFile(ctx, creds, link, func(buf *bytes.Buffer, id int32, _ inet.Interface, _ inet.StatDev) {
			fmt.Fprintf(buf, "%d\n", id)
		}),
		"statistics": fs.newDir(ctx, creds, defaultSysDirMode, stats),
	}
	d := &netLinkDir{link: link}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|0755)
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	d.InitRefs()
	d.IncLinks(d.OrderedChildren.Populate(contents))
	return d
}

// hashsizeFile is /sys/module/nf_conntrack/parameters/hashsize. The file stores
// the size of the table of the connection tracker. The tracker of the network
// stack does not read it.
type hashsizeFile struct {
	kernfs.DynamicBytesFile

	size atomicbitops.Uint32
}

var _ vfs.WritableDynamicBytesSource = (*hashsizeFile)(nil)

// defaultConntrackHashsize is the table size that goes with the default
// nf_conntrack_max of 262144 (four entries for each bucket).
const defaultConntrackHashsize = 65536

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *hashsizeFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", f.size.Load())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write. Like Linux, it needs a
// positive 32-bit number.
func (f *hashsizeFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
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
	v, err := strconv.ParseUint(strings.TrimSpace(string(buf)), 10, 32)
	if err != nil || v == 0 {
		return 0, linuxerr.EINVAL
	}
	f.size.Store(uint32(v))
	return int64(len(buf)), nil
}

// newModuleDirChildren returns the children of /sys/module: the parameters of
// the connection tracker that kube-proxy reads and writes, and the parameter of
// the IP sets.
func (fs *filesystem) newModuleDirChildren(ctx context.Context, creds *auth.Credentials) map[string]kernfs.Inode {
	hashsize := &hashsizeFile{}
	hashsize.size.Store(defaultConntrackHashsize)
	hashsize.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), hashsize, 0644)
	return map[string]kernfs.Inode{
		"ip_set": fs.newIPSetModuleDir(ctx, creds),
		"nf_conntrack": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
			"parameters": fs.newDir(ctx, creds, defaultSysDirMode, map[string]kernfs.Inode{
				"hashsize": hashsize,
			}),
		}),
	}
}
