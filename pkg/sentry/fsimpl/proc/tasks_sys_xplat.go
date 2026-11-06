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
	"slices"
	"strings"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The directories /proc/sys/net/ipv4/conf and /proc/sys/net/ipv6/conf have one
// subdirectory for each network link, as on Linux. dockerd writes
// conf/<bridge>/route_localnet when it runs with --userland-proxy=false, and it
// reads conf/<bridge>/accept_ra for IPv6 bridges.

const (
	netIPv4ConfPath = "net/ipv4/conf"
	netIPv6ConfPath = "net/ipv6/conf"
)

// netConfDir is a conf directory whose link subdirectories follow the links of
// the network stack. A lookup or an open of the directory first adds the
// subdirectories of new links and removes those of deleted links.
type netConfDir struct {
	*lazySysDir

	stack inet.Stack

	// syncMu serializes syncLinks calls.
	syncMu sync.Mutex `state:"nosave"`
}

var _ kernfs.Inode = (*netConfDir)(nil)

// newSysSubdir returns the directory inode for the subdirectory at path of a
// /proc/sys directory. Every subdirectory is a lazySysDir, except the conf
// directories of a network stack.
func (fs *filesystem) newSysSubdir(ctx context.Context, root *auth.Credentials, k *kernel.Kernel, stack inet.Stack, path string) kernfs.Inode {
	dir := fs.newLazySysDir(ctx, root, k, path).(*lazySysDir)
	if stack == nil || (path != netIPv4ConfPath && path != netIPv6ConfPath) {
		return dir
	}
	return &netConfDir{lazySysDir: dir, stack: stack}
}

// netLinkDir is the conf directory of one network link. A path walk drops its
// cached dentry when the link no longer exists, or when a new link took the
// name of the old one.
type netLinkDir struct {
	*lazySysDir

	stack inet.Stack
	// id is the index of the link. Link indexes never repeat. Immutable.
	id int32
	// link is the name of the link. Immutable.
	link string
}

var _ kernfs.Inode = (*netLinkDir)(nil)

// linkDirValid reports whether the link with index id still has the name. live
// maps the indexes of the links to their names.
func linkDirValid(live map[int32]string, id int32, name string) bool {
	got, ok := live[id]
	return ok && got == name
}

// liveLinks returns the names of the links of stack by index.
func liveLinks(stack inet.Stack) map[int32]string {
	live := make(map[int32]string)
	for id, nic := range stack.Interfaces() {
		live[id] = nic.Name
	}
	return live
}

// Valid implements kernfs.Inode.Valid.
func (d *netLinkDir) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	return linkDirValid(liveLinks(d.stack), d.id, d.link)
}

// diffLinkDirs compares the link directories of a conf directory with the live
// links. have maps the names of the directories to the indexes of their links.
// stale lists the directories to remove: their link is gone, or a link with
// another index took the name. add maps the names of the directories to
// create to the indexes of their links.
func diffLinkDirs(have map[string]int32, live map[int32]string) (stale []string, add map[string]int32) {
	add = make(map[string]int32)
	for name, id := range have {
		if !linkDirValid(live, id, name) {
			stale = append(stale, name)
		}
	}
	for id, name := range live {
		// The directories all and default belong to the conf directory. A link
		// with one of these names has no directory of its own.
		if name == "" || name == "all" || name == "default" || strings.Contains(name, "/") {
			continue
		}
		if haveID, ok := have[name]; !ok || haveID != id {
			add[name] = id
		}
	}
	slices.Sort(stale)
	return stale, add
}

// Lookup implements kernfs.Inode.Lookup.
func (d *netConfDir) Lookup(ctx context.Context, name string) (kernfs.Inode, error) {
	d.syncLinks(ctx)
	return d.lazySysDir.Lookup(ctx, name)
}

// Open implements kernfs.Inode.Open.
func (d *netConfDir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	d.syncLinks(ctx)
	return d.lazySysDir.Open(ctx, rp, kd, opts)
}

// syncLinks makes the subdirectories of d match the links of the stack. The
// subdirectories all and default always stay.
func (d *netConfDir) syncLinks(ctx context.Context) {
	d.populate(ctx)
	d.syncMu.Lock()
	defer d.syncMu.Unlock()

	have := make(map[string]int32)
	d.OrderedChildren.ForEachChild(func(name string, child kernfs.Inode) {
		if link, ok := child.(*netLinkDir); ok {
			have[name] = link.id
		}
	})
	stale, add := diffLinkDirs(have, liveLinks(d.stack))
	for _, name := range stale {
		if d.OrderedChildren.RemoveStatic(ctx, name) == nil {
			d.DecLinks()
		}
	}
	for name, id := range add {
		child := &netLinkDir{
			lazySysDir: d.fs.newLazySysDir(ctx, d.creds, d.k, d.path+"/"+name).(*lazySysDir),
			stack:      d.stack,
			id:         id,
			link:       name,
		}
		child.OrderedChildren.Populate(d.fs.linkConfFiles(ctx, d.creds, d.stack, d.path, id))
		child.populated.Store(true)
		d.OrderedChildren.Populate(map[string]kernfs.Inode{name: child})
		d.IncLinks(1)
	}
}

// linkConfFiles returns the files of the conf directory of one link. confPath
// is the path of the conf directory relative to /proc/sys.
func (fs *filesystem) linkConfFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, confPath string, id int32) map[string]kernfs.Inode {
	if confPath == netIPv4ConfPath {
		return map[string]kernfs.Inode{
			"route_localnet": fs.newInode(ctx, root, 0644, &routeLocalnetLinkData{stack: stack, id: id}),
			"rp_filter":      fs.newInode(ctx, root, 0644, &linkRPFilter{stack: stack, id: id}),
		}
	}
	acceptRA := new(atomicbitops.Int32)
	acceptRA.Store(1)
	return map[string]kernfs.Inode{
		"accept_ra": fs.newInode(ctx, root, 0644, &atomicInt32File{val: acceptRA, min: 0, max: 2}),
	}
}

// linkRouteLocalnet is the per-link route_localnet of a network stack. Linux
// accepts martian loopback packets on a link when conf/all or the conf of the
// link enables the setting.
type linkRouteLocalnet interface {
	LinkRouteLocalnet(id int32) (bool, error)
	SetLinkRouteLocalnet(id int32, enable bool) error
}

// routeLocalnetLinkData implements vfs.WritableDynamicBytesSource for
// /proc/sys/net/ipv4/conf/<link>/route_localnet. The value belongs to one link,
// so a write does not change the martian filter of any other link.
type routeLocalnetLinkData struct {
	kernfs.DynamicBytesFile

	stack inet.Stack
	id    int32
}

var _ vfs.WritableDynamicBytesSource = (*routeLocalnetLinkData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (r *routeLocalnetLinkData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, ok := r.stack.(linkRouteLocalnet)
	if !ok {
		return linuxerr.EOPNOTSUPP
	}
	enabled, err := s.LinkRouteLocalnet(r.id)
	if err != nil {
		return err
	}
	if enabled {
		buf.WriteString("1\n")
	} else {
		buf.WriteString("0\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (r *routeLocalnetLinkData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	s, ok := r.stack.(linkRouteLocalnet)
	if !ok {
		return 0, linuxerr.EOPNOTSUPP
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	if err := s.SetLinkRouteLocalnet(r.id, buf[0] != 0); err != nil {
		return 0, err
	}
	return n, nil
}

// boolSysctlFile is a sysctl file whose value is 0 or 1. A write of any other
// non-zero number stores 1, as Linux does for the bridge-nf-call files.
type boolSysctlFile struct {
	kernfs.DynamicBytesFile

	val *atomicbitops.Int32
}

var _ vfs.WritableDynamicBytesSource = (*boolSysctlFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *boolSysctlFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", f.val.Load())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *boolSysctlFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	f.val.Store(boolToInt32(buf[0] != 0))
	return n, nil
}

func boolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

// bridgeNetfilterStack is a network stack whose bridges pass the IP frames that
// they forward through the iptables hooks. See stack.Stack.SetBridgeNetfilter.
type bridgeNetfilterStack interface {
	BridgeNetfilter(protocol tcpip.NetworkProtocolNumber) bool
	SetBridgeNetfilter(protocol tcpip.NetworkProtocolNumber, enable bool)
}

// nsBridgeNetfilter is bridge-nf-call-iptables or bridge-nf-call-ip6tables. The
// value belongs to the network namespace of the caller. At 1, a bridge of that
// namespace passes the IP frames that it forwards between two ports through
// the iptables hooks. Any non-zero write stores 1, as on Linux.
type nsBridgeNetfilter struct {
	kernfs.DynamicBytesFile

	// stack is the stack of the root network namespace. It serves a caller that
	// has no network namespace of its own.
	stack    inet.Stack
	protocol tcpip.NetworkProtocolNumber
}

var _ vfs.WritableDynamicBytesSource = (*nsBridgeNetfilter)(nil)

func (f *nsBridgeNetfilter) bridgeStack(ctx context.Context) (bridgeNetfilterStack, error) {
	s, ok := sysctlStack(ctx, f.stack).(bridgeNetfilterStack)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return s, nil
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *nsBridgeNetfilter) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, err := f.bridgeStack(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "%d\n", boolToInt32(s.BridgeNetfilter(f.protocol)))
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *nsBridgeNetfilter) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	s, err := f.bridgeStack(ctx)
	if err != nil {
		return 0, err
	}
	s.SetBridgeNetfilter(f.protocol, buf[0] != 0)
	return n, nil
}

// sysBridgeNetfilterFiles returns the files of /proc/sys/net/bridge. dockerd
// requires bridge-nf-call-iptables when it runs without the userland proxy.
// The files for iptables and ip6tables switch the iptables hooks for the
// bridged IP frames of the network namespace. The other files store their
// values only.
func (fs *filesystem) sysBridgeNetfilterFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack) map[string]kernfs.Inode {
	files := make(map[string]kernfs.Inode)
	if _, ok := stack.(bridgeNetfilterStack); ok {
		files["bridge-nf-call-iptables"] = fs.newInode(ctx, root, 0644, &nsBridgeNetfilter{stack: stack, protocol: header.IPv4ProtocolNumber})
		files["bridge-nf-call-ip6tables"] = fs.newInode(ctx, root, 0644, &nsBridgeNetfilter{stack: stack, protocol: header.IPv6ProtocolNumber})
	}
	for name, initial := range map[string]int32{
		"bridge-nf-call-arptables":      1,
		"bridge-nf-call-ip6tables":      1,
		"bridge-nf-call-iptables":       1,
		"bridge-nf-filter-pppoe-tagged": 0,
		"bridge-nf-filter-vlan-tagged":  0,
		"bridge-nf-pass-vlan-input-dev": 0,
	} {
		if _, ok := files[name]; ok {
			continue
		}
		val := new(atomicbitops.Int32)
		val.Store(initial)
		files[name] = fs.newInode(ctx, root, 0644, &boolSysctlFile{val: val})
	}
	return files
}

// sysNetXplatFiles returns the files of the directories that this file adds to
// /proc/sys/net: net/bridge, net/netfilter, and net/*/neigh. It reports false for
// any other path. The files of net/netfilter and net/*/neigh/default come from
// addNodeSysctlFiles.
func (fs *filesystem) sysNetXplatFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, path string) (map[string]kernfs.Inode, bool) {
	switch {
	case path == "net/bridge":
		return fs.sysBridgeNetfilterFiles(ctx, root, stack), true
	case path == "net/netfilter":
		return make(map[string]kernfs.Inode), true
	case isNeighDir(path):
		return make(map[string]kernfs.Inode), true
	}
	return nil, false
}
