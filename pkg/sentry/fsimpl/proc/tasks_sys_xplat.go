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
	"math"
	"strings"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
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
// cached dentry when the link no longer exists.
type netLinkDir struct {
	*lazySysDir

	stack inet.Stack
	// link is the name of the link. Immutable.
	link string
}

var _ kernfs.Inode = (*netLinkDir)(nil)

// Valid implements kernfs.Inode.Valid.
func (d *netLinkDir) Valid(ctx context.Context, parent *kernfs.Dentry, name string) bool {
	for _, nic := range d.stack.Interfaces() {
		if nic.Name == d.link {
			return true
		}
	}
	return false
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

	live := make(map[string]struct{})
	for _, nic := range d.stack.Interfaces() {
		live[nic.Name] = struct{}{}
	}
	var stale []string
	have := make(map[string]struct{})
	d.OrderedChildren.ForEachChild(func(name string, _ kernfs.Inode) {
		have[name] = struct{}{}
		if _, ok := live[name]; !ok && name != "all" && name != "default" {
			stale = append(stale, name)
		}
	})
	for _, name := range stale {
		if d.OrderedChildren.RemoveStatic(ctx, name) == nil {
			d.DecLinks()
		}
	}
	for name := range live {
		if _, ok := have[name]; ok || name == "" || strings.Contains(name, "/") {
			continue
		}
		child := &netLinkDir{
			lazySysDir: d.fs.newLazySysDir(ctx, d.creds, d.k, d.path+"/"+name).(*lazySysDir),
			stack:      d.stack,
			link:       name,
		}
		d.OrderedChildren.Populate(map[string]kernfs.Inode{name: child})
		d.IncLinks(1)
	}
}

// sysBridgeNetfilterFiles returns the files of /proc/sys/net/bridge. dockerd
// requires bridge-nf-call-iptables when it runs without the userland proxy.
// The values are stored only. The bridge of the stack forwards Ethernet frames
// and does not pass them through iptables, so these values do not change how
// the guest filters bridged traffic.
func (fs *filesystem) sysBridgeNetfilterFiles(ctx context.Context, root *auth.Credentials) map[string]kernfs.Inode {
	files := make(map[string]kernfs.Inode)
	for name, initial := range map[string]int32{
		"bridge-nf-call-arptables":      1,
		"bridge-nf-call-ip6tables":      1,
		"bridge-nf-call-iptables":       1,
		"bridge-nf-filter-pppoe-tagged": 0,
		"bridge-nf-filter-vlan-tagged":  0,
		"bridge-nf-pass-vlan-input-dev": 0,
	} {
		val := new(atomicbitops.Int32)
		val.Store(initial)
		files[name] = fs.newInode(ctx, root, 0644, &atomicInt32File{val: val, min: math.MinInt32, max: math.MaxInt32})
	}
	return files
}

// sysNetXplatFiles returns the files of the directories that this file adds to
// /proc/sys/net: net/bridge and the conf directory of one network link. It
// reports false for any other path.
func (fs *filesystem) sysNetXplatFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, path string) (map[string]kernfs.Inode, bool) {
	switch {
	case path == "net/bridge":
		return fs.sysBridgeNetfilterFiles(ctx, root), true
	case strings.HasPrefix(path, netIPv4ConfPath+"/"):
		return map[string]kernfs.Inode{
			"route_localnet": fs.newInode(ctx, root, 0644, &routeLocalnetData{stack: stack}),
		}, true
	case strings.HasPrefix(path, netIPv6ConfPath+"/"):
		acceptRA := new(atomicbitops.Int32)
		acceptRA.Store(1)
		return map[string]kernfs.Inode{
			"accept_ra": fs.newInode(ctx, root, 0644, &atomicInt32File{val: acceptRA, min: 0, max: 2}),
		}, true
	}
	return nil, false
}
