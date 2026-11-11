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
	"math"
	"strconv"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The files of the IPv4 conf and neigh directories that this file lists hold
// one integer each. The guest tools write them: Calico and wg-quick write
// proxy_arp, src_valid_mark, proxy_delay, and others of this list. The stack
// stores the values with the defaults of Linux. The proxy_arp value changes the
// answers to ARP requests, and the other values change nothing yet.

// confInt is an integer file with its default.
//
// +stateify savable
type confInt struct {
	name string
	def  int32
}

// ipv4ConfInts lists the files of conf/all, conf/default, and conf/<link> that
// the store holds, besides forwarding, route_localnet, and rp_filter.
var ipv4ConfInts = []confInt{
	{"accept_local", 0}, {"accept_redirects", 1}, {"accept_source_route", 0},
	{"arp_accept", 0}, {"arp_announce", 0}, {"arp_filter", 0}, {"arp_ignore", 0}, {"arp_notify", 0},
	{"bc_forwarding", 0}, {"bootp_relay", 0}, {"disable_policy", 0}, {"disable_xfrm", 0},
	{"drop_gratuitous_arp", 0}, {"drop_unicast_in_l2_multicast", 0}, {"force_igmp_version", 0},
	{"igmpv2_unsolicited_report_interval", 10000}, {"igmpv3_unsolicited_report_interval", 1000},
	{"ignore_routes_with_linkdown", 0}, {"log_martians", 0}, {"mc_forwarding", 0}, {"medium_id", 0},
	{"promote_secondaries", 0}, {"proxy_arp", 0}, {"proxy_arp_pvlan", 0}, {"secure_redirects", 1},
	{"send_redirects", 1}, {"shared_media", 1}, {"src_valid_mark", 0}, {"tag", 0},
}

// ipv4NeighInts lists the files of neigh/default and neigh/<link>.
var ipv4NeighInts = []confInt{
	{"anycast_delay", 100}, {"app_solicit", 0}, {"base_reachable_time", 30}, {"base_reachable_time_ms", 30000},
	{"delay_first_probe_time", 5}, {"gc_stale_time", 60}, {"locktime", 100}, {"mcast_resolicit", 0},
	{"mcast_solicit", 3}, {"proxy_delay", 80}, {"proxy_qlen", 64}, {"retrans_time", 100},
	{"retrans_time_ms", 1000}, {"ucast_solicit", 3}, {"unres_qlen", 101}, {"unres_qlen_bytes", 212992},
}

// ipv4NeighDefaultOnly lists the files that only neigh/default has.
var ipv4NeighDefaultOnly = []confInt{
	{"gc_interval", 30}, {"gc_thresh1", 128}, {"gc_thresh2", 512}, {"gc_thresh3", 1024},
}

func init() {
	spec := func(id sysctlID, dir, sub string, c confInt) *sysctlSpec {
		return registerSysctlSpec(&sysctlSpec{
			id: id, scope: scopeNet, name: c.name, key: dir + "/" + sub + "/" + c.name,
			def: strconv.Itoa(int(c.def)), parse: intVecParser(1, math.MinInt32, math.MaxInt32, nil),
		})
	}
	for _, entry := range []struct {
		sub  string
		base sysctlID
	}{
		{"all", sysctlIPv4ConfAllBase},
		{"default", sysctlIPv4ConfDefaultBase},
	} {
		path := "net/" + netstack.ConfDirIPv4 + "/" + entry.sub
		for i, c := range ipv4ConfInts {
			nodeSysctlSpecs[path] = append(nodeSysctlSpecs[path], spec(entry.base+sysctlID(i), netstack.ConfDirIPv4, entry.sub, c))
		}
	}
	for i, c := range append(append([]confInt(nil), ipv4NeighInts...), ipv4NeighDefaultOnly...) {
		path := "net/" + netstack.NeighDirIPv4 + "/default"
		nodeSysctlSpecs[path] = append(nodeSysctlSpecs[path], spec(sysctlIPv4NeighDefaultBase+sysctlID(i), netstack.NeighDirIPv4, "default", c))
	}
}

// linkConfStack is a network stack that keeps the conf and neigh values of its
// links. See netstack.Stack.LinkConfValue.
type linkConfStack interface {
	LinkConfValue(id int32, dir, name string, def int32) (int32, error)
	SetLinkConfValue(id int32, dir, name string, v int32) error
}

// linkConfFile is one integer file of conf/<link> or neigh/<link>.
//
// +stateify savable
type linkConfFile struct {
	kernfs.DynamicBytesFile

	stack inet.Stack
	// id is the index of the link. Immutable.
	id int32
	// dir is netstack.ConfDirIPv4 or netstack.NeighDirIPv4. Immutable.
	dir string
	// conf holds the name and the default of the file. Immutable.
	conf confInt
}

var _ vfs.WritableDynamicBytesSource = (*linkConfFile)(nil)

func (f *linkConfFile) linkStack() (linkConfStack, error) {
	s, ok := f.stack.(linkConfStack)
	if !ok {
		return nil, linuxerr.EOPNOTSUPP
	}
	return s, nil
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *linkConfFile) Generate(_ context.Context, buf *bytes.Buffer) error {
	s, err := f.linkStack()
	if err != nil {
		return err
	}
	v, err := s.LinkConfValue(f.id, f.dir, f.conf.name, f.conf.def)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "%d\n", v)
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *linkConfFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	s, err := f.linkStack()
	if err != nil {
		return 0, err
	}
	v := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, v)
	if err != nil || n == 0 {
		return 0, err
	}
	if err := s.SetLinkConfValue(f.id, f.dir, f.conf.name, v[0]); err != nil {
		return 0, err
	}
	return n, nil
}

// linkForwardingStack is a network stack with the IPv4 forwarding switch of each
// link. See netstack.Stack.SetLinkForwarding.
type linkForwardingStack interface {
	LinkForwarding(id int32) (bool, error)
	SetLinkForwarding(id int32, enable bool) error
}

// linkForwarding is conf/<link>/forwarding.
//
// +stateify savable
type linkForwarding struct {
	kernfs.DynamicBytesFile

	stack inet.Stack
	// id is the index of the link. Immutable.
	id int32
}

var _ vfs.WritableDynamicBytesSource = (*linkForwarding)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *linkForwarding) Generate(_ context.Context, buf *bytes.Buffer) error {
	s, ok := f.stack.(linkForwardingStack)
	if !ok {
		return linuxerr.EOPNOTSUPP
	}
	on, err := s.LinkForwarding(f.id)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "%d\n", boolToInt32(on))
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *linkForwarding) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	s, ok := f.stack.(linkForwardingStack)
	if !ok {
		return 0, linuxerr.EOPNOTSUPP
	}
	v := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, v)
	if err != nil || n == 0 {
		return 0, err
	}
	if err := s.SetLinkForwarding(f.id, v[0] != 0); err != nil {
		return 0, err
	}
	return n, nil
}

// addLinkConfValueFiles adds the integer files and the forwarding switch of
// conf/<link>.
func (fs *filesystem) addLinkConfValueFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, id int32, files map[string]kernfs.Inode) {
	files["forwarding"] = fs.newInode(ctx, root, 0644, &linkForwarding{stack: stack, id: id})
	for _, c := range ipv4ConfInts {
		files[c.name] = fs.newInode(ctx, root, 0644, &linkConfFile{stack: stack, id: id, dir: netstack.ConfDirIPv4, conf: c})
	}
}

// linkNeighFiles returns the files of neigh/<link>.
func (fs *filesystem) linkNeighFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, id int32) map[string]kernfs.Inode {
	files := make(map[string]kernfs.Inode, len(ipv4NeighInts))
	for _, c := range ipv4NeighInts {
		files[c.name] = fs.newInode(ctx, root, 0644, &linkConfFile{stack: stack, id: id, dir: netstack.NeighDirIPv4, conf: c})
	}
	return files
}
