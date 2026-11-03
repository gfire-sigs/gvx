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
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
)

// netfilterTableNames is the content of /proc/net/ip_tables_names and
// /proc/net/ip6_tables_names. The network stack always has the four tables of
// iptables, so each one is loaded, as on a Linux host after the modules
// iptable_filter, iptable_nat, iptable_mangle, and iptable_raw loaded. The
// command iptables-legacy-save lists the tables of this file.
const netfilterTableNames = "filter\nnat\nmangle\nraw\n"

// addNetfilterNameFiles adds the files that list the iptables tables of the
// network namespace to the contents of /proc/net.
func (fs *filesystem) addNetfilterNameFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, contents map[string]kernfs.Inode) {
	contents["ip_tables_names"] = fs.newInode(ctx, root, 0440, newStaticFile(netfilterTableNames))
	if stack.SupportsIPv6() {
		contents["ip6_tables_names"] = fs.newInode(ctx, root, 0440, newStaticFile(netfilterTableNames))
	}
}
