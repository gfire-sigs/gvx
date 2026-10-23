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

package gvx

import (
	"bytes"
	"fmt"
	"strings"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// maxGuestIdentityFile bounds the passwd and group files that the sandbox reads.
const maxGuestIdentityFile = 1 << 20

// guestUser resolves the user of the guest process. The specification is
// Config.User, then the User of the image, then root. It reads /etc/passwd and
// /etc/group of the guest root. It returns the credentials of the process, which
// are the root credentials of the kernel when the user is root with group 0.
func (s *Sandbox) guestUser(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, root *auth.Credentials, rootDentry vfs.VirtualDentry) (execUser, *auth.Credentials, error) {
	spec := s.cfg.User
	if spec == "" && s.resolvedImg != nil {
		spec = s.resolvedImg.Config.User
	}
	passwd, err := readGuestFile(sctx, vfsObj, root, rootDentry, "/etc/passwd", maxGuestIdentityFile)
	if err != nil {
		return execUser{}, nil, err
	}
	group, err := readGuestFile(sctx, vfsObj, root, rootDentry, "/etc/group", maxGuestIdentityFile)
	if err != nil {
		return execUser{}, nil, err
	}
	user, err := resolveExecUser(spec, passwd, group)
	if err != nil {
		return execUser{}, nil, fmt.Errorf("gvx: resolve user %q: %w", spec, err)
	}
	if user.UID == 0 && user.GID == 0 && len(user.ExtraGIDs) == 0 {
		return user, root, nil
	}
	extra := make([]auth.KGID, len(user.ExtraGIDs))
	for i, g := range user.ExtraGIDs {
		extra[i] = auth.KGID(g)
	}
	return user, auth.NewUserCredentials(auth.KUID(user.UID), auth.KGID(user.GID), extra, nil, root.UserNamespace), nil
}

// writeGuestHostFiles makes /etc/hostname and /etc/hosts agree with the
// hostname of the guest, so that the guest resolves its own name. It runs
// before the root becomes read-only.
func (s *Sandbox) writeGuestHostFiles(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) error {
	hostname := s.hostname()
	if err := vfsWriteFile(sctx, vfsObj, creds, root, "/etc/hostname", []byte(hostname+"\n"), 0o644); err != nil {
		return fmt.Errorf("gvx: write /etc/hostname: %w", err)
	}
	hosts, err := readGuestFile(sctx, vfsObj, creds, root, "/etc/hosts", maxGuestIdentityFile)
	if err != nil {
		return err
	}
	updated := hostsWithEntries(hosts, hostname)
	if bytes.Equal(updated, hosts) {
		return nil
	}
	if err := vfsWriteFile(sctx, vfsObj, creds, root, "/etc/hosts", updated, 0o644); err != nil {
		return fmt.Errorf("gvx: write /etc/hosts: %w", err)
	}
	return nil
}

// hostname returns the hostname of the guest.
func (s *Sandbox) hostname() string {
	if s.cfg.Hostname != "" {
		return s.cfg.Hostname
	}
	return defaultHostname
}

// hostsWithEntries returns hosts with a line for the guest hostname and a line
// for host.docker.internal, unless a line already names them. It keeps every
// existing line. Names compare case-insensitively, as the resolver does.
func hostsWithEntries(hosts []byte, hostname string) []byte {
	named := map[string]bool{}
	for _, line := range strings.Split(string(hosts), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		for _, name := range fields[min(1, len(fields)):] {
			named[strings.ToLower(name)] = true
		}
	}
	out := string(hosts)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if !named[strings.ToLower(hostname)] {
		out += netbackend.DefaultGuestIPv4 + "\t" + hostname + "\n"
	}
	if !named["host.docker.internal"] {
		out += netbackend.HostGatewayIPv4 + "\thost.docker.internal\n"
	}
	return []byte(out)
}
