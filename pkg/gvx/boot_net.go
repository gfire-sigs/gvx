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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"weak"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// initKernelRootNetworkNamespace wraps the Sandbox network stack in a Sentry
// root network namespace and returns a cleanup callback for the netfilter log.
func (s *Sandbox) initKernelRootNetworkNamespace(k *kernel.Kernel, creds *auth.Credentials) (*inet.Namespace, func()) {
	if s.netStack == nil {
		return nil, func() {}
	}
	inetStack := netstack.NewStack(s.netStack, k.UniqueID())
	// The root network namespace is the network namespace of the container,
	// where Docker and containerd set ip_unprivileged_port_start to 0. A
	// namespace that the guest creates starts at 1024, as on Linux.
	inetStack.SetUnprivilegedPortStart(0)
	// Linux logs the LOG target of iptables only in the initial network
	// namespace, which is the root namespace of the guest.
	netfilter.SetStackLog(inetStack.Stack, kernelLogFunc(k))
	cleanup := func() {
		netfilter.SetStackLog(inetStack.Stack, nil)
	}
	inetStack.InitConntrackLimit(nil)
	rootNetNS := inet.NewRootNamespace(inetStack, newGuestNetnsCreator(k, s.stackOptions()), creds.UserNamespace)
	return rootNetNS, cleanup
}

// populateDefaultEtcFiles creates default /etc/passwd, /etc/group, /etc/hosts,
// and /etc/resolv.conf files when the guest rootfs does not already provide them.
func populateDefaultEtcFiles(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) error {
	for _, f := range []struct {
		path string
		data string
	}{
		{"/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n"},
		{"/etc/group", "root:x:0:root\nnogroup:x:65534:\n"},
		{"/etc/hosts", "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + netbackend.HostGatewayIPv4 + "\thost.docker.internal\n" + netbackend.DefaultGuestIPv4 + "\tgvx\n"},
		{"/etc/resolv.conf", "nameserver " + netbackend.HostDNSIPv4 + "\n"},
	} {
		if err := ensureGuestFileIfAbsent(sctx, vfsObj, creds, root, f.path, []byte(f.data), 0o644); err != nil {
			return fmt.Errorf("gvx: create guest file %s: %w", f.path, err)
		}
	}
	return nil
}

// initNATStack initializes the L4 NAT network stack and pre-binds any
// configured host port forwarders before lockdown.
func (s *Sandbox) initNATStack() error {
	natCfg := netbackend.NATConfig{
		IsolateLAN:        s.cfg.IsolateLAN,
		DNSServers:        s.cfg.HostDNSServers,
		StreamInterceptor: s.cfg.StreamInterceptor,
		Stack:             s.stackOptions(),
		Tuning:            s.cfg.Tuning,
	}
	if !s.cfg.DisableHostLockdown {
		dialTimeout := s.cfg.Tuning.Duration(tuning.NATDialTimeout)
		natCfg.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			return hostlockdown.DialContext(dctx, network, addr)
		}
	}
	st, fwd, err := netbackend.NewNATStack(natCfg)
	if err != nil {
		return err
	}
	s.netStack = st
	s.natForwarder = fwd
	return s.initPortForwarder()
}

// initPortForwarder pre-binds host listeners for all configured port forwards.
func (s *Sandbox) initPortForwarder() error {
	s.forwards = s.effectivePortForwards()
	if len(s.forwards) == 0 {
		return nil
	}
	pf := netbackend.NewPortForwarder(s.cfg.Tuning)
	if !s.cfg.DisableHostLockdown {
		pf.SetAccept(hostlockdown.AcceptListener)
	}
	rules := make([]netbackend.PortForwardRule, 0, len(s.forwards))
	for _, pfSpec := range s.forwards {
		rule, err := buildPortForwardRule(pfSpec)
		if err != nil {
			_ = pf.Close()
			return err
		}
		rules = append(rules, rule)
	}
	if err := pf.PreBind(rules); err != nil {
		_ = pf.Close()
		return err
	}
	s.portForwarder = pf
	return nil
}

func buildPortForwardRule(pfSpec PortForward) (netbackend.PortForwardRule, error) {
	hostIP := pfSpec.BindAddress
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	socket := pfSpec.HostSocket
	if socket != "" {
		if rest, ok := strings.CutPrefix(socket, "~/"); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return netbackend.PortForwardRule{}, fmt.Errorf("gvx: resolve ~ in the published socket %q: %w", socket, err)
			}
			socket = filepath.Join(home, rest)
		}
		abs, err := filepath.Abs(socket)
		if err != nil {
			return netbackend.PortForwardRule{}, fmt.Errorf("gvx: resolve the published socket %q: %w", socket, err)
		}
		socket = abs
	}
	return netbackend.PortForwardRule{
		Proto:      pfSpec.Protocol,
		HostIP:     hostIP,
		HostPort:   pfSpec.HostPort,
		GuestIP:    netbackend.DefaultGuestIPv4,
		GuestPort:  pfSpec.GuestPort,
		HostSocket: socket,
	}, nil
}

// initWireGuardStack initializes the L3 WireGuard tunnel stack and pre-binds
// its UDP socket before lockdown.
func (s *Sandbox) initWireGuardStack() error {
	wgCfg := s.cfg.WireGuardConfig
	if wgCfg == nil {
		rawINI, err := os.ReadFile(s.cfg.WireGuardConfigPath)
		if err != nil {
			return fmt.Errorf("gvx: read WireGuard config %q: %w", s.cfg.WireGuardConfigPath, err)
		}
		parsed, err := netbackend.ParseWireGuardINI(string(rawINI))
		if err != nil {
			return err
		}
		wgCfg = &parsed
	}
	peerPort, err := wireGuardPeerPort(wgCfg.PeerEndpoint)
	if err != nil {
		return err
	}
	if peerPort == 0 && !s.cfg.DisableHostLockdown {
		return fmt.Errorf("%w: network mode %q with host lockdown needs a peer Endpoint to pin the outbound UDP port; set the Endpoint or DisableHostLockdown", ErrInvalidConfig, NetModeWireGuard)
	}
	wgConfig := *wgCfg
	if len(s.cfg.HostDNSServers) > 0 {
		wgConfig.HostDNSServers = s.cfg.HostDNSServers
	}
	wgConfig.Stack = s.stackOptions()
	wgConfig.Tuning = s.cfg.Tuning
	wgEP, err := netbackend.NewWireGuardEndpoint(wgConfig)
	if err != nil {
		return err
	}
	if err := wgEP.PreBindUDP(); err != nil {
		_ = wgEP.Close()
		return err
	}
	st, err := wgEP.Start()
	if err != nil {
		_ = wgEP.Close()
		return err
	}
	s.wgEndpoint = wgEP
	s.wgPeerPort = peerPort
	s.netStack = st
	return nil
}

// kernelLogFunc returns the log function of the LOG rules of the root network
// stack. The function holds the kernel weakly. The registry of the log
// functions is global and the network stack, its key, is reachable from the
// kernel. A strong reference from the registry would keep the kernel and the
// stack alive for the life of the process.
func kernelLogFunc(k *kernel.Kernel) netfilter.LogFunc {
	weakKernel := weak.Make(k)
	return func(level int, line string) {
		if live := weakKernel.Value(); live != nil {
			live.KernelLog().Printk(level, line)
		}
	}
}
