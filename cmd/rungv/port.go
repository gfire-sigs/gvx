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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "port",
		summary: "Manage published host-to-guest ports of a running sandbox (ls, add, rm).",
		usage:   []string{"rungv port <ls|add|rm> -S <socket>|-n <name> [flags] [args...]"},
		run:     portGroupSubcommand,
	})
	register(command{
		name:    "port-forward",
		aliases: []string{"pf"},
		summary: "Forward local TCP or Unix sockets into a sandbox over its control socket (alias: pf).",
		usage:   []string{"rungv port-forward -S <socket>|-n <name> [--address 127.0.0.1] [--guest-ip IP] SPEC [SPEC...]"},
		run:     portForwardSubcommand,
	})
}

func portGroupSubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		w := streams.stdout
		code := 0
		if len(args) == 0 {
			w = streams.stderr
			code = 2
		}
		_, _ = fmt.Fprintln(w, "Usage: rungv port <ls|add|rm> -S <socket>|-n <name> [flags] [args...]")
		return code
	}
	switch args[0] {
	case "ls", "list":
		return portListSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	case "add":
		return portAddSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	case "rm", "remove":
		return portRemoveSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	default:
		return controlUsageError(streams.stderr, "port", "unknown subcommand %q (want ls, add, or rm)", args[0])
	}
}

func formatPortHostEndpoint(p control.PortRuleInfo) string {
	if p.HostSocket != "" {
		return "unix:" + p.HostSocket
	}
	return net.JoinHostPort(p.HostIP, strconv.Itoa(int(p.HostPort)))
}

func portListSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "port ls"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var quiet bool
	var format string
	registerAlias([]string{"q", "quiet"}, func(n string) {
		fs.BoolVar(&quiet, n, false, "Print only bound host endpoints")
	})
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var resp control.PortListResponse
	if err := client.Call(callCtx, control.MethodPortList, nil, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	if quiet {
		for _, p := range resp.Ports {
			_, _ = fmt.Fprintln(stdout, formatPortHostEndpoint(p))
		}
		return 0
	}
	usageErr, writeErr := renderListFormat(stdout, format, resp.Ports, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 8, 1, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "PROTO\tHOST\tGUEST\tSOURCE")
		for _, p := range resp.Ports {
			guest := net.JoinHostPort(p.GuestIP, strconv.Itoa(int(p.GuestPort)))
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Proto, formatPortHostEndpoint(p), guest, p.Source)
		}
		return tw.Flush()
	})
	if usageErr != nil {
		return controlUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return controlFail(stderr, cmdName, writeErr)
	}
	return 0
}

func portAddSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "port add"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	replace := fs.Bool("replace", false, "Replace an existing dynamic or auto port rule on the same host endpoint")
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format newly bound rules using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return controlUsageError(stderr, cmdName, "specify at least one port spec ([IP:][HOST:]GUEST[/tcp|udp])")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var resp control.PortAddResponse
	if err := client.Call(callCtx, control.MethodPortAdd, control.PortAddRequest{
		Specs:   fs.Args(),
		Replace: *replace,
	}, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	usageErr, writeErr := renderListFormat(stdout, format, resp.Ports, func(w io.Writer) error {
		for _, p := range resp.Ports {
			_, _ = fmt.Fprintf(w, "%s -> %d/%s (%s)\n", formatPortHostEndpoint(p), p.GuestPort, p.Proto, p.Source)
		}
		return nil
	})
	if usageErr != nil {
		return controlUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return controlFail(stderr, cmdName, writeErr)
	}
	return 0
}

func portRemoveSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "port rm"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	allDynamic := fs.Bool("all-dynamic", false, "Remove all dynamically added port rules")
	var force bool
	registerAlias([]string{"f", "force"}, func(n string) {
		fs.BoolVar(&force, n, false, "Do not fail if a specified rule is not currently bound")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if !*allDynamic && fs.NArg() == 0 {
		return controlUsageError(stderr, cmdName, "specify port specs or --all-dynamic")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var resp control.PortRemoveResponse
	if err := client.Call(callCtx, control.MethodPortRemove, control.PortRemoveRequest{
		Specs:      fs.Args(),
		AllDynamic: *allDynamic,
		Force:      force,
	}, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	for _, p := range resp.Removed {
		_, _ = fmt.Fprintf(stdout, "removed %s -> %d/%s\n", formatPortHostEndpoint(p), p.GuestPort, p.Proto)
	}
	return 0
}

type tunnelSpec struct {
	network    string
	listenAddr string
	guestIP    string
	guestPort  uint16
}

func parseTunnelSpec(spec, defaultBindIP, defaultGuestIP string) (tunnelSpec, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return tunnelSpec{}, errors.New("empty port-forward specification")
	}
	if strings.HasPrefix(s, "unix:") {
		rest := strings.TrimPrefix(s, "unix:")
		idx := strings.LastIndexByte(rest, ':')
		if idx <= 0 || idx == len(rest)-1 {
			return tunnelSpec{}, fmt.Errorf("invalid unix port-forward %q (want unix:/path:GUEST_PORT)", spec)
		}
		gp, err := parsePortNumber(rest[idx+1:])
		if err != nil {
			return tunnelSpec{}, err
		}
		return tunnelSpec{
			network:    "unix",
			listenAddr: rest[:idx],
			guestIP:    defaultGuestIP,
			guestPort:  gp,
		}, nil
	}

	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		gp, err := parsePortNumber(parts[0])
		if err != nil {
			return tunnelSpec{}, err
		}
		return tunnelSpec{
			network:    "tcp",
			listenAddr: net.JoinHostPort(defaultBindIP, strconv.Itoa(int(gp))),
			guestIP:    defaultGuestIP,
			guestPort:  gp,
		}, nil
	case 2:
		hp, err := parseListenPortNumber(parts[0])
		if err != nil {
			return tunnelSpec{}, err
		}
		gp, err := parsePortNumber(parts[1])
		if err != nil {
			return tunnelSpec{}, err
		}
		return tunnelSpec{
			network:    "tcp",
			listenAddr: net.JoinHostPort(defaultBindIP, strconv.Itoa(int(hp))),
			guestIP:    defaultGuestIP,
			guestPort:  gp,
		}, nil
	case 3:
		// Either HOST_IP:HOST_PORT:GUEST_PORT or HOST_PORT:GUEST_IP:GUEST_PORT.
		if net.ParseIP(parts[1]) != nil {
			hp, err := parseListenPortNumber(parts[0])
			if err != nil {
				return tunnelSpec{}, err
			}
			gp, err := parsePortNumber(parts[2])
			if err != nil {
				return tunnelSpec{}, err
			}
			return tunnelSpec{
				network:    "tcp",
				listenAddr: net.JoinHostPort(defaultBindIP, strconv.Itoa(int(hp))),
				guestIP:    parts[1],
				guestPort:  gp,
			}, nil
		}
		hp, err := parseListenPortNumber(parts[1])
		if err != nil {
			return tunnelSpec{}, err
		}
		gp, err := parsePortNumber(parts[2])
		if err != nil {
			return tunnelSpec{}, err
		}
		return tunnelSpec{
			network:    "tcp",
			listenAddr: net.JoinHostPort(parts[0], strconv.Itoa(int(hp))),
			guestIP:    defaultGuestIP,
			guestPort:  gp,
		}, nil
	case 4:
		hp, err := parseListenPortNumber(parts[1])
		if err != nil {
			return tunnelSpec{}, err
		}
		gp, err := parsePortNumber(parts[3])
		if err != nil {
			return tunnelSpec{}, err
		}
		return tunnelSpec{
			network:    "tcp",
			listenAddr: net.JoinHostPort(parts[0], strconv.Itoa(int(hp))),
			guestIP:    parts[2],
			guestPort:  gp,
		}, nil
	default:
		return tunnelSpec{}, fmt.Errorf("invalid port-forward spec %q", spec)
	}
}

func parsePortNumber(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid guest port %q", s)
	}
	return uint16(n), nil
}

func parseListenPortNumber(s string) (uint16, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("invalid host port %q", s)
	}
	return uint16(n), nil
}

type boundTunnelInfo struct {
	Listen    string `json:"listen"`
	GuestIP   string `json:"guest_ip,omitempty"`
	GuestPort uint16 `json:"guest_port"`
}

func portForwardSubcommand(ctx context.Context, args []string, streams cliIO) int {
	const cmdName = "port-forward"
	fs := newImageFlagSet(cmdName, streams.stderr)
	target := addControlFlags(fs, 0)
	var bindAddr, guestIP, format string
	registerAlias([]string{"b", "address"}, func(n string) {
		fs.StringVar(&bindAddr, n, "127.0.0.1", "Host listen IP address (e.g. 127.0.0.1 or 0.0.0.0)")
	})
	fs.StringVar(&guestIP, "guest-ip", "", "Target guest IP address (default eth0 with loopback fallback)")
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Print bound endpoints as json or plain text")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return controlUsageError(streams.stderr, cmdName, "specify at least one port-forward SPEC ([HOST:]GUEST)")
	}

	specs := make([]tunnelSpec, 0, fs.NArg())
	for _, raw := range fs.Args() {
		ts, err := parseTunnelSpec(raw, strings.TrimSpace(bindAddr), strings.TrimSpace(guestIP))
		if err != nil {
			return controlUsageError(streams.stderr, cmdName, "%v", err)
		}
		specs = append(specs, ts)
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer client.Close()

	if !client.HasCapability(control.CapNetDial) {
		return controlFail(streams.stderr, cmdName, control.NewError(control.CodeForbiddenByPolicy, "sandbox disabled net.dial capability"))
	}

	type activeListener struct {
		ln   net.Listener
		spec tunnelSpec
	}
	listeners := make([]activeListener, 0, len(specs))
	bound := make([]boundTunnelInfo, 0, len(specs))
	cleanup := func() {
		for _, al := range listeners {
			_ = al.ln.Close()
			if al.spec.network == "unix" {
				_ = os.Remove(al.spec.listenAddr)
			}
		}
	}
	defer cleanup()

	for _, ts := range specs {
		if ts.network == "unix" {
			_ = os.Remove(ts.listenAddr)
		}
		ln, err := net.Listen(ts.network, ts.listenAddr)
		if err != nil {
			return controlFail(streams.stderr, cmdName, fmt.Errorf("listen %s %s: %w", ts.network, ts.listenAddr, err))
		}
		listeners = append(listeners, activeListener{ln: ln, spec: ts})
		addr := ln.Addr().String()
		if ts.network == "unix" {
			addr = "unix:" + ts.listenAddr
		}
		bound = append(bound, boundTunnelInfo{
			Listen:    addr,
			GuestIP:   ts.guestIP,
			GuestPort: ts.guestPort,
		})
	}

	if strings.EqualFold(strings.TrimSpace(format), "json") {
		enc := json.NewEncoder(streams.stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(bound)
	} else {
		for _, b := range bound {
			_, _ = fmt.Fprintf(streams.stdout, "Forwarding %s -> %d/tcp\n", b.Listen, b.GuestPort)
		}
	}

	tunnelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-tunnelCtx.Done()
		for _, al := range listeners {
			_ = al.ln.Close()
		}
	}()

	var wg sync.WaitGroup
	for _, al := range listeners {
		wg.Add(1)
		go func(al activeListener) {
			defer wg.Done()
			for {
				conn, err := al.ln.Accept()
				if err != nil {
					return
				}
				wg.Add(1)
				go func(c net.Conn) {
					defer wg.Done()
					defer c.Close()
					proxyTunnelConn(tunnelCtx, client, c, al.spec, streams.stderr)
				}(conn)
			}
		}(al)
	}
	wg.Wait()
	return 0
}

func proxyTunnelConn(ctx context.Context, client *control.Client, local net.Conn, ts tunnelSpec, stderr io.Writer) {
	stream, err := client.OpenStream(ctx, control.MethodNetDial, control.NetDialRequest{
		Proto:            "tcp",
		GuestIP:          ts.guestIP,
		GuestPort:        ts.guestPort,
		LoopbackFallback: ts.guestIP == "",
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv port-forward: dial guest %d: %v\n", ts.guestPort, err)
		return
	}
	defer stream.Close()

	var resp control.NetDialResponse
	if err := stream.WaitResponse(ctx, &resp); err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv port-forward: dial guest %d: %v\n", ts.guestPort, err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w := stream.ChannelWriter(ctx, control.ChannelGeneric, false)
		_, _ = io.Copy(w, local)
		_ = w.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, stream.ChannelReader(ctx, control.ChannelGeneric))
		if tc, ok := local.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}
