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

// Command lockdownprobe starts a gvx sandbox, then tries to escape the host
// lockdown from inside the Go process. The e2e suite runs it as a child
// process because the lockdown is irreversible. The probe prints one JSON
// lockdownprobe.Report to stdout.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// wgRemote is the guest-side UDP destination that the WireGuard probe uses.
var wgRemote = netip.MustParseAddrPort(lockdownprobe.WireGuardRemote)

// wgWait bounds the handshake and the reply of the WireGuard probe.
const wgWait = 30 * time.Second

// childEnv makes the probe exit at once when it runs as the spawn target.
const childEnv = "GVX_LOCKDOWNPROBE_CHILD"

func main() {
	if os.Getenv(childEnv) != "" {
		return
	}
	worker := len(os.Args) > 1 && os.Args[1] == "worker"
	if worker {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	os.Exit(run(worker))
}

func run(worker bool) int {
	lockdown := flag.Bool("lockdown", true, "keep the default host lockdown")
	binPath := flag.String("bin", "", "guest ELF64 path")
	image := flag.String("image", "", "OCI image reference; the arguments after the flags become the guest command")
	workspace := flag.String("workspace", "", "workspace directory")
	cacheDir := flag.String("cache-dir", "", "layer cache directory")
	outsideFile := flag.String("outside-file", "", "existing host file outside the workspace")
	outsideDir := flag.String("outside-dir", "", "host directory outside the workspace")
	platformName := flag.String("platform", string(gvx.PlatformAuto), "execution backend: auto, hvf, whpx, or systrap")
	netMode := flag.String("net", string(gvx.NetModeNone), "network mode: none, nat, or wg")
	dialTarget := flag.String("dial-target", "", "host TCP address to dial after the lockdown")
	wgPrivate := flag.String("wg-private", "", "hex WireGuard private key of the guest")
	wgPeerPublic := flag.String("wg-peer-public", "", "hex WireGuard public key of the peer")
	wgEndpoint := flag.String("wg-endpoint", "", "WireGuard peer host:port")
	flag.Parse()

	cfg := gvx.Config{
		Platform:            gvx.PlatformType(*platformName),
		NetworkMode:         gvx.NetworkMode(*netMode),
		BinaryPath:          *binPath,
		OCIImage:            *image,
		Argv:                flag.Args(),
		WorkspacePath:       *workspace,
		OCICacheDir:         *cacheDir,
		DisableHostLockdown: !*lockdown,
	}
	var rep lockdownprobe.Report
	if cfg.NetworkMode == gvx.NetModeWireGuard {
		wgCfg, err := wireGuardConfig(*wgPrivate, *wgPeerPublic, *wgEndpoint)
		if err != nil {
			rep.NewErr = err.Error()
			return emit(rep, 1)
		}
		cfg.WireGuardConfig = &wgCfg
	}

	var guestOut bytes.Buffer
	cfg.Stdout = &guestOut
	cfg.Stderr = os.Stderr
	inspect := func(sb *gvx.Sandbox) lockdownprobe.Report {
		return inspectHost(sb, cfg, *outsideFile, *outsideDir, *dialTarget)
	}
	if worker {
		err := gvx.ServeProcess(context.Background(), gvx.WorkerOptions{AfterLockdown: func(_ context.Context, sb *gvx.Sandbox) error { return json.NewEncoder(os.Stdout).Encode(inspect(sb)) }})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if runtime.GOOS == "windows" && !cfg.DisableHostLockdown {
		executable, err := os.Executable()
		if err != nil {
			rep.NewErr = err.Error()
			return emit(rep, 1)
		}
		command := gvx.WorkerCommand{Executable: executable, Arguments: append([]string{"worker"}, os.Args[1:]...)}
		process, err := gvx.NewProcess(context.Background(), command, cfg)
		if err != nil {
			rep.NewErr = err.Error()
			return emit(rep, 1)
		}
		code, runErr := process.Run(context.Background())
		runErr = errors.Join(runErr, process.Close())
		decoder := json.NewDecoder(bytes.NewReader(guestOut.Bytes()))
		if err := decoder.Decode(&rep); err != nil {
			rep.NewErr = fmt.Sprintf("decode worker probes: %v", err)
			return emit(rep, 1)
		}
		output := guestOut.Bytes()[decoder.InputOffset():]
		output = bytes.TrimPrefix(output, []byte{'\n'})
		rep.GuestStdout = string(output)
		rep.GuestExitCode = code
		if runErr != nil {
			rep.GuestRunErr = runErr.Error()
		}
		return emit(rep, 0)
	}
	sb, err := gvx.New(context.Background(), cfg)
	if err != nil {
		rep.NewErr = err.Error()
		return emit(rep, 1)
	}
	defer func() {
		_ = sb.Close()
	}()
	rep = inspect(sb)
	code, err := sb.Run(context.Background())
	rep.GuestExitCode = code
	rep.GuestStdout = guestOut.String()
	if err != nil {
		rep.GuestRunErr = err.Error()
	}
	return emit(rep, 0)
}

func inspectHost(sb *gvx.Sandbox, cfg gvx.Config, outsideFile, outsideDir, dialTarget string) lockdownprobe.Report {
	rep := lockdownprobe.Report{Platform: sb.PlatformName(), Lockdown: sb.LockdownStatus(), LockedAPI: hostlockdown.IsLockedDown()}

	data, err := os.ReadFile(outsideFile)
	if err != nil {
		rep.ReadOutsideErr = err.Error()
	} else {
		rep.OutsideReadBytes = string(data)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "escape.txt"), []byte("escaped"), 0o600); err != nil {
		rep.WriteOutsideErr = err.Error()
	}
	spawn := exec.Command(os.Args[0])
	spawn.Env = append(os.Environ(), childEnv+"=1")
	if err := spawn.Run(); err != nil {
		rep.SpawnErr = err.Error()
	}

	if dialTarget != "" {
		rep.DialAttempted = true
		conn, err := dialAfterLockdown(sb, cfg, dialTarget)
		if err != nil {
			rep.DialErr = err.Error()
		} else if err := conn.Close(); err != nil {
			rep.DialErr = err.Error()
		}
	}
	if cfg.NetworkMode == gvx.NetModeWireGuard {
		rep.WireGuardErr = exchangeOverWireGuard(sb)
	}

	return rep
}

func dialAfterLockdown(sb *gvx.Sandbox, cfg gvx.Config, address string) (net.Conn, error) {
	if cfg.NetworkMode != gvx.NetModeNAT {
		return net.DialTimeout("tcp", address, 5*time.Second)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	if ip.IsLoopback() {
		ip = netip.MustParseAddr(netbackend.HostGatewayIPv4)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, sb.Stack(), tcpip.FullAddress{NIC: netbackend.Eth0NICID, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: uint16(number)}, ipv4.ProtocolNumber)
}

func emit(rep lockdownprobe.Report, code int) int {
	if err := json.NewEncoder(os.Stdout).Encode(rep); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "lockdownprobe: write report: %v\n", err)
		return 3
	}
	return code
}

func wireGuardConfig(privHex, peerPubHex, endpoint string) (netbackend.WireGuardConfig, error) {
	var cfg netbackend.WireGuardConfig
	for _, k := range []struct {
		hexKey string
		dst    *[32]byte
	}{{privHex, &cfg.PrivateKey}, {peerPubHex, &cfg.PeerPublicKey}} {
		raw, err := hex.DecodeString(k.hexKey)
		if err != nil || len(raw) != len(k.dst) {
			return cfg, fmt.Errorf("WireGuard key %q must be 64 hex digits", k.hexKey)
		}
		copy(k.dst[:], raw)
	}
	cfg.PeerEndpoint = endpoint
	cfg.GuestIPv4 = netip.MustParsePrefix("10.0.2.15/24")
	cfg.MTU = netbackend.DefaultWireGuardMTU
	return cfg, nil
}

// exchangeOverWireGuard sends one UDP datagram through the guest Netstack and
// waits for one reply. The handshake and both datagrams use the single UDP
// socket that gvx pre-bound before the lockdown. It returns an empty string on
// success.
func exchangeOverWireGuard(sb *gvx.Sandbox) string {
	conn, err := gonet.DialUDP(sb.Stack(), nil, &tcpip.FullAddress{
		NIC:  netbackend.Eth0NICID,
		Addr: tcpip.AddrFrom4(wgRemote.Addr().As4()),
		Port: wgRemote.Port(),
	}, ipv4.ProtocolNumber)
	if err != nil {
		return fmt.Sprintf("dial over WireGuard stack: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	if _, err := conn.Write([]byte(lockdownprobe.WireGuardPayload)); err != nil {
		return fmt.Sprintf("write over WireGuard stack: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wgWait)); err != nil {
		return fmt.Sprintf("set read deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Sprintf("read reply over WireGuard stack: %v", err)
	}
	if got := string(buf[:n]); got != lockdownprobe.WireGuardReply {
		return fmt.Sprintf("reply = %q, want %q", got, lockdownprobe.WireGuardReply)
	}
	return ""
}
