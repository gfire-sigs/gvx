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

package wireguard

import (
	stdcontext "context"
	"errors"
	"sync"
	"weak"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// birthplaces lists the live links by the network stack that created them. The
// sockets of a link belong to that stack, also when the link moves to another
// network namespace. The end of the stack closes the sockets of every link that
// it created, as wg_netns_exit_rtnl does, and the links that moved away keep
// their configuration.
var birthplaces struct {
	sync.Mutex
	links map[*stack.Stack]map[*linkEndpoint]struct{}
}

// register records e as a link that its birthplace stack created.
func (e *linkEndpoint) register() {
	if e.bind == nil || e.bind.stack == nil {
		return
	}
	birthplaces.Lock()
	defer birthplaces.Unlock()
	if birthplaces.links == nil {
		birthplaces.links = make(map[*stack.Stack]map[*linkEndpoint]struct{})
	}
	set := birthplaces.links[e.bind.stack]
	if set == nil {
		set = make(map[*linkEndpoint]struct{})
		birthplaces.links[e.bind.stack] = set
	}
	set[e] = struct{}{}
}

// unregister removes e from the links of its birthplace.
func (e *linkEndpoint) unregister() {
	if e.bind == nil || e.bind.stack == nil {
		return
	}
	birthplaces.Lock()
	defer birthplaces.Unlock()
	set := birthplaces.links[e.bind.stack]
	delete(set, e)
	if len(set) == 0 {
		delete(birthplaces.links, e.bind.stack)
	}
}

// stackEnded closes the sockets of every link that stk created and that still
// exists. It runs after the stack removed its own links, so only the links that
// moved to another namespace remain.
func stackEnded(stk *stack.Stack) {
	birthplaces.Lock()
	links := make([]*linkEndpoint, 0, len(birthplaces.links[stk]))
	for e := range birthplaces.links[stk] {
		links = append(links, e)
	}
	birthplaces.Unlock()
	for _, e := range links {
		e.bind.birthplaceEnded()
	}
}

// linkEndpoint is the link endpoint of a wireguard link in the stack. Packets
// that the stack routes to the link wait in the channel queue, and the tun
// adapter hands them to wireguard-go. Closing the endpoint closes the device.
//
// The link starts down and owns no socket. LinkUp opens the UDP endpoints on
// the stored port, and LinkDown closes them, as wg_open and wg_stop do.
//
// +stateify savable
type linkEndpoint struct {
	*channel.Endpoint
	name string
	tun  *tunDevice `state:"nosave"`

	bind *netBind
	// userNS is the user namespace of the network namespace that created the
	// link. A request that changes the socket needs CAP_NET_ADMIN in it.
	userNS *auth.UserNamespace

	// updateMu serializes the requests that change the device and the changes
	// of the link state, as device_update_lock does in Linux. It protects the
	// fields below.
	updateMu sync.Mutex `state:"nosave"`
	// up is true between LinkUp and LinkDown. It is netif_running.
	up bool
	// closed is true after Close. A request that finds it answers ENODEV,
	// because a closed device must not charge memory or open a socket again.
	closed bool
	// fwmark is the mark of the sockets, as WGDEVICE_A_FWMARK reports it.
	fwmark uint32
	// hasKey and public describe the static identity of the device.
	hasKey bool
	public [keyLen]byte
	// peers lists the peers of the device in the order of their creation.
	peers peerSet
	// savedConfig holds static device and peer configuration captured at
	// beforeSave with ephemeral session keys wiped.
	savedConfig *deviceInfo
	// acct is the memory accounting of the kernel that created the link, and
	// charged is the memory that the device and its peers hold against it.
	acct    *usage.MemoryLocked `state:"nosave"`
	charged uint64

	closeOnce sync.Once `state:"nosave"`
	suspended bool      `state:"nosave"`
	hookID    uint64    `state:"nosave"`
	// dev is set before the stack sees the endpoint.
	dev *device.Device `state:"nosave"`
}

var (
	_ stack.LinkEndpoint         = (*linkEndpoint)(nil)
	_ stack.RestoredEndpoint     = (*linkEndpoint)(nil)
	_ netstack.LinkStateListener = (*linkEndpoint)(nil)
)

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.Endpoint.Capabilities() | stack.CapabilitySaveRestore
}

// PreserveAcrossSaveRestore marks WireGuard NICs for virtual NIC preservation
// on Stack checkpoint and restore.
func (*linkEndpoint) PreserveAcrossSaveRestore() bool { return true }

// SetMTU implements stack.LinkEndpoint.SetMTU. It tells wireguard-go about
// the new MTU, which sets the padding limit of the encrypted packets.
func (e *linkEndpoint) SetMTU(mtu uint32) {
	e.Endpoint.SetMTU(mtu)
	e.updateMu.Lock()
	tun := e.tun
	e.updateMu.Unlock()
	if tun != nil {
		tun.notifyMTU()
	}
}

// Close implements stack.LinkEndpoint.Close. It stops every goroutine of the
// device and closes its UDP endpoints before it returns.
func (e *linkEndpoint) Close() {
	e.closeOnce.Do(func() {
		if e.bind != nil && e.bind.stack != nil && e.hookID != 0 {
			e.bind.stack.UnregisterLifecycleHooks(e.hookID)
			e.hookID = 0
		}
		e.Endpoint.Close()
		e.updateMu.Lock()
		dev := e.dev
		e.closed = true
		e.releaseMemory()
		e.updateMu.Unlock()
		if dev != nil {
			dev.Close()
		}
		e.unregister()
	})
}

func (e *linkEndpoint) ensureDeviceLocked() {
	if e.closed || e.dev != nil {
		return
	}
	e.tun = newTUN(e.Endpoint, e.name)
	e.dev = device.NewDevice(e.tun, e.bind, newLogger(e.name))
	if e.savedConfig != nil {
		_ = e.dev.IpcSet(formatIpcSet(e.savedConfig))
	}
}

// LinkUp implements netstack.LinkStateListener. It opens the UDP endpoints of
// the device on the stored port, and a stored port of 0 becomes the port that
// the stack picks. It starts the peers and sends the keepalives. A failure
// leaves the device down, as a failed wg_open leaves the link down.
func (e *linkEndpoint) LinkUp() tcpip.Error {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.closed {
		return &tcpip.ErrUnknownDevice{}
	}
	if e.up {
		return nil
	}
	e.ensureDeviceLocked()
	if err := e.dev.Up(); err != nil {
		return bindTCPIPError(err)
	}
	e.up = true
	return nil
}

// LinkDown implements netstack.LinkStateListener. It closes the UDP endpoints
// and stops the peers. The device keeps its configuration, and also the port
// that LinkUp picked.
func (e *linkEndpoint) LinkDown() {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if !e.up {
		return
	}
	if e.dev != nil {
		e.dev.Down()
	}
	e.up = false
}

func (e *linkEndpoint) registerHooks() {
	if e.bind == nil || e.bind.stack == nil || e.hookID != 0 {
		return
	}
	we := weak.Make(e)
	e.hookID = e.bind.stack.RegisterLifecycleHooks(
		func() {
			if ep := we.Value(); ep != nil {
				ep.suspendForSave()
			}
		},
		func() {
			if ep := we.Value(); ep != nil {
				ep.resumeAfterSave()
			}
		},
	)
}

// suspendForSave captures static device and peer configuration and wipes all
// ephemeral Noise session keys, handshake state, and open UDP sockets on e.dev.
func (e *linkEndpoint) suspendForSave() {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.closed || e.suspended || e.dev == nil {
		return
	}
	if text, err := e.dev.IpcGet(); err == nil {
		if info, err := parseIpcGet(text); err == nil {
			e.peers.sortPeers(info.peers)
			for i := range info.peers {
				info.peers[i].handshakeSec = 0
				info.peers[i].handshakeNsec = 0
				info.peers[i].rxBytes = 0
				info.peers[i].txBytes = 0
			}
			info.listenPort = e.bind.incomingPort()
			info.fwmark = e.fwmark
			e.savedConfig = info
		}
	}
	_ = e.dev.Down()
	e.bind.closePending()
	e.dev.RemoveAllPeers()
	_ = e.dev.SetPrivateKey(device.NoisePrivateKey{})
	e.suspended = true
}

func (e *linkEndpoint) resumeAfterSave() {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.closed || !e.suspended || e.dev == nil {
		return
	}
	if e.savedConfig != nil {
		_ = e.dev.IpcSet(formatIpcSet(e.savedConfig))
	}
	e.suspended = false
	if e.up && !e.bind.gone {
		_ = e.dev.Up()
	}
}

func (e *linkEndpoint) beforeSave() {
	e.suspendForSave()
}

func (e *linkEndpoint) afterLoad(ctx stdcontext.Context) {
	if e.peers.seq == nil {
		e.peers.init()
	}
	if e.closed {
		return
	}
	if gctx, ok := ctx.(context.Context); ok {
		e.acct = accountingOf(gctx)
	} else {
		e.acct = usage.MemoryAccounting
	}
	if e.charged > 0 {
		if err := chargeMemory(e.acct, e.charged); err != nil {
			e.charged = 0
		}
	}
	e.register()
	e.registerHooks()
	if e.bind != nil && e.bind.stack != nil {
		e.bind.stack.RegisterRestoredEndpoint(e)
	}
}

func (e *linkEndpoint) bringUpRestored() {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.closed {
		return
	}
	e.ensureDeviceLocked()
	if !e.up || e.dev == nil || e.bind == nil || e.bind.gone {
		return
	}
	_ = e.dev.Up()
}

// Restore implements stack.RestoredEndpoint.
func (e *linkEndpoint) Restore(_ *stack.Stack) {
	e.bringUpRestored()
}

// newLink creates the link endpoint and the wireguard-go device of a new
// "wireguard" link. The link starts down, so the device owns no UDP port until
// the link goes up. The memory of the device counts against the memory
// accounting of the sandbox, and a device that does not fit fails with ENOMEM.
func newLink(ctx context.Context, req *netstack.NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
	acct := accountingOf(ctx)
	charged := deviceBytes()
	if err := chargeMemory(acct, charged); err != nil {
		return nil, err
	}
	ch := channel.New(queueSize, defaultMTU, "")
	tunDev := newTUN(ch, req.Name)
	bind := newBind(req.Stack.Stack)
	ep := &linkEndpoint{
		Endpoint: ch,
		name:     req.Name,
		tun:      tunDev,
		bind:     bind,
		userNS:   req.UserNS,
		acct:     acct,
		charged:  charged,
	}
	ep.peers.init()
	ep.dev = device.NewDevice(tunDev, bind, newLogger(req.Name))
	ep.register()
	ep.registerHooks()
	return ep, nil
}

// bindSyserr returns the errno of an error from wireguard-go. An error of the
// UDP bind keeps its own errno.
func bindSyserr(err error) *syserr.Error {
	var be *bindError
	if errors.As(err, &be) {
		return be.err
	}
	var ie *device.IPCError
	if errors.As(err, &ie) {
		switch ie.ErrorCode() {
		case ipc.IpcErrorPortInUse:
			return syserr.ErrPortInUse
		case ipc.IpcErrorIO:
			return syserr.ErrIO
		}
	}
	return syserr.ErrInvalidArgument
}

// bindTCPIPError returns the error of the stack for an error from wireguard-go.
func bindTCPIPError(err error) tcpip.Error {
	var be *bindError
	if errors.As(err, &be) && be.terr != nil {
		return be.terr
	}
	return &tcpip.ErrInvalidOptionValue{}
}
