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

package netstack

import (
	"bytes"
	stdcontext "context"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

type savedNamespaceBundle struct {
	RootNS   *inet.Namespace
	ChildNS  *inet.Namespace
	ListenWQ *waiter.Queue
	ListenEP tcpip.Endpoint
}

func (*savedNamespaceBundle) StateTypeName() string {
	return "pkg/sentry/socket/netstack.savedNamespaceBundle"
}

func (*savedNamespaceBundle) StateFields() []string {
	return []string{"RootNS", "ChildNS", "ListenWQ", "ListenEP"}
}

func (b *savedNamespaceBundle) StateSave(sink state.Sink) {
	sink.Save(0, &b.RootNS)
	sink.Save(1, &b.ChildNS)
	sink.Save(2, &b.ListenWQ)
	sink.Save(3, &b.ListenEP)
}

func (b *savedNamespaceBundle) StateLoad(_ stdcontext.Context, src state.Source) {
	src.Load(0, &b.RootNS)
	src.Load(1, &b.ChildNS)
	src.Load(2, &b.ListenWQ)
	src.Load(3, &b.ListenEP)
}

func init() {
	state.RegisterNoHooks((*savedNamespaceBundle)(nil))
}

func newTestRootNetstack(t *testing.T) *Stack {
	t.Helper()
	st, err := NewStackCreator(nil).CreateStack()
	if err != nil {
		t.Fatalf("CreateStack: %v", err)
	}
	return st.(*Stack)
}

func TestRestoreRootStackPreservesChildNetworkNamespace(t *testing.T) {
	ctx := context.Background()
	userNS := auth.NewRootUserNamespace()

	rootStack := newTestRootNetstack(t)
	defer rootStack.Destroy()
	creator := NewStackCreator(rootStack)
	rootNS := inet.NewRootNamespace(rootStack, creator, userNS)
	defer rootNS.Destroy(ctx)

	childNS := rootNS.NewNetworkNamespace(userNS)
	defer childNS.Destroy(ctx)

	if childNS.Stack() == nil || childNS.Stack() == rootNS.Stack() {
		t.Fatalf("before save: childNS.Stack() = %v, want non-nil stack distinct from root %v", childNS.Stack(), rootNS.Stack())
	}

	childStack := childNS.Stack().(*Stack)
	const customNICID = 2
	vethRootEP, vethChildEP := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	defer vethRootEP.Close()
	if err := rootStack.Stack.CreateNICWithOptions(customNICID, newVethNICEndpoint(vethRootEP), stack.NICOptions{
		Name:   "veth0",
		Kind:   "veth",
		MinMTU: ethernetMinMTU,
		MaxMTU: ethernetMaxMTU,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth0): %s", err)
	}
	rootAddr := inet.InterfaceAddr{
		Family:    linux.AF_INET,
		PrefixLen: 24,
		Addr:      []byte{192, 168, 50, 1},
	}
	if err := rootStack.AddInterfaceAddr(ctx, customNICID, rootAddr); err != nil {
		t.Fatalf("AddInterfaceAddr(192.168.50.1/24): %v", err)
	}
	if err := childStack.Stack.CreateNICWithOptions(customNICID, newVethNICEndpoint(vethChildEP), stack.NICOptions{
		Name:   "veth1",
		Kind:   "veth",
		MinMTU: ethernetMinMTU,
		MaxMTU: ethernetMaxMTU,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth1): %s", err)
	}
	childAddr := inet.InterfaceAddr{
		Family:    linux.AF_INET,
		PrefixLen: 24,
		Addr:      []byte{192, 168, 50, 2},
	}
	if err := childStack.AddInterfaceAddr(ctx, customNICID, childAddr); err != nil {
		t.Fatalf("AddInterfaceAddr(192.168.50.2/24): %v", err)
	}

	customRouteMsg := buildRouteNetlinkMessage(t, linux.RTM_NEWROUTE, linux.NLM_F_CREATE|linux.NLM_F_EXCL, linux.RouteMessage{
		Family:   linux.AF_INET,
		DstLen:   16,
		Protocol: linux.RTPROT_STATIC,
		Scope:    linux.RT_SCOPE_UNIVERSE,
		Type:     linux.RTN_UNICAST,
	}, func(m *nlmsg.Message) {
		m.PutAttr(linux.RTA_DST, primitive.AsByteSlice([]byte{10, 99, 0, 0}))
		m.PutAttr(linux.RTA_GATEWAY, primitive.AsByteSlice([]byte{192, 168, 50, 1}))
		oif := primitive.Int32(customNICID)
		m.PutAttr(linux.RTA_OIF, &oif)
	})
	if err := childStack.NewRoute(ctx, customRouteMsg); err != nil {
		t.Fatalf("NewRoute(10.99.0.0/16): %v", err)
	}

	const listenPort = 18080
	var listenWQ waiter.Queue
	listenEP, tcpErr := childStack.Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenWQ)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint(TCP): %s", tcpErr)
	}
	defer listenEP.Close()
	if err := listenEP.Bind(tcpip.FullAddress{
		NIC:  customNICID,
		Addr: tcpip.AddrFrom4([4]byte{192, 168, 50, 2}),
		Port: listenPort,
	}); err != nil {
		t.Fatalf("listenEP.Bind: %s", err)
	}
	if err := listenEP.Listen(16); err != nil {
		t.Fatalf("listenEP.Listen: %s", err)
	}

	orig := savedNamespaceBundle{
		RootNS:   rootNS,
		ChildNS:  childNS,
		ListenWQ: &listenWQ,
		ListenEP: listenEP,
	}

	rootStack.SetRemoveConf(true)
	rootStack.Pause()
	var buf bytes.Buffer
	_, saveErr := state.Save(ctx, &buf, &orig)
	rootStack.Resume()
	if saveErr != nil {
		t.Fatalf("state.Save: %v", saveErr)
	}

	var restored savedNamespaceBundle
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		if restored.ListenEP != nil {
			restored.ListenEP.Close()
		}
		if restored.ChildNS != nil {
			restored.ChildNS.Destroy(ctx)
		}
		if restored.RootNS != nil {
			restored.RootNS.Destroy(ctx)
		}
	}()

	freshRoot := newTestRootNetstack(t)
	defer freshRoot.Destroy()
	restored.RootNS.RestoreRootStack(freshRoot)

	if restored.RootNS.Stack() == nil {
		t.Fatal("after RestoreRootStack: restored.RootNS.Stack() is nil")
	}
	if restored.ChildNS.Stack() == nil {
		t.Fatal("after RestoreRootStack: restored.ChildNS.Stack() is nil")
	}
	if restored.ChildNS.Stack() == restored.RootNS.Stack() {
		t.Fatal("after RestoreRootStack: child namespace shares the root stack")
	}

	rootIfaces := restored.RootNS.Stack().Interfaces()
	if rootIfaces[1].Name != "lo" || rootIfaces[customNICID].Name != "veth0" {
		t.Fatalf("restored root Interfaces() = %+v, want lo on 1 and veth0 on %d", rootIfaces, customNICID)
	}
	ifaces := restored.ChildNS.Stack().Interfaces()
	if ifaces[1].Name != "lo" || ifaces[customNICID].Name != "veth1" {
		t.Fatalf("restored child Interfaces() = %+v, want lo on 1 and veth1 on %d", ifaces, customNICID)
	}

	var sawCustomIP bool
	for _, a := range restored.ChildNS.Stack().InterfaceAddrs()[customNICID] {
		if a.Family == linux.AF_INET && a.PrefixLen == 24 && bytes.Equal(a.Addr, []byte{192, 168, 50, 2}) {
			sawCustomIP = true
			break
		}
	}
	if !sawCustomIP {
		t.Fatalf("restored child InterfaceAddrs()[%d] = %+v, missing 192.168.50.2/24", customNICID, restored.ChildNS.Stack().InterfaceAddrs()[customNICID])
	}

	var sawCustomRoute bool
	for _, rt := range restored.ChildNS.Stack().RouteTable() {
		if bytes.Equal(rt.DstAddr, []byte{10, 99, 0, 0}) && rt.DstLen == 16 && bytes.Equal(rt.GatewayAddr, []byte{192, 168, 50, 1}) && rt.OutputInterface == customNICID {
			sawCustomRoute = true
			break
		}
	}
	if !sawCustomRoute {
		t.Fatalf("restored child RouteTable() = %+v, missing 10.99.0.0/16 via 192.168.50.1 on NIC %d", restored.ChildNS.Stack().RouteTable(), customNICID)
	}

	restoredRootStack := restored.RootNS.Stack().(*Stack)
	var clientWQ waiter.Queue
	clientEP, clientErr := restoredRootStack.Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
	if clientErr != nil {
		t.Fatalf("NewEndpoint(client): %s", clientErr)
	}
	defer clientEP.Close()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	clientWQ.EventRegister(&waitEntry)
	defer clientWQ.EventUnregister(&waitEntry)

	acceptWaitEntry, acceptNotifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	restored.ListenWQ.EventRegister(&acceptWaitEntry)
	defer restored.ListenWQ.EventUnregister(&acceptWaitEntry)

	connErr := clientEP.Connect(tcpip.FullAddress{
		NIC:  customNICID,
		Addr: tcpip.AddrFrom4([4]byte{192, 168, 50, 2}),
		Port: listenPort,
	})
	if _, ok := connErr.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		connErr = nil
	}
	if connErr != nil {
		t.Fatalf("clientEP.Connect to restored child listener: %s", connErr)
	}

	var acceptedEP tcpip.Endpoint
	for {
		var acceptErr tcpip.Error
		acceptedEP, _, acceptErr = restored.ListenEP.Accept(nil)
		if _, ok := acceptErr.(*tcpip.ErrWouldBlock); ok {
			<-acceptNotifyCh
			continue
		}
		if acceptErr != nil {
			t.Fatalf("restored.ListenEP.Accept: %s", acceptErr)
		}
		break
	}
	defer acceptedEP.Close()

	if restored.ChildNS.Creator() == nil {
		t.Fatal("restored.ChildNS.Creator() is nil after RestoreRootStack")
	}
	grandchildNS := restored.ChildNS.NewNetworkNamespace(userNS)
	defer grandchildNS.Destroy(ctx)
	if grandchildNS.Stack() == nil {
		t.Fatal("grandchildNS.Stack() is nil after creating child namespace from restored child")
	}
	if grandchildNS.Stack() == restored.ChildNS.Stack() || grandchildNS.Stack() == restored.RootNS.Stack() {
		t.Fatal("grandchildNS.Stack() aliases parent or root stack")
	}
}

func TestRestoreRootStackWithTestStackCreator(t *testing.T) {
	ctx := context.Background()
	userNS := auth.NewRootUserNamespace()

	rootTestStack := inet.NewTestStack()
	rootNS := inet.NewRootNamespace(rootTestStack, rootTestStack.RestoreNetworkNamespaceCreator(), userNS)
	defer rootNS.Destroy(ctx)

	childNS := rootNS.NewNetworkNamespace(userNS)
	defer childNS.Destroy(ctx)
	childTestStack := childNS.Stack().(*inet.TestStack)
	childTestStack.InterfacesMap[7] = inet.Interface{Name: "veth-child"}

	orig := savedNamespaceBundle{
		RootNS:  rootNS,
		ChildNS: childNS,
	}

	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &orig); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var restored savedNamespaceBundle
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		restored.ChildNS.Destroy(ctx)
		restored.RootNS.Destroy(ctx)
	}()

	replacementRoot := inet.NewTestStack()
	restored.RootNS.RestoreRootStack(replacementRoot)
	restored.ChildNS.RestoreRootStack(replacementRoot)

	if restored.ChildNS.Stack() == nil || restored.ChildNS.Stack() == restored.RootNS.Stack() {
		t.Fatalf("restored.ChildNS.Stack() = %v, want distinct non-nil stack", restored.ChildNS.Stack())
	}
	if got := restored.ChildNS.Stack().Interfaces()[7].Name; got != "veth-child" {
		t.Fatalf("restored child interface[7].Name = %q, want %q", got, "veth-child")
	}
	grandchild := restored.ChildNS.NewNetworkNamespace(userNS)
	defer grandchild.Destroy(ctx)
	if grandchild.Stack() == nil || grandchild.Stack() == restored.ChildNS.Stack() {
		t.Fatalf("grandchild.Stack() = %v, want distinct non-nil stack", grandchild.Stack())
	}
}

func TestConcurrentTwoSandboxChildNamespaceRestoreAndDestroy(t *testing.T) {
	ctx := context.Background()
	userNS := auth.NewRootUserNamespace()

	buildSaved := func(t *testing.T, ifaceName string) []byte {
		t.Helper()
		rootTestStack := inet.NewTestStack()
		rootNS := inet.NewRootNamespace(rootTestStack, rootTestStack.RestoreNetworkNamespaceCreator(), userNS)
		defer rootNS.Destroy(ctx)

		ephemeralChild := rootNS.NewNetworkNamespace(userNS)
		ephemeralChild.Destroy(ctx)

		childNS := rootNS.NewNetworkNamespace(userNS)
		defer childNS.Destroy(ctx)
		childNS.Stack().(*inet.TestStack).InterfacesMap[9] = inet.Interface{Name: ifaceName}

		orig := savedNamespaceBundle{
			RootNS:  rootNS,
			ChildNS: childNS,
		}
		var buf bytes.Buffer
		if _, err := state.Save(ctx, &buf, &orig); err != nil {
			t.Fatalf("state.Save(%s): %v", ifaceName, err)
		}
		return buf.Bytes()
	}

	blobA := buildSaved(t, "sandbox-a-veth")
	blobB := buildSaved(t, "sandbox-b-veth")

	var restoredA, restoredB savedNamespaceBundle
	if _, err := state.Load(ctx, bytes.NewReader(blobA), &restoredA); err != nil {
		t.Fatalf("state.Load(A): %v", err)
	}
	defer restoredA.RootNS.Destroy(ctx)
	defer restoredA.ChildNS.Destroy(ctx)

	if _, err := state.Load(ctx, bytes.NewReader(blobB), &restoredB); err != nil {
		t.Fatalf("state.Load(B): %v", err)
	}
	defer restoredB.RootNS.Destroy(ctx)
	defer restoredB.ChildNS.Destroy(ctx)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		restoredA.RootNS.RestoreRootStack(inet.NewTestStack())
	}()
	go func() {
		defer wg.Done()
		restoredB.RootNS.RestoreRootStack(inet.NewTestStack())
	}()
	wg.Wait()

	if got := restoredA.ChildNS.Stack().Interfaces()[9].Name; got != "sandbox-a-veth" {
		t.Fatalf("Sandbox A child interface = %q, want sandbox-a-veth", got)
	}
	if got := restoredB.ChildNS.Stack().Interfaces()[9].Name; got != "sandbox-b-veth" {
		t.Fatalf("Sandbox B child interface = %q, want sandbox-b-veth", got)
	}
}

type trackingResumableEndpoint struct {
	resumed int
}

func (e *trackingResumableEndpoint) Resume() {
	e.resumed++
}

func TestDirectRootStackRestorePropagatesToChildNamespace(t *testing.T) {
	ctx := context.Background()
	userNS := auth.NewRootUserNamespace()

	rootStack := newTestRootNetstack(t)
	defer rootStack.Destroy()
	creator := NewStackCreator(rootStack)
	rootNS := inet.NewRootNamespace(rootStack, creator, userNS)
	defer rootNS.Destroy(ctx)

	childNS := rootNS.NewNetworkNamespace(userNS)
	defer childNS.Destroy(ctx)
	childStack := childNS.Stack().(*Stack)

	var trackEP trackingResumableEndpoint
	childStack.Stack.RegisterResumableEndpoint(&trackEP)
	rootStack.Pause()
	rootStack.Resume()
	if trackEP.resumed != 1 {
		t.Fatalf("child resumable endpoint resumed = %d after rootStack.Resume(), want 1", trackEP.resumed)
	}

	const customNICID = 2
	vethRootEP, vethChildEP := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
	defer vethRootEP.Close()
	if err := rootStack.Stack.CreateNICWithOptions(customNICID, newVethNICEndpoint(vethRootEP), stack.NICOptions{
		Name:   "veth0",
		Kind:   "veth",
		MinMTU: ethernetMinMTU,
		MaxMTU: ethernetMaxMTU,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth0): %s", err)
	}
	if err := rootStack.AddInterfaceAddr(ctx, customNICID, inet.InterfaceAddr{
		Family:    linux.AF_INET,
		PrefixLen: 24,
		Addr:      []byte{192, 168, 60, 1},
	}); err != nil {
		t.Fatalf("AddInterfaceAddr(192.168.60.1/24): %v", err)
	}
	if err := childStack.Stack.CreateNICWithOptions(customNICID, newVethNICEndpoint(vethChildEP), stack.NICOptions{
		Name:   "veth1",
		Kind:   "veth",
		MinMTU: ethernetMinMTU,
		MaxMTU: ethernetMaxMTU,
	}); err != nil {
		t.Fatalf("CreateNICWithOptions(veth1): %s", err)
	}
	if err := childStack.AddInterfaceAddr(ctx, customNICID, inet.InterfaceAddr{
		Family:    linux.AF_INET,
		PrefixLen: 24,
		Addr:      []byte{192, 168, 60, 2},
	}); err != nil {
		t.Fatalf("AddInterfaceAddr(192.168.60.2/24): %v", err)
	}

	const listenPort = 18081
	var listenWQ waiter.Queue
	listenEP, tcpErr := childStack.Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &listenWQ)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint(TCP): %s", tcpErr)
	}
	defer listenEP.Close()
	if err := listenEP.Bind(tcpip.FullAddress{
		NIC:  customNICID,
		Addr: tcpip.AddrFrom4([4]byte{192, 168, 60, 2}),
		Port: listenPort,
	}); err != nil {
		t.Fatalf("listenEP.Bind: %s", err)
	}
	if err := listenEP.Listen(16); err != nil {
		t.Fatalf("listenEP.Listen: %s", err)
	}

	orig := savedNamespaceBundle{
		RootNS:   rootNS,
		ChildNS:  childNS,
		ListenWQ: &listenWQ,
		ListenEP: listenEP,
	}

	rootStack.SetRemoveConf(true)
	rootStack.Pause()
	var buf bytes.Buffer
	_, saveErr := state.Save(ctx, &buf, &orig)
	rootStack.Resume()
	if saveErr != nil {
		t.Fatalf("state.Save: %v", saveErr)
	}

	var restored savedNamespaceBundle
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		if restored.ListenEP != nil {
			restored.ListenEP.Close()
		}
		if restored.ChildNS != nil {
			restored.ChildNS.Destroy(ctx)
		}
		if restored.RootNS != nil {
			restored.RootNS.Destroy(ctx)
		}
	}()

	// Simulate Kernel.LoadFrom for Netstack sandboxes: ResetConfig and Restore
	// are called directly on restored.RootNS.Stack() without RestoreRootStack.
	s := restored.RootNS.Stack()
	s.ResetConfig()
	s.Restore()

	if got := restored.ChildNS.Stack().Interfaces()[customNICID].Name; got != "veth1" {
		t.Fatalf("restored child interface[%d].Name = %q after direct s.Restore(), want veth1", customNICID, got)
	}

	restoredRootStack := s.(*Stack)
	var clientWQ waiter.Queue
	clientEP, clientErr := restoredRootStack.Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &clientWQ)
	if clientErr != nil {
		t.Fatalf("NewEndpoint(client): %s", clientErr)
	}
	defer clientEP.Close()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	clientWQ.EventRegister(&waitEntry)
	defer clientWQ.EventUnregister(&waitEntry)

	acceptWaitEntry, acceptNotifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	restored.ListenWQ.EventRegister(&acceptWaitEntry)
	defer restored.ListenWQ.EventUnregister(&acceptWaitEntry)

	connErr := clientEP.Connect(tcpip.FullAddress{
		NIC:  customNICID,
		Addr: tcpip.AddrFrom4([4]byte{192, 168, 60, 2}),
		Port: listenPort,
	})
	if _, ok := connErr.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		connErr = nil
	}
	if connErr != nil {
		t.Fatalf("clientEP.Connect after direct s.Restore(): %s", connErr)
	}

	var acceptedEP tcpip.Endpoint
	for {
		var acceptErr tcpip.Error
		acceptedEP, _, acceptErr = restored.ListenEP.Accept(nil)
		if _, ok := acceptErr.(*tcpip.ErrWouldBlock); ok {
			<-acceptNotifyCh
			continue
		}
		if acceptErr != nil {
			t.Fatalf("restored.ListenEP.Accept after direct s.Restore(): %s", acceptErr)
		}
		break
	}
	defer acceptedEP.Close()
}
