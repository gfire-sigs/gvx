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

package ipset

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeClock is a clock that a test moves by hand.
type fakeClock struct{ now time.Duration }

func (c *fakeClock) read() time.Duration { return c.now + time.Second }

func newTestRegistry(t *testing.T) (*Registry, *fakeClock) {
	t.Helper()
	c := &fakeClock{}
	return NewRegistry(DefaultMaxSets, c.read), c
}

func ip4(s string) Addr {
	a := netip.MustParseAddr(s).As4()
	return Addr{a[0], a[1], a[2], a[3]}
}

func ip6(s string) Addr { return Addr(netip.MustParseAddr(s).As16()) }

// create makes a set of the type, and it fails the test on an error.
func create(t *testing.T, r *Registry, name, typ string, family uint8, mutate func(*CreateParams)) {
	t.Helper()
	_, hi, err := FindType(typ, family)
	if err != nil {
		t.Fatalf("FindType(%s): %v", typ, err)
	}
	p := &CreateParams{Name: name, TypeName: typ, Family: family, Revision: hi}
	if mutate != nil {
		mutate(p)
	}
	if err := r.Create(p); err != nil {
		t.Fatalf("Create(%s %s): %v", name, typ, err)
	}
}

func code(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

// uadt runs an element operation and returns its code.
func uadt(r *Registry, name string, adt Adt, e Element, flags uint32) int {
	return r.Uadt(name, adt, &e, flags)
}

func hostElem(ip string) Element {
	return Element{Has: HasIP, IP: ip4(ip)}
}

func netElem(ip string, cidr uint8) Element {
	return Element{Has: HasIP | HasCIDR, IP: ip4(ip), CIDR: cidr}
}

func portElem(ip string, proto uint8, port uint16) Element {
	return Element{Has: HasIP | HasPort | HasProto, IP: ip4(ip), Port: port, Proto: proto}
}

func listAll(t *testing.T, r *Registry, name string) []Element {
	t.Helper()
	d, err := r.NewDump(name, true)
	if err != nil {
		t.Fatalf("NewDump: %v", err)
	}
	defer d.Close()
	if _, _, ok, err := d.Next(); !ok || err != nil {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	var out []Element
	for {
		e, ok := d.Cursor().Peek()
		if !ok {
			return out
		}
		out = append(out, e)
		d.Cursor().Advance()
	}
}

func TestHashIPAddTestDel(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "ips", "hash:ip", FamilyIPv4, nil)

	if got := uadt(r, "ips", AdtAdd, hostElem("10.0.0.1"), 0); got != 0 {
		t.Fatalf("add = %d", got)
	}
	if got := uadt(r, "ips", AdtAdd, hostElem("10.0.0.1"), 0); got != -ErrExist {
		t.Errorf("duplicate add = %d, want -ErrExist", got)
	}
	if got := uadt(r, "ips", AdtAdd, hostElem("10.0.0.1"), FlagExist); got != 0 {
		t.Errorf("duplicate add with exist = %d, want 0", got)
	}
	if got := uadt(r, "ips", AdtTest, hostElem("10.0.0.1"), 0); got <= 0 {
		t.Errorf("test of a member = %d, want a match", got)
	}
	if got := uadt(r, "ips", AdtTest, hostElem("10.0.0.2"), 0); got > 0 {
		t.Errorf("test of a non-member = %d, want no match", got)
	}
	if got := uadt(r, "ips", AdtDel, hostElem("10.0.0.1"), 0); got != 0 {
		t.Errorf("del = %d", got)
	}
	if got := uadt(r, "ips", AdtDel, hostElem("10.0.0.1"), 0); got != -ErrExist {
		t.Errorf("del of a missing element = %d, want -ErrExist", got)
	}
}

func TestHashIPRangeAndCIDR(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "ips", "hash:ip", FamilyIPv4, nil)

	e := Element{Has: HasIP | HasIPTo, IP: ip4("10.0.0.250"), IPTo: ip4("10.0.1.2")}
	if got := uadt(r, "ips", AdtAdd, e, 0); got != 0 {
		t.Fatalf("add range = %d", got)
	}
	if n := len(listAll(t, r, "ips")); n != 9 {
		t.Errorf("range holds %d elements, want 9", n)
	}
	c := Element{Has: HasIP | HasCIDR, IP: ip4("192.168.4.0"), CIDR: 30}
	if got := uadt(r, "ips", AdtAdd, c, 0); got != 0 {
		t.Fatalf("add cidr = %d", got)
	}
	if got := uadt(r, "ips", AdtTest, hostElem("192.168.4.3"), 0); got <= 0 {
		t.Errorf("last host of the /30 is missing")
	}
	bad := Element{Has: HasIP | HasCIDR, IP: ip4("192.168.4.0"), CIDR: 0}
	if got := uadt(r, "ips", AdtAdd, bad, 0); got != -ErrInvalidCIDR {
		t.Errorf("cidr 0 = %d, want -ErrInvalidCIDR", got)
	}
}

func TestHashIPv6(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "v6", "hash:ip", FamilyIPv6, nil)
	e := Element{Has: HasIP, IP: ip6("fd00::1")}
	if got := uadt(r, "v6", AdtAdd, e, 0); got != 0 {
		t.Fatalf("add = %d", got)
	}
	if got := uadt(r, "v6", AdtTest, e, 0); got <= 0 {
		t.Errorf("test = %d, want a match", got)
	}
	rng := Element{Has: HasIP | HasIPTo, IP: ip6("fd00::1"), IPTo: ip6("fd00::9")}
	if got := uadt(r, "v6", AdtAdd, rng, 0); got != -ErrHashRangeUnsupported {
		t.Errorf("IPv6 range = %d, want -ErrHashRangeUnsupported", got)
	}
}

func TestHashNetLongestMatchAndNomatch(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "nets", "hash:net", FamilyIPv4, nil)
	uadt(r, "nets", AdtAdd, netElem("10.0.0.0", 8), 0)
	nm := netElem("10.1.0.0", 16)
	nm.Has |= HasCadtFlags
	nm.CadtFlags = CadtNomatch
	if got := uadt(r, "nets", AdtAdd, nm, 0); got != 0 {
		t.Fatalf("add nomatch = %d", got)
	}

	if got := uadt(r, "nets", AdtTest, hostElem("10.2.3.4"), 0); got <= 0 {
		t.Errorf("host in the /8 = %d, want a match", got)
	}
	if got := uadt(r, "nets", AdtTest, hostElem("10.1.3.4"), 0); got > 0 {
		t.Errorf("host in the nomatch /16 = %d, want no match", got)
	}
	if got := uadt(r, "nets", AdtTest, hostElem("11.1.3.4"), 0); got > 0 {
		t.Errorf("host outside = %d, want no match", got)
	}
	// A test with the nomatch flag succeeds for a nomatch element only.
	probe := netElem("10.1.0.0", 16)
	probe.Has |= HasCadtFlags
	probe.CadtFlags = CadtNomatch
	if got := uadt(r, "nets", AdtTest, probe, 0); got <= 0 {
		t.Errorf("test nomatch of the nomatch element = %d, want a match", got)
	}
	probe = netElem("10.0.0.0", 8)
	probe.Has |= HasCadtFlags
	probe.CadtFlags = CadtNomatch
	if got := uadt(r, "nets", AdtTest, probe, 0); got > 0 {
		t.Errorf("test nomatch of a plain element = %d, want no match", got)
	}
}

func TestHashNetRangeToCIDR(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "nets", "hash:net", FamilyIPv4, nil)
	e := Element{Has: HasIP | HasIPTo, IP: ip4("10.0.0.3"), IPTo: ip4("10.0.0.9")}
	if got := uadt(r, "nets", AdtAdd, e, 0); got != 0 {
		t.Fatalf("add = %d", got)
	}
	var got []string
	for _, el := range listAll(t, r, "nets") {
		got = append(got, fmt.Sprintf("%d.%d.%d.%d/%d", el.IP[0], el.IP[1], el.IP[2], el.IP[3], el.CIDR))
	}
	want := []string{"10.0.0.3/32", "10.0.0.4/30", "10.0.0.8/31"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("blocks = %v, want %v", got, want)
	}
}

func TestHashIPPortMatchesProtocolAndPort(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "svc", "hash:ip,port", FamilyIPv4, nil)
	if got := uadt(r, "svc", AdtAdd, portElem("10.0.0.1", protoTCP, 80), 0); got != 0 {
		t.Fatalf("add = %d", got)
	}
	if got := uadt(r, "svc", AdtTest, portElem("10.0.0.1", protoTCP, 80), 0); got <= 0 {
		t.Errorf("tcp:80 = %d, want a match", got)
	}
	if got := uadt(r, "svc", AdtTest, portElem("10.0.0.1", protoUDP, 80), 0); got > 0 {
		t.Errorf("udp:80 = %d, want no match", got)
	}
	if got := uadt(r, "svc", AdtTest, portElem("10.0.0.1", protoTCP, 81), 0); got > 0 {
		t.Errorf("tcp:81 = %d, want no match", got)
	}
	noProto := Element{Has: HasIP | HasPort, IP: ip4("10.0.0.1"), Port: 80}
	if got := uadt(r, "svc", AdtAdd, noProto, 0); got != -ErrMissingProto {
		t.Errorf("missing proto = %d, want -ErrMissingProto", got)
	}
	rng := portElem("10.0.0.2", protoTCP, 8000)
	rng.Has |= HasPortTo
	rng.PortTo = 8002
	uadt(r, "svc", AdtAdd, rng, 0)
	if got := uadt(r, "svc", AdtTest, portElem("10.0.0.2", protoTCP, 8001), 0); got <= 0 {
		t.Errorf("tcp:8001 inside the port range = %d, want a match", got)
	}
}

func TestHashThreeDimensions(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "ipip", "hash:ip,port,ip", FamilyIPv4, nil)
	create(t, r, "ipnet", "hash:ip,port,net", FamilyIPv4, nil)
	create(t, r, "netnet", "hash:net,net", FamilyIPv4, nil)

	e := portElem("10.0.0.1", protoTCP, 443)
	e.Has |= HasIP2
	e.IP2 = ip4("10.0.0.2")
	if got := uadt(r, "ipip", AdtAdd, e, 0); got != 0 {
		t.Fatalf("ipip add = %d", got)
	}
	if got := uadt(r, "ipip", AdtTest, e, 0); got <= 0 {
		t.Errorf("ipip test = %d", got)
	}
	e.IP2 = ip4("10.0.0.3")
	if got := uadt(r, "ipip", AdtTest, e, 0); got > 0 {
		t.Errorf("ipip with another second ip = %d, want no match", got)
	}

	n := portElem("10.0.0.1", protoTCP, 443)
	n.Has |= HasIP2 | HasCIDR2
	n.IP2, n.CIDR2 = ip4("172.16.0.0"), 12
	if got := uadt(r, "ipnet", AdtAdd, n, 0); got != 0 {
		t.Fatalf("ipnet add = %d", got)
	}
	n.IP2, n.CIDR2 = ip4("172.20.1.1"), 32
	if got := uadt(r, "ipnet", AdtTest, n, 0); got <= 0 {
		t.Errorf("ipnet test of a host inside the net = %d, want a match", got)
	}

	nn := Element{Has: HasIP | HasCIDR | HasIP2 | HasCIDR2, IP: ip4("10.0.0.0"), CIDR: 8, IP2: ip4("192.168.0.0"), CIDR2: 16}
	if got := uadt(r, "netnet", AdtAdd, nn, 0); got != 0 {
		t.Fatalf("netnet add = %d", got)
	}
	probe := Element{Has: HasIP | HasIP2, IP: ip4("10.9.9.9"), IP2: ip4("192.168.7.7")}
	if got := uadt(r, "netnet", AdtTest, probe, 0); got <= 0 {
		t.Errorf("netnet test of two hosts = %d, want a match", got)
	}
	probe.IP2 = ip4("192.169.7.7")
	if got := uadt(r, "netnet", AdtTest, probe, 0); got > 0 {
		t.Errorf("netnet test outside the second net = %d, want no match", got)
	}
}

func TestTimeoutExpiry(t *testing.T) {
	r, clock := newTestRegistry(t)
	create(t, r, "ttl", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenTimeout
		p.Timeout = 60
	})
	short := hostElem("10.0.0.1")
	short.Has |= HasTimeout
	short.Timeout = 5
	uadt(r, "ttl", AdtAdd, short, 0)
	uadt(r, "ttl", AdtAdd, hostElem("10.0.0.2"), 0)
	forever := hostElem("10.0.0.3")
	forever.Has |= HasTimeout
	uadt(r, "ttl", AdtAdd, forever, 0)

	clock.now += 6 * time.Second
	if got := uadt(r, "ttl", AdtTest, hostElem("10.0.0.1"), 0); got > 0 {
		t.Errorf("expired element still matches")
	}
	if got := uadt(r, "ttl", AdtTest, hostElem("10.0.0.2"), 0); got <= 0 {
		t.Errorf("element with the default timeout expired early")
	}
	clock.now += 120 * time.Second
	if got := uadt(r, "ttl", AdtTest, hostElem("10.0.0.2"), 0); got > 0 {
		t.Errorf("element with the default timeout did not expire")
	}
	if got := uadt(r, "ttl", AdtTest, hostElem("10.0.0.3"), 0); got <= 0 {
		t.Errorf("element with timeout 0 expired")
	}
	if got := uadt(r, "ttl", AdtAdd, hostElem("10.0.0.1"), 0); got != 0 {
		t.Errorf("add over an expired element = %d, want 0", got)
	}
	if n := len(listAll(t, r, "ttl")); n != 2 {
		t.Errorf("listing holds %d elements, want 2", n)
	}
}

func TestMaxElemAndForceadd(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "small", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenMaxElem
		p.MaxElem = 2
	})
	uadt(r, "small", AdtAdd, hostElem("10.0.0.1"), 0)
	uadt(r, "small", AdtAdd, hostElem("10.0.0.2"), 0)
	if got := uadt(r, "small", AdtAdd, hostElem("10.0.0.3"), 0); got != -ErrHashFull {
		t.Errorf("third element = %d, want -ErrHashFull", got)
	}

	create(t, r, "force", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenMaxElem | GivenCadtFlags
		p.MaxElem = 2
		p.CadtFlags = CadtWithForceadd
	})
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if got := uadt(r, "force", AdtAdd, hostElem(ip), 0); got != 0 {
			t.Fatalf("forceadd %s = %d", ip, got)
		}
	}
	if got := uadt(r, "force", AdtTest, hostElem("10.0.0.3"), 0); got <= 0 {
		t.Errorf("the newest element is missing after forceadd")
	}
}

func TestExtensionsRequireCreateOptions(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "plain", "hash:ip", FamilyIPv4, nil)
	e := hostElem("10.0.0.1")
	e.Has |= HasComment
	e.Comment = "x"
	if got := uadt(r, "plain", AdtAdd, e, 0); got != -ErrComment {
		t.Errorf("comment on a set without comment = %d, want -ErrComment", got)
	}
	e = hostElem("10.0.0.1")
	e.Has |= HasPackets
	if got := uadt(r, "plain", AdtAdd, e, 0); got != -ErrCounter {
		t.Errorf("counter on a set without counters = %d, want -ErrCounter", got)
	}
	e = hostElem("10.0.0.1")
	e.Has |= HasTimeout
	if got := uadt(r, "plain", AdtAdd, e, 0); got != -ErrTimeout {
		t.Errorf("timeout on a set without timeout = %d, want -ErrTimeout", got)
	}
}

func TestCountersCommentAndListing(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "full", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenCadtFlags
		p.CadtFlags = CadtWithCounters | CadtWithComment
	})
	e := hostElem("10.0.0.1")
	e.Has |= HasComment | HasPackets | HasBytes
	e.Comment, e.Packets, e.Bytes = "web", 3, 300
	if got := uadt(r, "full", AdtAdd, e, 0); got != 0 {
		t.Fatalf("add = %d", got)
	}
	// A packet through a rule adds to the counters.
	id, _, _ := r.Lookup("full")
	pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.0.0.1"), Dst: ip4("10.0.0.9"), Len: 100}
	opt := &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}
	if r.Test(id, pkt, opt) <= 0 {
		t.Fatal("packet from a member does not match")
	}
	got := listAll(t, r, "full")
	if len(got) != 1 || got[0].Packets != 4 || got[0].Bytes != 400 || got[0].Comment != "web" {
		t.Errorf("listing = %+v, want packets 4, bytes 400, comment web", got)
	}
	// A counter condition selects by the counters.
	opt.CmdFlags = FlagMatchCounters | FlagSkipCounterUpdate
	opt.PacketsOp, opt.PacketsValue = CounterGT, 10
	if r.Test(id, pkt, opt) > 0 {
		t.Errorf("packets > 10 matches an element with 4 packets")
	}
	opt.PacketsValue = 3
	if r.Test(id, pkt, opt) <= 0 {
		t.Errorf("packets > 3 does not match an element with 4 packets")
	}
}

func TestKernelSourceAndDestinationSelection(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "svc", "hash:ip,port", FamilyIPv4, nil)
	uadt(r, "svc", AdtAdd, portElem("10.0.0.5", protoTCP, 443), 0)
	id, _, _ := r.Lookup("svc")
	pkt := &Packet{
		Family: FamilyIPv4, Src: ip4("10.9.9.9"), Dst: ip4("10.0.0.5"),
		SrcPort: 55555, DstPort: 443, Proto: protoTCP, PortsOK: true,
	}
	// "dst,dst": the destination address and the destination port.
	if r.Test(id, pkt, &KOpt{Dim: 2, Timeout: NoTimeout}) <= 0 {
		t.Error("dst,dst does not match")
	}
	// "src,dst" looks for the source address.
	if r.Test(id, pkt, &KOpt{Dim: 2, Flags: KDimOneSrc, Timeout: NoTimeout}) > 0 {
		t.Error("src,dst matches a source that is not in the set")
	}
	// A rule with one dimension never matches a two dimension set.
	if r.Test(id, pkt, &KOpt{Dim: 1, Timeout: NoTimeout}) > 0 {
		t.Error("a one dimension rule matches a two dimension set")
	}
	pkt.PortsOK = false
	if r.Test(id, pkt, &KOpt{Dim: 2, Timeout: NoTimeout}) > 0 {
		t.Error("a packet without port information matches")
	}
	v6 := &Packet{Family: FamilyIPv6, Dst: ip6("fd00::5"), DstPort: 443, Proto: protoTCP, PortsOK: true}
	if r.Test(id, v6, &KOpt{Dim: 2, Timeout: NoTimeout}) > 0 {
		t.Error("an IPv6 packet matches an IPv4 set")
	}
}

func TestKernelAddAndDel(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "seen", "hash:ip", FamilyIPv4, nil)
	id, _, _ := r.Lookup("seen")
	pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.1.1.1"), Dst: ip4("10.2.2.2")}
	opt := &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}
	if got := r.Add(id, pkt, opt); got != 0 {
		t.Fatalf("Add = %d", got)
	}
	if r.Test(id, pkt, opt) <= 0 {
		t.Error("the added address does not match")
	}
	if got := r.Del(id, pkt, opt); got != 0 {
		t.Fatalf("Del = %d", got)
	}
	if r.Test(id, pkt, opt) > 0 {
		t.Error("the deleted address still matches")
	}
}

func TestReturnNomatch(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "nets", "hash:net", FamilyIPv4, nil)
	uadt(r, "nets", AdtAdd, netElem("10.0.0.0", 8), 0)
	nm := netElem("10.1.0.0", 16)
	nm.Has |= HasCadtFlags
	nm.CadtFlags = CadtNomatch
	uadt(r, "nets", AdtAdd, nm, 0)
	id, _, _ := r.Lookup("nets")
	in := &Packet{Family: FamilyIPv4, Src: ip4("10.1.2.3")}
	out := &Packet{Family: FamilyIPv4, Src: ip4("10.2.2.3")}
	opt := &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}
	if r.Test(id, in, opt) > 0 || r.Test(id, out, opt) <= 0 {
		t.Fatal("plain match: nomatch element must not match, the covering net must")
	}
	opt.CmdFlags = FlagReturnNomatch
	if r.Test(id, in, opt) <= 0 || r.Test(id, out, opt) > 0 {
		t.Error("with return-nomatch the result of matching elements inverts")
	}
}

func TestBitmapPort(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "ports", "bitmap:port", FamilyUnspec, func(p *CreateParams) {
		p.Given |= GivenPortFrom | GivenPortTo
		p.PortFrom, p.PortTo = 1000, 2000
	})
	add := Element{Has: HasPort, Port: 1500}
	if got := uadt(r, "ports", AdtAdd, add, 0); got != 0 {
		t.Fatalf("add = %d", got)
	}
	if got := uadt(r, "ports", AdtTest, add, 0); got <= 0 {
		t.Errorf("test = %d, want a match", got)
	}
	out := Element{Has: HasPort, Port: 2001}
	if got := uadt(r, "ports", AdtAdd, out, 0); got != -ErrBitmapRange {
		t.Errorf("port outside the range = %d, want -ErrBitmapRange", got)
	}
	rng := Element{Has: HasPort | HasPortTo, Port: 1600, PortTo: 1602}
	uadt(r, "ports", AdtAdd, rng, 0)
	if n := len(listAll(t, r, "ports")); n != 4 {
		t.Errorf("listing holds %d ports, want 4", n)
	}
	id, _, _ := r.Lookup("ports")
	pkt := &Packet{Family: FamilyIPv4, DstPort: 1601, Proto: protoTCP, PortsOK: true}
	if r.Test(id, pkt, &KOpt{Dim: 1, Timeout: NoTimeout}) <= 0 {
		t.Error("a packet to a port in the set does not match")
	}
}

func TestListSetOrderReferencesAndLoops(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "a", "hash:ip", FamilyIPv4, nil)
	create(t, r, "b", "hash:ip", FamilyIPv4, nil)
	create(t, r, "c", "hash:ip", FamilyIPv4, nil)
	create(t, r, "all", "list:set", FamilyUnspec, nil)

	add := func(name string, extra Present, nameRef string, flags uint32) int {
		e := Element{Has: HasName | extra, Name: name, NameRef: nameRef, CadtFlags: flags}
		return uadt(r, "all", AdtAdd, e, 0)
	}
	if got := add("a", 0, "", 0); got != 0 {
		t.Fatalf("add a = %d", got)
	}
	if got := add("c", 0, "", 0); got != 0 {
		t.Fatalf("add c = %d", got)
	}
	// "after a" puts b between a and c: with a name reference and no before
	// flag, the new member follows the reference.
	if got := add("b", HasNameRef, "a", 0); got != 0 {
		t.Fatalf("add b after a = %d", got)
	}
	var names []string
	for _, e := range listAll(t, r, "all") {
		names = append(names, e.Name)
	}
	if fmt.Sprint(names) != "[a b c]" {
		t.Errorf("order = %v, want [a b c]", names)
	}
	if got := code(r.Destroy("a", false, false)); got != ErrBusy {
		t.Errorf("destroy of a member = %d, want ErrBusy", got)
	}
	if got := add("all", 0, "", 0); got != -ErrListLoop {
		t.Errorf("add of a list:set to itself = %d, want -ErrListLoop", got)
	}
	if got := uadt(r, "all", AdtDel, Element{Has: HasName, Name: "a"}, 0); got != 0 {
		t.Fatalf("del a = %d", got)
	}
	if err := r.Destroy("a", false, false); err != nil {
		t.Errorf("destroy of a freed set: %v", err)
	}

	// The list matches a packet when one member matches.
	uadt(r, "c", AdtAdd, hostElem("10.0.0.7"), 0)
	id, _, _ := r.Lookup("all")
	pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.0.0.7")}
	if r.Test(id, pkt, &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}) <= 0 {
		t.Error("list:set does not match a packet that a member matches")
	}
}

func TestRegistryCreateExistRenameSwapDestroy(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "one", "hash:ip", FamilyIPv4, nil)
	create(t, r, "two", "hash:ip", FamilyIPv4, nil)
	create(t, r, "net", "hash:net", FamilyIPv4, nil)
	uadt(r, "one", AdtAdd, hostElem("10.0.0.1"), 0)

	_, hi, _ := FindType("hash:ip", FamilyIPv4)
	dup := &CreateParams{Name: "one", TypeName: "hash:ip", Family: FamilyIPv4, Revision: hi}
	if got := code(r.Create(dup)); got != errnoEEXIST {
		t.Errorf("duplicate create = %d, want EEXIST", got)
	}
	dup.Exist = true
	if err := r.Create(dup); err != nil {
		t.Errorf("create with exist of an identical set: %v", err)
	}
	dup.Given, dup.MaxElem = GivenMaxElem, 5
	if got := code(r.Create(dup)); got != errnoEEXIST {
		t.Errorf("create with exist of a different set = %d, want EEXIST", got)
	}

	if err := r.Swap("one", "two"); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if got := uadt(r, "two", AdtTest, hostElem("10.0.0.1"), 0); got <= 0 {
		t.Errorf("after the swap the data of one belongs to two")
	}
	if got := code(r.Swap("one", "net")); got != ErrTypeMismatch {
		t.Errorf("swap of different types = %d, want ErrTypeMismatch", got)
	}
	if got := code(r.Rename("one", "two")); got != ErrExistSetname2 {
		t.Errorf("rename onto an existing name = %d, want ErrExistSetname2", got)
	}
	if err := r.Rename("one", "uno"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := code(r.Rename("one", "x")); got != errnoENOENT {
		t.Errorf("rename of a missing set = %d, want ENOENT", got)
	}

	id, _, _ := r.Lookup("uno")
	if !r.GetRef(id) {
		t.Fatal("GetRef failed")
	}
	if got := code(r.Destroy("uno", false, false)); got != ErrBusy {
		t.Errorf("destroy of a referenced set = %d, want ErrBusy", got)
	}
	if got := code(r.Rename("uno", "x")); got != ErrReferenced {
		t.Errorf("rename of a referenced set = %d, want ErrReferenced", got)
	}
	r.PutRef(id)
	if err := r.Destroy("uno", false, false); err != nil {
		t.Errorf("destroy after the reference ended: %v", err)
	}
	if err := r.Destroy("uno", false, true); err != nil {
		t.Errorf("destroy of a missing set with exist: %v", err)
	}
	if got := code(r.Destroy("uno", false, false)); got != errnoENOENT {
		t.Errorf("destroy of a missing set = %d, want ENOENT", got)
	}
	if err := r.Destroy("", true, false); err != nil {
		t.Errorf("destroy of every set: %v", err)
	}
	if _, _, ok := r.Lookup("two"); ok {
		t.Error("a set survived destroy of every set")
	}
}

func TestSwapKeepsRuleIndexOnTheSameName(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "live", "hash:ip", FamilyIPv4, nil)
	create(t, r, "next", "hash:ip", FamilyIPv4, nil)
	uadt(r, "next", AdtAdd, hostElem("10.0.0.9"), 0)
	liveID, _, _ := r.Lookup("live")
	r.GetRef(liveID)

	pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.0.0.9")}
	opt := &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}
	if r.Test(liveID, pkt, opt) > 0 {
		t.Fatal("the live set matches before the swap")
	}
	if err := r.Swap("live", "next"); err != nil {
		t.Fatal(err)
	}
	// The rule keeps its index, and the index now leads to the new data.
	if r.Test(liveID, pkt, opt) <= 0 {
		t.Error("after the swap the rule index does not see the new data")
	}
	// The references stay with the index.
	if got := code(r.Destroy("live", false, false)); got != ErrBusy {
		t.Errorf("destroy of the swapped-in set = %d, want ErrBusy", got)
	}
}

func TestTableGrowsLikeLinux(t *testing.T) {
	c := &fakeClock{}
	r := NewRegistry(4, c.read)
	for i := range 10 {
		create(t, r, fmt.Sprintf("s%d", i), "hash:ip", FamilyIPv4, nil)
	}
	if got := r.Len(); got != 4+setIncrement {
		t.Errorf("table size = %d, want %d", got, 4+setIncrement)
	}
	id, _, ok := r.Lookup("s9")
	if !ok || id != 9 {
		t.Errorf("s9 has index %d (found %v), want 9", id, ok)
	}
}

func TestNetmaskAndBitmask(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "masked", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenNetmask
		p.Netmask = 24
	})
	uadt(r, "masked", AdtAdd, hostElem("10.0.5.77"), 0)
	if got := uadt(r, "masked", AdtTest, hostElem("10.0.5.1"), 0); got <= 0 {
		t.Errorf("netmask 24 does not group the addresses of the /24")
	}
	_, hi, _ := FindType("hash:ip", FamilyIPv4)
	both := &CreateParams{
		Name: "both", TypeName: "hash:ip", Family: FamilyIPv4, Revision: hi,
		Given: GivenNetmask | GivenBitmask, Netmask: 24, Bitmask: ip4("255.255.0.0"),
	}
	if got := code(r.Create(both)); got != ErrBitmaskNetmaskExcl {
		t.Errorf("netmask with bitmask = %d, want ErrBitmaskNetmaskExcl", got)
	}
	bad := &CreateParams{
		Name: "bad", TypeName: "hash:ip", Family: FamilyIPv4, Revision: hi,
		Given: GivenNetmask, Netmask: 33,
	}
	if got := code(r.Create(bad)); got != ErrInvalidNetmask {
		t.Errorf("netmask 33 = %d, want ErrInvalidNetmask", got)
	}
}

func TestHeaderReportsCreateOptions(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "h", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenHashSize | GivenMaxElem | GivenTimeout | GivenCadtFlags
		p.HashSize, p.MaxElem, p.Timeout = 100, 5000, 30
		p.CadtFlags = CadtWithCounters
	})
	uadt(r, "h", AdtAdd, hostElem("10.0.0.1"), 0)
	d, _ := r.NewDump("h", true)
	defer d.Close()
	_, head, ok, _ := d.Next()
	if !ok {
		t.Fatal("no set")
	}
	if head.HashSize != 128 || head.MaxElem != 5000 || head.Elements != 1 || !head.HasTimeout || head.Timeout != 30 ||
		head.CadtFlags != CadtWithCounters || !head.HasBucket {
		t.Errorf("head = %+v", head)
	}
}

func TestDumpOrderPutsListSetsLastAndPinsTheSet(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "list", "list:set", FamilyUnspec, nil)
	create(t, r, "a", "hash:ip", FamilyIPv4, nil)
	create(t, r, "b", "hash:net", FamilyIPv4, nil)

	d, err := r.NewDump("", false)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for {
		info, _, ok, err := d.Next()
		if err != nil || !ok {
			break
		}
		order = append(order, info.Name)
		if len(order) == 1 {
			if got := code(r.Destroy("a", false, false)); got != ErrBusy {
				t.Errorf("destroy of a set in a dump = %d, want ErrBusy", got)
			}
		}
	}
	d.Close()
	if fmt.Sprint(order) != "[a b list]" {
		t.Errorf("order = %v, want [a b list]", order)
	}
	if err := r.Destroy("a", false, false); err != nil {
		t.Errorf("destroy after the dump: %v", err)
	}
}

func TestDumpSurvivesDeletesAndSkipsNewElements(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "s", "hash:ip", FamilyIPv4, nil)
	for i := range 100 {
		uadt(r, "s", AdtAdd, hostElem(fmt.Sprintf("10.0.0.%d", i)), 0)
	}
	d, _ := r.NewDump("s", true)
	defer d.Close()
	d.Next()
	c := d.Cursor()
	seen := map[Addr]bool{}
	for i := range 10 {
		e, _ := c.Peek()
		seen[e.IP] = true
		c.Advance()
		_ = i
	}
	// Delete most elements and add a new one while the listing runs.
	for i := 10; i < 95; i++ {
		uadt(r, "s", AdtDel, hostElem(fmt.Sprintf("10.0.0.%d", i)), 0)
	}
	uadt(r, "s", AdtAdd, hostElem("10.9.9.9"), 0)
	for {
		e, ok := c.Peek()
		if !ok {
			break
		}
		if seen[e.IP] {
			t.Fatalf("element %v listed twice", e.IP[:4])
		}
		seen[e.IP] = true
		c.Advance()
	}
	if seen[ip4("10.9.9.9")] {
		t.Error("an element added after the start appears")
	}
	if len(seen) != 15 {
		t.Errorf("listing returned %d elements, want 15", len(seen))
	}
}

func TestFindType(t *testing.T) {
	for _, name := range []string{"hash:ip", "hash:net", "hash:ip,port", "hash:net,port", "hash:ip,port,ip", "hash:ip,port,net", "hash:net,net", "list:set", "bitmap:port"} {
		lo, hi, err := FindType(name, FamilyIPv4)
		if err != nil || hi < lo {
			t.Errorf("FindType(%s) = %d, %d, %v", name, lo, hi, err)
		}
	}
	if _, _, err := FindType("hash:mac", FamilyIPv4); code(err) != ErrFindType {
		t.Errorf("unknown type: %v, want ErrFindType", err)
	}
}

func TestRangeToCIDR(t *testing.T) {
	cases := []struct {
		from, to uint32
		last     uint32
		cidr     uint8
	}{
		{0x0a000000, 0x0a0000ff, 0x0a0000ff, 24},
		{0x0a000001, 0x0a0000ff, 0x0a000001, 32},
		{0x0a000004, 0x0a000009, 0x0a000007, 30},
		{0x0a000000, 0x0a000000, 0x0a000000, 32},
		{0, 0xfffffffe, 0x7fffffff, 1},
	}
	for _, c := range cases {
		last, cidr := rangeToCIDR(c.from, c.to)
		if last != c.last || cidr != c.cidr {
			t.Errorf("rangeToCIDR(%#x, %#x) = %#x, %d; want %#x, %d", c.from, c.to, last, cidr, c.last, c.cidr)
		}
	}
}

// TestPurgeOfExpiredElementsKeepsTheStoreIntact adds an element to a full set of
// expired elements. The purge once compacted the slots while it walked them and
// panicked with an index out of range.
func TestPurgeOfExpiredElementsKeepsTheStoreIntact(t *testing.T) {
	r, clock := newTestRegistry(t)
	create(t, r, "ttl", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenTimeout | GivenMaxElem
		p.Timeout, p.MaxElem = 1, 100
	})
	for i := range 100 {
		if got := uadt(r, "ttl", AdtAdd, hostElem(fmt.Sprintf("10.0.0.%d", i+1)), 0); got != 0 {
			t.Fatalf("add %d = %d", i, got)
		}
	}
	clock.now += 5 * time.Second
	if got := uadt(r, "ttl", AdtAdd, hostElem("10.9.9.9"), 0); got != 0 {
		t.Fatalf("add after the expiry = %d, want 0", got)
	}
	if n := len(listAll(t, r, "ttl")); n != 1 {
		t.Errorf("listing holds %d elements, want 1", n)
	}
}

func TestNetmaskSetsStepFromNetworkToNetwork(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "masked", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenNetmask
		p.Netmask = 24
	})
	if got := uadt(r, "masked", AdtAdd, netElem("10.0.0.0", 24), 0); got != 0 {
		t.Fatalf("add cidr = %d", got)
	}
	if n := len(listAll(t, r, "masked")); n != 1 {
		t.Errorf("a /24 in a set with netmask 24 gives %d elements, want 1", n)
	}
	rng := Element{Has: HasIP | HasIPTo, IP: ip4("10.1.0.77"), IPTo: ip4("10.1.2.3")}
	if got := uadt(r, "masked", AdtAdd, rng, 0); got != 0 {
		t.Fatalf("add range = %d", got)
	}
	// 10.1.0.0, 10.1.1.0, and 10.1.2.0 from the range, and 10.0.0.0.
	if n := len(listAll(t, r, "masked")); n != 4 {
		t.Errorf("listing holds %d elements, want 4", n)
	}
}

func TestCreateExistIgnoresTheHashSize(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "s", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenHashSize
		p.HashSize = 128
	})
	_, hi, _ := FindType("hash:ip", FamilyIPv4)
	again := &CreateParams{Name: "s", TypeName: "hash:ip", Family: FamilyIPv4, Revision: hi, Exist: true,
		Given: GivenHashSize, HashSize: 4096}
	if err := r.Create(again); err != nil {
		t.Errorf("create with exist and another hashsize: %v", err)
	}
}

func TestPacketAddKeepsTheCommentOfTheElement(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "c", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenCadtFlags
		p.CadtFlags = CadtWithComment
	})
	e := hostElem("10.0.0.1")
	e.Has |= HasComment
	e.Comment = "web"
	uadt(r, "c", AdtAdd, e, 0)
	id, _, _ := r.Lookup("c")
	pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.0.0.1")}
	opt := &KOpt{Dim: 1, Flags: KDimOneSrc, CmdFlags: FlagExist, Timeout: NoTimeout}
	if got := r.Add(id, pkt, opt); got != 0 {
		t.Fatalf("Add = %d", got)
	}
	if got := listAll(t, r, "c"); len(got) != 1 || got[0].Comment != "web" {
		t.Errorf("listing = %+v, want the comment web", got)
	}
}

func TestListSetGivesTheSkbInfoOfTheMatchingMember(t *testing.T) {
	r, _ := newTestRegistry(t)
	create(t, r, "m", "hash:ip", FamilyIPv4, func(p *CreateParams) {
		p.Given |= GivenCadtFlags
		p.CadtFlags = CadtWithSkbinfo
	})
	create(t, r, "all", "list:set", FamilyUnspec, nil)
	e := hostElem("10.0.0.1")
	e.Has |= HasSkbMark
	e.SkbMark = 0x2a<<32 | 0xff
	uadt(r, "m", AdtAdd, e, 0)
	uadt(r, "all", AdtAdd, Element{Has: HasName, Name: "m"}, 0)
	id, _, _ := r.Lookup("all")
	pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.0.0.1")}
	opt := &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}
	if r.Test(id, pkt, opt) <= 0 {
		t.Fatal("the list does not match")
	}
	if opt.SkbInfo.Mark != 0x2a || opt.SkbInfo.MarkMask != 0xff {
		t.Errorf("skbinfo = %+v, want mark 0x2a and mask 0xff", opt.SkbInfo)
	}
}

// TestHugeRangeDoesNotBlockPackets deletes a multi-chunk address range alongside a packet lookup.
// It verifies that the lookup acquires the set lock at a chunk boundary.
func TestHugeRangeDoesNotBlockPackets(t *testing.T) {
	yielded := make(chan struct{})
	resume := make(chan struct{})
	var armYield sync.Mutex
	var armed bool
	var rangeCalls int
	r := NewRegistry(DefaultMaxSets, func() time.Duration {
		armYield.Lock()
		active := armed
		if active {
			rangeCalls++
		}
		call := rangeCalls
		armYield.Unlock()
		// Call 1 happens before the range operation takes the set lock. Call 2
		// refreshes the timestamp at the first rangeChunk boundary while hashUadt
		// releases the set lock.
		if active && call == 2 {
			close(yielded)
			<-resume
		}
		return time.Second
	})
	create(t, r, "s", "hash:ip", FamilyIPv4, nil)
	uadt(r, "s", AdtAdd, hostElem("10.0.0.1"), 0)
	id, _, _ := r.Lookup("s")

	armYield.Lock()
	armed = true
	armYield.Unlock()

	done := make(chan int, 1)
	go func() {
		e := Element{Has: HasIP | HasCIDR, IP: ip4("11.0.0.0"), CIDR: 16}
		done <- uadt(r, "s", AdtDel, e, FlagExist)
	}()

	select {
	case <-yielded:
	case <-time.After(10 * time.Second):
		t.Fatal("range delete did not yield at rangeChunk")
	}

	// While the range delete is paused at the chunk yield point, a packet lookup
	// must acquire s.mu and succeed without blocking on the range delete.
	lookupDone := make(chan int, 1)
	go func() {
		pkt := &Packet{Family: FamilyIPv4, Src: ip4("10.0.0.1")}
		opt := &KOpt{Dim: 1, Flags: KDimOneSrc, Timeout: NoTimeout}
		lookupDone <- r.Test(id, pkt, opt)
	}()
	select {
	case got := <-lookupDone:
		if got <= 0 {
			t.Fatal("the member does not match during range yield")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("packet lookup blocked while range delete paused at yield point")
	}

	close(resume)
	if got := <-done; got != 0 {
		t.Errorf("range delete = %d, want 0", got)
	}
}
