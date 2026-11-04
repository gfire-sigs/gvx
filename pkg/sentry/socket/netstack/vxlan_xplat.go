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
	"encoding/binary"
	"errors"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/packetsocket"
	"z.gfire.dev/gvx/pkg/tcpip/link/vxlan"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Attributes of IFLA_INFO_DATA for the kind "vxlan", from include/uapi/linux/if_link.h.
const (
	iflaVxlanID             = 1
	iflaVxlanGroup          = 2
	iflaVxlanLink           = 3
	iflaVxlanLocal          = 4
	iflaVxlanTTL            = 5
	iflaVxlanTOS            = 6
	iflaVxlanLearning       = 7
	iflaVxlanAgeing         = 8
	iflaVxlanLimit          = 9
	iflaVxlanPortRange      = 10
	iflaVxlanProxy          = 11
	iflaVxlanRSC            = 12
	iflaVxlanL2Miss         = 13
	iflaVxlanL3Miss         = 14
	iflaVxlanPort           = 15
	iflaVxlanGroup6         = 16
	iflaVxlanLocal6         = 17
	iflaVxlanUDPCsum        = 18
	iflaVxlanUDPZeroCsum6Tx = 19
	iflaVxlanUDPZeroCsum6Rx = 20
	iflaVxlanRemcsumTx      = 21
	iflaVxlanRemcsumRx      = 22
	iflaVxlanGBP            = 23
	iflaVxlanRemcsumNoPart  = 24
	iflaVxlanCollectMeta    = 25
	iflaVxlanLabel          = 26
	iflaVxlanGPE            = 27
	iflaVxlanTTLInherit     = 28
	iflaVxlanDF             = 29
	iflaVxlanVNIFilter      = 30
	iflaVxlanLocalBypass    = 31
)

// vxlanDFInherit is the largest value of IFLA_VXLAN_DF (VXLAN_DF_INHERIT).
const vxlanDFInherit = 2

func init() {
	RegisterLinkKind("vxlan", LinkKind{NamePrefix: "vxlan", New: newVxlanLink})
}

// vxlanAttrs reads the attributes of IFLA_INFO_DATA.
type vxlanAttrs map[uint16]nlmsg.BytesView

func (a vxlanAttrs) u8(typ uint16) (v uint8, present bool, err *syserr.Error) {
	b, ok := a[typ]
	if !ok {
		return 0, false, nil
	}
	if v, ok = b.Uint8(); !ok {
		return 0, true, syserr.ErrInvalidArgument
	}
	return v, true, nil
}

func (a vxlanAttrs) u32(typ uint16) (v uint32, present bool, err *syserr.Error) {
	b, ok := a[typ]
	if !ok {
		return 0, false, nil
	}
	if v, ok = b.Uint32(); !ok {
		return 0, true, syserr.ErrInvalidArgument
	}
	return v, true, nil
}

// flag reports whether the flag attribute is present.
func (a vxlanAttrs) flag(typ uint16) bool {
	_, ok := a[typ]
	return ok
}

// addr reads an IPv4 or IPv6 address attribute. It returns the address of
// length 0 when the attribute is absent.
func (a vxlanAttrs) addr(typ uint16, size int) (tcpip.Address, *syserr.Error) {
	b, ok := a[typ]
	if !ok {
		return tcpip.Address{}, nil
	}
	if len(b) != size {
		return tcpip.Address{}, syserr.ErrInvalidArgument
	}
	return tcpip.AddrFromSlice(b), nil
}

// parseVxlanConfig translates IFLA_INFO_DATA to the configuration of the link.
// It follows vxlan_nl2conf and vxlan_config_validate of Linux for the
// attributes that it supports, and it ignores the others.
func parseVxlanConfig(req *NewLinkRequest) (vxlan.Config, *syserr.Error) {
	a := vxlanAttrs(req.Data)
	cfg := vxlan.Config{ID: req.ID, Learning: true, UDPCsum: true, AgeingSeconds: vxlan.DefaultAgeing}
	var err *syserr.Error

	vni, ok, err := a.u32(iflaVxlanID)
	if err != nil {
		return cfg, err
	}
	if !ok {
		return cfg, syserr.ErrInvalidArgument
	}
	if vni > vxlan.MaxVNI {
		return cfg, syserr.ErrRange
	}
	cfg.VNI = vni

	if a.flag(iflaVxlanGroup) && a.flag(iflaVxlanGroup6) || a.flag(iflaVxlanLocal) && a.flag(iflaVxlanLocal6) {
		return cfg, syserr.ErrInvalidArgument
	}
	if a.flag(iflaVxlanGPE) {
		return cfg, syserr.ErrNotSupported
	}
	if v, present, err := a.u8(iflaVxlanCollectMeta); err != nil {
		return cfg, err
	} else if present && v != 0 {
		return cfg, syserr.ErrNotSupported
	}
	for _, p := range []struct {
		typ  uint16
		size int
		dst  *tcpip.Address
	}{
		{iflaVxlanGroup, header.IPv4AddressSize, &cfg.Group},
		{iflaVxlanGroup6, header.IPv6AddressSize, &cfg.Group},
		{iflaVxlanLocal, header.IPv4AddressSize, &cfg.Local},
		{iflaVxlanLocal6, header.IPv6AddressSize, &cfg.Local},
	} {
		v, err := a.addr(p.typ, p.size)
		if err != nil {
			return cfg, err
		}
		if v.Len() != 0 {
			*p.dst = v
		}
	}
	if cfg.Local.Len() != 0 && cfg.Group.Len() != 0 && cfg.Local.Len() != cfg.Group.Len() {
		return cfg, syserr.ErrInvalidArgument
	}

	if b, ok := a[iflaVxlanPort]; ok {
		if len(b) != 2 {
			return cfg, syserr.ErrInvalidArgument
		}
		cfg.Port = binary.BigEndian.Uint16(b)
	}
	if b, ok := a[iflaVxlanPortRange]; ok {
		if len(b) != 4 {
			return cfg, syserr.ErrInvalidArgument
		}
		cfg.PortLow, cfg.PortHigh = binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])
	}
	if v, ok, err := a.u32(iflaVxlanLink); err != nil {
		return cfg, err
	} else if ok && v != 0 {
		if _, found := req.Stack.Stack.SingleNICInfo(tcpip.NICID(v)); !found {
			return cfg, syserr.ErrNoDevice
		}
		cfg.Link = tcpip.NICID(v)
	}

	u8s := []struct {
		typ uint16
		dst *uint8
	}{{iflaVxlanTTL, &cfg.TTL}, {iflaVxlanTOS, &cfg.TOS}, {iflaVxlanDF, &cfg.DF}}
	for _, p := range u8s {
		v, ok, err := a.u8(p.typ)
		if err != nil {
			return cfg, err
		}
		if ok {
			*p.dst = v
		}
	}
	if cfg.DF > vxlanDFInherit {
		return cfg, syserr.ErrInvalidArgument
	}
	bools := []struct {
		typ uint16
		dst *bool
	}{
		{iflaVxlanLearning, &cfg.Learning}, {iflaVxlanProxy, &cfg.Proxy}, {iflaVxlanRSC, &cfg.RSC},
		{iflaVxlanL2Miss, &cfg.L2Miss}, {iflaVxlanL3Miss, &cfg.L3Miss},
		{iflaVxlanUDPCsum, &cfg.UDPCsum}, {iflaVxlanUDPZeroCsum6Tx, &cfg.UDPZeroCsum6Tx},
		{iflaVxlanUDPZeroCsum6Rx, &cfg.UDPZeroCsum6Rx}, {iflaVxlanRemcsumTx, &cfg.RemcsumTx},
		{iflaVxlanRemcsumRx, &cfg.RemcsumRx},
	}
	for _, p := range bools {
		v, ok, err := a.u8(p.typ)
		if err != nil {
			return cfg, err
		}
		if ok {
			*p.dst = v != 0
		}
	}
	cfg.GBP = a.flag(iflaVxlanGBP)
	cfg.RemcsumNoPartial = a.flag(iflaVxlanRemcsumNoPart)
	cfg.TTLInherit = a.flag(iflaVxlanTTLInherit)

	if v, ok, err := a.u32(iflaVxlanAgeing); err != nil {
		return cfg, err
	} else if ok {
		cfg.AgeingSeconds = v
	}
	if v, _, err := a.u32(iflaVxlanLimit); err != nil {
		return cfg, err
	} else {
		cfg.Limit = v
	}
	if b, ok := a[iflaVxlanLabel]; ok {
		if len(b) != 4 {
			return cfg, syserr.ErrInvalidArgument
		}
		cfg.Label = binary.BigEndian.Uint32(b)
	}
	return cfg, nil
}

// newVxlanLink creates the link endpoint of a new "vxlan" link. The endpoint
// sends and receives in the network stack of the request, so the outer packets
// follow the routes of that stack.
func newVxlanLink(_ context.Context, req *NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
	cfg, err := parseVxlanConfig(req)
	if err != nil {
		return nil, err
	}
	ep, verr := vxlan.New(req.Stack.Stack, cfg)
	if verr != nil {
		return nil, vxlanSyserr(verr)
	}
	return packetsocket.New(ep), nil
}

// vxlanSyserr returns the errno for an error of the vxlan package.
func vxlanSyserr(err error) *syserr.Error {
	var se *vxlan.StackError
	switch {
	case errors.Is(err, vxlan.ErrDuplicate), errors.Is(err, vxlan.ErrExists):
		return syserr.ErrExists
	case errors.As(err, &se):
		return syserr.TranslateNetstackError(se.Err)
	case errors.Is(err, vxlan.ErrNotFound):
		return syserr.ErrNoFileOrDir
	case errors.Is(err, vxlan.ErrNotSupported):
		return syserr.ErrNotSupported
	case errors.Is(err, vxlan.ErrBadAddress):
		return syserr.ErrAddressFamilyNotSupported
	}
	return syserr.ErrInvalidArgument
}

// VxlanSyserr returns the errno for an error of the vxlan package. The
// neighbor netlink code of the route protocol uses it for FDB requests.
func VxlanSyserr(err error) *syserr.Error { return vxlanSyserr(err) }

// VxlanLink returns the vxlan endpoint of the interface, or nil when the
// interface is not a vxlan link.
func (s *Stack) VxlanLink(id tcpip.NICID) *vxlan.Endpoint {
	info, ok := s.Stack.SingleNICInfo(id)
	if !ok || info.Kind != "vxlan" {
		return nil
	}
	ep := s.Stack.GetLinkEndpointByName(info.Name)
	for ep != nil {
		switch e := ep.(type) {
		case *vxlan.Endpoint:
			return e
		case interface{ Child() stack.LinkEndpoint }:
			ep = e.Child()
		default:
			return nil
		}
	}
	return nil
}

// VxlanInfoData appends IFLA_INFO_DATA with the configuration of the vxlan
// link, in the attributes that vxlan_fill_info writes.
func (s *Stack) VxlanInfoData(id tcpip.NICID, info *nlmsg.NestedAttr) {
	ep := s.VxlanLink(id)
	if ep == nil {
		return
	}
	c := ep.Config()
	var d nlmsg.NestedAttr
	u8 := func(typ uint16, v uint8) { d.PutAttr(typ, primitive.AllocateUint8(v)) }
	boolean := func(typ uint16, v bool) {
		if v {
			u8(typ, 1)
		} else {
			u8(typ, 0)
		}
	}
	flag := func(typ uint16, v bool) {
		if v {
			d.PutAttr(typ, primitive.AsByteSlice(nil))
		}
	}
	be16 := func(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

	d.PutAttr(iflaVxlanID, primitive.AllocateUint32(c.VNI))
	if !c.Group.Unspecified() {
		typ := uint16(iflaVxlanGroup)
		if c.Group.Len() == header.IPv6AddressSize {
			typ = iflaVxlanGroup6
		}
		d.PutAttr(typ, primitive.AsByteSlice(c.Group.AsSlice()))
	}
	if c.Link != 0 {
		d.PutAttr(iflaVxlanLink, primitive.AllocateUint32(uint32(c.Link)))
	}
	if !c.Local.Unspecified() {
		typ := uint16(iflaVxlanLocal)
		if c.Local.Len() == header.IPv6AddressSize {
			typ = iflaVxlanLocal6
		}
		d.PutAttr(typ, primitive.AsByteSlice(c.Local.AsSlice()))
	}
	u8(iflaVxlanTTL, c.TTL)
	flag(iflaVxlanTTLInherit, c.TTLInherit)
	u8(iflaVxlanTOS, c.TOS)
	u8(iflaVxlanDF, c.DF)
	d.PutAttr(iflaVxlanLabel, primitive.AsByteSlice(binary.BigEndian.AppendUint32(nil, c.Label)))
	boolean(iflaVxlanLearning, c.Learning)
	boolean(iflaVxlanProxy, c.Proxy)
	boolean(iflaVxlanRSC, c.RSC)
	boolean(iflaVxlanL2Miss, c.L2Miss)
	boolean(iflaVxlanL3Miss, c.L3Miss)
	u8(iflaVxlanCollectMeta, 0)
	d.PutAttr(iflaVxlanAgeing, primitive.AllocateUint32(c.AgeingSeconds))
	d.PutAttr(iflaVxlanLimit, primitive.AllocateUint32(c.Limit))
	low, high := c.PortLow, c.PortHigh
	if low == 0 && high == 0 {
		low, high = 32768, 60999
	}
	d.PutAttr(iflaVxlanPortRange, primitive.AsByteSlice(append(be16(low), be16(high)...)))
	d.PutAttr(iflaVxlanPort, primitive.AsByteSlice(be16(c.Port)))
	boolean(iflaVxlanUDPCsum, c.UDPCsum)
	boolean(iflaVxlanUDPZeroCsum6Tx, c.UDPZeroCsum6Tx)
	boolean(iflaVxlanUDPZeroCsum6Rx, c.UDPZeroCsum6Rx)
	boolean(iflaVxlanRemcsumTx, c.RemcsumTx)
	boolean(iflaVxlanRemcsumRx, c.RemcsumRx)
	flag(iflaVxlanGBP, c.GBP)
	flag(iflaVxlanRemcsumNoPart, c.RemcsumNoPartial)
	info.PutAttr(linux.IFLA_INFO_DATA, primitive.AsByteSlice(d))
}
