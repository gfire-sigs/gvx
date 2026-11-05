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
	"bytes"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// This file validates the attributes of a request with the policies of
// drivers/net/wireguard/generated/netlink.c, in the strict mode that Linux
// uses for the commands of this family. The order of the checks and the
// error numbers follow lib/nlattr.c: validate_nla and __nla_validate_parse.

// errRange is ERANGE. A binary attribute of the wrong size and a malformed
// array fail with it.
var errRange = syserr.FromError(linuxerr.ERANGE)

// attrKind is the type of an attribute in a policy, as the NLA_* values of
// Linux.
type attrKind uint8

const (
	// kindUnspec is an attribute that the family does not use. The strict mode
	// rejects it.
	kindUnspec attrKind = iota
	// kindU16, kindU32, kindU64, and kindU8 need an exact length.
	kindU8
	kindU16
	kindU32
	kindU64
	// kindExact is NLA_POLICY_EXACT_LEN: a binary attribute of n bytes.
	kindExact
	// kindMin is NLA_POLICY_MIN_LEN: a binary attribute of at least n bytes.
	kindMin
	// kindString is NLA_NUL_STRING with the maximum length n.
	kindString
	// kindArray is NLA_POLICY_NESTED_ARRAY with the policy nested.
	kindArray
)

// attrPolicy is the policy of one attribute type.
type attrPolicy struct {
	kind attrKind
	// n is the length of kindExact, the minimum of kindMin, and the maximum of
	// kindString.
	n int
	// mask is the set of bits that an unsigned integer may have. Zero means
	// every bit.
	mask uint32
	// nested is the policy of the elements of kindArray.
	nested policy
}

// policy lists the attribute policies of one nesting level by type. Type 0 and
// every type after the last entry are unknown.
type policy []attrPolicy

var (
	allowedIPPolicy = policy{
		allowedIPAttrFamily: {kind: kindU16},
		allowedIPAttrIPAddr: {kind: kindMin, n: 4},
		allowedIPAttrCIDR:   {kind: kindU8},
		allowedIPAttrFlags:  {kind: kindU32, mask: allowedIPFlagRemoveMe},
	}

	peerPolicy = policy{
		peerAttrPublicKey:    {kind: kindExact, n: keyLen},
		peerAttrPresharedKey: {kind: kindExact, n: keyLen},
		peerAttrFlags:        {kind: kindU32, mask: peerFlagRemoveMe | peerFlagReplaceAllowedIP | peerFlagUpdateOnly},
		peerAttrEndpoint:     {kind: kindMin, n: sockaddrInSize},
		peerAttrKeepalive:    {kind: kindU16},
		peerAttrLastHshake:   {kind: kindExact, n: 16},
		peerAttrRxBytes:      {kind: kindU64},
		peerAttrTxBytes:      {kind: kindU64},
		peerAttrAllowedIPs:   {kind: kindArray, nested: allowedIPPolicy},
		peerAttrProtoVersion: {kind: kindU32},
	}

	// getDevicePolicy is the policy of WG_CMD_GET_DEVICE.
	getDevicePolicy = policy{
		deviceAttrIfindex: {kind: kindU32},
		deviceAttrIfname:  {kind: kindString, n: ifnameMax},
	}

	// setDevicePolicy is the policy of WG_CMD_SET_DEVICE.
	setDevicePolicy = policy{
		deviceAttrIfindex:    {kind: kindU32},
		deviceAttrIfname:     {kind: kindString, n: ifnameMax},
		deviceAttrPrivateKey: {kind: kindExact, n: keyLen},
		deviceAttrPublicKey:  {kind: kindExact, n: keyLen},
		deviceAttrFlags:      {kind: kindU32, mask: deviceFlagReplacePeers},
		deviceAttrListenPort: {kind: kindU16},
		deviceAttrFwmark:     {kind: kindU32},
		deviceAttrPeers:      {kind: kindArray, nested: peerPolicy},
	}
)

// ifnameMax is IFNAMSIZ - 1, the longest interface name.
const ifnameMax = 15

// parseWithPolicy validates view against p and returns its attributes by
// type, without the NLA_F_NESTED flag. A later attribute of one type replaces
// an earlier one, as in the parser of Linux. It fails on the first violation in
// the order of the attributes.
func parseWithPolicy(view nlmsg.AttrsView, p policy) (map[uint16]nlmsg.BytesView, *syserr.Error) {
	attrs := make(map[uint16]nlmsg.BytesView)
	for !view.Empty() {
		hdr, value, rest, ok := view.ParseFirst()
		if !ok {
			// A header that does not fit, or a length that overruns the data,
			// leaves bytes after the last whole attribute.
			return nil, syserr.ErrInvalidArgument
		}
		view = rest
		typ := hdr.Type & linux.NLA_TYPE_MASK
		if typ == 0 || int(typ) >= len(p) {
			return nil, syserr.ErrInvalidArgument
		}
		if err := validateAttr(hdr.Type, value, &p[typ]); err != nil {
			return nil, err
		}
		attrs[typ] = nlmsg.BytesView(value)
	}
	return attrs, nil
}

// validateAttr applies one attribute policy to the attribute with the raw type
// rawType and the payload value.
func validateAttr(rawType uint16, value []byte, p *attrPolicy) *syserr.Error {
	nestedFlag := rawType&linux.NLA_F_NESTED != 0
	if p.kind == kindArray {
		if !nestedFlag {
			return syserr.ErrInvalidArgument
		}
	} else if p.kind != kindUnspec && nestedFlag {
		return syserr.ErrInvalidArgument
	}
	switch p.kind {
	case kindUnspec:
		return syserr.ErrInvalidArgument
	case kindU8, kindU16, kindU32, kindU64:
		if len(value) != intSize(p.kind) {
			return syserr.ErrInvalidArgument
		}
		if p.mask != 0 && p.kind == kindU32 && hostarch.ByteOrder.Uint32(value)&^p.mask != 0 {
			return syserr.ErrInvalidArgument
		}
	case kindExact:
		if len(value) != p.n {
			return errRange
		}
	case kindMin:
		if len(value) < p.n {
			return errRange
		}
	case kindString:
		return validateString(value, p.n)
	case kindArray:
		return validateArray(value, p.nested)
	}
	return nil
}

// intSize returns the size of an unsigned integer attribute.
func intSize(k attrKind) int {
	switch k {
	case kindU8:
		return 1
	case kindU16:
		return 2
	case kindU32:
		return 4
	}
	return 8
}

// validateString applies NLA_NUL_STRING with the maximum length max. The
// string needs a NUL byte in its first max+1 bytes.
func validateString(value []byte, max int) *syserr.Error {
	head := value[:min(len(value), max+1)]
	if len(head) == 0 || bytes.IndexByte(head, 0) < 0 {
		return syserr.ErrInvalidArgument
	}
	n := len(value)
	if value[n-1] == 0 {
		n--
	}
	if n > max {
		return errRange
	}
	return nil
}

// validateArray applies NLA_NESTED_ARRAY. An empty array is valid. Each element
// that has a payload holds the attributes of the element policy.
func validateArray(value []byte, elem policy) *syserr.Error {
	if len(value) == 0 {
		return nil
	}
	if len(value) < linux.NetlinkAttrHeaderSize {
		return errRange
	}
	view := nlmsg.AttrsView(value)
	for !view.Empty() {
		_, payload, rest, ok := view.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		view = rest
		if len(payload) == 0 {
			continue
		}
		if len(payload) < linux.NetlinkAttrHeaderSize {
			return errRange
		}
		if _, err := parseWithPolicy(nlmsg.AttrsView(payload), elem); err != nil {
			return err
		}
	}
	return nil
}
