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

// Package ipset implements the IP sets of Linux (net/netfilter/ipset). A
// Registry holds the named sets of one network namespace. The netlink
// subsystem NFNL_SUBSYS_IPSET, the iptables match "set", and the iptables
// target "SET" use the Registry. The package follows the semantics and the
// error codes of Linux, so that the ipset tool, kube-router, and Calico work.
//
// The package has no dependency on netlink or on the packet types of the
// network stack. A caller parses its messages into an Element or a Packet.
package ipset

import (
	"fmt"
	"math/bits"
)

// Protocol versions of include/uapi/linux/netfilter/ipset/ip_set.h.
const (
	ProtocolVersion    = 7
	ProtocolVersionMin = 6
)

// Limits and defaults of Linux.
const (
	// MaxNameLen is IPSET_MAXNAMELEN. A set name has at most MaxNameLen-1 bytes.
	MaxNameLen = 32

	// MaxCommentSize is IPSET_MAX_COMMENT_SIZE.
	MaxCommentSize = 255

	// InvalidID is IPSET_INVALID_ID.
	InvalidID ID = 65535

	// DefaultMaxSets is CONFIG_IP_SET_MAX of Linux. The module parameter
	// max_sets of ip_set sets the initial size of the table of sets of a
	// network namespace. The table grows by setIncrement sets, up to
	// InvalidID-1 sets, as in Linux.
	DefaultMaxSets = 256

	// setIncrement is IP_SET_INC of Linux.
	setIncrement = 64

	// NoTimeout is IPSET_NO_TIMEOUT: the element or the set has no timeout.
	NoTimeout = ^uint32(0)

	// maxTimeout is IPSET_MAX_TIMEOUT in seconds.
	maxTimeout = (^uint32(0) >> 1) / 1000

	defaultHashSize = 1024
	minimalHashSize = 64
	defaultMaxElem  = 65536

	// ahashMaxSize is AHASH_MAX_SIZE: the largest bucket size of a hash set.
	ahashMaxSize  = 12
	ahashInitSize = 2

	listDefaultSize = 8
	listMinSize     = 4
	listMaxSize     = 65536
)

// ID is the index of a set in the table of sets of a Registry (ip_set_id_t).
type ID uint16

// Address families of the first byte of a netfilter message.
const (
	FamilyUnspec uint8 = 0
	FamilyIPv4   uint8 = 2
	FamilyIPv6   uint8 = 10
)

// Command flags: the lower half of IPSET_ATTR_FLAGS and of the flags of the
// kernel interface (enum ipset_cmd_flags).
const (
	FlagExist               uint32 = 1 << 0
	FlagListSetname         uint32 = 1 << 1
	FlagListHeader          uint32 = 1 << 2
	FlagSkipCounterUpdate   uint32 = 1 << 3
	FlagSkipSubcounterUpdte uint32 = 1 << 4
	FlagMatchCounters       uint32 = 1 << 5
	FlagReturnNomatch       uint32 = 1 << 7
	FlagMapSkbmark          uint32 = 1 << 8
	FlagMapSkbprio          uint32 = 1 << 9
	FlagMapSkbqueue         uint32 = 1 << 10
)

// Flags of IPSET_ATTR_CADT_FLAGS (enum ipset_cadt_flags).
const (
	CadtBefore        uint32 = 1 << 0
	CadtPhysdev       uint32 = 1 << 1
	CadtNomatch       uint32 = 1 << 2
	CadtWithCounters  uint32 = 1 << 3
	CadtWithComment   uint32 = 1 << 4
	CadtWithForceadd  uint32 = 1 << 5
	CadtWithSkbinfo   uint32 = 1 << 6
	CadtIfaceWildcard uint32 = 1 << 7
)

// Create flags (enum ipset_create_flags).
const (
	createFlagForceadd   uint32 = 1 << 0
	createFlagBucketsize uint32 = 1 << 1
)

// Error numbers of Linux. The package uses these values and not the
// constants of package syscall, which differ on Windows.
const (
	errnoENOENT     = 2
	errnoEBUSY      = 16
	errnoEEXIST     = 17
	errnoEINVAL     = 22
	errnoERANGE     = 34
	errnoENOTEMPTY  = 39
	errnoEOVERFLOW  = 75
	errnoEOPNOTSUPP = 95
)

// Error numbers of ipset (enum ipset_errno and the type specific errors).
const (
	ErrPrivate              = 4096
	ErrProtocol             = 4097
	ErrFindType             = 4098
	ErrMaxSets              = 4099
	ErrBusy                 = 4100
	ErrExistSetname2        = 4101
	ErrTypeMismatch         = 4102
	ErrExist                = 4103
	ErrInvalidCIDR          = 4104
	ErrInvalidNetmask       = 4105
	ErrInvalidFamily        = 4106
	ErrTimeout              = 4107
	ErrReferenced           = 4108
	ErrIPAddrIPv4           = 4109
	ErrIPAddrIPv6           = 4110
	ErrCounter              = 4111
	ErrComment              = 4112
	ErrInvalidMarkmask      = 4113
	ErrSkbinfo              = 4114
	ErrBitmaskNetmaskExcl   = 4115
	errTypeSpecific         = 4352
	ErrHashFull             = errTypeSpecific
	ErrHashElem             = errTypeSpecific + 1
	ErrInvalidProto         = errTypeSpecific + 2
	ErrMissingProto         = errTypeSpecific + 3
	ErrHashRangeUnsupported = errTypeSpecific + 4
	ErrHashRange            = errTypeSpecific + 5
	ErrBitmapRange          = errTypeSpecific
	ErrBitmapRangeSize      = errTypeSpecific + 1
	ErrListName             = errTypeSpecific
	ErrListLoop             = errTypeSpecific + 1
	ErrListBefore           = errTypeSpecific + 2
	ErrListNameref          = errTypeSpecific + 3
	ErrListFull             = errTypeSpecific + 4
	ErrListRefExist         = errTypeSpecific + 5
)

// Error is a failure with a Linux error number. Code is the positive number
// that a netlink error message carries as its negative.
type Error struct {
	Code int
}

func (e *Error) Error() string {
	return fmt.Sprintf("ipset: error %d", e.Code)
}

// errCode converts the negative result code of an operation into an error.
func errCode(ret int) error {
	if ret >= 0 {
		return nil
	}
	return &Error{Code: -ret}
}

// Addr is an IP address in network byte order. An IPv4 address uses the first
// four bytes and leaves the others zero.
type Addr [16]byte

// prefixMask returns the first n bits set, over a space of size bytes.
func prefixMask(n, size int) Addr {
	var m Addr
	for i := range size {
		switch {
		case n >= 8:
			m[i] = 0xff
		case n > 0:
			m[i] = byte(0xff << (8 - n))
		}
		n -= 8
	}
	return m
}

// and returns the bitwise AND of a and mask.
func (a Addr) and(mask Addr) Addr {
	for i := range a {
		a[i] &= mask[i]
	}
	return a
}

// addrSize returns the size in bytes of an address of the family.
func addrSize(family uint8) int {
	if family == FamilyIPv6 {
		return 16
	}
	return 4
}

// hostBits returns the length of a host prefix of the family.
func hostBits(family uint8) uint8 {
	if family == FamilyIPv6 {
		return 128
	}
	return 32
}

// ip4 returns the IPv4 address in host order.
func (a Addr) ip4() uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

// addr4 returns the address of an IPv4 address in host order.
func addr4(v uint32) Addr {
	return Addr{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// rangeToCIDR returns the last address of the largest block that starts at
// from and ends at or before to, with the prefix length of that block. It is
// ip_set_range_to_cidr of Linux.
func rangeToCIDR(from, to uint32) (last uint32, cidr uint8) {
	for i := uint8(1); i < 32; i++ {
		mask := ^uint32(0) << (32 - uint(i))
		if from&mask != from {
			continue
		}
		if last := from | ^mask; last <= to {
			return last, i
		}
	}
	return from, 32
}

// popcount counts the set bits of the first size bytes of a.
func (a Addr) popcount(size int) int {
	n := 0
	for i := range size {
		n += bits.OnesCount8(a[i])
	}
	return n
}
