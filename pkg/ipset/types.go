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

// Features of a set type (enum ip_set_feature of Linux).
const (
	featureIP      uint16 = 1 << 0
	featurePort    uint16 = 1 << 1
	featureIP2     uint16 = 1 << 3
	featureName    uint16 = 1 << 4
	featureNomatch uint16 = 1 << 7
	// featureDumpLast makes a dump of all sets list this type last.
	featureDumpLast uint16 = 1 << 8
)

// kind selects the storage of a set type.
type kind uint8

const (
	kindHash kind = iota
	kindBitmapPort
	kindListSet
)

// typeSpec describes one set type.
type typeSpec struct {
	name string
	kind kind
	// dimension is the count of elements that the type matches.
	dimension uint8
	features  uint16
	// revisionMin and revisionMax bound the revisions that this
	// implementation serves. They equal the range of Linux.
	revisionMin, revisionMax uint8

	// The fields below describe a hash type.

	// ipNet is true when the first address of an element is a network with
	// a prefix length.
	ipNet bool
	// hasPort is true when an element has a port and a protocol.
	hasPort bool
	// hasIP2 is true when an element has a second address.
	hasIP2 bool
	// ip2Net is true when the second address is a network.
	ip2Net bool
	// netmask is true when the type has the create options netmask and
	// bitmask.
	netmask bool
	// bitmask is true when the type accepts the create option bitmask.
	bitmask bool
}

// typeSpecs lists the supported types. The revision ranges equal those of
// the Linux kernel 7.0 (net/netfilter/ipset/ip_set_*.c).
var typeSpecs = []*typeSpec{
	{
		name: "hash:ip", kind: kindHash, dimension: 1, features: featureIP,
		revisionMax: 6, netmask: true, bitmask: true,
	},
	{
		name: "hash:net", kind: kindHash, dimension: 1, features: featureIP | featureNomatch,
		revisionMax: 7, ipNet: true,
	},
	{
		name: "hash:ip,port", kind: kindHash, dimension: 2, features: featureIP | featurePort,
		revisionMax: 7, hasPort: true, netmask: true, bitmask: true,
	},
	{
		name: "hash:net,port", kind: kindHash, dimension: 2, features: featureIP | featurePort | featureNomatch,
		revisionMax: 8, ipNet: true, hasPort: true,
	},
	{
		name: "hash:ip,port,ip", kind: kindHash, dimension: 3, features: featureIP | featurePort | featureIP2,
		revisionMax: 6, hasPort: true, hasIP2: true,
	},
	{
		name: "hash:ip,port,net", kind: kindHash, dimension: 3,
		features:    featureIP | featurePort | featureIP2 | featureNomatch,
		revisionMax: 8, hasPort: true, hasIP2: true, ip2Net: true,
	},
	{
		name: "hash:net,net", kind: kindHash, dimension: 2, features: featureIP | featureIP2 | featureNomatch,
		revisionMax: 4, ipNet: true, hasIP2: true, ip2Net: true, bitmask: true,
	},
	{
		name: "bitmap:port", kind: kindBitmapPort, dimension: 1, features: featurePort,
		revisionMax: 3,
	},
	{
		name: "list:set", kind: kindListSet, dimension: 1, features: featureName | featureDumpLast,
		revisionMax: 3,
	},
}

// findType returns the type with the name, and whether a type exists.
func findType(name string) (*typeSpec, bool) {
	for _, t := range typeSpecs {
		if t.name == name {
			return t, true
		}
	}
	return nil, false
}

// FindType reports the revision range of a set type for a family, as the
// command IPSET_CMD_TYPE does. It returns the error that Linux returns when no
// type matches.
func FindType(name string, family uint8) (revisionMin, revisionMax uint8, err error) {
	t, ok := findType(name)
	if !ok {
		return 0, 0, &Error{Code: ErrFindType}
	}
	// Every type of this implementation serves both families and the
	// unspecified family, as the types of Linux with NFPROTO_UNSPEC do.
	if family != FamilyUnspec && family != FamilyIPv4 && family != FamilyIPv6 {
		return 0, 0, &Error{Code: errnoEOPNOTSUPP}
	}
	return t.revisionMin, t.revisionMax, nil
}
