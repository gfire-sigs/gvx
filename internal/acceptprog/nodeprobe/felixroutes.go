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

//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The felixroutes checks send the route requests that Calico Felix sends
// through github.com/vishvananda/netlink (felix/routetable createL3Route): a
// route of a type without a device, with the protocol 80, the universe scope,
// and the table 254. Felix lists the routes with a filter on the table and the
// protocol.

// felixProtocol is the route protocol that Felix gives its routes.
const felixProtocol = 80

func felixRoute(cidr string, routeType int, linkIndex int) netlink.Route {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return netlink.Route{
		LinkIndex: linkIndex,
		Dst:       dst,
		Type:      routeType,
		Protocol:  felixProtocol,
		Scope:     netlink.SCOPE_UNIVERSE,
		Table:     unix.RT_TABLE_MAIN,
	}
}

// listFelixRoutes lists the routes of the table 254 with the protocol 80, as
// Felix does when it resyncs.
func listFelixRoutes(family int) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, &netlink.Route{
		Table:    unix.RT_TABLE_MAIN,
		Protocol: felixProtocol,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
}

func felixRouteChecks() []check {
	return []check{
		{"felixroutes-blackhole-without-device", func() error {
			for _, t := range []struct {
				name string
				typ  int
			}{
				{"blackhole", unix.RTN_BLACKHOLE},
				{"unreachable", unix.RTN_UNREACHABLE},
				{"prohibit", unix.RTN_PROHIBIT},
				{"throw", unix.RTN_THROW},
			} {
				r := felixRoute("10.42.225.0/26", t.typ, 0)
				if err := netlink.RouteAdd(&r); err != nil {
					return fmt.Errorf("add %s route: %w", t.name, err)
				}
				routes, err := listFelixRoutes(netlink.FAMILY_V4)
				if err != nil {
					return fmt.Errorf("list: %w", err)
				}
				var found bool
				for _, got := range routes {
					if got.Dst != nil && got.Dst.String() == "10.42.225.0/26" {
						found = true
						if got.Type != t.typ || got.LinkIndex != 0 || got.Protocol != felixProtocol {
							return fmt.Errorf("%s route lists as type %d, link %d, protocol %d", t.name, got.Type, got.LinkIndex, got.Protocol)
						}
					}
				}
				if !found {
					return fmt.Errorf("the %s route is missing from the list", t.name)
				}
				if err := netlink.RouteDel(&r); err != nil {
					return fmt.Errorf("delete %s route: %w", t.name, err)
				}
			}
			return nil
		}},
		{"felixroutes-replace-and-duplicate", func() error {
			r := felixRoute("10.42.226.0/26", unix.RTN_BLACKHOLE, 0)
			if err := netlink.RouteReplace(&r); err != nil {
				return fmt.Errorf("replace creates the route: %w", err)
			}
			if err := netlink.RouteReplace(&r); err != nil {
				return fmt.Errorf("replace of an existing route: %w", err)
			}
			if err := netlink.RouteAdd(&r); !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("add of an existing route = %v, want EEXIST", err)
			}
			if err := netlink.RouteDel(&r); err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			if err := netlink.RouteDel(&r); !errors.Is(err, unix.ESRCH) {
				return fmt.Errorf("delete of a missing route = %v, want ESRCH", err)
			}
			return nil
		}},
		{"felixroutes-ipv6-blackhole-on-lo", func() error {
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return err
			}
			r := felixRoute("fd00:42:225::/64", unix.RTN_BLACKHOLE, lo.Attrs().Index)
			if err := netlink.RouteAdd(&r); err != nil {
				return fmt.Errorf("add: %w", err)
			}
			if err := netlink.RouteDel(&r); err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			return nil
		}},
		{"felixroutes-unicast-without-device-fails", func() error {
			r := felixRoute("10.42.227.0/26", unix.RTN_UNICAST, 0)
			if err := netlink.RouteAdd(&r); !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("unicast route without a device = %v, want ENODEV", err)
			}
			return nil
		}},
	}
}
