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
	"fmt"

	"github.com/vishvananda/netlink"
)

// The rpfilter checks read and write net/ipv4/conf/{all,default,<link>}/rp_filter
// and check the rules of net/ipv4/devinet.c: each file stores an integer, a
// write to default reaches the links that have no value of their own, a write to
// all reaches no link, a new link starts with the default, and a new network
// namespace inherits all and default from the root namespace.

const (
	rpAll     = "/proc/sys/net/ipv4/conf/all/rp_filter"
	rpDefault = "/proc/sys/net/ipv4/conf/default/rp_filter"
)

func rpLink(name string) string { return "/proc/sys/net/ipv4/conf/" + name + "/rp_filter" }

// expectValues checks the values of several files. The arguments are
// path/value pairs.
func expectValues(pairs ...string) error {
	for i := 0; i < len(pairs); i += 2 {
		if err := expectValue(pairs[i], pairs[i+1]); err != nil {
			return err
		}
	}
	return nil
}

// addVeth creates a veth pair in the namespace of the calling thread.
func addVeth(name, peer string) error {
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}); err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	return nil
}

// delLink deletes the link with the name.
func delLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

// rpFilterChecks checks the rp_filter files in the root namespace and in a
// child namespace.
func rpFilterChecks() []check {
	return []check{
		{"rpfilter-starts-at-zero", func() error {
			return expectValues(rpAll, "0", rpDefault, "0", rpLink("lo"), "0")
		}},
		{"rpfilter-keeps-any-integer", func() error {
			for _, p := range []string{rpAll, rpDefault, rpLink("lo")} {
				for _, v := range []string{"1", "2", "0", "5", "-1", "2147483647"} {
					if err := writeAndExpect(p, v+"\n", v); err != nil {
						return err
					}
				}
				if err := writeAndExpect(p, "  2  ", "2"); err != nil {
					return err
				}
				for _, bad := range []string{"abc\n", "1.5\n", "99999999999\n"} {
					if err := rejectValue(p, bad); err != nil {
						return err
					}
				}
				if err := writeValue(p, "0\n"); err != nil {
					return err
				}
			}
			return nil
		}},
		{"rpfilter-all-changes-no-link", func() error {
			if err := writeValue(rpAll, "1\n"); err != nil {
				return err
			}
			if err := expectValues(rpAll, "1", rpDefault, "0", rpLink("lo"), "0"); err != nil {
				return err
			}
			return writeValue(rpAll, "0\n")
		}},
		{"rpfilter-new-link-starts-with-the-default", func() error {
			if err := writeAndExpect(rpDefault, "2\n", "2"); err != nil {
				return err
			}
			if err := addVeth("rpa0", "rpa1"); err != nil {
				return err
			}
			return expectValues(rpLink("rpa0"), "2", rpLink("rpa1"), "2", rpAll, "0")
		}},
		{"rpfilter-default-reaches-links-without-a-value", func() error {
			if err := writeValue(rpDefault, "1\n"); err != nil {
				return err
			}
			// lo got its value of 0 in an earlier check and keeps it.
			return expectValues(rpLink("rpa0"), "1", rpLink("rpa1"), "1", rpLink("lo"), "0", rpDefault, "1")
		}},
		{"rpfilter-link-keeps-the-value-that-the-guest-wrote", func() error {
			if err := writeAndExpect(rpLink("rpa0"), "2\n", "2"); err != nil {
				return err
			}
			if err := writeValue(rpDefault, "0\n"); err != nil {
				return err
			}
			// rpa1 follows the default, and rpa0 does not.
			return expectValues(rpLink("rpa0"), "2", rpLink("rpa1"), "0", rpLink("lo"), "0")
		}},
		{"rpfilter-removed-link-loses-its-value", func() error {
			if err := writeValue(rpDefault, "2\n"); err != nil {
				return err
			}
			if err := delLink("rpa0"); err != nil {
				return err
			}
			if err := addVeth("rpa0", "rpb0"); err != nil {
				return err
			}
			if err := expectValue(rpLink("rpa0"), "2"); err != nil {
				return fmt.Errorf("the new link rpa0: %w", err)
			}
			return writeValue(rpDefault, "0\n")
		}},
		{"rpfilter-new-namespace-inherits-all-and-default", func() error {
			if err := writeValue(rpAll, "1\n"); err != nil {
				return err
			}
			if err := writeValue(rpDefault, "2\n"); err != nil {
				return err
			}
			return inNewNetns(func() error {
				return expectValues(rpAll, "1", rpDefault, "2")
			})
		}},
		{"rpfilter-namespaces-are-independent", func() error {
			child, err := newNsThread()
			if err != nil {
				return err
			}
			defer child.close()
			if err := child.do(func() error {
				if err := writeAndExpect(rpAll, "0\n", "0"); err != nil {
					return err
				}
				return writeAndExpect(rpDefault, "5\n", "5")
			}); err != nil {
				return err
			}
			if err := expectValues(rpAll, "1", rpDefault, "2"); err != nil {
				return fmt.Errorf("the root namespace after writes in a child: %w", err)
			}
			if err := writeValue(rpAll, "2\n"); err != nil {
				return err
			}
			if err := writeValue(rpDefault, "0\n"); err != nil {
				return err
			}
			return child.do(func() error {
				return expectValues(rpAll, "0", rpDefault, "5")
			})
		}},
		{"rpfilter-ordinary-user-reads-but-cannot-write", func() error {
			child, err := newThread(false, true)
			if err != nil {
				return err
			}
			defer child.close()
			return child.do(func() error {
				if err := expectValue(rpAll, "2"); err != nil {
					return fmt.Errorf("an ordinary user reads the file: %w", err)
				}
				if err := writeValue(rpAll, "0\n"); err == nil {
					return fmt.Errorf("an ordinary user wrote %s", rpAll)
				}
				return nil
			})
		}},
	}
}
