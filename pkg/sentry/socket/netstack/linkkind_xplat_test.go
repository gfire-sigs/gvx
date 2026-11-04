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
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func newNothing(context.Context, *NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
	return nil, syserr.ErrNotSupported
}

func TestRegisterLinkKindRejectsInvalidKinds(t *testing.T) {
	good := LinkKind{NamePrefix: "t", New: newNothing}
	// -count=2 runs the test twice in one process, so the kind leaves with it.
	const kind = "test-kind"
	RegisterLinkKind(kind, good)
	t.Cleanup(func() { delete(linkKinds, kind) })
	for name, tc := range map[string]struct {
		kind string
		k    LinkKind
	}{
		"empty kind":       {"", good},
		"no creator":       {"test-nocreator", LinkKind{NamePrefix: "t"}},
		"no name prefix":   {"test-noprefix", LinkKind{New: newNothing}},
		"kind of the veth": {"veth", good},
		"kind of bridge":   {"bridge", good},
		"duplicate kind":   {kind, good},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("RegisterLinkKind did not panic")
				}
			}()
			RegisterLinkKind(tc.kind, tc.k)
		})
	}
}

func TestNewRegisteredLinkAnswersNotSupportedForAnUnknownKind(t *testing.T) {
	s := &Stack{}
	if err := s.newRegisteredLink(nil, "no-such-kind", nil, map[uint16]nlmsg.BytesView{}); err != syserr.ErrNotSupported {
		t.Errorf("newRegisteredLink = %v, want ErrNotSupported", err)
	}
}
