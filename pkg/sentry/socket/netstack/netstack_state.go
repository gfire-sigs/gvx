// Copyright 2021 The gVisor Authors.
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
	"context"
	"math/rand"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

type iptablesCheckpointRestoreKey struct{}

// WithIPTablesCheckpointRestore enables iptables capture after restore, even
// when the input checkpoint has no iptables snapshot.
func WithIPTablesCheckpointRestore(ctx gvcontext.Context) gvcontext.Context {
	return gvcontext.WithValue(ctx, iptablesCheckpointRestoreKey{}, true)
}

func defaultLinuxIPTables(clock tcpip.Clock, rng *rand.Rand) *stack.IPTables {
	return netfilter.DefaultLinuxTables(clock, rng)
}

func (s *Stack) saveStack() *stack.Stack {
	return s.Stack
}

func (s *Stack) loadStack(ctx context.Context, st *stack.Stack) {
	s.Stack = st
	s.bindStackPolicies()
	if st != nil {
		// The low-level stack restores its RNG before it runs this callback.
		capture := ctx.Value(iptablesCheckpointRestoreKey{}) == true
		st.ScheduleAfterStackLoad(func() { s.restoreIPTablesCheckpoint(capture) })
	}
}

func (s *Stack) afterLoad(context.Context) {
	s.bindStackPolicies()
}

func (s *Stack) restoreIPTablesCheckpoint(capture bool) {
	st := s.Stack
	restored := st.RestoreIPTablesCheckpoint()
	if restored {
		netfilter.WrapLinuxTableTargets(st.IPTables())
	} else if st.IPTables() == nil {
		st.SetIPTables(defaultLinuxIPTables(st.Clock(), st.InsecureRNG()))
		if capture {
			s.InitConntrackLimit(nil)
		}
	}
	if capture && !restored {
		st.EnableIPTablesCheckpoint()
	}
}

func (s *Stack) bindStackPolicies() {
	if s.Stack != nil {
		s.Stack.SetProxyARPPolicy(s.proxyARPEnabled)
		s.Stack.SetRPFilterPolicy(s.rpFilterPolicy)
		s.restoreBridgeNetfilter()
	}
}
