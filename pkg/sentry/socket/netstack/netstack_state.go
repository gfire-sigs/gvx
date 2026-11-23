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
	"fmt"
	"math/rand"

	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func defaultLinuxIPTables(clock tcpip.Clock, rng *rand.Rand) *stack.IPTables {
	return netfilter.DefaultLinuxTables(clock, rng)
}

func (s *Stack) saveStack() *stack.Stack {
	return s.Stack
}

func (s *Stack) loadStack(ctx context.Context, st *stack.Stack) {
	s.Stack = st
	s.bindStackPolicies()
	if st != nil && !inet.IsNetworkCheckpointRestore(ctx) {
		// The low-level stack restores its RNG before it runs this callback.
		st.ScheduleAfterStackLoad(s.restoreIPTablesCheckpoint)
	}
}

func (s *Stack) afterLoad(context.Context) {
	s.bindStackPolicies()
}

func (s *Stack) restoreIPTablesCheckpoint() {
	st := s.Stack
	install, err := st.PrepareIPTablesCheckpoint(func(tables *stack.IPTables, _ bool) error {
		netfilter.WrapLinuxTableTargets(tables)
		return nil
	})
	if err != nil {
		state.Failf("%v", err)
	}
	if install != nil {
		install()
	} else if st.IPTables() == nil {
		st.SetIPTables(defaultLinuxIPTables(st.Clock(), st.InsecureRNG()))
	}
}

// PrepareNetworkCheckpoint validates the decoded rules of this namespace.
// Only explicit legacy imports may substitute defaults for absent rules.
func (s *Stack) PrepareNetworkCheckpoint(ctx context.Context, mode inet.NetworkCheckpointMode) (*stack.Stack, func(), error) {
	if s == nil || s.Stack == nil {
		return nil, nil, fmt.Errorf("missing saved netstack")
	}
	st := s.Stack
	if err := st.ValidateCheckpointExtensions(); err != nil {
		return nil, nil, err
	}
	install, err := st.PrepareIPTablesCheckpoint(func(tables *stack.IPTables, modified bool) error {
		return netfilter.ValidateIPTablesCheckpoint(ctx, st, tables, modified)
	})
	if err != nil || install != nil {
		return st, install, err
	}
	if mode != inet.ImportLegacyNetworkCheckpoint {
		return nil, nil, fmt.Errorf("missing iptables checkpoint rules")
	}
	if err := netfilter.ValidateIPTablesCheckpoint(ctx, st, nil, false); err != nil {
		return nil, nil, err
	}
	return st, func() {
		st.SetIPTables(defaultLinuxIPTables(st.Clock(), st.InsecureRNG()))
		s.InitConntrackLimit(nil)
		st.EnableIPTablesCheckpoint()
	}, nil
}

// StageRecreatedNetworkCheckpoint puts a legacy replacement on the local
// restore path and enables capture of its new rules.
func (s *Stack) StageRecreatedNetworkCheckpoint() error {
	if s == nil || s.Stack == nil {
		return fmt.Errorf("missing recreated netstack")
	}
	s.Stack.EnableIPTablesCheckpoint()
	s.Stack.PrepareStagedRestore()
	return nil
}

func (s *Stack) bindStackPolicies() {
	if s.Stack != nil {
		s.Stack.SetProxyARPPolicy(s.proxyARPEnabled)
		s.Stack.SetRPFilterPolicy(s.rpFilterPolicy)
		s.restoreBridgeNetfilter()
	}
}
