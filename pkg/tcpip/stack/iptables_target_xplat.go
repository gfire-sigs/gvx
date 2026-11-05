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

package stack

// An InterfaceTarget is a Target that logs the interfaces of a packet. The
// iptables LOG target needs the names after IN= and OUT=. Target.Action gets
// the packet and the route and no interface name, so checkRule calls
// ActionOnInterfaces instead of Action for a target that implements it.
type InterfaceTarget interface {
	Target

	// ActionOnInterfaces is Action with the names of the interface that
	// received the packet and the interface that sends it. Each name is empty
	// when the hook does not know the interface.
	ActionOnInterfaces(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) (RuleVerdict, int)
}

// runTarget runs the target of a rule that matched.
func runTarget(target Target, pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) (RuleVerdict, int) {
	if t, ok := target.(InterfaceTarget); ok {
		return t.ActionOnInterfaces(pkt, hook, r, addressEP, inNicName, outNicName)
	}
	return target.Action(pkt, hook, r, addressEP)
}
