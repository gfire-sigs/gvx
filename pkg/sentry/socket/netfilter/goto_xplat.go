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

package netfilter

import "z.gfire.dev/gvx/pkg/tcpip/stack"

// IPT_F_GOTO is the flag of struct ipt_ip that turns the jump of a rule into a
// goto. ip6tables uses linux.IP6T_F_GOTO for the same flag.
const iptFGoto = 0x02

// markGoto makes the jump target a goto when the entry sets the goto flag.
// A goto enters the chain without a return address, so the end of that chain
// returns to the caller of the current chain. The flag has no effect on
// any other target.
func markGoto(target stack.Target, flags, gotoFlag uint8) {
	if jump, ok := target.(*JumpTarget); ok && flags&gotoFlag != 0 {
		jump.Goto = true
	}
}

// gotoFlags returns the goto flag of the entry for a rule, or 0 when the rule
// is not a goto.
func gotoFlags(target stack.Target, gotoFlag uint8) uint8 {
	if jump, ok := target.(*JumpTarget); ok && jump.Goto {
		return gotoFlag
	}
	return 0
}
