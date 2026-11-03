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

	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// nestedAttr returns one netlink attribute.
func nestedAttr(typ uint16, data ...byte) nlmsg.BytesView {
	n := 4 + len(data)
	b := []byte{byte(n), byte(n >> 8), byte(typ), byte(typ >> 8)}
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestCheckBridgePortInfo(t *testing.T) {
	tests := []struct {
		name string
		attr nlmsg.BytesView
		want *syserr.Error
	}{
		{"hairpin on", nestedAttr(iflaBrportMode, 1), nil},
		{"hairpin off", nestedAttr(iflaBrportMode, 0), nil},
		{"any non-zero byte is on", nestedAttr(iflaBrportMode, 2), nil},
		{"mode of two bytes", nestedAttr(iflaBrportMode, 1, 1), syserr.ErrInvalidArgument},
		{"another bridge port attribute", nestedAttr(iflaBrportMode+1, 1), syserr.ErrNotSupported},
		{"truncated attribute", nlmsg.BytesView{8, 0, 4}, syserr.ErrInvalidArgument},
	}
	for _, tc := range tests {
		if got := checkBridgePortInfo(tc.attr); got != tc.want {
			t.Errorf("%s: checkBridgePortInfo = %v, want %v", tc.name, got, tc.want)
		}
	}
}
