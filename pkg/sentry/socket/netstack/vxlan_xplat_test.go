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
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/link/vxlan"
)

func vxlanData(extra map[uint16]nlmsg.BytesView) map[uint16]nlmsg.BytesView {
	data := map[uint16]nlmsg.BytesView{iflaVxlanID: binary.NativeEndian.AppendUint32(nil, 42)}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// TestVxlanLimitAttribute reads IFLA_VXLAN_LIMIT. Linux stores it in
// vxlan->cfg.addrmax, and the value 0 means no limit.
func TestVxlanLimitAttribute(t *testing.T) {
	tests := []struct {
		name    string
		extra   map[uint16]nlmsg.BytesView
		want    uint32
		wantErr *syserr.Error
	}{
		{"absent means no limit", nil, 0, nil},
		{"zero means no limit", map[uint16]nlmsg.BytesView{iflaVxlanLimit: binary.NativeEndian.AppendUint32(nil, 0)}, 0, nil},
		{"small limit", map[uint16]nlmsg.BytesView{iflaVxlanLimit: binary.NativeEndian.AppendUint32(nil, 5)}, 5, nil},
		{"limit above the old fixed table size", map[uint16]nlmsg.BytesView{iflaVxlanLimit: binary.NativeEndian.AppendUint32(nil, 1<<20)}, 1 << 20, nil},
		{"largest limit", map[uint16]nlmsg.BytesView{iflaVxlanLimit: binary.NativeEndian.AppendUint32(nil, 1<<32-1)}, 1<<32 - 1, nil},
		{"short attribute", map[uint16]nlmsg.BytesView{iflaVxlanLimit: {1, 0}}, 0, syserr.ErrInvalidArgument},
	}
	for _, tc := range tests {
		cfg, err := parseVxlanConfig(&NewLinkRequest{Data: vxlanData(tc.extra)})
		if err != tc.wantErr {
			t.Errorf("%s: error = %v, want %v", tc.name, err, tc.wantErr)
			continue
		}
		if err == nil && cfg.Limit != tc.want {
			t.Errorf("%s: Limit = %d, want %d", tc.name, cfg.Limit, tc.want)
		}
	}
}

// TestFullFDBAnswersENOSPC maps the error of a full table to the errno that
// vxlan_fdb_create returns.
func TestFullFDBAnswersENOSPC(t *testing.T) {
	if got := vxlanSyserr(vxlan.ErrNoSpace); got != syserr.ErrNoSpace {
		t.Errorf("vxlanSyserr(ErrNoSpace) = %v, want ENOSPC", got)
	}
}
