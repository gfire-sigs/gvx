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

import (
	"bytes"
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/syserr"
)

// setRequest builds a request of SO_IP_SET: the operation, the version, the
// words in between, and the 32 bytes of the union ip_set_name_index.
func setRequest(op, version uint32, middle []uint32, name string, index uint16) []byte {
	buf := binary.LittleEndian.AppendUint32(nil, op)
	buf = binary.LittleEndian.AppendUint32(buf, version)
	for _, w := range middle {
		buf = binary.LittleEndian.AppendUint32(buf, w)
	}
	field := make([]byte, ipset.MaxNameLen)
	copy(field, name)
	if name == "" {
		binary.LittleEndian.PutUint16(field, index)
	}
	return append(buf, field...)
}

func requestName(reply []byte, off int) string {
	field := reply[off : off+ipset.MaxNameLen]
	if end := bytes.IndexByte(field, 0); end >= 0 {
		field = field[:end]
	}
	return string(field)
}

func TestIPSetSockOptVersion(t *testing.T) {
	req := binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, ipSetOpVersion), 0)
	reply, err := ipSetGet(nil, req)
	if err != nil {
		t.Fatalf("IP_SET_OP_VERSION = %v, want nil", err)
	}
	if got := binary.LittleEndian.Uint32(reply[4:]); got != ipset.ProtocolVersion {
		t.Errorf("version = %d, want %d", got, ipset.ProtocolVersion)
	}
	if got := binary.LittleEndian.Uint32(reply[0:]); got != ipSetOpVersion {
		t.Errorf("operation of the reply = 0x%x, want 0x%x", got, ipSetOpVersion)
	}
	if _, err := ipSetGet(nil, append(req, 0)); err != syserr.ErrInvalidArgument {
		t.Errorf("IP_SET_OP_VERSION with a longer request = %v, want EINVAL", err)
	}
}

func TestIPSetSockOptResolvesNamesAndIndexes(t *testing.T) {
	env := newSetEnv(t)
	env.create(t, "first", "hash:ip", ipset.FamilyIPv4, nil)
	id := env.create(t, "second", "hash:net", ipset.FamilyIPv6, nil)

	t.Run("get by name", func(t *testing.T) {
		reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetByName, ipset.ProtocolVersion, nil, "second", 0))
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_BYNAME = %v, want nil", err)
		}
		if got := ipset.ID(binary.LittleEndian.Uint16(reply[8:])); got != id {
			t.Errorf("index = %d, want %d", got, id)
		}
	})
	t.Run("get by name of an unknown set", func(t *testing.T) {
		reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetByName, ipset.ProtocolVersion, nil, "missing", 0))
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_BYNAME = %v, want nil", err)
		}
		if got := ipset.ID(binary.LittleEndian.Uint16(reply[8:])); got != ipset.InvalidID {
			t.Errorf("index = %d, want the invalid index %d", got, ipset.InvalidID)
		}
	})
	t.Run("get by name without name terminator", func(t *testing.T) {
		req := setRequest(ipSetOpGetByName, ipset.ProtocolVersion, nil, "second", 0)
		for i := 8 + len("second"); i < len(req); i++ {
			req[i] = 'x'
		}
		reply, err := ipSetGet(env.reg, req)
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_BYNAME = %v, want nil", err)
		}
		if got := ipset.ID(binary.LittleEndian.Uint16(reply[8:])); got != ipset.InvalidID {
			t.Errorf("a name of 31 other bytes resolved to index %d", got)
		}
	})
	t.Run("get family and index by name", func(t *testing.T) {
		reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetFName, ipset.ProtocolVersion, []uint32{0}, "second", 0))
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_FNAME = %v, want nil", err)
		}
		if got := ipset.ID(binary.LittleEndian.Uint16(reply[12:])); got != id {
			t.Errorf("index = %d, want %d", got, id)
		}
		if got := binary.LittleEndian.Uint32(reply[8:]); got != uint32(ipset.FamilyIPv6) {
			t.Errorf("family = %d, want %d", got, ipset.FamilyIPv6)
		}
	})
	t.Run("get family of an unknown set keeps the family field", func(t *testing.T) {
		reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetFName, ipset.ProtocolVersion, []uint32{99}, "missing", 0))
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_FNAME = %v, want nil", err)
		}
		if got := ipset.ID(binary.LittleEndian.Uint16(reply[12:])); got != ipset.InvalidID {
			t.Errorf("index = %d, want the invalid index", got)
		}
		if got := binary.LittleEndian.Uint32(reply[8:]); got != 99 {
			t.Errorf("family = %d, want the request value 99", got)
		}
	})
	t.Run("get by index", func(t *testing.T) {
		reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetByIndex, ipset.ProtocolVersion, nil, "", uint16(id)))
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_BYINDEX = %v, want nil", err)
		}
		if got := requestName(reply, 8); got != "second" {
			t.Errorf("name = %q, want %q", got, "second")
		}
	})
	t.Run("get by index of a free slot", func(t *testing.T) {
		reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetByIndex, ipset.ProtocolVersion, nil, "", 200))
		if err != nil {
			t.Fatalf("IP_SET_OP_GET_BYINDEX = %v, want nil", err)
		}
		if got := requestName(reply, 8); got != "" {
			t.Errorf("name = %q, want empty", got)
		}
	})
	t.Run("get by index beyond the table", func(t *testing.T) {
		req := setRequest(ipSetOpGetByIndex, ipset.ProtocolVersion, nil, "", uint16(env.reg.Len()))
		if _, err := ipSetGet(env.reg, req); err != syserr.ErrInvalidArgument {
			t.Errorf("IP_SET_OP_GET_BYINDEX = %v, want EINVAL", err)
		}
	})
}

func TestIPSetSockOptWithoutSets(t *testing.T) {
	reply, err := ipSetGet(nil, setRequest(ipSetOpGetByName, ipset.ProtocolVersion, nil, "any", 0))
	if err != nil {
		t.Fatalf("IP_SET_OP_GET_BYNAME = %v, want nil", err)
	}
	if got := ipset.ID(binary.LittleEndian.Uint16(reply[8:])); got != ipset.InvalidID {
		t.Errorf("index = %d, want the invalid index", got)
	}
	reply, err = ipSetGet(nil, setRequest(ipSetOpGetByIndex, ipset.ProtocolVersion, nil, "", 3))
	if err != nil {
		t.Fatalf("IP_SET_OP_GET_BYINDEX = %v, want nil", err)
	}
	if got := requestName(reply, 8); got != "" {
		t.Errorf("name = %q, want empty", got)
	}
}

func TestIPSetSockOptRejectsBadRequests(t *testing.T) {
	env := newSetEnv(t)
	env.create(t, "a", "hash:ip", ipset.FamilyIPv4, nil)
	good := setRequest(ipSetOpGetByName, ipset.ProtocolVersion, nil, "a", 0)
	tests := []struct {
		name string
		req  []byte
		want *syserr.Error
	}{
		{"shorter than the version header", good[:6], syserr.ErrInvalidArgument},
		{"protocol older than the minimum", setRequest(ipSetOpGetByName, ipset.ProtocolVersionMin-1, nil, "a", 0), syserr.ErrProtocol},
		{"by name with the size of by family", setRequest(ipSetOpGetByName, ipset.ProtocolVersion, []uint32{0}, "a", 0), syserr.ErrInvalidArgument},
		{"by family with the size of by name", setRequest(ipSetOpGetFName, ipset.ProtocolVersion, nil, "a", 0), syserr.ErrInvalidArgument},
		{"by index with a short request", setRequest(ipSetOpGetByIndex, ipset.ProtocolVersion, nil, "", 0)[:20], syserr.ErrInvalidArgument},
		{"unknown operation", setRequest(5, ipset.ProtocolVersion, nil, "a", 0), syserr.ErrInvalidDataMessage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ipSetGet(env.reg, tc.req); err != tc.want {
				t.Errorf("ipSetGet = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIPSetSockOptAcceptsTheMinimumProtocol(t *testing.T) {
	env := newSetEnv(t)
	id := env.create(t, "a", "hash:ip", ipset.FamilyIPv4, nil)
	reply, err := ipSetGet(env.reg, setRequest(ipSetOpGetByName, ipset.ProtocolVersionMin, nil, "a", 0))
	if err != nil {
		t.Fatalf("IP_SET_OP_GET_BYNAME with the minimum version = %v, want nil", err)
	}
	if got := ipset.ID(binary.LittleEndian.Uint16(reply[8:])); got != id {
		t.Errorf("index = %d, want %d", got, id)
	}
}
