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

package oci

import (
	"reflect"
	"testing"
)

func TestParseRuntimeConfigExposedPorts(t *testing.T) {
	cfg, err := ParseRuntimeConfig([]byte(`{"config":{"ExposedPorts":{
		"8080/tcp":{}, "53/udp":{}, "443":{}, "80/tcp":{}, "0/tcp":{}, "70000/tcp":{}, "9/sctp":{}, "x/tcp":{}}}}`))
	if err != nil {
		t.Fatalf("ParseRuntimeConfig: %v", err)
	}
	want := []ExposedPort{
		{Port: 53, Protocol: "udp"},
		{Port: 80, Protocol: "tcp"},
		{Port: 443, Protocol: "tcp"},
		{Port: 8080, Protocol: "tcp"},
	}
	if got := cfg.ExposedPortList(); !reflect.DeepEqual(got, want) {
		t.Errorf("ExposedPortList() = %v, want %v (ordered by port, a key without protocol is tcp, invalid keys skipped)", got, want)
	}
}

func TestExposedPortListEmptyWithoutDeclaration(t *testing.T) {
	cfg, err := ParseRuntimeConfig([]byte(`{"config":{}}`))
	if err != nil {
		t.Fatalf("ParseRuntimeConfig: %v", err)
	}
	if got := cfg.ExposedPortList(); len(got) != 0 {
		t.Errorf("ExposedPortList() = %v, want none", got)
	}
}
