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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type textReplacement struct {
	label string
	old   string
	new   string
}

func applyReplacements(fileLabel, src string, reps []textReplacement) (string, error) {
	out := src
	for _, r := range reps {
		count := strings.Count(out, r.old)
		if count != 1 {
			return "", fmt.Errorf("slimlink: patch %s (%s): matched %d times, want 1", fileLabel, r.label, count)
		}
		out = strings.Replace(out, r.old, r.new, 1)
	}
	return out, nil
}

// patchDeadcodeSource patches GOROOT/src/cmd/link/internal/ld/deadcode.go so
// name-only R_USENAMEDMETHOD("Methods") relocations do not falsely mark
// reflect iterator Methods() implementations (including promoted methods on
// types embedding reflect.Value or reflect.Type) reachable and flip
// reflectSeen across the entire binary.
//
// Soundness contract: direct calls to reflect.Type.Methods / reflect.Value.Methods
// and concrete interface calls remain reachable via flood() and d.ifaceMethod.
// Programs that invoke reflect's iterator Methods() exclusively through a
// generic type-parameter interface or via reflect.Value.MethodByName("Methods")
// must disable -fix-reflect-methods.
func patchDeadcodeSource(src string) (string, error) {
	reps := []textReplacement{
		{
			label: "import os",
			old: `	"strings"
	"unicode"
)`,
			new: `	"os"
	"strings"
	"unicode"
)

var slimFixReflectMethods = os.Getenv("GVX_SLIMLINK_FIX_REFLECT_METHODS") == "1"`,
		},
		{
			label: "guard reflect Methods generic match",
			old: `		for _, m := range d.markableMethods {
			if (d.reflectSeen && (m.isExported() || d.dynlink)) || d.ifaceMethod[m.m] || d.genericIfaceMethod[m.m.name] {
				d.markMethod(m)
			} else {
				rem = append(rem, m)
			}
		}`,
			new: `		for _, m := range d.markableMethods {
			genericMatch := d.genericIfaceMethod[m.m.name]
			if slimFixReflectMethods && genericMatch && m.m.name == "Methods" {
				typName := d.ldr.SymName(m.m.typ)
				if typName == "type:func() iter.Seq[reflect.Method]" ||
					typName == "type:func() iter.Seq2[reflect.Method,reflect.Value]" {
					genericMatch = false
				}
			}
			if (d.reflectSeen && (m.isExported() || d.dynlink)) || d.ifaceMethod[m.m] || genericMatch {
				d.markMethod(m)
			} else {
				rem = append(rem, m)
			}
		}`,
		},
	}
	return applyReplacements("deadcode.go", src, reps)
}

func computePatchKey(goVersion, hostOS, hostArch, deadcodePatched string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("slimlink-dce-v1\n"))
	_, _ = h.Write([]byte(goVersion + "\n" + hostOS + "/" + hostArch + "\n"))
	_, _ = h.Write([]byte(deadcodePatched))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
