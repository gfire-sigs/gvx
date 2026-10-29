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
	"embed"
	"slices"
	"strings"
)

// noAssertion is the SPDX identifier of a text that no reference matches.
const noAssertion = "NOASSERTION"

// referenceFiles holds the well-known license texts that the matcher uses.
// The texts serve for matching only; the printed texts come from the modules.
//
//go:embed spdx/*.txt
var referenceFiles embed.FS

// referenceFileIDs maps each reference file to its SPDX identifier.
// BSD-3-Clause has four files. The SPDX text names the copyright holder in
// general terms. The other three name the holder of a common copy: the Go project,
// Google Inc., and the notice that Google puts in its source headers.
var referenceFileIDs = []struct{ file, id string }{
	{"Apache-2.0.txt", "Apache-2.0"},
	{"BSD-2-Clause.txt", "BSD-2-Clause"},
	{"BSD-3-Clause.txt", "BSD-3-Clause"},
	{"BSD-3-Clause-go.txt", "BSD-3-Clause"},
	{"BSD-3-Clause-google-inc.txt", "BSD-3-Clause"},
	{"BSD-3-Clause-notice.txt", "BSD-3-Clause"},
	{"BSD-3-Clause-notice-file.txt", "BSD-3-Clause"},
	{"ISC.txt", "ISC"},
	{"MIT.txt", "MIT"},
	{"MPL-2.0.txt", "MPL-2.0"},
}

// reference is one well-known license text in matching form.
type reference struct {
	id   string
	form string
}

// newReference returns the reference for id and the license text.
func newReference(id, text string) reference {
	return reference{id: id, form: matchForm(text)}
}

// loadReferences returns the embedded reference texts.
func loadReferences() ([]reference, error) {
	refs := make([]reference, 0, len(referenceFileIDs))
	for _, rf := range referenceFileIDs {
		data, err := referenceFiles.ReadFile("spdx/" + rf.file)
		if err != nil {
			return nil, err
		}
		refs = append(refs, newReference(rf.id, string(data)))
	}
	return refs, nil
}

// spdxExpression returns the SPDX expression of a license text. A reference matches
// when the text contains the reference in matching form. The identifiers of all
// matching references join with AND, because the text carries each license.
// A text with no matching reference yields noAssertion.
func spdxExpression(text string, refs []reference) string {
	form := matchForm(text)
	var ids []string
	for _, ref := range refs {
		if ref.form != "" && strings.Contains(form, ref.form) {
			ids = appendDistinct(ids, ref.id)
		}
	}
	if len(ids) == 0 {
		return noAssertion
	}
	slices.Sort(ids)
	return strings.Join(ids, " AND ")
}
