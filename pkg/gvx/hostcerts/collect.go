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

// Package hostcerts reads the root certificates that the host trusts and
// installs them into the file system of a guest.
//
// The package exists for hosts behind a proxy that inspects TLS, and for hosts
// that use a private registry. The proxy and the registry have certificates
// that a private root signs, and only the host knows that root.
//
// Collect reads the host side. It must run before the host lockdown, because
// it opens host files and, on macOS, starts a child process. Install writes
// the guest side.
package hostcerts

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Collect returns the root certificates that the host trusts, as DER, without
// a repeated certificate. The sources are:
//
//   - Linux: the file that SSL_CERT_FILE names, or else the first system
//     bundle that Go reads, and the directories of SSL_CERT_DIR, or else the
//     system certificate directories. Go uses the same rule.
//   - macOS: the System and SystemRootCertificates keychains and the login
//     keychain, filtered by the SSL trust settings of the user, admin, and
//     system domains.
//   - Windows: the ROOT system store.
//
// On macOS and Windows, the files that SSL_CERT_FILE and SSL_CERT_DIR name add
// roots. A source that fails gives a line on warnings, when warnings is not
// nil. Collect returns an error when no source gives a certificate.
func Collect(ctx context.Context, warnings io.Writer) ([][]byte, error) {
	ders, err := collectSystem(ctx)
	roots := dedupe(ders)
	if len(roots) == 0 {
		return nil, errors.Join(errors.New("hostcerts: the host has no root certificate to copy"), err)
	}
	if err != nil && warnings != nil {
		_, _ = fmt.Fprintf(warnings, "gvx: warning: a source of host root certificates failed: %v\n", err)
	}
	return roots, nil
}
