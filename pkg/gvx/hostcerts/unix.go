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

package hostcerts

import (
	"errors"
	"io/fs"
	"strings"
)

// unixCertFiles and unixCertDirs are the system locations that crypto/x509
// reads on Linux, in its order.
var (
	unixCertFiles = []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Gentoo
		"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL 6
		"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
		"/etc/pki/tls/cacert.pem",                           // OpenELEC
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7
		"/etc/ssl/cert.pem",                                 // Alpine, macOS-like layouts
	}
	unixCertDirs = []string{
		"/etc/ssl/certs",     // SLES 10, SLES 11, Debian
		"/etc/pki/tls/certs", // Fedora, RHEL
	}
)

// collectUnix applies the rule of crypto/x509 on Linux. SSL_CERT_FILE replaces
// files, and SSL_CERT_DIR replaces dirs. It reads the first file that exists,
// and every directory.
func collectUnix(getenv func(string) string, files, dirs []string) ([][]byte, error) {
	explicitFile := getenv("SSL_CERT_FILE")
	if explicitFile != "" {
		files = []string{explicitFile}
	}
	if explicit := getenv("SSL_CERT_DIR"); explicit != "" {
		dirs = strings.Split(explicit, ":")
	}
	var out [][]byte
	var errs []error
	for _, file := range files {
		ders, err := readCertFile(file)
		if err == nil {
			out = append(out, ders...)
			break
		}
		if explicitFile != "" || !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		ders, err := readCertDir(dir)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, ders...)
	}
	return out, errors.Join(errs...)
}
