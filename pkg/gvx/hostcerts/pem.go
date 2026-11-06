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
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const certBlockType = "CERTIFICATE"

// ParsePEM returns the DER encoding of each certificate in data. It skips a
// block of another type, a block with headers, and a certificate that
// crypto/x509 cannot parse, as x509.CertPool.AppendCertsFromPEM does.
func ParsePEM(data []byte) [][]byte {
	var out [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return out
		}
		if block.Type != certBlockType || len(block.Headers) != 0 {
			continue
		}
		if !validDER(block.Bytes) {
			continue
		}
		out = append(out, block.Bytes)
	}
}

// validDER reports whether crypto/x509 parses der as a certificate.
func validDER(der []byte) bool {
	_, err := x509.ParseCertificate(der)
	return err == nil
}

// encodePEM returns the PEM text of a certificate, ended by a newline.
func encodePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: certBlockType, Bytes: der})
}

// fingerprint is the SHA-256 digest of a DER certificate. Two certificates are
// the same root when their fingerprints are equal.
type fingerprint [sha256.Size]byte

func fingerprintOf(der []byte) fingerprint { return sha256.Sum256(der) }

// derSet is a set of certificates, keyed by fingerprint.
type derSet map[fingerprint]struct{}

func newDERSet(ders [][]byte) derSet {
	set := make(derSet, len(ders))
	for _, der := range ders {
		set[fingerprintOf(der)] = struct{}{}
	}
	return set
}

func (s derSet) has(der []byte) bool {
	_, ok := s[fingerprintOf(der)]
	return ok
}

// missingFrom returns the certificates of ders that set lacks, in order, and
// without a repeat.
func missingFrom(set derSet, ders [][]byte) [][]byte {
	seen := make(derSet, len(ders))
	var out [][]byte
	for _, der := range ders {
		fp := fingerprintOf(der)
		if _, ok := set[fp]; ok {
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, der)
	}
	return out
}

// dedupe returns ders without a repeated certificate, in first-seen order.
func dedupe(ders [][]byte) [][]byte { return missingFrom(nil, ders) }

// readCertFile returns the certificates of one PEM file.
func readCertFile(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePEM(data), nil
}

// readCertDir returns the certificates of every file in a directory, in name
// order. It skips a subdirectory and a broken link. A directory that does not
// exist gives no certificates and no error.
func readCertDir(dir string) ([][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out [][]byte
	var errs []error
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			continue
		}
		ders, err := readCertFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, ders...)
	}
	return out, errors.Join(errs...)
}

// envRoots returns the certificates that the variables SSL_CERT_FILE and
// SSL_CERT_DIR name. dirSep separates the directories of SSL_CERT_DIR.
func envRoots(getenv func(string) string, dirSep string) ([][]byte, error) {
	var out [][]byte
	var errs []error
	if file := getenv("SSL_CERT_FILE"); file != "" {
		ders, err := readCertFile(file)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, ders...)
	}
	if dirs := getenv("SSL_CERT_DIR"); dirs != "" {
		for _, dir := range strings.Split(dirs, dirSep) {
			if dir == "" {
				continue
			}
			ders, err := readCertDir(dir)
			if err != nil {
				errs = append(errs, err)
			}
			out = append(out, ders...)
		}
	}
	return out, errors.Join(errs...)
}
