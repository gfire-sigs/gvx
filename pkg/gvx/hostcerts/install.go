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
	"bytes"
	"encoding/hex"
	"fmt"
	"path"
)

// BundlePaths lists the files that guest programs read as the bundle of trust
// anchors, in the layouts of the common distributions.
var BundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Alpine
	"/etc/ssl/cert.pem",                                 // Alpine, OpenSSL default
	"/etc/pki/tls/certs/ca-bundle.crt",                  // RHEL, Fedora
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL, Fedora
	"/etc/ssl/ca-bundle.pem",                            // SUSE
}

// Directories that hold the source anchors of the update tools.
const (
	// DebianAnchorDir is the source directory of update-ca-certificates. It
	// reads only the files with the suffix .crt.
	DebianAnchorDir = "/usr/local/share/ca-certificates"
	// RedHatAnchorDir is the source directory of update-ca-trust.
	RedHatAnchorDir = "/etc/pki/ca-trust/source/anchors"
	// anchorPrefix starts the name of every anchor file that Install writes.
	anchorPrefix = "gvx-host-"
)

// DefaultBundlePath is the bundle that Install creates in an image that has no
// bundle.
const DefaultBundlePath = "/etc/ssl/certs/ca-certificates.crt"

// GuestFS is the part of the guest file system that Install uses.
type GuestFS interface {
	// ReadFile returns the content of a file and follows a symbolic link. The
	// result found is false, with no error, when the path does not exist.
	ReadFile(path string) (data []byte, found bool, err error)
	// DirExists reports whether the path is a directory.
	DirExists(path string) (bool, error)
	// WriteFile replaces the content of a file, or creates it with the mode
	// 0644, and creates the missing directories. It follows a symbolic link.
	WriteFile(path string, data []byte) error
}

// Install makes the guest trust roots, as DER certificates.
//
// It never replaces a bundle of the image. It adds the roots that the bundle
// lacks to each bundle in BundlePaths that exists. When the image has no
// bundle, it creates DefaultBundlePath. It also writes each root that no
// bundle of the image holds as a file in the anchor directory of the
// distribution, so that update-ca-certificates and update-ca-trust keep the
// root. The files go to RedHatAnchorDir when it exists, and to DebianAnchorDir
// when it exists or RedHatAnchorDir does not.
//
// A path for which covered returns true is not read and not written: the
// caller mounts something there. covered must report true for every path
// below a mount point too.
func Install(guest GuestFS, roots [][]byte, covered func(path string) bool) error {
	roots = dedupe(roots)
	if len(roots) == 0 {
		return nil
	}
	if covered == nil {
		covered = func(string) bool { return false }
	}

	// The first pass finds the bundles and the roots of the image. The second
	// pass reads each bundle again, because two paths can name one file.
	var present []string
	imageRoots := derSet{}
	for _, bundle := range BundlePaths {
		if covered(bundle) {
			continue
		}
		data, found, err := guest.ReadFile(bundle)
		if err != nil {
			return fmt.Errorf("hostcerts: read %s: %w", bundle, err)
		}
		if !found {
			continue
		}
		present = append(present, bundle)
		for _, der := range ParsePEM(data) {
			imageRoots[fingerprintOf(der)] = struct{}{}
		}
	}

	for _, bundle := range present {
		data, _, err := guest.ReadFile(bundle)
		if err != nil {
			return fmt.Errorf("hostcerts: read %s: %w", bundle, err)
		}
		if err := writeMissing(guest, bundle, data, roots); err != nil {
			return err
		}
	}
	if len(present) == 0 && !covered(DefaultBundlePath) {
		if err := writeMissing(guest, DefaultBundlePath, nil, roots); err != nil {
			return err
		}
	}

	extra := missingFrom(imageRoots, roots)
	if len(extra) == 0 {
		return nil
	}
	dirs, err := anchorDirs(guest)
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		for _, der := range extra {
			file := path.Join(dir, anchorName(der))
			if covered(file) {
				continue
			}
			if err := guest.WriteFile(file, encodePEM(der)); err != nil {
				return fmt.Errorf("hostcerts: write %s: %w", file, err)
			}
		}
	}
	return nil
}

// writeMissing appends the roots that the bundle data lacks, and writes the
// file only when it has something to add.
func writeMissing(guest GuestFS, bundle string, data []byte, roots [][]byte) error {
	missing := missingFrom(newDERSet(ParsePEM(data)), roots)
	if len(missing) == 0 {
		return nil
	}
	merged := bytes.Clone(data)
	if len(merged) > 0 && !bytes.HasSuffix(merged, []byte("\n")) {
		merged = append(merged, '\n')
	}
	for _, der := range missing {
		merged = append(merged, encodePEM(der)...)
	}
	if err := guest.WriteFile(bundle, merged); err != nil {
		return fmt.Errorf("hostcerts: write %s: %w", bundle, err)
	}
	return nil
}

// anchorDirs returns the anchor directories that Install fills.
func anchorDirs(guest GuestFS) ([]string, error) {
	redHat, err := guest.DirExists(RedHatAnchorDir)
	if err != nil {
		return nil, fmt.Errorf("hostcerts: look up %s: %w", RedHatAnchorDir, err)
	}
	var dirs []string
	if redHat {
		dirs = append(dirs, RedHatAnchorDir)
	}
	debian, err := guest.DirExists(DebianAnchorDir)
	if err != nil {
		return nil, fmt.Errorf("hostcerts: look up %s: %w", DebianAnchorDir, err)
	}
	if debian || !redHat {
		dirs = append(dirs, DebianAnchorDir)
	}
	return dirs, nil
}

// anchorName returns the file name of an anchor. It derives from the
// fingerprint, so a second run writes the same file.
func anchorName(der []byte) string {
	fp := fingerprintOf(der)
	return anchorPrefix + hex.EncodeToString(fp[:8]) + ".crt"
}
