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

//go:build windows

package hostcerts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// errCryptNotFound is CRYPT_E_NOT_FOUND. CertEnumCertificatesInStore returns
// it after the last certificate.
const errCryptNotFound = syscall.Errno(0x80092004)

// collectSystem reads the ROOT system store, as crypto/x509 does. The store
// holds the trust anchors of Windows, the roots that a group policy adds, and
// the roots that the user added. It leaves out the CA store, because that store
// holds intermediate certificates, which are not trust anchors.
func collectSystem(_ context.Context) ([][]byte, error) {
	var errs []error
	ders, err := readSystemStore("ROOT")
	if err != nil {
		errs = append(errs, err)
	}
	extra, err := envRoots(os.Getenv, ";")
	if err != nil {
		errs = append(errs, err)
	}
	return append(ders, extra...), errors.Join(errs...)
}

func readSystemStore(name string) ([][]byte, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	store, err := syscall.CertOpenSystemStore(0, namePtr)
	if err != nil {
		return nil, fmt.Errorf("hostcerts: open the %s system store: %w", name, err)
	}
	var ders [][]byte
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			if errors.Is(err, errCryptNotFound) {
				break
			}
			return ders, errors.Join(fmt.Errorf("hostcerts: read the %s system store: %w", name, err), syscall.CertCloseStore(store, 0))
		}
		if cert == nil {
			break
		}
		// Copy the bytes, because the store frees the context at the next call.
		der := make([]byte, cert.Length)
		copy(der, unsafe.Slice(cert.EncodedCert, cert.Length))
		if validDER(der) {
			ders = append(ders, der)
		}
	}
	if err := syscall.CertCloseStore(store, 0); err != nil {
		return ders, fmt.Errorf("hostcerts: close the %s system store: %w", name, err)
	}
	return ders, nil
}
