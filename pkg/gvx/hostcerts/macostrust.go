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
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The macOS trust settings come from `security trust-settings-export`. The
// command writes one property list for each domain. The list maps the SHA-1
// fingerprint of a certificate to its trust settings. This file parses the
// list and applies the rules of the Security framework for the SSL policy. It
// has no build tag, so every platform can test it.

// Values of kSecTrustSettingsResult.
const (
	trustSettingsResultTrustRoot   = 1
	trustSettingsResultTrustAsRoot = 2
	trustSettingsResultDeny        = 3
)

// sslServerOID is the DER content of the object identifier of the SSL server
// policy, 1.2.840.113635.100.1.3.
var sslServerOID = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x01, 0x03}

// trustSetting is one entry of the array trustSettings of a certificate.
type trustSetting struct {
	// policyName and policyOID name the policy. Both are empty when the entry
	// applies to every policy.
	policyName string
	policyOID  []byte
	// restricted is true when the entry applies to one application or one host
	// name only.
	restricted bool
	result     int
}

// appliesToSSL reports whether the entry covers the SSL server policy for
// every application and every host name.
func (s trustSetting) appliesToSSL() bool {
	if s.restricted {
		return false
	}
	if s.policyName == "" && len(s.policyOID) == 0 {
		return true
	}
	if s.policyName != "" {
		return s.policyName == "sslServer"
	}
	return bytes.Equal(s.policyOID, sslServerOID)
}

// trustEntry holds the trust settings of one certificate in one domain.
type trustEntry struct {
	settings []trustSetting
}

// trustList maps an upper-case SHA-1 fingerprint to the entry of that
// certificate.
type trustList map[string]trustEntry

type trustVerdict int

const (
	trustUndecided trustVerdict = iota
	trustAccepted
	trustDenied
)

// verdict applies the trust settings to the SSL server policy. An entry
// without settings, or with an empty array, trusts the certificate for every
// policy. The result TrustRoot is valid for a self-signed certificate only.
func (e trustEntry) verdict(selfSigned bool) trustVerdict {
	if len(e.settings) == 0 {
		return acceptRoot(selfSigned)
	}
	for _, s := range e.settings {
		if !s.appliesToSSL() {
			continue
		}
		switch s.result {
		case trustSettingsResultDeny:
			return trustDenied
		case trustSettingsResultTrustRoot:
			if selfSigned {
				return trustAccepted
			}
		case trustSettingsResultTrustAsRoot:
			return trustAccepted
		}
	}
	return trustUndecided
}

func acceptRoot(selfSigned bool) trustVerdict {
	if selfSigned {
		return trustAccepted
	}
	return trustUndecided
}

// trustedForSSL reports whether the lists trust der for TLS servers. The lists
// go in order of precedence: user, admin, system. The first list that decides
// wins. A certificate that no list names is not trusted.
func trustedForSSL(lists []trustList, der []byte) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)
	sum := sha1.Sum(der)
	key := strings.ToUpper(hex.EncodeToString(sum[:]))
	for _, list := range lists {
		entry, ok := list[key]
		if !ok {
			continue
		}
		switch entry.verdict(selfSigned) {
		case trustAccepted:
			return true
		case trustDenied:
			return false
		}
	}
	return false
}

// parseTrustList parses the property list of `security trust-settings-export`.
func parseTrustList(data []byte) (trustList, error) {
	root, err := parsePlist(data)
	if err != nil {
		return nil, err
	}
	top, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("hostcerts: the trust settings list is not a dictionary")
	}
	entries, ok := top["trustList"].(map[string]any)
	if !ok {
		return nil, errors.New("hostcerts: the trust settings list has no trustList dictionary")
	}
	list := make(trustList, len(entries))
	for fingerprint, raw := range entries {
		dict, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("hostcerts: the trust settings of %s are not a dictionary", fingerprint)
		}
		var entry trustEntry
		array, _ := dict["trustSettings"].([]any)
		for _, item := range array {
			setting, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("hostcerts: a trust setting of %s is not a dictionary", fingerprint)
			}
			entry.settings = append(entry.settings, trustSettingOf(setting))
		}
		list[strings.ToUpper(fingerprint)] = entry
	}
	return list, nil
}

func trustSettingOf(dict map[string]any) trustSetting {
	s := trustSetting{result: trustSettingsResultTrustRoot}
	s.policyName, _ = dict["kSecTrustSettingsPolicyName"].(string)
	s.policyOID, _ = dict["kSecTrustSettingsPolicy"].([]byte)
	if v, ok := dict["kSecTrustSettingsResult"].(int64); ok {
		s.result = int(v)
	}
	for _, key := range []string{"kSecTrustSettingsApplication", "kSecTrustSettingsPolicyString"} {
		if _, ok := dict[key]; ok {
			s.restricted = true
		}
	}
	return s
}

// parsePlist parses an XML property list into maps, slices, strings, int64,
// []byte, and bool. It keeps a date and a real number as a string.
func parsePlist(data []byte) (any, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "plist" {
			continue
		}
		return parsePlistChild(dec)
	}
}

// parsePlistChild parses the first value element below the current element.
func parsePlistChild(dec *xml.Decoder) (any, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return parsePlistValue(dec, t)
		case xml.EndElement:
			return nil, errors.New("hostcerts: the property list has no value")
		}
	}
}

func parsePlistValue(dec *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		dict := map[string]any{}
		key := ""
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					if err := dec.DecodeElement(&key, &t); err != nil {
						return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
					}
					continue
				}
				value, err := parsePlistValue(dec, t)
				if err != nil {
					return nil, err
				}
				dict[key] = value
			case xml.EndElement:
				return dict, nil
			}
		}
	case "array":
		array := []any{}
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
			}
			switch t := tok.(type) {
			case xml.StartElement:
				value, err := parsePlistValue(dec, t)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			case xml.EndElement:
				return array, nil
			}
		}
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
		}
		return start.Name.Local == "true", nil
	}
	var text string
	if err := dec.DecodeElement(&text, &start); err != nil {
		return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
	}
	switch start.Name.Local {
	case "integer":
		n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
		}
		return n, nil
	case "data":
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
		if err != nil {
			return nil, fmt.Errorf("hostcerts: parse the property list: %w", err)
		}
		return raw, nil
	}
	return text, nil
}
