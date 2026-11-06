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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// trustPlist returns the property list that `security trust-settings-export`
// writes for entries that map a certificate to the XML of its settings array.
// A nil array writes an entry without trustSettings.
func trustPlist(entries map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>trustList</key>
	<dict>
`)
	for fp, settings := range entries {
		fmt.Fprintf(&b, "<key>%s</key>\n<dict>\n<key>issuerName</key>\n<data>\nMA==\n</data>\n<key>modDate</key>\n<date>2025-04-04T00:45:24Z</date>\n", fp)
		if settings != "" {
			fmt.Fprintf(&b, "<key>trustSettings</key>\n<array>\n%s</array>\n", settings)
		}
		b.WriteString("</dict>\n")
	}
	b.WriteString("</dict>\n<key>trustVersion</key>\n<integer>1</integer>\n</dict>\n</plist>\n")
	return []byte(b.String())
}

func settingXML(policyName string, result int) string {
	var b strings.Builder
	b.WriteString("<dict>\n")
	if policyName != "" {
		oid := map[string]string{"sslServer": "KoZIhvdjZAED", "basicX509": "KoZIhvdjZAEC", "eapServer": "KoZIhvdjZAEF"}[policyName]
		fmt.Fprintf(&b, "<key>kSecTrustSettingsPolicy</key>\n<data>\n%s\n</data>\n<key>kSecTrustSettingsPolicyName</key>\n<string>%s</string>\n", oid, policyName)
	}
	if result != 0 {
		fmt.Fprintf(&b, "<key>kSecTrustSettingsResult</key>\n<integer>%d</integer>\n", result)
	}
	b.WriteString("</dict>\n")
	return b.String()
}

func sha1Key(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func mustTrustList(t *testing.T, entries map[string]string) trustList {
	t.Helper()
	list, err := parseTrustList(trustPlist(entries))
	if err != nil {
		t.Fatalf("parseTrustList: %v", err)
	}
	return list
}

func TestTrustedForSSLAppliesTheTrustSettingsOfOneDomain(t *testing.T) {
	root := makeRoot(t, "root")
	inter := makeIntermediate(t, "inter")
	const restricted = `<dict>
<key>kSecTrustSettingsApplication</key>
<data>
MA==
</data>
<key>kSecTrustSettingsResult</key>
<integer>1</integer>
</dict>
`
	const oidOnly = `<dict>
<key>kSecTrustSettingsPolicy</key>
<data>
KoZIhvdjZAED
</data>
</dict>
`
	for _, tc := range []struct {
		name     string
		der      []byte
		settings string
		want     bool
	}{
		{"no settings trust a self-signed root", root, "", true},
		{"no settings do not trust an intermediate", inter, "", false},
		{"TrustRoot for sslServer", root, settingXML("sslServer", 1), true},
		{"a missing result means TrustRoot", root, settingXML("sslServer", 0), true},
		{"TrustRoot does not trust an intermediate", inter, settingXML("sslServer", 1), false},
		{"TrustAsRoot trusts an intermediate", inter, settingXML("sslServer", 2), true},
		{"Deny for sslServer", root, settingXML("sslServer", 3), false},
		{"a policy that is not SSL does not decide", root, settingXML("basicX509", 1), false},
		{"a Deny for another policy does not distrust", root, settingXML("eapServer", 3) + settingXML("sslServer", 1), true},
		{"Unspecified does not decide", root, settingXML("sslServer", 4), false},
		{"an entry without a policy covers SSL", root, settingXML("", 1), true},
		{"the SSL policy OID without a name", root, oidOnly, true},
		{"an entry for one application does not count", root, restricted, false},
		{"the first deciding entry wins", root, settingXML("sslServer", 3) + settingXML("sslServer", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := mustTrustList(t, map[string]string{sha1Key(tc.der): tc.settings})
			if got := trustedForSSL([]trustList{list}, tc.der); got != tc.want {
				t.Errorf("trustedForSSL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTrustedForSSLUsesTheDomainOrder(t *testing.T) {
	root := makeRoot(t, "root")
	key := sha1Key(root)
	accept := mustTrustList(t, map[string]string{key: ""})
	deny := mustTrustList(t, map[string]string{key: settingXML("sslServer", 3)})
	basicOnly := mustTrustList(t, map[string]string{key: settingXML("basicX509", 1)})
	var empty trustList

	for _, tc := range []struct {
		name  string
		lists []trustList
		want  bool
	}{
		{"a user denial beats a system trust", []trustList{deny, accept}, false},
		{"a user trust beats an admin denial", []trustList{accept, deny}, true},
		{"an undecided domain falls to the next one", []trustList{basicOnly, accept}, true},
		{"a domain without the certificate falls to the next one", []trustList{empty, empty, accept}, true},
		{"no domain names the certificate", []trustList{empty, empty, empty}, false},
		{"only undecided entries", []trustList{basicOnly}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trustedForSSL(tc.lists, root); got != tc.want {
				t.Errorf("trustedForSSL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseTrustListRejectsBrokenInput(t *testing.T) {
	for name, data := range map[string]string{
		"not xml":                           "this is not a property list",
		"no plist element":                  "<root/>",
		"array at the top":                  "<plist><array/></plist>",
		"no trustList":                      "<plist><dict><key>other</key><integer>1</integer></dict></plist>",
		"an entry that is not a dictionary": "<plist><dict><key>trustList</key><dict><key>AB</key><string>x</string></dict></dict></plist>",
		"a bad integer":                     "<plist><dict><key>trustList</key><dict><key>AB</key><dict><key>trustSettings</key><array><dict><key>kSecTrustSettingsResult</key><integer>x</integer></dict></array></dict></dict></dict></plist>",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTrustList([]byte(data)); err == nil {
				t.Errorf("parseTrustList accepted %q", data)
			}
		})
	}
}

// TestParseTrustListReadsAnExportOfSecurity parses text that has the layout of
// a real export.
func TestParseTrustListReadsAnExportOfSecurity(t *testing.T) {
	const export = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>trustList</key>
	<dict>
		<key>53C8022ED7C7772DD3741DF23BEF120CC950268E</key>
		<dict>
			<key>issuerName</key>
			<data>
			MHkxHjAcBgNVBAoTFW1rY2VydCBkZXZlbG9wbWVudCBDQTEnMCUG
			A1UECwwedXNlckB1c2Vycy1NYWNCb29rLUFpci00LmxvY2FsMS4w
			</data>
			<key>modDate</key>
			<date>2025-04-04T00:45:24Z</date>
			<key>serialNumber</key>
			<data>
			FJQC8xrXXZ2/7BjnvcfDGQ==
			</data>
			<key>trustSettings</key>
			<array>
				<dict>
					<key>kSecTrustSettingsPolicy</key>
					<data>
					KoZIhvdjZAED
					</data>
					<key>kSecTrustSettingsPolicyName</key>
					<string>sslServer</string>
					<key>kSecTrustSettingsResult</key>
					<integer>1</integer>
				</dict>
				<dict>
					<key>kSecTrustSettingsPolicy</key>
					<data>
					KoZIhvdjZAEC
					</data>
					<key>kSecTrustSettingsPolicyName</key>
					<string>basicX509</string>
					<key>kSecTrustSettingsResult</key>
					<integer>1</integer>
				</dict>
			</array>
		</dict>
		<key>6360F9B95FBE28449C95EBDA27D7E1BAA91E685A</key>
		<dict>
			<key>modDate</key>
			<date>2026-01-06T04:50:51Z</date>
		</dict>
	</dict>
	<key>trustVersion</key>
	<integer>1</integer>
</dict>
</plist>`
	list, err := parseTrustList([]byte(export))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("parsed %d entries, want 2", len(list))
	}
	mkcert := list["53C8022ED7C7772DD3741DF23BEF120CC950268E"]
	if len(mkcert.settings) != 2 || mkcert.settings[0].policyName != "sslServer" || mkcert.settings[0].result != 1 || !mkcert.settings[0].appliesToSSL() {
		t.Errorf("first entry = %+v, want two settings and sslServer with TrustRoot first", mkcert.settings)
	}
	if mkcert.settings[1].appliesToSSL() {
		t.Errorf("the basicX509 setting applies to SSL")
	}
	if got := list["6360F9B95FBE28449C95EBDA27D7E1BAA91E685A"]; len(got.settings) != 0 {
		t.Errorf("an entry without trustSettings has %d settings, want 0", len(got.settings))
	}
}
