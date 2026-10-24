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

package hostfs

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// codecPrefix starts every host name that NameCodec escapes. A host name
	// without the prefix stands for itself.
	codecPrefix = "~gvx~"

	// ephemeralTmpPrefix and ephemeralSwapPrefix start the names of the
	// internal host files of hostfs. NameCodec never produces these prefixes
	// for a guest name, and every guest listing hides them.
	ephemeralTmpPrefix  = codecPrefix + "tmp."
	ephemeralSwapPrefix = codecPrefix + "swap."

	// winForbiddenBytes lists the bytes that Windows refuses in a file name,
	// besides the control bytes. The backslash is a path separator.
	winForbiddenBytes = `\/:*?"<>|`

	upperHex = "0123456789ABCDEF"
)

// errNameTooLong reports an encoded name that exceeds the name length limit
// of the host file system. translateHostError maps it to ENAMETOOLONG.
var errNameTooLong = errors.New("hostfs: encoded name exceeds the length limit of the host file system")

// NameCodec translates file names between the guest and the host. A guest name
// is any byte string without "/" and NUL. A host file system can reject such a
// name, reserve it, fold its case, or change its Unicode form.
//
// On a host that needs none of these rules, NameCodec is the identity and
// allocates nothing. Otherwise it keeps ordinary names unchanged. It escapes a
// name with the prefix "~gvx~" followed by the name, where each escaped byte
// becomes "%XX" with upper-case hexadecimal digits. The escape grammar needs
// no stored state: ToGuest reverses every well-formed host name.
//
// A host name that starts with the prefix and holds a "%" without two
// hexadecimal digits is malformed. NameCodec never writes such a name. ToGuest
// returns a malformed name unchanged, and Workspace hides the entry from the
// guest, so that two host names never show as one guest name.
//
// A guest name has up to three host forms on a volume that folds case:
//
//	form 0: the name itself, or its escape when the host needs one.
//	form 1: the prefix, then the name with every letter that has an upper-case
//	        variant escaped. Letters that stay are the lower-case
//	        representatives of their case-folding orbit.
//	form 2: the prefix, then the name with every cased letter escaped.
//
// Form 1 and form 2 never fold to the same name as the form of another guest
// name, so any number of case variants can coexist. ToHost picks the first
// form that no stored entry occupies.
type NameCodec struct {
	// active is false for the identity codec.
	active bool
	// winNames enables the Windows name rules.
	winNames bool
	// foldCase enables the case collision forms.
	foldCase bool
}

// newNameCodec builds the codec for a volume with the given capabilities.
func newNameCodec(caps WorkspaceCaps) NameCodec {
	return NameCodec{
		active:   caps.RestrictsWinNames || !caps.CaseSensitive || caps.UnicodeNormalized,
		winNames: caps.RestrictsWinNames,
		foldCase: !caps.CaseSensitive,
	}
}

// ToHost maps a guest name to the host name that a new entry gets. The
// function exists reports whether the host directory already holds an entry
// that the host treats as the same name. On a volume that folds case, exists
// compares names without case. A nil exists means that no entry occupies a
// name.
//
// ToHost chooses the name for a new entry. It does not find an existing
// entry: Workspace compares the stored names with the forms of the guest name
// for that. ToHost returns ENAMETOOLONG semantics (errNameTooLong) when the
// encoded name exceeds the host limit, and errInvalidHostName for an empty
// name, ".", "..", or a name with "/" or NUL.
//
// For every guest name g that ToHost accepts, ToGuest(ToHost(g)) equals g.
func (c NameCodec) ToHost(guest string, exists func(host string) bool) (string, error) {
	if !c.active {
		return guest, nil
	}
	if !validGuestName(guest) {
		return "", fmt.Errorf("%w: %q", errInvalidHostName, guest)
	}
	var host string
	for level := 0; level <= c.maxLevel(); level++ {
		h, err := c.encode(guest, level)
		if err != nil {
			return "", err
		}
		host = h
		if exists == nil || !exists(h) {
			break
		}
	}
	return host, nil
}

// ToGuest maps a host name back to the guest name. It needs no state. It
// returns a malformed name unchanged.
func (c NameCodec) ToGuest(host string) string {
	if !c.active {
		return host
	}
	if guest, ok := c.decode(host); ok {
		return guest
	}
	return host
}

func (c NameCodec) maxLevel() int {
	if c.foldCase {
		return 2
	}
	return 0
}

// forms returns the distinct host forms of a guest name, in the order that
// ToHost tries them.
func (c NameCodec) forms(guest string) ([]string, error) {
	if !c.active {
		return []string{guest}, nil
	}
	if !validGuestName(guest) {
		return nil, fmt.Errorf("%w: %q", errInvalidHostName, guest)
	}
	out := make([]string, 0, 3)
	for level := 0; level <= c.maxLevel(); level++ {
		h, err := c.encode(guest, level)
		if err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1] != h {
			out = append(out, h)
		}
	}
	return out, nil
}

// leafForm returns form 0 of a guest name. It makes no allocation when the
// name needs no escape.
func (c NameCodec) leafForm(guest string) (string, error) {
	if !c.active {
		return guest, nil
	}
	if !validGuestName(guest) {
		return "", fmt.Errorf("%w: %q", errInvalidHostName, guest)
	}
	return c.encode(guest, 0)
}

func validGuestName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

// needsPrefix reports whether the host cannot store guest as it is.
func (c NameCodec) needsPrefix(guest string) bool {
	if strings.HasPrefix(guest, codecPrefix) || !utf8.ValidString(guest) {
		return true
	}
	if !c.winNames {
		return false
	}
	for i := range len(guest) {
		if b := guest[i]; b < 0x20 || strings.IndexByte(winForbiddenBytes, b) >= 0 {
			return true
		}
	}
	if last := guest[len(guest)-1]; last == '.' || last == ' ' {
		return true
	}
	return isReservedDeviceName(guest)
}

// escapes reports whether the form at level writes r as hexadecimal bytes.
func (c NameCodec) escapes(r rune, level int) bool {
	switch {
	case r == '%':
		return true
	case c.winNames && (r < 0x20 || (r < utf8.RuneSelf && strings.IndexByte(winForbiddenBytes, byte(r)) >= 0)):
		return true
	case level >= 1 && !isFoldRepresentative(r):
		return true
	case level >= 2 && hasCase(r):
		return true
	}
	return false
}

// encode builds the host form of guest at the given level. Level 0 leaves a
// name unchanged when the host stores it as it is.
func (c NameCodec) encode(guest string, level int) (string, error) {
	if level == 0 && !c.needsPrefix(guest) {
		return guest, c.checkLength(guest)
	}
	// The remainder of an escaped name must never start with an internal
	// prefix, or a guest name could produce an ephemeral host name.
	guard := strings.HasPrefix(guest, "tmp.") || strings.HasPrefix(guest, "swap.")
	var b strings.Builder
	b.Grow(len(codecPrefix) + len(guest) + 8)
	b.WriteString(codecPrefix)
	for i := 0; i < len(guest); {
		r, size := utf8.DecodeRuneInString(guest[i:])
		escape := r == utf8.RuneError && size == 1
		escape = escape || c.escapes(r, level) || (i == 0 && guard)
		// Windows removes a trailing dot or space, so the last one needs an escape.
		escape = escape || (c.winNames && i+size == len(guest) && (r == '.' || r == ' '))
		if escape {
			for j := i; j < i+size; j++ {
				b.WriteByte('%')
				b.WriteByte(upperHex[guest[j]>>4])
				b.WriteByte(upperHex[guest[j]&0x0F])
			}
		} else {
			b.WriteString(guest[i : i+size])
		}
		i += size
	}
	out := b.String()
	return out, c.checkLength(out)
}

// checkLength enforces the name length limit of the host. NTFS counts UTF-16
// code units, and the other file systems count bytes.
func (c NameCodec) checkLength(host string) error {
	n := len(host)
	if c.winNames {
		n = 0
		for _, r := range host {
			n++
			if r >= 0x10000 {
				n++
			}
		}
	}
	if n > maxFilenameLen {
		return fmt.Errorf("%w: %d units", errNameTooLong, n)
	}
	return nil
}

// decode reverses encode. The second result is false for a malformed host
// name. A host name without the prefix decodes to itself.
func (c NameCodec) decode(host string) (string, bool) {
	rest, ok := strings.CutPrefix(host, codecPrefix)
	if !ok {
		return host, true
	}
	if strings.IndexByte(rest, '%') < 0 {
		return rest, validGuestName(rest)
	}
	b := make([]byte, 0, len(rest))
	for i := 0; i < len(rest); i++ {
		if rest[i] != '%' {
			b = append(b, rest[i])
			continue
		}
		if i+2 >= len(rest) {
			return "", false
		}
		hi, okHi := hexValue(rest[i+1])
		lo, okLo := hexValue(rest[i+2])
		if !okHi || !okLo {
			return "", false
		}
		b = append(b, hi<<4|lo)
		i += 2
	}
	guest := string(b)
	return guest, validGuestName(guest)
}

// canonicalGuest decodes host and reports whether this codec can write the
// host name for that guest name. A host name that decodes but that no form of
// the guest name matches comes from another tool, and Workspace hides it so
// that lookups and listings agree.
func (c NameCodec) canonicalGuest(host string) (string, bool) {
	guest, ok := c.decode(host)
	if !ok {
		return "", false
	}
	if !strings.HasPrefix(host, codecPrefix) {
		return guest, true
	}
	for level := 0; level <= c.maxLevel(); level++ {
		if form, err := c.encode(guest, level); err == nil && form == host {
			return guest, true
		}
	}
	return guest, false
}

func hexValue(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// hasCase reports whether r belongs to a case-folding orbit with other runes.
func hasCase(r rune) bool {
	if r < utf8.RuneSelf {
		return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
	}
	return unicode.SimpleFold(r) != r
}

// isFoldRepresentative reports whether r stays literal in form 1. A rune
// without case stays. In an orbit, the smallest lower-case rune stays and the
// others are escaped, so no two form-1 names fold to the same name.
func isFoldRepresentative(r rune) bool {
	if r < utf8.RuneSelf {
		return r < 'A' || r > 'Z'
	}
	next := unicode.SimpleFold(r)
	if next == r {
		return true
	}
	if !unicode.IsLower(r) {
		return false
	}
	for o := next; o != r; o = unicode.SimpleFold(o) {
		if unicode.IsLower(o) && o < r {
			return false
		}
	}
	return true
}

// foldKey returns the key that two names share when the host treats them as
// one name. The key uses the smallest rune of each case-folding orbit. With
// normalize, it also converts the name to NFC first.
func foldKey(name string, normalize bool) string {
	if normalize && !isASCII(name) {
		name = norm.NFC.String(name)
	}
	ascii := isASCII(name)
	if ascii {
		lower := false
		for i := range len(name) {
			if name[i] >= 'a' && name[i] <= 'z' {
				lower = true
				break
			}
		}
		if !lower {
			return name
		}
	}
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		m := r
		if r < utf8.RuneSelf {
			if r >= 'a' && r <= 'z' {
				m = r - 'a' + 'A'
			}
		} else {
			for o := unicode.SimpleFold(r); o != r; o = unicode.SimpleFold(o) {
				if o < m {
					m = o
				}
			}
		}
		b.WriteRune(m)
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// isReservedDeviceName reports whether Windows treats name as a device. The
// match ignores case and any extension, so "nul.txt" is reserved. The check
// allocates nothing, because every Windows lookup runs it.
func isReservedDeviceName(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.TrimRight(stem, " ")
	// The shortest device name has 3 bytes, and the longest, CONOUT$, has 7.
	if len(stem) < 3 || len(stem) > 7 {
		return false
	}
	for _, device := range [...]string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} {
		if strings.EqualFold(stem, device) {
			return true
		}
	}
	if !strings.EqualFold(stem[:3], "COM") && !strings.EqualFold(stem[:3], "LPT") {
		return false
	}
	r, size := utf8.DecodeRuneInString(stem[3:])
	if size == 0 || size != len(stem)-3 {
		return false
	}
	// The superscript digits are device names too.
	return (r >= '0' && r <= '9') || r == '\u00b9' || r == '\u00b2' || r == '\u00b3'
}

// isEphemeralName reports whether name belongs to the internal namespace of
// hostfs: unnamed temporary files and swap files.
func isEphemeralName(name string) bool {
	return strings.HasPrefix(name, ephemeralTmpPrefix) || strings.HasPrefix(name, ephemeralSwapPrefix)
}
