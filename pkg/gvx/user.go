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

package gvx

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// execUser is the guest identity that a user specification resolves to.
type execUser struct {
	UID, GID uint32
	// ExtraGIDs lists the supplementary groups.
	ExtraGIDs []uint32
	// Home is the home directory of the user, "/" for a numeric user that the
	// passwd file does not list, and "/root" for the default root user.
	Home string
}

// errUnknownUser and errUnknownGroup report a name that the guest files do not list.
var (
	errUnknownUser  = errors.New("unable to find user")
	errUnknownGroup = errors.New("unable to find group")
)

type passwdEntry struct {
	name     string
	uid, gid uint32
	home     string
}

type groupEntry struct {
	name    string
	gid     uint32
	members []string
}

// maxGuestID is the largest valid guest user or group ID. The kernel keeps
// 4294967295 as the invalid ID.
const maxGuestID = 1<<32 - 2

func parseID(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n > maxGuestID {
		return 0, false
	}
	return uint32(n), true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parsePasswd reads the entries of an /etc/passwd file. It skips comments,
// blank lines, and lines that do not have seven fields with numeric IDs.
func parsePasswd(data []byte) []passwdEntry {
	var out []passwdEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 6 {
			continue
		}
		uid, ok1 := parseID(f[2])
		gid, ok2 := parseID(f[3])
		if f[0] == "" || !ok1 || !ok2 {
			continue
		}
		out = append(out, passwdEntry{name: f[0], uid: uid, gid: gid, home: f[5]})
	}
	return out
}

// parseGroup reads the entries of an /etc/group file with the same leniency.
func parseGroup(data []byte) []groupEntry {
	var out []groupEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		gid, ok := parseID(f[2])
		if f[0] == "" || !ok {
			continue
		}
		e := groupEntry{name: f[0], gid: gid}
		if len(f) > 3 && f[3] != "" {
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					e.members = append(e.members, m)
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// splitUserSpec splits "user:group" and rejects an empty part or a third part.
// An empty specification is valid and means the default user.
func splitUserSpec(spec string) (user, group string, hasGroup bool, err error) {
	user, group, hasGroup = strings.Cut(spec, ":")
	if spec != "" && (user == "" || (hasGroup && group == "") || strings.Contains(group, ":")) {
		return "", "", false, fmt.Errorf("invalid user specification %q: want user, user:group, uid, or uid:gid", spec)
	}
	return user, group, hasGroup, nil
}

// resolveExecUser resolves a Docker user specification against the passwd and
// group files of the guest. The specification is "", "user", "uid", "user:group",
// or any mix of names and numbers.
//
// A name must exist in the files. A number need not exist. A numeric user that
// the passwd file does not list gets the primary group 0 and the home "/", as
// Docker does. A specification without a group adds the supplementary groups
// that list the user as a member. A specification with a group adds none.
func resolveExecUser(spec string, passwd, group []byte) (execUser, error) {
	userPart, groupPart, hasGroup, err := splitUserSpec(spec)
	if err != nil {
		return execUser{}, err
	}
	pw := parsePasswd(passwd)
	gr := parseGroup(group)

	if spec == "" {
		u := execUser{Home: "/root"}
		for _, e := range pw {
			if e.uid == 0 {
				u.Home = e.home
				break
			}
		}
		return u, nil
	}

	var (
		u    execUser
		name string
	)
	if uid, ok := parseID(userPart); ok && isDigits(userPart) {
		u.UID, u.Home = uid, "/"
		for _, e := range pw {
			if e.uid == uid {
				u.GID, u.Home, name = e.gid, e.home, e.name
				break
			}
		}
	} else {
		if isDigits(userPart) {
			return execUser{}, fmt.Errorf("user ID %q is out of range", userPart)
		}
		found := false
		for _, e := range pw {
			if e.name == userPart {
				u.UID, u.GID, u.Home, name, found = e.uid, e.gid, e.home, e.name, true
				break
			}
		}
		if !found {
			return execUser{}, fmt.Errorf("%w %q in the guest /etc/passwd", errUnknownUser, userPart)
		}
	}

	if hasGroup {
		if isDigits(groupPart) {
			gid, ok := parseID(groupPart)
			if !ok {
				return execUser{}, fmt.Errorf("group ID %q is out of range", groupPart)
			}
			u.GID = gid
		} else {
			found := false
			for _, e := range gr {
				if e.name == groupPart {
					u.GID, found = e.gid, true
					break
				}
			}
			if !found {
				return execUser{}, fmt.Errorf("%w %q in the guest /etc/group", errUnknownGroup, groupPart)
			}
		}
		return u, nil
	}

	if name == "" {
		return u, nil
	}
	seen := map[uint32]bool{u.GID: true}
	for _, e := range gr {
		if seen[e.gid] {
			continue
		}
		for _, m := range e.members {
			if m == name {
				seen[e.gid] = true
				u.ExtraGIDs = append(u.ExtraGIDs, e.gid)
				break
			}
		}
	}
	return u, nil
}
