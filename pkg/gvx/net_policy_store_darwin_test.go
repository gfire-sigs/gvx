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

//go:build darwin && !ios

package gvx

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNetPolicyStoreRejectsDarwinACLGrant(t *testing.T) {
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	seed := policyStoreTestConfig("ACCEPT")
	mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
	if out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
		t.Fatalf("grant ACL read access: %v\n%s", err, out)
	}
	requirePolicyStoreRejection(t, path, nil, errPolicyStoreUnsafe)
}
