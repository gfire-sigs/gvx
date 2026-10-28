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

//go:build darwin || windows

package systraptest

import (
	"errors"

	"z.gfire.dev/gvx/pkg/sentry/platform/systrap"
)

// probe starts and stops the engine stub. It reports whether a failure is a
// missing prerequisite.
func probe() (missing bool, err error) {
	if _, err := systrap.Probe(); err != nil {
		var unavailable *systrap.ErrUnavailable
		return errors.As(err, &unavailable), err
	}
	return false, nil
}
