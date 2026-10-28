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

// Package bootclock records the time at which the Go runtime reaches the
// package initializers. It has no dependency except the standard library, and
// its import path sorts before the packages of the Sentry. The Go runtime
// initializes the ready package with the smallest import path first, so the
// value is the earliest time that code of this module can see. The stub host of
// the Windows systrap engine compares it with the creation time of its process,
// to find how much of its start time is the loader and the runtime, and how much
// is the package initializers.
package bootclock

import "time"

// Start is the time of the initialization of this package.
var Start = time.Now()
