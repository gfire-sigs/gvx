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

// Package guestcpu runs controlled CPU-state experiments in a Linux guest. A
// guest program fills a State with test values, calls Run, and gets the
// registers back after an event: a system call, a page fault, or a signal that
// a handler delivers while the thread runs. A handler in this package destroys
// every register on purpose, so only a correct sigreturn restores them.
//
// The package supports linux/amd64 and linux/arm64. Other targets compile an
// empty package so that guest programs build on every host.
package guestcpu
