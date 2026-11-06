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

package kernel

import "math/rand"

// bootMessages are the lines that the Sentry writes to the kernel log at boot
// when it starts the guest. dmesg shows a random choice of them, as it showed the
// messages of the log of gVisor before the kernel had a ring buffer.
var bootMessages = []string{
	"Synthesizing system calls...",
	"Mounting deweydecimalfs...",
	"Moving files to filing cabinet...",
	"Digging up root...",
	"Constructing home...",
	"Segmenting fault lines...",
	"Creating bureaucratic processes...",
	"Searching for needles in stacks...",
	"Preparing for the zombie uprising...",
	"Feeding the init monster...",
	"Creating cloned children...",
	"Daemonizing children...",
	"Waiting for children...",
	"Gathering forks...",
	"Committing treasure map to memory...",
	"Reading process obituaries...",
	"Searching for socket adapter...",
	"Creating process schedule...",
	"Generating random numbers by fair dice roll...",
	"Rewriting operating system in Javascript...",
	"Reticulating splines...",
	"Consulting tar man page...",
	"Forking spaghetti code...",
	"Checking naughty and nice process list...",
	"Granting licence to kill(2)...", // British spelling for British movie.
	"Letting the watchdogs out...",
	"Conjuring /dev/null black hole...",
	"Adversarially training Redcode AI...",
	"Singleplexing /dev/ptmx...",
	"Recruiting cron-ies...",
	"Verifying that no non-zero bytes made their way into /dev/zero...",
	"Accelerating teletypewriter to 9600 baud...",
	"DeFUSEing fork bombs...",
	"Deleting VFS and rebuilding it from scratch...",
	"Asking an AI agent to fix the bugs...",
	"Rewriting the kernel in Rust...",
	"Politicking the oom killer...",
}

// bootMessageCount is the number of random lines between the first and the
// last line of the boot messages.
const bootMessageCount = 10

// WriteBootMessages writes the boot messages to the log: "Starting gVisor...",
// ten random lines, and "Ready!". They have the level info and the time of the
// call.
func (l *KernelLog) WriteBootMessages() {
	l.Printk(LogInfo, "Starting gVisor...")
	for _, i := range rand.Perm(len(bootMessages))[:bootMessageCount] {
		l.Printk(LogInfo, bootMessages[i])
	}
	l.Printk(LogInfo, "Ready!")
}
