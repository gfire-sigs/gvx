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
	"context"
	"errors"

	"z.gfire.dev/gvx/pkg/hostlockdown"
)

// ErrProcessIsolationRequired directs Windows callers to the process boundary.
var ErrProcessIsolationRequired = errors.New("gvx: Windows host isolation requires NewProcess and a trusted worker executable")

// WorkerCommand selects a trusted executable that calls ServeProcess with these arguments.
type WorkerCommand struct {
	Executable string
	Arguments  []string
}

// WorkerOptions supplies trusted initialization inside the AppContainer.
type WorkerOptions struct {
	// AfterLockdown borrows the sandbox before the guest starts. It must not close the sandbox.
	AfterLockdown func(context.Context, *Sandbox) error
}

// ProcessSandbox runs Sentry in a Windows AppContainer and keeps the caller outside its restrictions.
// Close releases the worker and broker after Run. A ProcessSandbox executes one guest command.
type ProcessSandbox struct {
	state     *processState
	status    hostlockdown.Status
	ports     []int
	published []PublishedPort
	limits    LimitReport
	platform  string
}

// NewProcess prepares image layers before it starts an isolated worker. Windows supports this API.
// The worker borrows Config.Stdin as an *os.File. The caller owns the standard streams.
func NewProcess(ctx context.Context, worker WorkerCommand, cfg Config) (*ProcessSandbox, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return startProcess(ctx, worker, cfg)
}

// ServeProcess runs the worker protocol. Call it only from the trusted worker entry point.
func ServeProcess(ctx context.Context, options WorkerOptions) error {
	return serveProcess(ctx, options)
}

func (p *ProcessSandbox) Run(ctx context.Context) (int, error) { return p.state.run(ctx) }
func (p *ProcessSandbox) Close() error                         { return p.state.close() }
func (p *ProcessSandbox) PlatformName() string                 { return p.platform }
func (p *ProcessSandbox) LockdownStatus() hostlockdown.Status  { return p.status }
func (p *ProcessSandbox) PublishedPorts() []PublishedPort {
	return append([]PublishedPort(nil), p.published...)
}
func (p *ProcessSandbox) Limits() LimitReport { return p.limits }
func (p *ProcessSandbox) BoundPort(index int) int {
	if index < 0 || index >= len(p.ports) {
		return 0
	}
	return p.ports[index]
}
