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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

const (
	envControlSocket = "GVX_CONTROL_SOCKET"
	envControlToken  = "GVX_CONTROL_TOKEN"
)

// controlTargetFlags holds the shared target and authentication flags for
// control-socket subcommands.
type controlTargetFlags struct {
	socket    string
	name      string
	token     string
	tokenFile string
	timeout   time.Duration
}

func addControlFlags(fs *flag.FlagSet, defaultTimeout time.Duration) *controlTargetFlags {
	f := &controlTargetFlags{}
	registerAlias([]string{"control-socket", "S"}, func(n string) {
		fs.StringVar(&f.socket, n, "", "Control socket path or loopback TCP address (env: "+envControlSocket+")")
	})
	registerAlias([]string{"name", "n"}, func(n string) {
		fs.StringVar(&f.name, n, "", "Sandbox name launched with --control")
	})
	fs.StringVar(&f.token, "token", "", "Control authentication token (env: "+envControlToken+")")
	fs.StringVar(&f.tokenFile, "token-file", "", "Path to a control authentication token file")
	fs.DurationVar(&f.timeout, "timeout", defaultTimeout, "Connection and unary RPC timeout (0 disables RPC timeout)")
	return f
}

func (f *controlTargetFlags) resolveEndpoint(inlineName string) (string, error) {
	if s := strings.TrimSpace(f.socket); s != "" {
		return s, nil
	}
	name := strings.TrimSpace(f.name)
	if name == "" {
		name = strings.TrimSpace(inlineName)
	}
	if name != "" {
		return control.NamedSocketPath(name)
	}
	if env := strings.TrimSpace(os.Getenv(envControlSocket)); env != "" {
		return env, nil
	}
	return "", errors.New("specify -control-socket=<path>, -S <path>, -n <name>, or set " + envControlSocket)
}

func (f *controlTargetFlags) resolveToken() string {
	if t := strings.TrimSpace(f.token); t != "" {
		return t
	}
	return strings.TrimSpace(os.Getenv(envControlToken))
}

func (f *controlTargetFlags) handshakeTimeout() time.Duration {
	if f.timeout > 0 {
		return f.timeout
	}
	return 10 * time.Second
}

func (f *controlTargetFlags) dial(ctx context.Context, inlineName string) (*control.Client, error) {
	endpoint, err := f.resolveEndpoint(inlineName)
	if err != nil {
		return nil, err
	}
	return control.Dial(ctx, control.DialOptions{
		Endpoint:         endpoint,
		Token:            f.resolveToken(),
		TokenFile:        strings.TrimSpace(f.tokenFile),
		ClientName:       "rungv",
		HandshakeTimeout: f.handshakeTimeout(),
	})
}

func (f *controlTargetFlags) callContext(parent context.Context) (context.Context, context.CancelFunc) {
	if f.timeout > 0 {
		return context.WithTimeout(parent, f.timeout)
	}
	return context.WithCancel(parent)
}

func controlErrorExitCode(err error) int {
	var pe *control.ProtoError
	if errors.As(err, &pe) {
		switch pe.Code {
		case control.CodeUnauthorized, control.CodeForbiddenByPolicy, control.CodeLockdownDenied:
			return 126
		}
	}
	return 1
}

func controlFail(stderr io.Writer, cmdName string, err error) int {
	_, _ = fmt.Fprintf(stderr, "rungv %s: %v\n", cmdName, err)
	return controlErrorExitCode(err)
}

func controlUsageError(stderr io.Writer, cmdName, format string, args ...any) int {
	_, _ = fmt.Fprintf(stderr, "rungv %s: "+format+"\n", args...)
	return 2
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	suffixes := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	return fmt.Sprintf("%.1f%s", float64(n)/float64(div), suffixes[exp])
}

func formatUptime(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	d = d.Truncate(time.Second)
	return d.String()
}
