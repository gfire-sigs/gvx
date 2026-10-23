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
	"fmt"
	"io"
	"strings"

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name: "login",
		summary: "Log in to a registry and store the credentials in the Docker config.\n" +
			"Without a registry the command uses Docker Hub. It reads the password without echo from a terminal,\n" +
			"and one line from standard input otherwise.",
		usage: []string{"rungv login [-u USER] [-p PASSWORD | --password-stdin] [REGISTRY]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return loginSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "logout",
		summary: "Remove the stored credentials of a registry. Without a registry the command uses Docker Hub.",
		usage:   []string{"rungv logout [REGISTRY]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return logoutSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func loginSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("login", stderr)
	var username, password string
	var passwordStdin bool
	fs.StringVar(&username, "u", "", "User name")
	fs.StringVar(&username, "username", "", "User name")
	fs.StringVar(&password, "p", "", "Password. Prefer --password-stdin, because a command line is visible to other users")
	fs.StringVar(&password, "password", "", "Password. Prefer --password-stdin, because a command line is visible to other users")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read the password from standard input")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 1 {
		return imageUsageError(stderr, "login", "at most one REGISTRY argument, got %d", fs.NArg())
	}
	if passwordStdin && password != "" {
		return imageUsageError(stderr, "login", "--password and --password-stdin are mutually exclusive")
	}
	if passwordStdin && username == "" {
		return imageUsageError(stderr, "login", "--password-stdin needs --username")
	}
	if password != "" {
		_, _ = fmt.Fprintln(stderr, "WARNING! Using --password via the CLI is insecure. Use --password-stdin.")
	}
	server := fs.Arg(0)

	if stdin == nil {
		stdin = strings.NewReader("")
	}
	if username == "" {
		if oci.IsTerminal(stdin) {
			_, _ = fmt.Fprint(stderr, "Username: ")
		}
		line, err := oci.ReadLine(stdin)
		if err != nil {
			return imageFail(stderr, "login", fmt.Errorf("read the user name: %w", err))
		}
		username = line
	}
	if password == "" {
		var err error
		if passwordStdin {
			var raw []byte
			if raw, err = io.ReadAll(stdin); err == nil {
				password = strings.TrimRight(string(raw), "\r\n")
			}
		} else {
			password, err = oci.ReadPassword(stdin, stderr)
		}
		if err != nil {
			return imageFail(stderr, "login", fmt.Errorf("read the password: %w", err))
		}
	}
	if username == "" || password == "" {
		return imageUsageError(stderr, "login", "a user name and a password are required")
	}

	err := oci.Login(ctx, oci.CredentialStore{}, nil, server, oci.Credentials{Username: username, Password: password})
	if err != nil {
		return imageFail(stderr, "login", err)
	}
	_, _ = fmt.Fprintln(stdout, "Login Succeeded")
	return 0
}

func logoutSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("logout", stderr)
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 1 {
		return imageUsageError(stderr, "logout", "at most one REGISTRY argument, got %d", fs.NArg())
	}
	server := fs.Arg(0)
	key, err := oci.RegistryConfigKey(server)
	if err != nil {
		return imageFail(stderr, "logout", err)
	}
	found, err := oci.Logout(ctx, oci.CredentialStore{}, server)
	if err != nil {
		return imageFail(stderr, "logout", err)
	}
	if !found {
		_, _ = fmt.Fprintf(stdout, "Not logged in to %s\n", key)
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "Removing login credentials for %s\n", key)
	return 0
}
