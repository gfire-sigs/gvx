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
	"fmt"
	"io"
	"strings"

	"z.gfire.dev/gvx/pkg/oci"
)

const maxAuthPayloadBytes = 64 << 10

func init() {
	register(command{
		name: "push",
		summary: "Upload a cached OCI image to a registry.\n" +
			"The command skips blobs the target registry already holds and uses cross-repository mounts when possible.\n" +
			"Credentials come from the Docker config store, or per-request via --password-stdin, --auth-stdin, or --auth-fd.",
		usage: []string{"rungv push [flags] IMAGE [TARGET]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return pushSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
}

func pushSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("push", stderr)
	cacheFlags := addImageCacheFlags(fs)
	platformFlag := fs.String("platform", "", "Target image platform (linux/amd64 or linux/arm64)")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL that replaces the registry of the target reference")
	hostDNS := addHostDNSFlag(fs)
	var quiet bool
	fs.BoolVar(&quiet, "q", false, "Print only the pushed manifest digest")
	fs.BoolVar(&quiet, "quiet", false, "Print only the pushed manifest digest")
	var username string
	var passwordStdin, authStdin bool
	var authFD int
	fs.StringVar(&username, "u", "", "Registry user name (use with --password-stdin)")
	fs.StringVar(&username, "username", "", "Registry user name (use with --password-stdin)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read the registry password from standard input (requires --username)")
	fs.BoolVar(&authStdin, "auth-stdin", false, "Read Docker X-Registry-Auth JSON (or base64 JSON) from standard input")
	fs.IntVar(&authFD, "auth-fd", -1, "Read Docker X-Registry-Auth JSON (or base64 JSON) from inherited file descriptor N (>= 3)")

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return imageUsageError(stderr, "push", "want IMAGE [TARGET], got %d arguments", fs.NArg())
	}
	if _, err := applyPlatformFlag(fs, *platformFlag, cacheFlags.arch); err != nil {
		return imageUsageError(stderr, "push", "%v", err)
	}

	creds, usageErr, readErr := readPushCredentials(username, passwordStdin, authStdin, authFD, stdin)
	if usageErr != nil {
		return imageUsageError(stderr, "push", "%v", usageErr)
	}
	if readErr != nil {
		return imageFail(stderr, "push", readErr)
	}

	cache, arch, err := cacheFlags.openPullCache(*hostDNS)
	if err != nil {
		return imageFail(stderr, "push", err)
	}

	registryURL := strings.TrimSpace(*registryURLFlag)
	imageArg := fs.Arg(0)
	sel, err := cache.Select(imageArg, arch)
	if err != nil && errors.Is(err, oci.ErrNotCached) && registryURL != "" {
		if altRef, refErr := oci.ParseReferenceAt(imageArg, registryURL); refErr == nil {
			if altSel, altErr := cache.Select(altRef.Familiar(), arch); altErr == nil {
				sel, err = altSel, nil
			}
		}
	}
	if err != nil {
		return imageFail(stderr, "push", imageNotFound(imageArg, err))
	}

	var target oci.Reference
	if fs.NArg() == 2 {
		targetArg := fs.Arg(1)
		if registryURL != "" {
			target, err = oci.ParseReferenceAt(targetArg, registryURL)
		} else {
			target, err = oci.ParseReference(targetArg)
		}
		if err != nil {
			return imageUsageError(stderr, "push", "%v", err)
		}
	} else {
		switch {
		case registryURL != "":
			target, err = oci.ParseReferenceAt(imageArg, registryURL)
			if err != nil {
				return imageUsageError(stderr, "push", "%v", err)
			}
		case sel.Ref != nil:
			target = *sel.Ref
		default:
			return imageUsageError(stderr, "push", "push by image ID requires a TARGET reference")
		}
	}

	if !quiet {
		_, _ = fmt.Fprintf(stdout, "The push refers to repository [%s]\n", target.FamiliarName())
	}

	opts := oci.PushOptions{
		BaseURL:     registryURL,
		Credentials: creds,
	}
	if !quiet {
		opts.Progress = func(ev oci.PushEvent) {
			if ev.Kind == "manifest" {
				return
			}
			label := shortImageID(ev.Digest)
			switch ev.Status {
			case "exists":
				_, _ = fmt.Fprintf(stdout, "%s: Layer already exists\n", label)
			case "mounted":
				_, _ = fmt.Fprintf(stdout, "%s: Mounted\n", label)
			case "pushed":
				_, _ = fmt.Fprintf(stdout, "%s: Pushed\n", label)
			}
		}
	}

	res, err := cache.PushImage(ctx, sel.Images[0], target, opts)
	if err != nil {
		return imageFail(stderr, "push", err)
	}
	if quiet {
		_, _ = fmt.Fprintln(stdout, res.Digest)
		return 0
	}
	refLabel := target.ManifestReference()
	_, _ = fmt.Fprintf(stdout, "%s: digest: %s\n", refLabel, res.Digest)
	return 0
}

func readPushCredentials(username string, passwordStdin, authStdin bool, authFD int, stdin io.Reader) (creds *oci.Credentials, usageErr, readErr error) {
	modes := 0
	if passwordStdin {
		modes++
	}
	if authStdin {
		modes++
	}
	if authFD >= 0 {
		modes++
	}
	if modes > 1 {
		return nil, errors.New("--password-stdin, --auth-stdin, and --auth-fd are mutually exclusive"), nil
	}
	if username != "" && !passwordStdin {
		return nil, errors.New("--username requires --password-stdin"), nil
	}
	if passwordStdin && username == "" {
		return nil, errors.New("--password-stdin requires --username"), nil
	}
	if modes == 0 {
		return nil, nil, nil
	}
	if passwordStdin {
		if stdin == nil {
			return nil, errors.New("--password-stdin requires input on standard input"), nil
		}
		raw, err := readBoundedAuth(stdin, "standard input")
		if err != nil {
			return nil, nil, err
		}
		password := strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return nil, errors.New("password read from standard input is empty"), nil
		}
		return &oci.Credentials{Username: username, Password: password}, nil, nil
	}
	if authStdin {
		if stdin == nil {
			return nil, errors.New("--auth-stdin requires input on standard input"), nil
		}
		raw, err := readBoundedAuth(stdin, "standard input")
		if err != nil {
			return nil, nil, err
		}
		parsed, err := oci.ParseAuthConfig(raw)
		if err != nil {
			return nil, nil, err
		}
		return &parsed, nil, nil
	}
	if authFD < 3 {
		return nil, fmt.Errorf("--auth-fd must be >= 3, got %d", authFD), nil
	}
	raw, err := readAuthFD(authFD)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := oci.ParseAuthConfig(raw)
	if err != nil {
		return nil, nil, err
	}
	return &parsed, nil, nil
}

func readBoundedAuth(r io.Reader, source string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxAuthPayloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read auth credentials from %s: %w", source, err)
	}
	if len(raw) > maxAuthPayloadBytes {
		return nil, fmt.Errorf("auth credentials from %s exceed %d bytes", source, maxAuthPayloadBytes)
	}
	return raw, nil
}
