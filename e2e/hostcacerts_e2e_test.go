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

//go:build darwin || windows || linux

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx"
)

// testCA is a certificate authority that no host trusts. It signs the
// certificate of a TLS server that runs on the host.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create the CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// serverCert returns a TLS certificate for the names that a guest uses to reach
// the host: host.docker.internal and its address 10.0.2.2.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate the server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "host.docker.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"host.docker.internal"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.2.2")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create the server certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// trustAsHostRoot makes the CA a root of the host for the rest of the test.
// The variable SSL_CERT_FILE is the test hook of gvx.Config.HostCACerts on
// every host OS. A real host reads its system store instead.
func (ca *testCA) trustAsHostRoot(t *testing.T) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "host-root.pem")
	if err := os.WriteFile(file, ca.pem, 0o600); err != nil {
		t.Fatalf("write the host root file: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", file)
}

// startTLSServer serves the body "tls-ok" over HTTPS on the host loopback with
// a certificate of the CA. It returns the port.
func startTLSServer(t *testing.T, ca *testCA) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls-ok\n")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split the server address: %v", err)
	}
	return port
}

// hostCAPlatform picks the hardware backend when it starts, and else systrap.
// The tests check files and TLS, which every backend serves the same way, so
// a hosted runner without a hypervisor still runs them.
func hostCAPlatform(t *testing.T) gvx.PlatformType {
	t.Helper()
	if runtime.GOOS == "darwin" {
		hvtest.Require(t)
		return gvx.PlatformHVF
	}
	if hvtest.Available() {
		return gvx.PlatformAuto
	}
	systraptest.Require(t)
	return gvx.PlatformSystrap
}

// runHostCAGuest runs cfg to its end and returns the exit code with the
// output.
func runHostCAGuest(t *testing.T, cfg gvx.Config) (code int, stdout, stderr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	cfg.Platform = hostCAPlatform(t)
	cfg.Stdout, cfg.Stderr = &outBuf, &errBuf
	cfg.DisableHostLockdown = true
	sb, err := gvx.New(ctx, cfg)
	if err != nil {
		t.Fatalf("gvx.New: %v", err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	code, err = sb.Run(ctx)
	if err != nil {
		t.Fatalf("Run = (%d, %v)\nstdout=%s\nstderr=%s", code, err, outBuf.String(), errBuf.String())
	}
	return code, outBuf.String(), errBuf.String()
}

// TestE2EHostCACertsMergeIntoTheBundlesOfTheImage reads the bundles of a small
// image with its own cat program. It needs no network and no registry.
func TestE2EHostCACertsMergeIntoTheBundlesOfTheImage(t *testing.T) {
	cat, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	imageCA := newTestCA(t, "image CA")
	hostCA := newTestCA(t, "host CA")
	hostCA.trustAsHostRoot(t)

	const bundle = "/etc/ssl/certs/ca-certificates.crt"
	withBundle := mustTar(t,
		testimage.File{Name: "bin/cat", Data: cat, Mode: 0o755},
		testimage.File{Name: "etc/ssl/certs/ca-certificates.crt", Data: imageCA.pem},
		testimage.File{Name: "etc/ssl/cert.pem", Type: '2', Linkname: "certs/ca-certificates.crt"},
	)
	withoutBundle := mustTar(t, testimage.File{Name: "bin/cat", Data: cat, Mode: 0o755})
	registry := func(layer []byte) string {
		return testimage.NewRegistry(t, "gvx/e2e", "1", testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{layer}})
	}
	run := func(t *testing.T, base gvx.Config, files ...string) string {
		t.Helper()
		base.OCIImage = "gvx/e2e:1"
		base.OCICacheDir = t.TempDir()
		base.NetworkMode = gvx.NetModeNone
		base.Argv = append([]string{"/bin/cat"}, files...)
		code, stdout, stderr := runHostCAGuest(t, base)
		if code != 0 {
			t.Fatalf("cat %v = (code %d, stdout %q, stderr %q), want 0", files, code, stdout, stderr)
		}
		return stdout
	}

	t.Run("the default leaves the bundle of the image as it is", func(t *testing.T) {
		got := run(t, gvx.Config{RegistryBaseURL: registry(withBundle)}, bundle, "/etc/ssl/cert.pem")
		if want := string(imageCA.pem) + string(imageCA.pem); got != want {
			t.Errorf("bundles = %q, want the image bundle twice: %q", got, want)
		}
	})

	t.Run("the flag adds the host roots after the roots of the image", func(t *testing.T) {
		got := run(t, gvx.Config{RegistryBaseURL: registry(withBundle), HostCACerts: true}, bundle, "/etc/ssl/cert.pem")
		// /etc/ssl/cert.pem is a link to the bundle, so both reads agree.
		if len(got)%2 != 0 || got[:len(got)/2] != got[len(got)/2:] {
			t.Fatalf("the bundle and the link to it differ")
		}
		merged := got[:len(got)/2]
		if !strings.HasPrefix(merged, string(imageCA.pem)) {
			t.Errorf("the bundle does not start with the image roots: %.80q", merged)
		}
		if n := strings.Count(merged, string(imageCA.pem)); n != 1 {
			t.Errorf("the image root appears %d times, want 1", n)
		}
		if n := strings.Count(merged, string(hostCA.pem)); n != 1 {
			t.Errorf("the host root appears %d times, want 1", n)
		}
	})

	t.Run("an image without a bundle gets one", func(t *testing.T) {
		got := run(t, gvx.Config{RegistryBaseURL: registry(withoutBundle), HostCACerts: true}, bundle)
		if strings.Count(got, string(hostCA.pem)) != 1 {
			t.Errorf("new bundle holds the host root %d times, want 1", strings.Count(got, string(hostCA.pem)))
		}
	})

	t.Run("a mount over the bundle wins", func(t *testing.T) {
		own := []byte(string(newTestCA(t, "own CA").pem))
		ownFile := filepath.Join(t.TempDir(), "own.pem")
		if err := os.WriteFile(ownFile, own, 0o600); err != nil {
			t.Fatal(err)
		}
		got := run(t, gvx.Config{
			RegistryBaseURL: registry(withBundle),
			HostCACerts:     true,
			Mounts:          []gvx.Mount{{Kind: gvx.MountBind, HostPath: ownFile, GuestPath: bundle, ReadOnly: true}},
		}, bundle, "/etc/ssl/cert.pem")
		if want := string(own) + string(own); got != want {
			t.Errorf("bundles = %q, want the mounted file twice: %q", got, want)
		}
	})
}

func hostCAURL(port string) string { return "https://host.docker.internal:" + port + "/" }

// TestE2EHostCACertsAlpineWgetTrustsTheHostRoot fetches a page from a host TLS
// server that a private CA signed. Without the flag the guest rejects the
// certificate. With the flag the guest trusts it, and the trust survives
// update-ca-certificates.
func TestE2EHostCACertsAlpineWgetTrustsTheHostRoot(t *testing.T) {
	requireRegistry(t)
	ca := newTestCA(t, "gvx e2e host CA")
	port := startTLSServer(t, ca)
	cache := sharedCacheDir(t)

	run := func(t *testing.T, hostCA bool, script string) (int, string, string) {
		t.Helper()
		return runHostCAGuest(t, gvx.Config{
			OCIImage:     "alpine:3.20",
			OCICacheDir:  cache,
			NetworkMode:  gvx.NetModeNAT,
			Argv:         []string{"sh", "-c", script},
			HostCACerts:  hostCA,
			PullPolicy:   gvx.PullMissing,
			Warnings:     io.Discard,
			AllowSUID:    false,
			Architecture: runtime.GOARCH,
		})
	}
	fetch := "wget -qO- " + hostCAURL(port)

	code, stdout, stderr := run(t, false, fetch)
	if code == 0 || strings.Contains(stdout, "tls-ok") {
		t.Fatalf("wget without the flag = (code %d, stdout %q, stderr %q), want a certificate failure", code, stdout, stderr)
	}

	// The hook goes in after the first run: on Linux, SSL_CERT_FILE also steers
	// the TLS client of this process.
	ca.trustAsHostRoot(t)

	code, stdout, stderr = run(t, true, fetch)
	if code != 0 || strings.TrimSpace(stdout) != "tls-ok" {
		t.Fatalf("wget with the flag = (code %d, stdout %q, stderr %q), want tls-ok", code, stdout, stderr)
	}

	// The anchor file keeps the root when a later update rebuilds the bundle.
	update := `set -e
ls /usr/local/share/ca-certificates/gvx-host-*.crt >/dev/null
apk add --no-cache ca-certificates >/dev/null
update-ca-certificates >/dev/null 2>&1
` + fetch
	code, stdout, stderr = run(t, true, update)
	if code != 0 || strings.TrimSpace(stdout) != "tls-ok" {
		t.Fatalf("update-ca-certificates in the guest = (code %d, stdout %q, stderr %q), want tls-ok after the update", code, stdout, stderr)
	}
}

// TestE2EHostCACertsDindPullsFromATLSRegistry starts docker:dind in the guest
// and pulls an image from a registry on the host that a private CA signs. The
// engine reads the bundle of the guest, so the flag decides the result.
func TestE2EHostCACertsDindPullsFromATLSRegistry(t *testing.T) {
	requireRegistry(t)
	cat, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	ca := newTestCA(t, "gvx e2e registry CA")
	reg := testimage.NewTLSRegistryServer(t, ca.serverCert(t), "gvx/e2e", "1",
		testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{mustTar(t, testimage.File{Name: "bin/cat", Data: cat, Mode: 0o755})}})
	regURL, err := url.Parse(reg.URL)
	if err != nil {
		t.Fatal(err)
	}
	image := "host.docker.internal:" + regURL.Port() + "/gvx/e2e:1"

	script := fmt.Sprintf(`
dockerd-entrypoint.sh --tls=false >/tmp/dockerd.log 2>&1 &
i=0
until docker info >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 180 ] && { echo "DOCKERD-FAILED"; tail -n 40 /tmp/dockerd.log; exit 1; }
  sleep 1
done
if out=$(docker pull %s 2>&1); then echo PULL-OK; else echo PULL-FAILED; echo "$out"; fi
`, image)
	run := func(t *testing.T, hostCA bool) string {
		t.Helper()
		code, stdout, stderr := runHostCAGuest(t, gvx.Config{
			OCIImage:      "docker:dind",
			OCICacheDir:   sharedCacheDir(t),
			NetworkMode:   gvx.NetModeNAT,
			Entrypoint:    []string{"sh", "-c"},
			EntrypointSet: true,
			Cmd:           []string{script},
			Envv:          []string{"DOCKER_TLS_CERTDIR="},
			NetRaw:        true, AllowPacketSocketWrite: true, AllowSUID: true,
			Mounts:      []gvx.Mount{{Kind: gvx.MountTmpfs, GuestPath: "/var/lib/docker", TmpfsSizeBytes: 2 << 30}},
			HostCACerts: hostCA,
			Warnings:    io.Discard,
		})
		if code != 0 {
			t.Fatalf("dind script = (code %d, stdout %q, stderr %q)", code, stdout, stderr)
		}
		return stdout
	}

	if out := run(t, false); !strings.Contains(out, "PULL-FAILED") || !strings.Contains(out, "x509") {
		t.Fatalf("docker pull without the flag = %q, want a certificate failure", out)
	}
	ca.trustAsHostRoot(t)
	if out := run(t, true); !strings.Contains(out, "PULL-OK") {
		t.Fatalf("docker pull with the flag = %q, want PULL-OK", out)
	}
}
