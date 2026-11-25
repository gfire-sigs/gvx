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
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx"
)

// buildCheckpointProbeOCIArchive writes a single-arch OCI layout tar archive
// containing /bin/checkpointprobe and sample image files for offline rungvx E2E
// tests.
func buildCheckpointProbeOCIArchive(t *testing.T) string {
	t.Helper()
	probePath := acceptprog.BuildCheckpointProbe(t, hostArch())
	probeBytes, err := os.ReadFile(probePath)
	if err != nil {
		t.Fatalf("read checkpointprobe: %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/checkpointprobe", Data: probeBytes, Mode: 0o755},
		testimage.File{Name: "etc/image-keep.txt", Data: []byte("keep-v1\n"), Mode: 0o644},
		testimage.File{Name: "etc/image-mod.txt", Data: []byte("mod-v1\n"), Mode: 0o644},
		testimage.File{Name: "etc/image-del.txt", Data: []byte("delete-me\n"), Mode: 0o644},
		testimage.File{Name: "opt/dir/child.txt", Data: []byte("lower-child\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	sumHex := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	layerHex := sumHex(layer)

	cfgObj := map[string]any{
		"architecture": hostArch(),
		"os":           "linux",
		"config": map[string]any{
			"Entrypoint": []string{"/bin/checkpointprobe"},
		},
		"rootfs": map[string]any{
			"type":     "layers",
			"diff_ids": []string{"sha256:" + layerHex},
		},
	}
	cfgBytes, err := json.Marshal(cfgObj)
	if err != nil {
		t.Fatal(err)
	}
	cfgHex := sumHex(cfgBytes)

	manifestObj := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    "sha256:" + cfgHex,
			"size":      len(cfgBytes),
		},
		"layers": []map[string]any{
			{
				"mediaType": "application/vnd.oci.image.layer.v1.tar",
				"digest":    "sha256:" + layerHex,
				"size":      len(layer),
			},
		},
	}
	manifestBytes, err := json.Marshal(manifestObj)
	if err != nil {
		t.Fatal(err)
	}
	manifestHex := sumHex(manifestBytes)

	indexObj := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest":    "sha256:" + manifestHex,
				"size":      len(manifestBytes),
				"platform": map[string]any{
					"os":           "linux",
					"architecture": hostArch(),
				},
			},
		},
	}
	indexBytes, err := json.Marshal(indexObj)
	if err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(t.TempDir(), "checkpointprobe-oci.tar")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, member := range []struct {
		name string
		data []byte
	}{
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)},
		{"index.json", indexBytes},
		{"blobs/sha256/" + manifestHex, manifestBytes},
		{"blobs/sha256/" + cfgHex, cfgBytes},
		{"blobs/sha256/" + layerHex, layer},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name:     member.name,
			Mode:     0o644,
			Size:     int64(len(member.data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return archivePath
}

func writeE2ETestHostCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "gvx-e2e-rootvol-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA cert: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "e2e-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write test CA PEM: %v", err)
	}
	return caPath
}

func TestE2ERootfsVolumePersistenceAndCLI(t *testing.T) {
	rungvxBin := toolPath(t, rungvxPkg)
	archive := buildCheckpointProbeOCIArchive(t)
	t.Setenv("SSL_CERT_FILE", writeE2ETestHostCAPEM(t))

	for _, b := range fixedAddressBackends() {
		for _, layout := range []struct {
			name    string
			managed bool
			spec    func(cacheDir string) (flagVal, imgPath string)
		}{
			{
				name:    "managed",
				managed: true,
				spec: func(cacheDir string) (string, string) {
					return "e2eroot", filepath.Join(cacheDir, "volumes", "e2eroot.ext4")
				},
			},
			{
				name: "image_path",
				spec: func(string) (string, string) {
					p := filepath.Join(t.TempDir(), "rootfs.ext4")
					return p, p
				},
			},
		} {
			t.Run(b.name+"/"+layout.name, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				cacheDir := t.TempDir()
				rootSpec, imgPath := layout.spec(cacheDir)

				runStep := func(mode, wantBanner string) {
					t.Helper()
					stdout, stderr, code := runTool(t, rungvxBin,
						"run",
						"-platform="+string(b.plat),
						"-net=none",
						"-cache-dir="+cacheDir,
						"--host-ca-certs",
						"-rootfs-volume="+rootSpec,
						archive,
						"-mode="+mode,
					)
					if code != 0 {
						skipWhenFixedAddressRefused(t, "rungvx run rootfs-volume", fmt.Errorf("exit %d: %s", code, stderr))
						t.Fatalf("rungvx run (%s) = (code %d, stdout %q, stderr %q)", mode, code, stdout, stderr)
					}
					if !strings.Contains(stdout, wantBanner) {
						t.Fatalf("rungvx run (%s) stdout = %q, want %q", mode, stdout, wantBanner)
					}
				}

				runStep("rootfs-write", "WRITTEN:rootfs")
				requireCleanImage(t, imgPath, "rootfs-write")

				if layout.managed {
					lsOut, lsErr, lsCode := runTool(t, rungvxBin, "volume", "ls", "-q", "-cache-dir="+cacheDir)
					if lsCode != 0 || strings.TrimSpace(lsOut) != "e2eroot" {
						t.Fatalf("rungvx volume ls -q = (%d, %q, %q), want e2eroot", lsCode, lsOut, lsErr)
					}
					inspOut, inspErr, inspCode := runTool(t, rungvxBin, "volume", "inspect", "e2eroot", "-cache-dir="+cacheDir)
					if inspCode != 0 {
						t.Fatalf("rungvx volume inspect = (%d, %q, %q)", inspCode, inspOut, inspErr)
					}
					var infos []gvx.VolumeInfo
					if err := json.Unmarshal([]byte(inspOut), &infos); err != nil || len(infos) != 1 || infos[0].Driver != gvx.DriverExt4lite || infos[0].InUse {
						t.Fatalf("volume inspect parsed = (%+v, %v), want 1 unlocked ext4lite volume", infos, err)
					}
					dfOut, dfErr, dfCode := runTool(t, rungvxBin, "system", "df", "-v", "-cache-dir="+cacheDir)
					if dfCode != 0 || !strings.Contains(dfOut, "e2eroot") {
						t.Fatalf("rungvx system df -v = (%d, %q, %q), want e2eroot", dfCode, dfOut, dfErr)
					}
				}

				runStep("rootfs-verify", "VERIFIED:rootfs")
				requireCleanImage(t, imgPath, "rootfs-verify")
				runStep("rootfs-verify", "VERIFIED:rootfs")
				requireCleanImage(t, imgPath, "rootfs-verify-boot3")
				if fsck, err := exec.LookPath("e2fsck"); err == nil {
					if out, err := exec.Command(fsck, "-fn", imgPath).CombinedOutput(); err != nil {
						t.Errorf("e2fsck -fn %s: %v\n%s", imgPath, err, out)
					}
				}

				if layout.managed {
					rmOut, rmErr, rmCode := runTool(t, rungvxBin, "volume", "rm", "e2eroot", "-cache-dir="+cacheDir)
					if rmCode != 0 {
						t.Fatalf("rungvx volume rm = (%d, %q, %q), want 0", rmCode, rmOut, rmErr)
					}
				}
			})
		}
	}
}

func TestE2ERootfsVolumeLockdownUnboundBlocked(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	archive := buildCheckpointProbeOCIArchive(t)

	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			cacheDir := t.TempDir()
			outside := t.TempDir()
			secret := filepath.Join(outside, "secret.txt")
			if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}

			stdout, stderr, code := runTool(t, probe,
				"-platform="+string(b.plat),
				"-cache-dir="+cacheDir,
				"-image="+archive,
				"-rootfs-volume=lockroot",
				"-outside-file="+secret,
				"-outside-dir="+outside,
				"--",
				"/bin/checkpointprobe",
				"-mode=rootfs-write",
			)
			if code != 0 {
				t.Fatalf("lockdownprobe: exit %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
			}
			var rep lockdownprobe.Report
			if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
				t.Fatalf("decode report %q: %v", stdout, err)
			}
			if msg := rep.NewErr; msg != "" {
				skipWhenFixedAddressRefused(t, "lockdownprobe New", fmt.Errorf("%s", msg))
				t.Fatalf("New failed: %s", msg)
			}
			if !rep.Lockdown.Applied || !rep.LockedAPI {
				t.Errorf("Lockdown.Applied=%v LockedAPI=%v, want both true", rep.Lockdown.Applied, rep.LockedAPI)
			}
			if !rep.Lockdown.UnboundFileOpenBlocked {
				t.Errorf("UnboundFileOpenBlocked = false, want true when only RootVolume is used")
			}
			if rep.WriteOutsideErr == "" || rep.ReadOutsideErr == "" {
				t.Errorf("outside access = (read=%q write=%q), want both denied", rep.ReadOutsideErr, rep.WriteOutsideErr)
			}
			if msg := rep.GuestRunErr; msg != "" {
				skipWhenFixedAddressRefused(t, "lockdownprobe Run", fmt.Errorf("%s", msg))
				t.Fatalf("GuestRunErr = %s", msg)
			}
			if rep.GuestExitCode != 0 || !strings.Contains(rep.GuestStdout, "WRITTEN:rootfs") {
				t.Fatalf("guest = (code %d, stdout %q), want exit 0 with WRITTEN:rootfs", rep.GuestExitCode, rep.GuestStdout)
			}
		})
	}
}

func TestE2ERootfsVolumeCheckpointAndRestore(t *testing.T) {
	rungvxBin := toolPath(t, rungvxPkg)
	archive := buildCheckpointProbeOCIArchive(t)

	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cacheDir := t.TempDir()
			ckptDir := filepath.Join(t.TempDir(), "bundle")
			sockDir := shortCheckpointSocketDir(t)
			controlAddr := filepath.Join(sockDir, "ctrl.sock")
			if !canBindUnixControlSocket(sockDir) {
				controlAddr = freeLoopbackControlSocketAddr(t)
			}

			stdinR, stdinW := io.Pipe()
			defer stdinW.Close()
			stdout1 := newCheckpointNotifyBuffer()
			stderr1 := newCheckpointNotifyBuffer()

			runCmd := exec.CommandContext(ctx, rungvxBin,
				"run",
				"-platform="+string(b.plat),
				"-net=none",
				"-cache-dir="+cacheDir,
				"-rootfs-volume=e2eckpt",
				"-checkpoint-dir="+ckptDir,
				"-control-socket="+controlAddr,
				archive,
				"-mode=rootfs-ckpt",
			)
			runCmd.Stdin = stdinR
			runCmd.Stdout = stdout1
			runCmd.Stderr = stderr1
			if err := runCmd.Start(); err != nil {
				t.Fatalf("start rungvx run: %v", err)
			}
			runWaitCh := make(chan error, 1)
			go func() {
				runWaitCh <- runCmd.Wait()
			}()
			defer func() {
				_ = stdinW.Close()
				if runCmd.Process != nil {
					_ = runCmd.Process.Kill()
				}
			}()

			readyTimer := time.NewTimer(30 * time.Second)
			defer readyTimer.Stop()
			for !strings.Contains(stdout1.String(), "READY:rootfs-ckpt\n") {
				select {
				case wErr := <-runWaitCh:
					skipWhenFixedAddressRefused(t, "rungvx run", fmt.Errorf("%w: %s", wErr, stderr1.String()))
					t.Fatalf("rungvx run exited before READY: %v (stdout=%q stderr=%q)", wErr, stdout1.String(), stderr1.String())
				case <-stdout1.ch:
				case <-stderr1.ch:
				case <-readyTimer.C:
					t.Fatalf("timed out waiting for READY:rootfs-ckpt (stdout=%q stderr=%q)", stdout1.String(), stderr1.String())
				}
			}

			ckptOut, ckptErr, ckptCode := runTool(t, rungvxBin,
				"checkpoint",
				"-control-socket="+controlAddr,
				"-checkpoint-dir="+ckptDir,
			)
			if ckptCode != 0 {
				t.Fatalf("rungvx checkpoint = (code %d, stdout %q, stderr %q), want 0", ckptCode, ckptOut, ckptErr)
			}
			_ = stdinW.Close()
			if wErr := <-runWaitCh; wErr != nil {
				t.Fatalf("rungvx run exit after checkpoint: %v (stderr=%q)", wErr, stderr1.String())
			}
			verifyCheckpointBundleFiles(t, ckptDir)

			// Restoring without -rootfs-volume must fail manifest validation.
			_, badErr, badCode := runTool(t, rungvxBin,
				"restore",
				"-platform="+string(b.plat),
				"-net=none",
				"-cache-dir="+cacheDir,
				"-checkpoint-dir="+ckptDir,
			)
			if badCode == 0 || !strings.Contains(badErr, "root volume mismatch") {
				t.Fatalf("rungvx restore without -rootfs-volume = (code %d, stderr %q), want mismatch failure", badCode, badErr)
			}

			// Restore with -rootfs-volume and finish guest.
			var restoreOut, restoreErr bytes.Buffer
			restoreCmd := exec.CommandContext(ctx, rungvxBin,
				"restore",
				"-platform="+string(b.plat),
				"-net=none",
				"-cache-dir="+cacheDir,
				"-rootfs-volume=e2eckpt",
				"-checkpoint-dir="+ckptDir,
			)
			restoreCmd.Stdin = strings.NewReader("go\n")
			restoreCmd.Stdout = &restoreOut
			restoreCmd.Stderr = &restoreErr
			if err := restoreCmd.Run(); err != nil {
				t.Fatalf("rungvx restore failed: %v (stdout=%q stderr=%q)", err, restoreOut.String(), restoreErr.String())
			}
			if !strings.Contains(restoreOut.String(), "VERIFIED:rootfs-ckpt\n") {
				t.Fatalf("rungvx restore stdout = %q, want VERIFIED:rootfs-ckpt", restoreOut.String())
			}

			// Boot a 3rd fresh sandbox to verify post-restore root writes persisted in .ext4.
			verifyOut, verifyErr, verifyCode := runTool(t, rungvxBin,
				"run",
				"-platform="+string(b.plat),
				"-net=none",
				"-cache-dir="+cacheDir,
				"-rootfs-volume=e2eckpt",
				archive,
				"-mode=rootfs-ckpt-verify",
			)
			if verifyCode != 0 || !strings.Contains(verifyOut, "VERIFIED:rootfs-ckpt-persist\n") {
				t.Fatalf("3rd rungvx run = (code %d, stdout %q, stderr %q), want VERIFIED:rootfs-ckpt-persist", verifyCode, verifyOut, verifyErr)
			}

			imgPath := filepath.Join(cacheDir, "volumes", "e2eckpt.ext4")
			requireCleanImage(t, imgPath, "restore-and-reopen")
			if fsck, err := exec.LookPath("e2fsck"); err == nil {
				if out, err := exec.Command(fsck, "-fn", imgPath).CombinedOutput(); err != nil {
					t.Errorf("e2fsck -fn %s: %v\n%s", imgPath, err, out)
				}
			}
		})
	}
}
