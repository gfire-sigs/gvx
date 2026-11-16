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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func buildRootVolumeTestLayer(t *testing.T) []byte {
	t.Helper()
	probePath := acceptprog.BuildCheckpointProbe(t, runtime.GOARCH)
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
		testimage.File{Name: "etc/ssl/certs/ca-certificates.crt", Data: nil, Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	return layer
}

func writeTestHostCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "gvx-root-volume-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA certificate: %v", err)
	}
	caPath := filepath.Join(t.TempDir(), "test-host-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write test CA PEM: %v", err)
	}
	return caPath
}

func assertExt4SuperblockClean(t *testing.T, imgPath string) {
	t.Helper()
	f, err := os.Open(imgPath)
	if err != nil {
		t.Fatalf("open %s: %v", imgPath, err)
	}
	defer f.Close()
	var state [2]byte
	if _, err := f.ReadAt(state[:], 1024+0x3A); err != nil {
		t.Fatalf("read ext4 s_state from %s: %v", imgPath, err)
	}
	if binary.LittleEndian.Uint16(state[:])&1 == 0 {
		t.Fatalf("%s superblock is not marked clean (s_state=%#x)", imgPath, state)
	}
}

func TestRootVolumeMultiRunPersistenceAndHostCACerts(t *testing.T) {
	requireCheckpointGuestBackend(t)
	layer := buildRootVolumeTestLayer(t)
	t.Setenv("SSL_CERT_FILE", writeTestHostCAPEM(t))

	for _, tc := range []struct {
		name    string
		rootVol func(cacheDir string) (spec, imgPath string)
	}{
		{
			name: "managed_name",
			rootVol: func(cacheDir string) (string, string) {
				return "persist-root", filepath.Join(cacheDir, "volumes", "persist-root.ext4")
			},
		},
		{
			name: "image_path",
			rootVol: func(string) (string, string) {
				p := filepath.Join(t.TempDir(), "custom-rootfs.ext4")
				return p, p
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			rootSpec, imgPath := tc.rootVol(cacheDir)

			runMode := func(mode, wantBanner string) {
				t.Helper()
				var stdout, stderr bytes.Buffer
				cfg := newCheckpointTestConfig(t, cacheDir)
				cfg.OCILayerTars = [][]byte{layer}
				cfg.RootVolume = rootSpec
				cfg.HostCACerts = true
				cfg.Argv = []string{"/bin/checkpointprobe", "-mode=" + mode}
				cfg.Stdout = &stdout
				cfg.Stderr = &stderr

				sb, err := New(context.Background(), cfg)
				if err != nil {
					t.Fatalf("New(%s): %v", mode, err)
				}
				code, runErr := sb.Run(context.Background())
				closeErr := sb.Close()
				if runErr != nil || closeErr != nil || code != 0 {
					t.Fatalf("Run(%s) = (%d, %v) Close=%v stdout=%q stderr=%q",
						mode, code, runErr, closeErr, stdout.String(), stderr.String())
				}
				if !strings.Contains(stdout.String(), wantBanner) {
					t.Fatalf("Run(%s) stdout = %q, want %q", mode, stdout.String(), wantBanner)
				}
				assertExt4SuperblockClean(t, imgPath)
			}

			// Boot 1: write files, whiteouts, opaque dir, links, chmod /, xattrs.
			runMode("rootfs-write", "WRITTEN:rootfs")
			// Boot 2: verify persisted state, resolv.conf, hosts, and CA certs.
			runMode("rootfs-verify", "VERIFIED:rootfs")
			// Boot 3: verify repeated startup remains idempotent.
			runMode("rootfs-verify", "VERIFIED:rootfs")
		})
	}
}

func TestRootVolumeValidationErrors(t *testing.T) {
	cacheDir := t.TempDir()
	elfBytes, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: elfBytes, Mode: 0o755})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	t.Run("bin_without_image_layers", func(t *testing.T) {
		cfg := Config{
			Platform:            PlatformAuto,
			NetworkMode:         NetModeNone,
			OCICacheDir:         cacheDir,
			ELFBytes:            elfBytes,
			RootVolume:          "bad-bin-root",
			DisableHostLockdown: true,
		}
		_, nErr := New(context.Background(), cfg)
		if !errors.Is(nErr, ErrInvalidConfig) {
			t.Fatalf("New(-bin with RootVolume) = %v, want ErrInvalidConfig", nErr)
		}
	})

	t.Run("duplicate_volume_in_mounts", func(t *testing.T) {
		cfg := Config{
			Platform:            PlatformAuto,
			NetworkMode:         NetModeNone,
			OCICacheDir:         cacheDir,
			OCILayerTars:        [][]byte{layer},
			RootVolume:          "dup-root",
			Mounts:              []Mount{{Kind: MountVolume, VolumeName: "dup-root", GuestPath: "/data"}},
			DisableHostLockdown: true,
		}
		_, nErr := New(context.Background(), cfg)
		if !errors.Is(nErr, ErrInvalidConfig) || !strings.Contains(nErr.Error(), "mounted twice") {
			t.Fatalf("New(duplicate RootVolume) = %v, want ErrInvalidConfig(mounted twice)", nErr)
		}
	})

	t.Run("concurrent_lock_returns_err_volume_in_use", func(t *testing.T) {
		requireCheckpointGuestBackend(t)
		cfg1 := newCheckpointTestConfig(t, cacheDir)
		cfg1.OCILayerTars = [][]byte{layer}
		cfg1.RootVolume = "locked-root"
		sb1, err := New(context.Background(), cfg1)
		if err != nil {
			t.Fatalf("New(sb1): %v", err)
		}
		defer sb1.Close()

		cfg2 := newCheckpointTestConfig(t, cacheDir)
		cfg2.OCILayerTars = [][]byte{layer}
		cfg2.RootVolume = "locked-root"
		_, err2 := New(context.Background(), cfg2)
		if !errors.Is(err2, ext4lite.ErrVolumeInUse) {
			t.Fatalf("concurrent New(sb2) = %v, want ErrVolumeInUse", err2)
		}
	})
}

func TestRootVolumeCheckpointAndRestore(t *testing.T) {
	requireCheckpointGuestBackend(t)
	cacheDir := t.TempDir()
	layer := buildRootVolumeTestLayer(t)
	ckptDir := filepath.Join(t.TempDir(), "bundle-rootvol")

	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout1 := newNotifyBuffer()
	var stderr1 syncBuffer

	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.RootVolume = "ckpt-root"
	cfg.CheckpointDir = ckptDir
	cfg.Argv = []string{"/bin/checkpointprobe", "-mode=rootfs-ckpt"}
	cfg.Stdin = stdinR
	cfg.Stdout = stdout1
	cfg.Stderr = &stderr1

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	type runResult struct {
		code int
		err  error
	}
	runCh := make(chan runResult, 1)
	go func() {
		code, rErr := sb.Run(context.Background())
		runCh <- runResult{code: code, err: rErr}
	}()

	stdout1.waitForSubstring(t, "READY:rootfs-ckpt\n", 15*time.Second)

	if err := sb.Checkpoint(context.Background(), CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	res1 := <-runCh
	if res1.err != nil || res1.code != 0 {
		t.Fatalf("Run 1 = (%d, %v), stderr=%q", res1.code, res1.err, stderr1.String())
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	manifest, err := readAndParseManifest(ckptDir)
	if err != nil {
		t.Fatalf("readAndParseManifest: %v", err)
	}
	if !manifest.RootVolume {
		t.Fatalf("manifest.RootVolume = false, want true")
	}

	// Restore without RootVolume must fail with ErrCheckpointManifest.
	missingRootCfg := newCheckpointTestConfig(t, cacheDir)
	if _, err := Restore(context.Background(), missingRootCfg, RestoreOptions{Dir: ckptDir}); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("Restore without RootVolume = %v, want ErrCheckpointManifest", err)
	}

	// Verify manifest mismatch when RootVolume is passed for a non-RootVolume bundle.
	noRootBundle := filepath.Join(t.TempDir(), "no-root-bundle")
	if err := os.MkdirAll(noRootBundle, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{checkpointStateFileName, checkpointPagesMetaFileName, checkpointPagesFileName} {
		if err := os.WriteFile(filepath.Join(noRootBundle, name), []byte("stub"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mNoRoot := manifest
	mNoRoot.RootVolume = false
	mBytes, err := json.Marshal(mNoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(noRootBundle, checkpointManifestFileName), mBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	extraRootCfg := newCheckpointTestConfig(t, cacheDir)
	extraRootCfg.RootVolume = "ckpt-root"
	if _, err := Restore(context.Background(), extraRootCfg, RestoreOptions{Dir: noRootBundle}); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("Restore with unexpected RootVolume = %v, want ErrCheckpointManifest", err)
	}

	// Restore with RootVolume and verify open/unlinked FD + post-restore writes.
	var stdout2, stderr2 bytes.Buffer
	restoreCfg := newCheckpointTestConfig(t, cacheDir)
	restoreCfg.RootVolume = "ckpt-root"
	restoreCfg.Stdin = strings.NewReader("go\n")
	restoreCfg.Stdout = &stdout2
	restoreCfg.Stderr = &stderr2

	restoredSB, err := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	code2, runErr2 := restoredSB.Run(context.Background())
	closeErr2 := restoredSB.Close()
	if runErr2 != nil || closeErr2 != nil || code2 != 0 {
		t.Fatalf("restored Run = (%d, %v) Close=%v stdout=%q stderr=%q",
			code2, runErr2, closeErr2, stdout2.String(), stderr2.String())
	}
	if !strings.Contains(stdout2.String(), "VERIFIED:rootfs-ckpt") {
		t.Fatalf("restored stdout = %q, want VERIFIED:rootfs-ckpt", stdout2.String())
	}

	// Boot a 3rd fresh sandbox on the same RootVolume and verify post-restore writes persisted.
	var stdout3, stderr3 bytes.Buffer
	cfg3 := newCheckpointTestConfig(t, cacheDir)
	cfg3.OCILayerTars = [][]byte{layer}
	cfg3.RootVolume = "ckpt-root"
	cfg3.Argv = []string{"/bin/checkpointprobe", "-mode=rootfs-ckpt-verify"}
	cfg3.Stdout = &stdout3
	cfg3.Stderr = &stderr3

	sb3, err := New(context.Background(), cfg3)
	if err != nil {
		t.Fatalf("New(sb3): %v", err)
	}
	code3, runErr3 := sb3.Run(context.Background())
	closeErr3 := sb3.Close()
	if runErr3 != nil || closeErr3 != nil || code3 != 0 {
		t.Fatalf("sb3 Run = (%d, %v) Close=%v stdout=%q stderr=%q",
			code3, runErr3, closeErr3, stdout3.String(), stderr3.String())
	}
	if !strings.Contains(stdout3.String(), "VERIFIED:rootfs-ckpt-persist") {
		t.Fatalf("sb3 stdout = %q, want VERIFIED:rootfs-ckpt-persist", stdout3.String())
	}
	assertExt4SuperblockClean(t, filepath.Join(cacheDir, "volumes", "ckpt-root.ext4"))
}

func TestRootVolumeClearsStaleWorkDirectoryOnBoot(t *testing.T) {
	requireCheckpointGuestBackend(t)
	cacheDir := t.TempDir()
	layer := buildRootVolumeTestLayer(t)
	imgPath := filepath.Join(t.TempDir(), "stale-work.ext4")

	// Boot 1 populates the root volume.
	var out1, err1 bytes.Buffer
	cfg1 := newCheckpointTestConfig(t, cacheDir)
	cfg1.OCILayerTars = [][]byte{layer}
	cfg1.RootVolume = imgPath
	cfg1.Argv = []string{"/bin/checkpointprobe", "-mode=rootfs-write"}
	cfg1.Stdout = &out1
	cfg1.Stderr = &err1
	sb1, err := New(context.Background(), cfg1)
	if err != nil {
		t.Fatalf("New(boot1): %v", err)
	}
	if code, runErr := sb1.Run(context.Background()); runErr != nil || code != 0 {
		_ = sb1.Close()
		t.Fatalf("Run(boot1) = (%d, %v) stderr=%q", code, runErr, err1.String())
	}
	if err := sb1.Close(); err != nil {
		t.Fatalf("Close(boot1): %v", err)
	}

	// Seed stale entries inside /work in the .ext4 image directly.
	seedWork := func() {
		f, oErr := os.OpenFile(imgPath, os.O_RDWR, 0)
		if oErr != nil {
			t.Fatal(oErr)
		}
		vol, vErr := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{})
		if vErr != nil {
			t.Fatal(vErr)
		}
		defer func() {
			if cErr := vol.Close(); cErr != nil {
				t.Fatalf("close seeded volume: %v", cErr)
			}
		}()

		vfsObj := &vfs.VirtualFilesystem{}
		if initErr := vfsObj.Init(gvcontext.Background()); initErr != nil {
			t.Fatal(initErr)
		}
		creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
		sctx := gvcontext.Background()
		fs, rootDentry, fsErr := ext4lite.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
			InternalData: ext4lite.InternalFilesystemOptions{Volume: vol, UniqueID: "/"},
		})
		if fsErr != nil {
			t.Fatal(fsErr)
		}
		mnt := vfsObj.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{})
		fs.DecRef(sctx)
		root := vfs.MakeVirtualDentry(mnt, rootDentry)
		defer root.DecRef(sctx)

		if mkErr := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/work/stale/sub", 0o755); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wErr := vfsWriteFile(sctx, vfsObj, creds, root, "/work/stale/sub/junk.txt", []byte("junk"), 0o644); wErr != nil {
			t.Fatal(wErr)
		}
		if wErr := vfsWriteFile(sctx, vfsObj, creds, root, "/work/top.txt", []byte("top"), 0o644); wErr != nil {
			t.Fatal(wErr)
		}
	}
	seedWork()

	// Boot 2 must clear /work cleanly while preserving /upper.
	var out2, err2 bytes.Buffer
	cfg2 := newCheckpointTestConfig(t, cacheDir)
	cfg2.OCILayerTars = [][]byte{layer}
	cfg2.RootVolume = imgPath
	cfg2.Argv = []string{"/bin/checkpointprobe", "-mode=rootfs-verify"}
	cfg2.Stdout = &out2
	cfg2.Stderr = &err2
	sb2, err := New(context.Background(), cfg2)
	if err != nil {
		t.Fatalf("New(boot2): %v", err)
	}
	code2, runErr2 := sb2.Run(context.Background())
	closeErr2 := sb2.Close()
	if runErr2 != nil || closeErr2 != nil || code2 != 0 {
		t.Fatalf("Run(boot2) = (%d, %v) Close=%v stdout=%q stderr=%q", code2, runErr2, closeErr2, out2.String(), err2.String())
	}
	if !strings.Contains(out2.String(), "VERIFIED:rootfs") {
		t.Fatalf("Run(boot2) stdout = %q, want VERIFIED:rootfs", out2.String())
	}

	// Verify /work is empty inside the .ext4 volume.
	f, err := os.OpenFile(imgPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(gvcontext.Background()); err != nil {
		t.Fatal(err)
	}
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	sctx := gvcontext.Background()
	fs, rootDentry, err := ext4lite.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
		InternalData: ext4lite.InternalFilesystemOptions{Volume: vol, UniqueID: "/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{ReadOnly: true})
	fs.DecRef(sctx)
	root := vfs.MakeVirtualDentry(mnt, rootDentry)
	defer root.DecRef(sctx)

	fd, err := vfsObj.OpenAt(sctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/work")}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		t.Fatalf("open /work: %v", err)
	}
	defer fd.DecRef(sctx)
	var entries []string
	if err := fd.IterDirents(sctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name != "." && d.Name != ".." {
			entries = append(entries, d.Name)
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("/work entries after boot = %v, want empty", entries)
	}
}
