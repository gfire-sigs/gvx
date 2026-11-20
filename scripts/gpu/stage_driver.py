#!/usr/bin/env python3
# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Stage, close, rewrite, sign, and verify KosmicKrisp driver libraries."""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

VALID_SOURCES = ("pinned", "homebrew", "mesa-source")
VALID_TAGS = ("arm64_golden_gate", "arm64_tahoe")
VALID_DRIVER_KEYS = (
    "DRIVER_NAME",
    "DRIVER_FORMULA",
    "DRIVER_LIBRARY",
    "DRIVER_SOURCE_VERSION",
    "DRIVER_SOURCE_URL",
    "DRIVER_SOURCE_SHA256",
    "DRIVER_SOURCE_PYTHON_REQUIREMENTS",
)
VALID_BOTTLE_FIELDS = ("version", "arm64_golden_gate", "arm64_tahoe")
MESA_SOURCE_RUNTIME_FORMULAS = ("spirv-tools",)
MESA_SOURCE_BUILD_TOOLS = (
    "llvm",
    "libclc",
    "spirv-llvm-translator",
    "spirv-tools",
    "meson",
)
LICENSE_CANDIDATES = (
    "license.rst",
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "COPYING.md",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HOMEBREW_OPT_RE = re.compile(r"^@@HOMEBREW_PREFIX@@/opt/([^/]+)/lib/([^/]+)$")
HOMEBREW_CELLAR_RE = re.compile(r"^@@HOMEBREW_CELLAR@@/([^/]+)/[^/]+/lib/([^/]+)$")


def die(msg: str) -> None:
    print(f"stage_driver: {msg}", file=sys.stderr)
    sys.exit(1)


def run_cmd(cmd: list[str], *, capture: bool = False) -> str:
    res = subprocess.run(
        cmd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if res.returncode != 0:
        detail = ""
        if capture and res.stderr:
            detail = f": {res.stderr.strip()}"
        die(f"command failed ({' '.join(cmd)}){detail}")
    return res.stdout if capture else ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def parse_lock(
    lock_path: Path,
    tag: str | None,
    source: str,
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    if not lock_path.is_file():
        die(f"missing lock file: {lock_path}")

    driver: dict[str, str] = {}
    bottles: dict[str, dict[str, str]] = {}
    seen_keys: set[str] = set()

    for lineno, raw_line in enumerate(lock_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            die(f"malformed line {lineno} in {lock_path}: {line}")
        key, val = line.split("=", 1)
        if not (key.startswith("DRIVER_") or key.startswith("BOTTLE.")):
            continue
        if key in seen_keys:
            die(f"duplicate key in {lock_path}: {key}")
        seen_keys.add(key)
        if not val:
            die(f"empty value in {lock_path}: {key}")

        if key.startswith("DRIVER_"):
            if key not in VALID_DRIVER_KEYS:
                die(f"unknown driver key in {lock_path}: {key}")
            driver[key] = val
            continue

        parts = key.split(".")
        if len(parts) != 3 or parts[0] != "BOTTLE" or not parts[1]:
            die(f"malformed bottle key in {lock_path}: {key}")
        _, formula, field = parts
        if field not in VALID_BOTTLE_FIELDS:
            die(f"unknown bottle field in {lock_path}: {key}")
        bottles.setdefault(formula, {})[field] = val

    for req in VALID_DRIVER_KEYS:
        if req not in driver:
            die(f"missing key in {lock_path}: {req}")
    if "/" in driver["DRIVER_LIBRARY"] or ".." in driver["DRIVER_LIBRARY"]:
        die(f"invalid DRIVER_LIBRARY in {lock_path}: {driver['DRIVER_LIBRARY']}")
    if driver["DRIVER_FORMULA"] not in bottles:
        die(f"DRIVER_FORMULA {driver['DRIVER_FORMULA']} has no BOTTLE entries")
    if not SHA256_RE.match(driver["DRIVER_SOURCE_SHA256"]):
        die(f"invalid SHA-256 hash for DRIVER_SOURCE_SHA256: {driver['DRIVER_SOURCE_SHA256']}")

    for formula, fields in bottles.items():
        if "version" not in fields:
            die(f"formula {formula} missing version in {lock_path}")
        for t in VALID_TAGS:
            if t in fields and not SHA256_RE.match(fields[t]):
                die(f"invalid SHA-256 hash for BOTTLE.{formula}.{t}: {fields[t]}")
        if source == "pinned":
            assert tag is not None
            if tag not in fields:
                die(f"formula {formula} missing {tag} hash in {lock_path}")

    mesa_bottle_ver = bottles[driver["DRIVER_FORMULA"]]["version"]
    if driver["DRIVER_SOURCE_VERSION"] != mesa_bottle_ver:
        die(
            f"DRIVER_SOURCE_VERSION ({driver['DRIVER_SOURCE_VERSION']}) "
            f"does not match BOTTLE.{driver['DRIVER_FORMULA']}.version ({mesa_bottle_ver})"
        )

    return driver, bottles


def fetch_bottles(
    bottles: dict[str, dict[str, str]],
    tag: str,
    bottles_dir: Path,
    offline: bool,
) -> tuple[dict[str, Path], set[str]]:
    bottles_dir.mkdir(parents=True, exist_ok=True)
    archives: dict[str, Path] = {}
    redownloaded: set[str] = set()

    for formula, fields in bottles.items():
        version = fields["version"]
        want_sha = fields[tag]
        archive = bottles_dir / f"{formula}-{version}.{tag}.tar.gz"

        need_download = True
        if archive.is_file():
            got_sha = sha256_file(archive)
            if got_sha == want_sha:
                need_download = False
            else:
                die(f"SHA-256 mismatch for cached bottle {archive}: got {got_sha}, want {want_sha}")

        if need_download:
            if offline:
                die(f"offline mode: missing verified bottle {archive}")
            url = f"https://ghcr.io/v2/homebrew/core/{formula}/blobs/sha256:{want_sha}"
            fd, tmp_name = tempfile.mkstemp(prefix=f".tmp-{formula}.", dir=bottles_dir)
            os.close(fd)
            tmp_path = Path(tmp_name)
            try:
                run_cmd([
                    "curl",
                    "-fL",
                    "--retry",
                    "3",
                    "--proto",
                    "=https",
                    "--max-filesize",
                    "134217728",
                    "--connect-timeout",
                    "30",
                    "--max-time",
                    "300",
                    "-H",
                    "Authorization: Bearer QQ==",
                    "-o",
                    str(tmp_path),
                    "--",
                    url,
                ])
                got_sha = sha256_file(tmp_path)
                if got_sha != want_sha:
                    die(f"SHA-256 mismatch for {formula} bottle: got {got_sha}, want {want_sha}")
                os.replace(tmp_path, archive)
                redownloaded.add(formula)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)

        archives[formula] = archive

    return archives, redownloaded


def is_safe_member_path(name: str) -> PurePosixPath:
    if "\x00" in name:
        die(f"archive member contains NUL byte: {name!r}")
    if name.startswith("/"):
        die(f"archive member has absolute path: {name}")
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        die(f"archive member escapes root: {name}")
    return p


def matches_bottle_version(dir_ver: str, lock_ver: str) -> bool:
    if dir_ver == lock_ver:
        return True
    prefix = f"{lock_ver}_"
    return dir_ver.startswith(prefix) and dir_ver[len(prefix) :].isdigit()


def find_extracted_keg(keg_parent: Path, formula: str, version: str) -> Path | None:
    formula_dir = keg_parent / formula
    if not formula_dir.is_dir():
        return None
    matches = sorted(
        p for p in formula_dir.iterdir()
        if p.is_dir() and not p.is_symlink() and matches_bottle_version(p.name, version)
    )
    if len(matches) == 1:
        return matches[0]
    return None


def should_extract_member(path: PurePosixPath, formula: str, version: str) -> bool:
    parts = path.parts
    if len(parts) < 3 or parts[0] != formula or not matches_bottle_version(parts[1], version):
        return False
    if len(parts) == 3 and parts[2] in LICENSE_CANDIDATES:
        return True
    if len(parts) == 4 and parts[2] == "lib" and parts[3].endswith(".dylib"):
        return True
    return False


def verify_symlink_stays_in_keg(member: tarfile.TarInfo, keg_prefix: PurePosixPath) -> None:
    target = member.linkname
    if not target or "\x00" in target:
        die(f"symlink {member.name} has invalid target {target!r}")
    if target.startswith("/"):
        die(f"symlink {member.name} has absolute target {target}")
    joined = PurePosixPath(member.name).parent.joinpath(target)
    norm_parts: list[str] = []
    for part in joined.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not norm_parts:
                die(f"symlink {member.name} -> {target} escapes archive root")
            norm_parts.pop()
        else:
            norm_parts.append(part)
    if tuple(norm_parts[: len(keg_prefix.parts)]) != keg_prefix.parts:
        die(f"symlink {member.name} -> {target} escapes keg {keg_prefix}")


MAX_BOTTLE_MEMBERS = 10000
MAX_BOTTLE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_BOTTLE_TOTAL_BYTES = 256 * 1024 * 1024


def extract_bottles(
    bottles: dict[str, dict[str, str]],
    tag: str,
    bottles_dir: Path,
    archives: dict[str, Path],
    redownloaded: set[str],
) -> dict[str, Path]:
    kegs: dict[str, Path] = {}
    use_data_filter = hasattr(tarfile, "data_filter")
    for formula, fields in bottles.items():
        version = fields["version"]
        keg_parent = bottles_dir / f"{formula}-{version}.{tag}"
        keg_root = None if formula in redownloaded else find_extracted_keg(keg_parent, formula, version)
        if keg_root is None:
            tmp_dir = Path(tempfile.mkdtemp(prefix=f".tmp-ext-{formula}.", dir=bottles_dir))
            try:
                with tarfile.open(archives[formula], "r:gz") as tf:
                    members = tf.getmembers()
                    if len(members) > MAX_BOTTLE_MEMBERS:
                        die(f"bottle {formula} has {len(members)} members, limit {MAX_BOTTLE_MEMBERS}")
                    selected: list[tarfile.TarInfo] = []
                    seen_paths: set[PurePosixPath] = set()
                    total_bytes = 0
                    actual_ver: str | None = None
                    for m in members:
                        p = is_safe_member_path(m.name)
                        if not should_extract_member(p, formula, version):
                            continue
                        if len(p.parts) == 3:
                            if not m.isreg():
                                die(f"bottle {formula} license entry must be a regular file: {m.name}")
                        elif not (m.isreg() or m.issym()):
                            continue
                        if p in seen_paths:
                            die(f"bottle {formula} contains duplicate member path: {m.name}")
                        seen_paths.add(p)
                        if m.size < 0 or m.size > MAX_BOTTLE_MEMBER_BYTES:
                            die(f"bottle {formula} member {m.name} size {m.size} exceeds {MAX_BOTTLE_MEMBER_BYTES}")
                        total_bytes += m.size
                        if total_bytes > MAX_BOTTLE_TOTAL_BYTES:
                            die(f"bottle {formula} extracted bytes {total_bytes} exceed {MAX_BOTTLE_TOTAL_BYTES}")
                        member_ver = p.parts[1]
                        if actual_ver is None:
                            actual_ver = member_ver
                        elif actual_ver != member_ver:
                            die(
                                f"bottle {formula} contains conflicting versions "
                                f"{actual_ver} and {member_ver}"
                            )
                        if m.issym():
                            verify_symlink_stays_in_keg(m, PurePosixPath(formula, member_ver))
                        selected.append(m)
                    for m in selected:
                        if use_data_filter:
                            tf.extract(m, path=tmp_dir, filter="data")
                        else:
                            tf.extract(m, path=tmp_dir)
                if keg_parent.exists():
                    shutil.rmtree(keg_parent)
                os.replace(tmp_dir, keg_parent)
            finally:
                if tmp_dir.exists():
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            keg_root = find_extracted_keg(keg_parent, formula, version)
        if keg_root is None or not keg_root.is_dir():
            die(f"extracted bottle missing keg root for {formula} {version} under {keg_parent}")
        kegs[formula] = keg_root
    return kegs


def discover_homebrew_kegs(
    bottles: dict[str, dict[str, str]],
) -> tuple[str, dict[str, Path], dict[str, str]]:
    brew_prefix = run_cmd(["brew", "--prefix"], capture=True).strip()
    if not brew_prefix:
        die("brew --prefix returned empty path")

    kegs: dict[str, Path] = {}
    versions: dict[str, str] = {}
    for formula in bottles:
        keg_text = run_cmd(["brew", "--prefix", formula], capture=True).strip()
        keg_path = Path(keg_text)
        if not keg_path.is_dir():
            die(f"homebrew formula {formula} is not installed (missing {keg_path})")
        ver_line = run_cmd(["brew", "list", "--versions", formula], capture=True).strip()
        if not ver_line:
            die(f"homebrew formula {formula} has no installed version")
        kegs[formula] = keg_path
        versions[formula] = ver_line

    return brew_prefix, kegs, versions


def verify_link_stays_in_root(member: tarfile.TarInfo, root_prefix: PurePosixPath) -> None:
    target = member.linkname
    if not target or "\x00" in target:
        die(f"archive link {member.name} has invalid target {target!r}")
    if target.startswith("/"):
        die(f"archive link {member.name} has absolute target {target}")
    if member.islnk():
        joined = PurePosixPath(target)
    else:
        joined = PurePosixPath(member.name).parent.joinpath(target)
    norm_parts: list[str] = []
    for part in joined.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not norm_parts:
                die(f"archive link {member.name} -> {target} escapes archive root")
            norm_parts.pop()
        else:
            norm_parts.append(part)
    if tuple(norm_parts[: len(root_prefix.parts)]) != root_prefix.parts:
        die(f"archive link {member.name} -> {target} escapes root {root_prefix}")


def fetch_mesa_source(
    driver: dict[str, str],
    cache_dir: Path,
    offline: bool,
) -> tuple[Path, bool]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    version = driver["DRIVER_SOURCE_VERSION"]
    url = driver["DRIVER_SOURCE_URL"]
    want_sha = driver["DRIVER_SOURCE_SHA256"]
    archive = cache_dir / f"mesa-{version}.tar.xz"

    need_download = True
    if archive.is_file():
        got_sha = sha256_file(archive)
        if got_sha == want_sha:
            need_download = False
        else:
            die(f"SHA-256 mismatch for cached mesa source {archive}: got {got_sha}, want {want_sha}")

    redownloaded = False
    if need_download:
        if offline:
            die(f"offline mode: missing verified mesa source {archive}")
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-mesa-src.", dir=cache_dir)
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            run_cmd([
                "curl",
                "-fL",
                "--retry",
                "3",
                "--proto",
                "=https",
                "--max-filesize",
                "268435456",
                "--connect-timeout",
                "30",
                "--max-time",
                "600",
                "-o",
                str(tmp_path),
                "--",
                url,
            ])
            got_sha = sha256_file(tmp_path)
            if got_sha != want_sha:
                die(f"SHA-256 mismatch for mesa source {archive}: got {got_sha}, want {want_sha}")
            os.replace(tmp_path, archive)
            redownloaded = True
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    return archive, redownloaded


def extract_mesa_source(
    archive: Path,
    version: str,
    cache_dir: Path,
    redownloaded: bool,
) -> Path:
    src_dir = cache_dir / f"mesa-{version}"
    if not redownloaded and (src_dir / "meson.build").is_file():
        return src_dir

    use_data_filter = hasattr(tarfile, "data_filter")
    root_name = f"mesa-{version}"
    root_prefix = PurePosixPath(root_name)
    tmp_dir = Path(tempfile.mkdtemp(prefix=".tmp-mesa-ext.", dir=cache_dir))
    try:
        with tarfile.open(archive, "r:xz") as tf:
            members = tf.getmembers()
            for m in members:
                p = is_safe_member_path(m.name)
                if not p.parts or p.parts[0] != root_name:
                    die(f"mesa source archive member outside {root_name}: {m.name}")
                if m.issym() or m.islnk():
                    verify_link_stays_in_root(m, root_prefix)
            if use_data_filter:
                tf.extractall(path=tmp_dir, members=members, filter="data")
            else:
                tf.extractall(path=tmp_dir, members=members)
        extracted_root = tmp_dir / root_name
        if not (extracted_root / "meson.build").is_file():
            die(f"extracted mesa source missing meson.build in {extracted_root}")
        if src_dir.exists():
            shutil.rmtree(src_dir)
        os.replace(extracted_root, src_dir)
    finally:
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return src_dir


def build_mesa_source(
    driver: dict[str, str],
    src_dir: Path,
    cache_dir: Path,
    redownloaded: bool,
    jobs: int | None,
) -> Path:
    version = driver["DRIVER_SOURCE_VERSION"]
    build_dir = cache_dir / f"mesa-build-{version}"
    if redownloaded and build_dir.exists():
        shutil.rmtree(build_dir)

    if not (build_dir / "build.ninja").is_file():
        if build_dir.exists():
            shutil.rmtree(build_dir)
        run_cmd([
            "meson",
            "setup",
            str(build_dir),
            str(src_dir),
            "--buildtype=release",
            "-Db_ndebug=true",
            "--prefer-static",
            "-Dplatforms=macos",
            "-Dvulkan-drivers=kosmickrisp",
            "-Dgallium-drivers=",
            "-Dopengl=false",
            "-Dzstd=disabled",
        ])

    compile_cmd = ["meson", "compile", "-C", str(build_dir), "vulkan_kosmickrisp"]
    if jobs is not None:
        compile_cmd.extend(["-j", str(jobs)])
    run_cmd(compile_cmd)

    built_dylib = build_dir / "src" / "kosmickrisp" / "vulkan" / driver["DRIVER_LIBRARY"]
    if not built_dylib.is_file():
        die(f"mesa source build did not produce {built_dylib}")
    return built_dylib


def compute_mesa_source_closure(
    driver: dict[str, str],
    built_dylib: Path,
) -> tuple[dict[str, Path], dict[str, Path], dict[str, str]]:
    brew_prefix = run_cmd(["brew", "--prefix"], capture=True).strip()
    if not brew_prefix:
        die("brew --prefix returned empty path")

    patterns = build_dep_patterns(brew_prefix)
    start_name = driver["DRIVER_LIBRARY"]
    staged: dict[str, Path] = {start_name: built_dylib}
    dep_kegs: dict[str, Path] = {}
    dep_versions: dict[str, str] = {}
    queue: deque[tuple[str, Path]] = deque([(start_name, built_dylib)])
    visited: set[Path] = set()

    while queue:
        cur_name, cur_src = queue.popleft()
        if cur_src in visited:
            continue
        visited.add(cur_src)

        self_id = parse_otool_id(cur_src)
        for dep in parse_otool_deps(cur_src):
            if dep == self_id:
                continue
            if dep.startswith("/usr/lib/") or dep.startswith("/System/Library/"):
                continue

            dep_base = PurePosixPath(dep).name
            if dep_base.startswith("libX") or dep_base.startswith("libxcb"):
                die(f"the release driver must not link {dep_base} (found in {cur_name})")

            matched = match_dep(dep, patterns)
            if matched is None:
                die(f"the release driver must not link {dep} (found in {cur_name})")
            dep_formula, dep_name = matched
            if dep_name.startswith("libX") or dep_name.startswith("libxcb"):
                die(f"the release driver must not link {dep_name} (found in {cur_name})")
            if dep_formula == "llvm":
                die(f"the release driver must not link {dep_name} (runtime dependency on llvm)")
            if dep_formula not in MESA_SOURCE_RUNTIME_FORMULAS:
                die(f"the release driver must not link {dep_name} (disallowed formula {dep_formula})")

            if dep_formula not in dep_kegs:
                keg_text = run_cmd(["brew", "--prefix", dep_formula], capture=True).strip()
                keg_path = Path(keg_text)
                if not keg_path.is_dir():
                    die(f"homebrew formula {dep_formula} is not installed (missing {keg_path})")
                ver_line = run_cmd(["brew", "list", "--versions", dep_formula], capture=True).strip()
                if not ver_line:
                    die(f"homebrew formula {dep_formula} has no installed version")
                dep_kegs[dep_formula] = keg_path
                dep_versions[dep_formula] = ver_line

            dep_src = resolve_in_keg(dep_kegs[dep_formula], dep_name)
            prev = staged.get(dep_name)
            if prev is not None and prev != dep_src:
                die(f"conflicting sources for {dep_name}: {prev} vs {dep_src}")
            if prev is None:
                staged[dep_name] = dep_src
                queue.append((dep_name, dep_src))

    # Always record spirv-tools so its license and version stay indexed even if
    # Homebrew ships static archives that Meson links into libvulkan_kosmickrisp.dylib.
    if "spirv-tools" not in dep_kegs:
        keg_text = run_cmd(["brew", "--prefix", "spirv-tools"], capture=True).strip()
        keg_path = Path(keg_text)
        if not keg_path.is_dir():
            die(f"homebrew formula spirv-tools is not installed (missing {keg_path})")
        ver_line = run_cmd(["brew", "list", "--versions", "spirv-tools"], capture=True).strip()
        if not ver_line:
            die("homebrew formula spirv-tools has no installed version")
        dep_kegs["spirv-tools"] = keg_path
        dep_versions["spirv-tools"] = ver_line

    return staged, dep_kegs, dep_versions


def collect_build_tool_versions() -> list[str]:
    lines: list[str] = []
    for formula in MESA_SOURCE_BUILD_TOOLS:
        ver_line = run_cmd(["brew", "list", "--versions", formula], capture=True).strip()
        if not ver_line:
            die(f"build tool formula {formula} has no installed Homebrew version")
        lines.append(f"BUILD_TOOL {ver_line}")
    return lines


def parse_otool_deps(path: Path) -> list[str]:
    out = run_cmd(["otool", "-L", str(path)], capture=True)
    lines = out.splitlines()
    if len(lines) < 2:
        die(f"unexpected otool -L output for {path}")
    deps: list[str] = []
    for raw in lines[1:]:
        stripped = raw.strip()
        if not stripped:
            continue
        dep = stripped.split(" (", 1)[0]
        deps.append(dep)
    return deps


def parse_otool_id(path: Path) -> str:
    out = run_cmd(["otool", "-D", str(path)], capture=True)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        return ""
    return lines[1]


def parse_otool_rpaths_and_minos(path: Path) -> tuple[list[str], list[tuple[int, int, int]]]:
    out = run_cmd(["otool", "-l", str(path)], capture=True)
    rpaths: list[str] = []
    minos_list: list[tuple[int, int, int]] = []
    cur_cmd = ""
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("cmd "):
            cur_cmd = line.split()[1]
            continue
        if cur_cmd == "LC_RPATH" and line.startswith("path "):
            rpaths.append(line.split(" ", 1)[1].split(" (offset", 1)[0])
        elif cur_cmd == "LC_BUILD_VERSION" and line.startswith("minos "):
            ver_text = line.split()[1]
            parts = ver_text.split(".")
            nums = [int(p) for p in parts]
            while len(nums) < 3:
                nums.append(0)
            minos_list.append((nums[0], nums[1], nums[2]))
    return rpaths, minos_list


def resolve_in_keg(keg_root: Path, name: str) -> Path:
    lib_dir = keg_root / "lib"
    candidate = lib_dir / name
    if not candidate.exists() and not candidate.is_symlink():
        die(f"missing library {name} in {lib_dir}")
    resolved = candidate.resolve(strict=True)
    keg_real = keg_root.resolve(strict=True)
    try:
        resolved.relative_to(keg_real)
    except ValueError:
        die(f"library {candidate} resolves outside keg {keg_real}: {resolved}")
    if not resolved.is_file():
        die(f"resolved library is not a regular file: {resolved}")
    return resolved


def build_dep_patterns(brew_prefix: str | None) -> list[re.Pattern[str]]:
    patterns = [HOMEBREW_OPT_RE, HOMEBREW_CELLAR_RE]
    if brew_prefix is not None:
        prefixes = {brew_prefix, str(Path(brew_prefix).resolve())}
        for prefix in sorted(prefixes):
            escaped = re.escape(prefix.rstrip("/"))
            patterns.append(re.compile(rf"^{escaped}/opt/([^/]+)/lib/([^/]+)$"))
            patterns.append(re.compile(rf"^{escaped}/Cellar/([^/]+)/[^/]+/lib/([^/]+)$"))
    return patterns


def match_dep(dep: str, patterns: list[re.Pattern[str]]) -> tuple[str, str] | None:
    for pat in patterns:
        m = pat.match(dep)
        if m:
            return m.group(1), m.group(2)
    return None


def compute_closure(
    driver: dict[str, str],
    kegs: dict[str, Path],
    brew_prefix: str | None,
) -> dict[str, Path]:
    start_formula = driver["DRIVER_FORMULA"]
    start_name = driver["DRIVER_LIBRARY"]
    start_src = resolve_in_keg(kegs[start_formula], start_name)
    patterns = build_dep_patterns(brew_prefix)

    staged: dict[str, Path] = {start_name: start_src}
    queue: deque[tuple[str, Path]] = deque([(start_name, start_src)])
    visited: set[Path] = set()

    while queue:
        cur_name, cur_src = queue.popleft()
        if cur_src in visited:
            continue
        visited.add(cur_src)

        self_id = parse_otool_id(cur_src)
        for dep in parse_otool_deps(cur_src):
            if dep == self_id:
                continue
            if dep.startswith("/usr/lib/") or dep.startswith("/System/Library/"):
                continue

            matched = match_dep(dep, patterns)
            if matched is None:
                die(f"unexpected dependency {dep} of {cur_name}")
            dep_formula, dep_name = matched
            if dep_formula not in kegs:
                die(f"unpinned dependency {dep_formula} of {cur_name}")
            dep_src = resolve_in_keg(kegs[dep_formula], dep_name)
            prev = staged.get(dep_name)
            if prev is not None and prev != dep_src:
                die(f"conflicting sources for {dep_name}: {prev} vs {dep_src}")
            if prev is None:
                staged[dep_name] = dep_src
                queue.append((dep_name, dep_src))

    return staged


def format_version(ver: tuple[int, int, int]) -> str:
    if ver[2] == 0:
        return f"{ver[0]}.{ver[1]}"
    return f"{ver[0]}.{ver[1]}.{ver[2]}"


def stage_and_check(
    staged: dict[str, Path],
    bottles: dict[str, dict[str, str]],
    kegs: dict[str, Path],
    *,
    source: str,
    tag: str | None,
    homebrew_versions: dict[str, str] | None,
    mesa_src_dir: Path | None = None,
    mesa_version: str | None = None,
    mesa_sha256: str | None = None,
    build_tool_versions: list[str] | None = None,
    out_dir: Path,
) -> None:
    lib_out = out_dir / "lib"
    lic_out = out_dir / "licenses"
    lib_out.mkdir(parents=True, exist_ok=False)
    lic_out.mkdir(parents=True, exist_ok=False)

    for name, src in sorted(staged.items()):
        dst = lib_out / name
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o755)

        self_id = parse_otool_id(dst)
        deps = parse_otool_deps(dst)
        rpaths, _ = parse_otool_rpaths_and_minos(dst)

        cmd = ["install_name_tool", "-id", f"@loader_path/{name}"]
        seen_changes: set[str] = set()
        for dep in deps:
            if dep == self_id:
                continue
            if dep.startswith("/usr/lib/") or dep.startswith("/System/Library/"):
                continue
            if dep in seen_changes:
                continue
            seen_changes.add(dep)
            dep_base = PurePosixPath(dep).name
            cmd.extend(["-change", dep, f"@loader_path/{dep_base}"])
        for rp in rpaths:
            cmd.extend(["-delete_rpath", rp])
        cmd.append(str(dst))
        run_cmd(cmd)
        run_cmd(["codesign", "--force", "--sign", "-", str(dst)])

    max_minos = (0, 0, 0)
    staged_names = set(staged.keys())
    for name in sorted(staged_names):
        dst = lib_out / name
        want_id = f"@loader_path/{name}"
        got_id = parse_otool_id(dst)
        if got_id != want_id:
            die(f"staged library {name} has install name {got_id}, want {want_id}")

        for dep in parse_otool_deps(dst):
            if dep.startswith("/usr/lib/") or dep.startswith("/System/Library/"):
                continue
            if dep.startswith("@loader_path/"):
                dep_name = dep[len("@loader_path/") :]
                if dep_name in staged_names:
                    continue
            die(f"staged library {name} has disallowed dependency {dep}")

        rpaths, minos_list = parse_otool_rpaths_and_minos(dst)
        if rpaths:
            die(f"staged library {name} retains LC_RPATH: {rpaths}")
        for m in minos_list:
            if m > max_minos:
                max_minos = m
        run_cmd(["codesign", "--verify", "--strict", str(dst)])

    if max_minos == (0, 0, 0):
        die("no LC_BUILD_VERSION minos found in staged libraries")

    if source == "mesa-source":
        assert mesa_src_dir is not None
        mesa_lic = mesa_src_dir / "docs" / "license.rst"
        if not mesa_lic.is_file():
            die(f"mesa source license not found: {mesa_lic}")
        shutil.copyfile(mesa_lic, lic_out / "mesa.txt")

    for formula, keg_root in kegs.items():
        found: Path | None = None
        for cand in LICENSE_CANDIDATES:
            p = keg_root / cand
            if p.is_file():
                found = p
                break
        if found is None:
            die(f"no license file found in {keg_root}")
        shutil.copyfile(found, lic_out / f"{formula}.txt")

    if source == "pinned":
        assert tag is not None
        report_lines = [
            "SOURCE=pinned",
            f"MIN_MACOS={format_version(max_minos)}",
        ]
        report_lines.extend(
            f"{formula} {fields['version']} {tag} sha256:{fields[tag]}"
            for formula, fields in bottles.items()
        )
    elif source == "mesa-source":
        assert mesa_version is not None and mesa_sha256 is not None
        assert build_tool_versions is not None and homebrew_versions is not None
        report_lines = [
            "SOURCE=mesa-source",
            f"MESA={mesa_version} sha256:{mesa_sha256}",
            f"MIN_MACOS={format_version(max_minos)}",
        ]
        report_lines.extend(build_tool_versions)
        report_lines.extend(homebrew_versions[formula] for formula in sorted(homebrew_versions))
    else:
        assert homebrew_versions is not None
        report_lines = [
            "SOURCE=homebrew unpinned",
            f"MIN_MACOS={format_version(max_minos)}",
        ]
        report_lines.extend(homebrew_versions[formula] for formula in bottles)

    (out_dir / "driver.txt").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="stage_driver.py",
        description="Stage, close, rewrite, sign, and verify KosmicKrisp driver libraries.",
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--source", choices=VALID_SOURCES, default="pinned")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--tag", choices=VALID_TAGS)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--jobs", type=int)
    parser.add_argument("--verify-cache-only", action="store_true")
    args = parser.parse_args(argv)

    if args.verify_cache_only:
        if args.source != "pinned" or args.cache is None or args.tag is None:
            die("--verify-cache-only requires --source pinned, --cache, and --tag")
        _, bottles = parse_lock(args.lock, args.tag, "pinned")
        fetch_bottles(bottles, args.tag, args.cache / "bottles", offline=True)
        return 0

    if args.out is None:
        die("--out is required")
    if args.out.exists() or args.out.is_symlink():
        die(f"output directory already exists: {args.out}")
    if args.jobs is not None and args.jobs < 1:
        die(f"--jobs must be >= 1, got {args.jobs}")

    if args.source == "pinned":
        if args.cache is None:
            die("--cache is required when --source is pinned")
        if args.tag is None:
            die("--tag is required when --source is pinned")
    elif args.source == "mesa-source":
        if args.cache is None:
            die("--cache is required when --source is mesa-source")

    driver, bottles = parse_lock(args.lock, args.tag, args.source)

    if args.source == "pinned":
        assert args.cache is not None and args.tag is not None
        bottles_dir = args.cache / "bottles"
        archives, redownloaded = fetch_bottles(bottles, args.tag, bottles_dir, args.offline)
        kegs = extract_bottles(bottles, args.tag, bottles_dir, archives, redownloaded)
        staged = compute_closure(driver, kegs, None)
        stage_and_check(
            staged,
            bottles,
            kegs,
            source="pinned",
            tag=args.tag,
            homebrew_versions=None,
            out_dir=args.out,
        )
    elif args.source == "mesa-source":
        assert args.cache is not None
        archive, redownloaded = fetch_mesa_source(driver, args.cache, args.offline)
        src_dir = extract_mesa_source(archive, driver["DRIVER_SOURCE_VERSION"], args.cache, redownloaded)
        built_dylib = build_mesa_source(driver, src_dir, args.cache, redownloaded, args.jobs)
        staged, dep_kegs, dep_versions = compute_mesa_source_closure(driver, built_dylib)
        build_tools = collect_build_tool_versions()
        stage_and_check(
            staged,
            bottles,
            dep_kegs,
            source="mesa-source",
            tag=None,
            homebrew_versions=dep_versions,
            mesa_src_dir=src_dir,
            mesa_version=driver["DRIVER_SOURCE_VERSION"],
            mesa_sha256=driver["DRIVER_SOURCE_SHA256"],
            build_tool_versions=build_tools,
            out_dir=args.out,
        )
    else:
        brew_prefix, kegs, homebrew_versions = discover_homebrew_kegs(bottles)
        staged = compute_closure(driver, kegs, brew_prefix)
        stage_and_check(
            staged,
            bottles,
            kegs,
            source="homebrew",
            tag=None,
            homebrew_versions=homebrew_versions,
            out_dir=args.out,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
