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

// The guest scripts of the M4 gate. Every script prints the line ALL-OK as
// its last output and stops with a non-zero status at the first failed
// expectation. The tests read both the exit code and the marker.

// posixTortureScript runs in busybox sh. It renames and unlinks files that a
// descriptor holds open, replaces files atomically, removes trees with open
// files, and covers links, ownership, and case rules. The variable
// CASE_INSENSITIVE is 1 when the host volume ignores case. The variable
// OPEN_DIR_RENAME is 0 when the host refuses to rename a directory that has an
// open descendant, as NTFS does. The script then closes the descriptor first.
const posixTortureScript = `set -eu
cd /workspace
fail() { echo "FAIL: $*"; exit 1; }
expect() { [ "$1" = "$2" ] || fail "$3: got [$1] want [$2]"; }

# 1. rename over an open file keeps the old inode readable.
echo old > f; echo new > g
exec 3<f
mv g f
expect "$(cat <&3)" old "fd after rename-over"
expect "$(cat f)" new "path after rename-over"
exec 3<&-
echo T1-OK

# 2. unlink an open file.
echo keep-me > h
exec 4<h
rm h
[ ! -e h ] || fail "h still visible"
expect "$(cat <&4)" keep-me "fd after unlink"
exec 4<&-
echo T2-OK

# 3. unlink then recreate the same name while the old file is open.
echo v1 > r
exec 5<r
rm r
echo v2 > r
expect "$(cat <&5)" v1 "old inode"
expect "$(cat r)" v2 "new inode"
exec 5<&-
echo T3-OK

# 4. rename a directory that holds an open file.
mkdir d1
echo inside > d1/k
exec 6<d1/k
[ "$OPEN_DIR_RENAME" = 1 ] || exec 6<&-
mv d1 d3
[ ! -e d1 ] || fail "d1 still visible"
expect "$(cat d3/k)" inside "moved file"
if [ "$OPEN_DIR_RENAME" = 1 ]; then
  expect "$(cat <&6)" inside "fd in moved dir"
  exec 6<&-
fi
echo T4-OK

# 5. atomic replace pattern, 200 rounds, with a reader on the first version.
echo gen0 > target
exec 7<target
i=1
while [ $i -le 200 ]; do
  echo "gen$i" > target.tmp
  mv -f target.tmp target
  i=$((i+1))
done
expect "$(cat target)" gen200 "final generation"
expect "$(cat <&7)" gen0 "reader on first generation"
exec 7<&-
[ ! -e target.tmp ] || fail "temporary file leaked"
echo T5-OK

# 6. rm -rf of a tree while files in it are open.
mkdir -p t/a/b/c t/x
echo deep > t/a/b/c/leaf
echo top > t/x/top
exec 8<t/a/b/c/leaf 9<t/x/top
rm -rf t
[ ! -e t ] || fail "tree still visible"
expect "$(cat <&8)" deep "deep fd after rm -rf"
expect "$(cat <&9)" top "top fd after rm -rf"
exec 8<&- 9<&-
echo T6-OK

# 7. hard links and link counts.
echo linked > l1
ln l1 l2
expect "$(stat -c %h l1)" 2 "link count"
rm l1
expect "$(cat l2)" linked "survivor of unlinked hard link"
expect "$(stat -c %h l2)" 1 "link count after unlink"
echo T7-OK

# 8. symlinks, including a dangling one and a directory link.
mkdir real
echo via-link > real/file
ln -s real dirlink
ln -s missing dangling
expect "$(cat dirlink/file)" via-link "directory symlink"
expect "$(readlink dangling)" missing "dangling target"
[ -L dangling ] || fail "dangling is not a symlink"
mv dirlink dirlink2
expect "$(readlink dirlink2)" real "renamed symlink"
echo T8-OK

# 9. case-sensitive names on the host volume.
mkdir cs
echo upper > cs/File.txt
[ -e cs/File.txt ] || fail "exact-case lookup failed"
if [ -e cs/file.txt ]; then fail "other-case lookup resolved"; fi
if [ "$CASE_INSENSITIVE" = 1 ]; then
  if { echo lower > cs/file.txt; } 2>/dev/null; then fail "colliding create succeeded"; fi
  expect "$(cat cs/File.txt)" upper "File.txt after collision"
  expect "$(ls cs)" File.txt "listing after collision"
else
  echo lower > cs/file.txt
  echo shout > cs/FILE.TXT
  expect "$(ls cs | wc -l)" 3 "case variants"
  expect "$(cat cs/file.txt)" lower "file.txt"
  expect "$(cat cs/FILE.TXT)" shout "FILE.TXT"
fi
mv cs/File.txt cs/Renamed.txt
expect "$(cat cs/Renamed.txt)" upper "renamed"
echo x > cs/Casey.txt
mv cs/Casey.txt cs/casey.txt
[ -e cs/casey.txt ] || fail "case-only rename lost the file"
if [ -e cs/Casey.txt ]; then fail "old case still resolves"; fi
expect "$(ls cs | grep -ci casey)" 1 "case-only rename listing"
echo T9-OK

# 10. permissions and ownership persist.
echo x > perm
chmod 0640 perm
expect "$(stat -c %a perm)" 640 "mode"
chown 1234:5678 perm
expect "$(stat -c '%u:%g' perm)" 1234:5678 "owner"
echo T10-OK
echo ALL-OK
`

// gitScript runs in an image that contains git. It covers init, commit,
// branch, rebase, a 2100-file tree, gc, and fsck on /workspace.
const gitScript = `set -eu
cd /workspace
fail() { echo "FAIL: $*"; exit 1; }
expect() { [ "$1" = "$2" ] || fail "$3: got [$1] want [$2]"; }
export HOME=/root GIT_CONFIG_NOSYSTEM=1
git config --global user.email gvx@example.test
git config --global user.name "gvx e2e"
git config --global init.defaultBranch main
git config --global gc.auto 0

git init -q repo
cd repo
echo one > a.txt
git add a.txt
git commit -q -m c1

git checkout -q -b feature
echo feat > f.txt
printf '#!/bin/sh\necho hi\n' > run.sh
chmod 755 run.sh
ln -s a.txt link
git add f.txt run.sh link
git commit -q -m feat1
echo feat2 >> f.txt
git commit -q -am feat2

git checkout -q main
echo two > b.txt
git add b.txt
git commit -q -m c2

git checkout -q feature
git rebase main >/dev/null
expect "$(git rev-list --count main..feature)" 2 "commits replayed by rebase"
expect "$(git rev-list --count feature)" 4 "history length after rebase"
expect "$(git ls-files -s run.sh | cut -c1-6)" 100755 "executable bit"
expect "$(git ls-files -s link | cut -c1-6)" 120000 "symlink mode"
[ -x run.sh ] || fail "run.sh lost its executable bit after rebase"
expect "$(readlink link)" a.txt "symlink target after rebase"
echo REBASE-OK

i=0
mkdir -p tree
while [ $i -lt 2100 ]; do
  d=tree/d$((i % 40))
  mkdir -p "$d"
  echo "file $i" > "$d/f$i.txt"
  i=$((i + 1))
done
git add tree
git commit -q -m bulk
expect "$(git ls-files tree | wc -l)" 2100 "tracked files in the bulk tree"
expect "$(git status --porcelain | wc -l)" 0 "dirty files after commit"
echo BULK-OK

git gc -q
expect "$(git count-objects -v | sed -n 's/^count: //p')" 0 "loose objects after gc"
ls .git/objects/pack/*.pack >/dev/null || fail "no pack file after gc"
git fsck --full 2>&1 | grep -v '^Checking' || true
git fsck --full >/dev/null 2>&1 || fail "git fsck reports corruption"
expect "$(git rev-list --count feature)" 5 "history length after gc"
git checkout -q main
[ ! -e f.txt ] || fail "checkout of main kept feature files"
git checkout -q feature
expect "$(cat tree/d7/f47.txt)" "file 47" "bulk file after checkout"
echo GC-OK
echo ALL-OK
`

// nodeTortureScript runs in node:22-alpine. It builds a node_modules-like
// tree with symlinks and hard links, then renames and removes parts of it.
const nodeTortureScript = `const fs = require("fs");
const path = require("path");
const assert = require("assert");
const root = "/workspace/app";
fs.mkdirSync(root, { recursive: true });
process.chdir(root);

// 1. node_modules-like tree: packages, nested dependencies, .bin symlinks,
// and hard links into a content store.
const store = path.join(root, ".store");
fs.mkdirSync(store);
fs.mkdirSync("node_modules/.bin", { recursive: true });
const pkgCount = 60;
for (let i = 0; i < pkgCount; i++) {
  const dir = "node_modules/pkg" + i;
  fs.mkdirSync(dir + "/lib/deep", { recursive: true });
  fs.writeFileSync(dir + "/package.json", JSON.stringify({ name: "pkg" + i, version: "1.0." + i }));
  const shared = path.join(store, "blob" + (i % 5) + ".js");
  if (!fs.existsSync(shared)) fs.writeFileSync(shared, "module.exports = " + (i % 5) + ";\n");
  fs.linkSync(shared, dir + "/lib/shared.js");
  fs.writeFileSync(dir + "/lib/deep/index.js", "exports.id = " + i + ";\n");
  fs.writeFileSync(dir + "/cli.js", "#!/usr/bin/env node\nconsole.log('cli');\n", { mode: 0o755 });
  fs.symlinkSync("../pkg" + i + "/cli.js", "node_modules/.bin/pkg" + i);
}
assert.strictEqual(fs.lstatSync("node_modules/.bin/pkg7").isSymbolicLink(), true);
assert.strictEqual(fs.readlinkSync("node_modules/.bin/pkg7"), "../pkg7/cli.js");
assert.strictEqual(fs.statSync("node_modules/.bin/pkg7").mode & 0o777, 0o755);
assert.strictEqual(require(root + "/node_modules/pkg12/lib/deep/index.js").id, 12);
assert.strictEqual(require(root + "/node_modules/pkg12/lib/shared.js"), 2);
// 60 packages over 5 blobs: each blob has 12 package links plus the store name.
assert.strictEqual(fs.statSync(store + "/blob0.js").nlink, 13);
console.log("tree=ok");

// 2. rename over an existing file while a reader holds the old one.
fs.writeFileSync("conf.json", '{"gen":0}');
const reader = fs.openSync("conf.json", "r");
for (let g = 1; g <= 100; g++) {
  fs.writeFileSync("conf.json.tmp", '{"gen":' + g + "}");
  fs.renameSync("conf.json.tmp", "conf.json");
}
assert.strictEqual(JSON.parse(fs.readFileSync("conf.json", "utf8")).gen, 100);
const old = Buffer.alloc(32);
const n = fs.readSync(reader, old, 0, 32, 0);
assert.strictEqual(old.toString("utf8", 0, n), '{"gen":0}');
fs.closeSync(reader);
assert.strictEqual(fs.existsSync("conf.json.tmp"), false);
console.log("rename-over=ok");

// 3. rename a directory tree and replace an empty directory.
fs.renameSync("node_modules/pkg1", "node_modules/pkg1-moved");
assert.strictEqual(fs.existsSync("node_modules/pkg1/package.json"), false);
assert.strictEqual(require(root + "/node_modules/pkg1-moved/lib/deep/index.js").id, 1);
fs.mkdirSync("empty-target");
fs.mkdirSync("src-dir");
fs.writeFileSync("src-dir/f", "payload");
fs.renameSync("src-dir", "empty-target");
assert.strictEqual(fs.readFileSync("empty-target/f", "utf8"), "payload");
console.log("rename-dir=ok");

// 4. rm -rf of a tree whose files are open.
const fds = [];
for (let i = 10; i < 20; i++) {
  fds.push(fs.openSync("node_modules/pkg" + i + "/lib/deep/index.js", "r"));
}
fs.rmSync("node_modules", { recursive: true, force: true });
assert.strictEqual(fs.existsSync("node_modules"), false);
fds.forEach((fd, k) => {
  const buf = Buffer.alloc(64);
  const len = fs.readSync(fd, buf, 0, 64, 0);
  assert.strictEqual(buf.toString("utf8", 0, len), "exports.id = " + (10 + k) + ";\n");
  fs.closeSync(fd);
});
console.log("rm-rf-open=ok");

// 5. the store survives and keeps its link counts after the tree is gone.
assert.strictEqual(fs.statSync(store + "/blob0.js").nlink, 1);

// 6. cpSync, utimes, truncate, and case-different names.
fs.cpSync(store, "store-copy", { recursive: true });
assert.deepStrictEqual(fs.readdirSync("store-copy").sort(), fs.readdirSync(store).sort());
fs.writeFileSync("Readme.md", "upper");
assert.strictEqual(fs.existsSync("readme.md"), false);
fs.truncateSync("Readme.md", 2);
assert.strictEqual(fs.readFileSync("Readme.md", "utf8"), "up");
const stamp = new Date("2020-01-02T03:04:05Z");
fs.utimesSync("Readme.md", stamp, stamp);
assert.strictEqual(fs.statSync("Readme.md").mtimeMs, stamp.getTime());
console.log("misc=ok");
console.log("ALL-OK");
`
