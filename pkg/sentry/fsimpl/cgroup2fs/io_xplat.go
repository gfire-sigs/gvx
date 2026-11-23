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

package cgroup2fs

import (
	"bytes"
	goContext "context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"weak"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	ioDefaultWeight uint64 = 100
	ioMinWeight     uint64 = 1
	ioMaxWeight     uint64 = 10000
	ioMaxWriteLen          = 4096
	ioLimitMax      uint64 = math.MaxUint64
)

func init() {
	ctrlNames["io"] = kernel.Cgroup2IO
	ctrlTypeStr[kernel.Cgroup2IO] = "io"
}

func packIODev(major, minor uint32) uint64 {
	return (uint64(major) << 32) | uint64(minor)
}

func unpackIODev(key uint64) (major, minor uint32) {
	return uint32(key >> 32), uint32(key)
}

func parseIODev(s string) (uint64, error) {
	majStr, minStr, ok := strings.Cut(s, ":")
	if !ok || majStr == "" || minStr == "" {
		return 0, linuxerr.EINVAL
	}
	maj, err := strconv.ParseUint(majStr, 10, 32)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	min, err := strconv.ParseUint(minStr, 10, 32)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	return packIODev(uint32(maj), uint32(min)), nil
}

// +stateify savable
type ioDevStats struct {
	rbytes uint64
	wbytes uint64
	rios   uint64
	wios   uint64
	dbytes uint64
	dios   uint64
}

func (s *ioDevStats) isZero() bool {
	return s.rbytes == 0 && s.wbytes == 0 && s.rios == 0 && s.wios == 0 && s.dbytes == 0 && s.dios == 0
}

// +stateify savable
type ioMaxRule struct {
	rbps  uint64
	wbps  uint64
	riops uint64
	wiops uint64
}

func defaultIOMaxRule() ioMaxRule {
	return ioMaxRule{
		rbps:  ioLimitMax,
		wbps:  ioLimitMax,
		riops: ioLimitMax,
		wiops: ioLimitMax,
	}
}

func (r ioMaxRule) isUnbounded() bool {
	return r.rbps == ioLimitMax && r.wbps == ioLimitMax && r.riops == ioLimitMax && r.wiops == ioLimitMax
}

func formatIOLimit(v uint64) string {
	if v == ioLimitMax {
		return "max"
	}
	return strconv.FormatUint(v, 10)
}

// ioCtrl implements the cgroup v2 "io" block I/O accounting controller.
//
// +stateify savable
type ioCtrl struct {
	c        *cgroup
	parent   *ioCtrl
	detached atomicbitops.Bool

	mu            sync.Mutex `state:"nosave"`
	stats         map[uint64]*ioDevStats
	defaultWeight uint64
	weights       map[uint64]uint64
	maxRules      map[uint64]ioMaxRule
}

// +checklocksread:c.fs.treeMu
func (c *cgroup) newControllerWithXplat(cType kernel.Cgroup2Ctrl) controller {
	if ctrl := c.newController(cType); ctrl != nil {
		return ctrl
	}
	return c.newXplatController(cType)
}

// +checklocksread:c.fs.treeMu
func (c *cgroup) newXplatController(cType kernel.Cgroup2Ctrl) controller {
	if cType != kernel.Cgroup2IO {
		return nil
	}
	var parent *ioCtrl
	if c.parent != nil {
		p := c.parent.ctrls[cType] // +checklocksforce: c.fs.treeMu is locked
		if p == nil {
			panic("unified cgroups inconsistency: parent io controller is nil")
		}
		parent = p.(*ioCtrl)
	}
	return &ioCtrl{
		c:             c,
		parent:        parent,
		defaultWeight: ioDefaultWeight,
	}
}

func (ic *ioCtrl) canEnter(context.Context, *kernel.Task) bool { return true }
func (ic *ioCtrl) cancelEnter(context.Context, *kernel.Task)   {}
func (ic *ioCtrl) enter(context.Context, *kernel.Task)         {}
func (ic *ioCtrl) exit(context.Context, *kernel.Task)          {}
func (ic *ioCtrl) canAttach(context.Context, *attachCtx) bool  { return true }
func (ic *ioCtrl) cancelAttach(context.Context, *attachCtx)    {}
func (ic *ioCtrl) attach(context.Context, *attachCtx)          {}
func (ic *ioCtrl) detach()                                     { ic.detached.Store(true) }
func (ic *ioCtrl) isActive() bool                              { return !ic.detached.Load() }

func (ic *ioCtrl) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "io.stat", source: &ioStat{io: ic}, perm: 0444, showAtRoot: true},
		{name: "io.weight", source: &ioWeight{io: ic}, perm: 0644},
		{name: "io.max", source: &ioMax{io: ic}, perm: 0644},
	}
}

func (ic *ioCtrl) interfaceFileNames() []string {
	return []string{"io.stat", "io.weight", "io.max"}
}

// account charges one I/O operation to ic and every active ancestor ioCtrl up
// to the root cgroup. Locks are acquired one level at a time (leaf mutex) so
// no nested locking occurs.
func (ic *ioCtrl) account(major, minor uint32, op blockdev.Op, nbytes, ios uint64) {
	key := packIODev(major, minor)
	for cur := ic; cur != nil; cur = cur.parent {
		cur.mu.Lock()
		if cur.stats == nil {
			cur.stats = make(map[uint64]*ioDevStats)
		}
		st := cur.stats[key]
		if st == nil {
			st = &ioDevStats{}
			cur.stats[key] = st
		}
		switch op {
		case blockdev.Read:
			st.rbytes += nbytes
			st.rios += ios
		case blockdev.Write:
			st.wbytes += nbytes
			st.wios += ios
		case blockdev.Discard:
			st.dbytes += nbytes
			st.dios += ios
		}
		cur.mu.Unlock()
	}
}

type weakIOAccountant struct {
	fs weak.Pointer[filesystem]
}

func (w *weakIOAccountant) AccountIO(ctx context.Context, major, minor uint32, op blockdev.Op, nbytes, ios uint64) {
	if fs := w.fs.Value(); fs != nil {
		fs.AccountIO(ctx, major, minor, op, nbytes, ios)
	}
}

// bindIOAccountant registers a weak reference to fs as the per-VFS
// blockdev.IOAccountant so the blockdev registry never pins fs or its VFS.
func (fs *filesystem) bindIOAccountant(vfsObj *vfs.VirtualFilesystem) {
	if fs == nil || vfsObj == nil {
		return
	}
	blockdev.Of(vfsObj).SetIOAccountant(&weakIOAccountant{fs: weak.Make(fs)})
}

// unbindIOAccountant clears fs from the per-VFS blockdev registry on Release.
func (fs *filesystem) unbindIOAccountant() {
	if fs == nil {
		return
	}
	if vfsfs := fs.VFSFilesystem(); vfsfs != nil {
		if vfsObj := vfsfs.VirtualFilesystem(); vfsObj != nil {
			blockdev.Of(vfsObj).SetIOAccountant(nil)
		}
	}
}

// AccountIO implements blockdev.IOAccountant. It charges the calling task's
// closest active cgroup v2 io controller (and its ancestors up to root).
func (fs *filesystem) AccountIO(ctx context.Context, major, minor uint32, op blockdev.Op, nbytes, ios uint64) {
	if fs == nil || ctx == nil || (nbytes == 0 && ios == 0) {
		return
	}
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return
	}
	var cg *cgroup
	if node := t.Cgroup2(); node != nil {
		cg, _ = node.(*cgroup)
	}
	if cg == nil || cg.fs != fs {
		if fs.root != nil {
			cg, _ = fs.root.Inode().(*cgroup)
		}
	}
	if cg == nil {
		return
	}
	set := cg.closestCtrls.Load()
	if set == nil {
		return
	}
	ctrl, _ := set[kernel.Cgroup2IO].(*ioCtrl)
	if ctrl == nil {
		return
	}
	ctrl.account(major, minor, op, nbytes, ios)
}

// +stateify savable
type ioStat struct {
	io *ioCtrl
}

func (is *ioStat) afterLoad(goContext.Context) {
	if is.io == nil || is.io.c == nil || is.io.c.parent != nil || is.io.c.fs == nil {
		return
	}
	fs := is.io.c.fs
	if vfsfs := fs.VFSFilesystem(); vfsfs != nil {
		fs.bindIOAccountant(vfsfs.VirtualFilesystem())
	}
}

// Generate implements vfs.DynamicBytesSource.Generate for io.stat.
func (is *ioStat) Generate(_ context.Context, buf *bytes.Buffer) error {
	is.io.mu.Lock()
	keys := make([]uint64, 0, len(is.io.stats))
	for k, st := range is.io.stats {
		if st != nil && !st.isZero() {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	type row struct {
		major, minor uint32
		st           ioDevStats
	}
	rows := make([]row, 0, len(keys))
	for _, k := range keys {
		maj, min := unpackIODev(k)
		rows = append(rows, row{major: maj, minor: min, st: *is.io.stats[k]})
	}
	is.io.mu.Unlock()

	for _, r := range rows {
		fmt.Fprintf(buf, "%d:%d rbytes=%d wbytes=%d rios=%d wios=%d dbytes=%d dios=%d\n",
			r.major, r.minor,
			r.st.rbytes, r.st.wbytes,
			r.st.rios, r.st.wios,
			r.st.dbytes, r.st.dios)
	}
	return nil
}

// +stateify savable
type ioWeight struct {
	io *ioCtrl
}

// Generate implements vfs.DynamicBytesSource.Generate for io.weight.
func (iw *ioWeight) Generate(_ context.Context, buf *bytes.Buffer) error {
	iw.io.mu.Lock()
	defW := iw.io.defaultWeight
	if defW == 0 {
		defW = ioDefaultWeight
	}
	keys := make([]uint64, 0, len(iw.io.weights))
	for k := range iw.io.weights {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	type row struct {
		major, minor uint32
		weight       uint64
	}
	rows := make([]row, 0, len(keys))
	for _, k := range keys {
		maj, min := unpackIODev(k)
		rows = append(rows, row{major: maj, minor: min, weight: iw.io.weights[k]})
	}
	iw.io.mu.Unlock()

	fmt.Fprintf(buf, "default %d\n", defW)
	for _, r := range rows {
		fmt.Fprintf(buf, "%d:%d %d\n", r.major, r.minor, r.weight)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write for io.weight.
func (iw *ioWeight) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, _ int64) (int64, error) {
	if src.NumBytes() == 0 || src.NumBytes() > ioMaxWriteLen {
		return 0, linuxerr.EINVAL
	}
	raw := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, raw)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw[:n]))
	if len(fields) == 0 || len(fields) > 2 {
		return 0, linuxerr.EINVAL
	}

	parseWeight := func(s string) (uint64, error) {
		w, err := strconv.ParseUint(s, 10, 64)
		if err != nil || w < ioMinWeight || w > ioMaxWeight {
			return 0, linuxerr.EINVAL
		}
		return w, nil
	}

	if len(fields) == 1 {
		w, err := parseWeight(fields[0])
		if err != nil {
			return 0, err
		}
		iw.io.mu.Lock()
		iw.io.defaultWeight = w
		iw.io.mu.Unlock()
		return int64(n), nil
	}

	if fields[0] == "default" {
		w, err := parseWeight(fields[1])
		if err != nil {
			return 0, err
		}
		iw.io.mu.Lock()
		iw.io.defaultWeight = w
		iw.io.mu.Unlock()
		return int64(n), nil
	}

	key, err := parseIODev(fields[0])
	if err != nil {
		return 0, err
	}
	if fields[1] == "default" {
		iw.io.mu.Lock()
		delete(iw.io.weights, key)
		iw.io.mu.Unlock()
		return int64(n), nil
	}
	w, err := parseWeight(fields[1])
	if err != nil {
		return 0, err
	}
	iw.io.mu.Lock()
	if iw.io.weights == nil {
		iw.io.weights = make(map[uint64]uint64)
	}
	iw.io.weights[key] = w
	iw.io.mu.Unlock()
	return int64(n), nil
}

// +stateify savable
type ioMax struct {
	io *ioCtrl
}

// Generate implements vfs.DynamicBytesSource.Generate for io.max.
func (im *ioMax) Generate(_ context.Context, buf *bytes.Buffer) error {
	im.io.mu.Lock()
	keys := make([]uint64, 0, len(im.io.maxRules))
	for k := range im.io.maxRules {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	type row struct {
		major, minor uint32
		rule         ioMaxRule
	}
	rows := make([]row, 0, len(keys))
	for _, k := range keys {
		maj, min := unpackIODev(k)
		rows = append(rows, row{major: maj, minor: min, rule: im.io.maxRules[k]})
	}
	im.io.mu.Unlock()

	for _, r := range rows {
		fmt.Fprintf(buf, "%d:%d rbps=%s wbps=%s riops=%s wiops=%s\n",
			r.major, r.minor,
			formatIOLimit(r.rule.rbps),
			formatIOLimit(r.rule.wbps),
			formatIOLimit(r.rule.riops),
			formatIOLimit(r.rule.wiops))
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write for io.max.
func (im *ioMax) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, _ int64) (int64, error) {
	if src.NumBytes() == 0 || src.NumBytes() > ioMaxWriteLen {
		return 0, linuxerr.EINVAL
	}
	raw := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, raw)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw[:n]))
	if len(fields) < 2 {
		return 0, linuxerr.EINVAL
	}
	key, err := parseIODev(fields[0])
	if err != nil {
		return 0, err
	}

	parseVal := func(v string) (uint64, error) {
		if v == "max" {
			return ioLimitMax, nil
		}
		u, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, linuxerr.EINVAL
		}
		return u, nil
	}

	type kvUpdate struct {
		k string
		v uint64
	}
	updates := make([]kvUpdate, 0, len(fields)-1)
	for _, tok := range fields[1:] {
		k, vStr, ok := strings.Cut(tok, "=")
		if !ok {
			return 0, linuxerr.EINVAL
		}
		switch k {
		case "rbps", "wbps", "riops", "wiops":
		default:
			return 0, linuxerr.EINVAL
		}
		v, err := parseVal(vStr)
		if err != nil {
			return 0, err
		}
		updates = append(updates, kvUpdate{k: k, v: v})
	}

	im.io.mu.Lock()
	rule, exists := im.io.maxRules[key]
	if !exists {
		rule = defaultIOMaxRule()
	}
	for _, u := range updates {
		switch u.k {
		case "rbps":
			rule.rbps = u.v
		case "wbps":
			rule.wbps = u.v
		case "riops":
			rule.riops = u.v
		case "wiops":
			rule.wiops = u.v
		}
	}
	if rule.isUnbounded() {
		delete(im.io.maxRules, key)
	} else {
		if im.io.maxRules == nil {
			im.io.maxRules = make(map[uint64]ioMaxRule)
		}
		im.io.maxRules[key] = rule
	}
	im.io.mu.Unlock()
	return int64(n), nil
}
