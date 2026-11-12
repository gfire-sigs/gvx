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

package netfilter

import (
	"context"

	"z.gfire.dev/gvx/pkg/state"
)

// This file holds the state methods of the upstream matchers and targets that
// carry no "+stateify savable" tag. The methods follow the output of
// tools/gostateify for the same structs. Keeping them here leaves the upstream
// files unchanged. TestSavableStateFieldsMatchStructs fails when a struct
// gains, loses, or renames a field without a matching edit here.

func (c *commentMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.commentMatcher"
}

func (c *commentMatcher) StateFields() []string {
	return []string{
		"comment",
	}
}

func (c *commentMatcher) beforeSave() {}

// +checklocksignore
func (c *commentMatcher) StateSave(stateSinkObject state.Sink) {
	c.beforeSave()
	stateSinkObject.SaveString(0, &c.comment)
}

func (c *commentMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (c *commentMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadString(0, &c.comment)
}

func (m *conntrackMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.conntrackMatcher"
}

func (m *conntrackMatcher) StateFields() []string {
	return []string{
		"rev",
		"matchFlags",
		"invertFlags",
		"stateMask",
		"raw",
	}
}

func (m *conntrackMatcher) beforeSave() {}

// +checklocksignore
func (m *conntrackMatcher) StateSave(stateSinkObject state.Sink) {
	m.beforeSave()
	stateSinkObject.SaveUint8(0, &m.rev)
	stateSinkObject.SaveUint16(1, &m.matchFlags)
	stateSinkObject.SaveUint16(2, &m.invertFlags)
	stateSinkObject.SaveUint16(3, &m.stateMask)
	stateSinkObject.Save(4, &m.raw)
}

func (m *conntrackMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (m *conntrackMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadUint8(0, &m.rev)
	stateSourceObject.LoadUint16(1, &m.matchFlags)
	stateSourceObject.LoadUint16(2, &m.invertFlags)
	stateSourceObject.LoadUint16(3, &m.stateMask)
	stateSourceObject.Load(4, &m.raw)
}

func (dt *dnatTarget) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.dnatTarget"
}

func (dt *dnatTarget) StateFields() []string {
	return []string{
		"DNATTarget",
		"revision",
	}
}

func (dt *dnatTarget) beforeSave() {}

// +checklocksignore
func (dt *dnatTarget) StateSave(stateSinkObject state.Sink) {
	dt.beforeSave()
	stateSinkObject.Save(0, &dt.DNATTarget)
	stateSinkObject.SaveUint8(1, &dt.revision)
}

func (dt *dnatTarget) afterLoad(context.Context) {}

// +checklocksignore
func (dt *dnatTarget) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &dt.DNATTarget)
	stateSourceObject.LoadUint8(1, &dt.revision)
}

func (mm *MarkMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.MarkMatcher"
}

func (mm *MarkMatcher) StateFields() []string {
	return []string{
		"mark",
		"mask",
		"invert",
	}
}

func (mm *MarkMatcher) beforeSave() {}

// +checklocksignore
func (mm *MarkMatcher) StateSave(stateSinkObject state.Sink) {
	mm.beforeSave()
	stateSinkObject.SaveUint32(0, &mm.mark)
	stateSinkObject.SaveUint32(1, &mm.mask)
	stateSinkObject.SaveBool(2, &mm.invert)
}

func (mm *MarkMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (mm *MarkMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadUint32(0, &mm.mark)
	stateSourceObject.LoadUint32(1, &mm.mask)
	stateSourceObject.LoadBool(2, &mm.invert)
}

func (m *multiportMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.multiportMatcher"
}

func (m *multiportMatcher) StateFields() []string {
	return []string{
		"flags",
		"count",
		"ports",
	}
}

func (m *multiportMatcher) beforeSave() {}

// +checklocksignore
func (m *multiportMatcher) StateSave(stateSinkObject state.Sink) {
	m.beforeSave()
	stateSinkObject.SaveUint8(0, &m.flags)
	stateSinkObject.SaveUint8(1, &m.count)
	stateSinkObject.Save(2, &m.ports)
}

func (m *multiportMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (m *multiportMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadUint8(0, &m.flags)
	stateSourceObject.LoadUint8(1, &m.count)
	stateSourceObject.Load(2, &m.ports)
}

func (m *multiportMatcherV1) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.multiportMatcherV1"
}

func (m *multiportMatcherV1) StateFields() []string {
	return []string{
		"flags",
		"count",
		"ports",
		"pflags",
		"invert",
	}
}

func (m *multiportMatcherV1) beforeSave() {}

// +checklocksignore
func (m *multiportMatcherV1) StateSave(stateSinkObject state.Sink) {
	m.beforeSave()
	stateSinkObject.SaveUint8(0, &m.flags)
	stateSinkObject.SaveUint8(1, &m.count)
	stateSinkObject.Save(2, &m.ports)
	stateSinkObject.Save(3, &m.pflags)
	stateSinkObject.SaveBool(4, &m.invert)
}

func (m *multiportMatcherV1) afterLoad(context.Context) {}

// +checklocksignore
func (m *multiportMatcherV1) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadUint8(0, &m.flags)
	stateSourceObject.LoadUint8(1, &m.count)
	stateSourceObject.Load(2, &m.ports)
	stateSourceObject.Load(3, &m.pflags)
	stateSourceObject.LoadBool(4, &m.invert)
}

func (om *OwnerMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.OwnerMatcher"
}

func (om *OwnerMatcher) StateFields() []string {
	return []string{
		"uid",
		"gid",
		"matchUID",
		"matchGID",
		"invertUID",
		"invertGID",
	}
}

func (om *OwnerMatcher) beforeSave() {}

// +checklocksignore
func (om *OwnerMatcher) StateSave(stateSinkObject state.Sink) {
	om.beforeSave()
	stateSinkObject.Save(0, &om.uid)
	stateSinkObject.Save(1, &om.gid)
	stateSinkObject.SaveBool(2, &om.matchUID)
	stateSinkObject.SaveBool(3, &om.matchGID)
	stateSinkObject.SaveBool(4, &om.invertUID)
	stateSinkObject.SaveBool(5, &om.invertGID)
}

func (om *OwnerMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (om *OwnerMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &om.uid)
	stateSourceObject.Load(1, &om.gid)
	stateSourceObject.LoadBool(2, &om.matchUID)
	stateSourceObject.LoadBool(3, &om.matchGID)
	stateSourceObject.LoadBool(4, &om.invertUID)
	stateSourceObject.LoadBool(5, &om.invertGID)
}

func (om *OwnerMatcherV1) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.OwnerMatcherV1"
}

func (om *OwnerMatcherV1) StateFields() []string {
	return []string{
		"uid",
		"gid",
		"matchUID",
		"matchGID",
		"invertUID",
		"invertGID",
	}
}

func (om *OwnerMatcherV1) beforeSave() {}

// +checklocksignore
func (om *OwnerMatcherV1) StateSave(stateSinkObject state.Sink) {
	om.beforeSave()
	stateSinkObject.Save(0, &om.uid)
	stateSinkObject.Save(1, &om.gid)
	stateSinkObject.SaveBool(2, &om.matchUID)
	stateSinkObject.SaveBool(3, &om.matchGID)
	stateSinkObject.SaveBool(4, &om.invertUID)
	stateSinkObject.SaveBool(5, &om.invertGID)
}

func (om *OwnerMatcherV1) afterLoad(context.Context) {}

// +checklocksignore
func (om *OwnerMatcherV1) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &om.uid)
	stateSourceObject.Load(1, &om.gid)
	stateSourceObject.LoadBool(2, &om.matchUID)
	stateSourceObject.LoadBool(3, &om.matchGID)
	stateSourceObject.LoadBool(4, &om.invertUID)
	stateSourceObject.LoadBool(5, &om.invertGID)
}

func (st *snatTarget) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.snatTarget"
}

func (st *snatTarget) StateFields() []string {
	return []string{
		"SNATTarget",
		"revision",
	}
}

func (st *snatTarget) beforeSave() {}

// +checklocksignore
func (st *snatTarget) StateSave(stateSinkObject state.Sink) {
	st.beforeSave()
	stateSinkObject.Save(0, &st.SNATTarget)
	stateSinkObject.SaveUint8(1, &st.revision)
}

func (st *snatTarget) afterLoad(context.Context) {}

// +checklocksignore
func (st *snatTarget) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &st.SNATTarget)
	stateSourceObject.LoadUint8(1, &st.revision)
}

func (tm *TCPMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.TCPMatcher"
}

func (tm *TCPMatcher) StateFields() []string {
	return []string{
		"sourcePortStart",
		"sourcePortEnd",
		"destinationPortStart",
		"destinationPortEnd",
		"flagMask",
		"flagCompare",
		"inverseFlags",
	}
}

func (tm *TCPMatcher) beforeSave() {}

// +checklocksignore
func (tm *TCPMatcher) StateSave(stateSinkObject state.Sink) {
	tm.beforeSave()
	stateSinkObject.SaveUint16(0, &tm.sourcePortStart)
	stateSinkObject.SaveUint16(1, &tm.sourcePortEnd)
	stateSinkObject.SaveUint16(2, &tm.destinationPortStart)
	stateSinkObject.SaveUint16(3, &tm.destinationPortEnd)
	stateSinkObject.SaveUint8(4, &tm.flagMask)
	stateSinkObject.SaveUint8(5, &tm.flagCompare)
	stateSinkObject.SaveUint8(6, &tm.inverseFlags)
}

func (tm *TCPMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (tm *TCPMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadUint16(0, &tm.sourcePortStart)
	stateSourceObject.LoadUint16(1, &tm.sourcePortEnd)
	stateSourceObject.LoadUint16(2, &tm.destinationPortStart)
	stateSourceObject.LoadUint16(3, &tm.destinationPortEnd)
	stateSourceObject.LoadUint8(4, &tm.flagMask)
	stateSourceObject.LoadUint8(5, &tm.flagCompare)
	stateSourceObject.LoadUint8(6, &tm.inverseFlags)
}

func (um *UDPMatcher) StateTypeName() string {
	return "pkg/sentry/socket/netfilter.UDPMatcher"
}

func (um *UDPMatcher) StateFields() []string {
	return []string{
		"sourcePortStart",
		"sourcePortEnd",
		"destinationPortStart",
		"destinationPortEnd",
	}
}

func (um *UDPMatcher) beforeSave() {}

// +checklocksignore
func (um *UDPMatcher) StateSave(stateSinkObject state.Sink) {
	um.beforeSave()
	stateSinkObject.SaveUint16(0, &um.sourcePortStart)
	stateSinkObject.SaveUint16(1, &um.sourcePortEnd)
	stateSinkObject.SaveUint16(2, &um.destinationPortStart)
	stateSinkObject.SaveUint16(3, &um.destinationPortEnd)
}

func (um *UDPMatcher) afterLoad(context.Context) {}

// +checklocksignore
func (um *UDPMatcher) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.LoadUint16(0, &um.sourcePortStart)
	stateSourceObject.LoadUint16(1, &um.sourcePortEnd)
	stateSourceObject.LoadUint16(2, &um.destinationPortStart)
	stateSourceObject.LoadUint16(3, &um.destinationPortEnd)
}

func init() {
	state.RegisterNoHooks((*commentMatcher)(nil))
	state.RegisterNoHooks((*conntrackMatcher)(nil))
	state.RegisterNoHooks((*dnatTarget)(nil))
	state.RegisterNoHooks((*MarkMatcher)(nil))
	state.RegisterNoHooks((*multiportMatcher)(nil))
	state.RegisterNoHooks((*multiportMatcherV1)(nil))
	state.RegisterNoHooks((*OwnerMatcher)(nil))
	state.RegisterNoHooks((*OwnerMatcherV1)(nil))
	state.RegisterNoHooks((*snatTarget)(nil))
	state.RegisterNoHooks((*TCPMatcher)(nil))
	state.RegisterNoHooks((*UDPMatcher)(nil))
}
