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

package stack

import (
	"context"
	"maps"

	"z.gfire.dev/gvx/pkg/state"
)

const iptablesCheckpointKey = "iptables-rules"

// iptablesCheckpoint is a live marker. The extension saver replaces it with
// the current rules in a copy of the map.
type iptablesCheckpoint struct {
	owner    *Stack
	restored bool
}

type iptablesRuleSnapshot struct {
	tables   *[2][NumTables]Table
	modified bool
	config   *conntrackConfig
	limit    *ConntrackLimit
}

// The extension value uses only built-in types and existing state types.
// Registering a new type would change the fingerprint of old checkpoints.
func (r iptablesRuleSnapshot) encode() [4]any {
	return [4]any{r.tables, r.modified, r.config, r.limit}
}

func decodeIPTablesRules(value any) iptablesRuleSnapshot {
	fields, ok := value.([4]any)
	if !ok {
		state.Failf("invalid iptables checkpoint value: %T", value)
	}
	tables, tablesOK := fields[0].(*[2][NumTables]Table)
	modified, modifiedOK := fields[1].(bool)
	config, configOK := fields[2].(*conntrackConfig)
	limit, limitOK := fields[3].(*ConntrackLimit)
	if !tablesOK || tables == nil || !modifiedOK || !configOK || !limitOK {
		state.Failf("invalid iptables checkpoint fields")
	}
	return iptablesRuleSnapshot{tables: tables, modified: modified, config: config, limit: limit}
}

func (it *IPTables) snapshotRules() iptablesRuleSnapshot {
	it.mu.RLock()
	defer it.mu.RUnlock()
	// ReplaceTable publishes whole rule slices. Keep the matcher and target
	// objects so their state hooks restore bindings to the same registries.
	return iptablesRuleSnapshot{
		tables:   &[2][NumTables]Table{it.v4Tables, it.v6Tables},
		modified: it.modified,
		config:   it.connections.cfg.Load(),
		limit:    it.connections.limit.Load(),
	}
}

// EnableIPTablesCheckpoint includes rules and connection tracker settings in
// subsequent saves of the stack. It does not include tracked connections.
func (s *Stack) EnableIPTablesCheckpoint() {
	s.LoadOrStoreExtensionState(iptablesCheckpointKey, func() any {
		return iptablesCheckpoint{owner: s}
	})
}

// RestoreIPTablesCheckpoint installs decoded rules before the stack resumes.
// It returns true only when it installs a snapshot.
func (s *Stack) RestoreIPTablesCheckpoint() bool {
	value, ok := s.ExtensionState(iptablesCheckpointKey)
	if !ok {
		return false
	}
	if _, live := value.(iptablesCheckpoint); live {
		return false
	}
	snapshot := decodeIPTablesRules(value)
	s.ensureRNG()
	it := &IPTables{
		connections: ConnTrack{
			seed:  s.insecureRNG.Uint32(),
			clock: s.clock,
			rng:   s.insecureRNG,
		},
		v4Tables: snapshot.tables[0],
		v6Tables: snapshot.tables[1],
		modified: snapshot.modified,
	}
	it.connections.cfg.Store(snapshot.config)
	it.connections.limit.Store(snapshot.limit)
	if snapshot.modified {
		it.connections.init()
	}
	s.tables = it
	s.SetExtensionState(iptablesCheckpointKey, iptablesCheckpoint{owner: s, restored: true})
	return true
}

func (s *Stack) hasRestoredIPTables() bool {
	value, _ := s.ExtensionState(iptablesCheckpointKey)
	checkpoint, ok := value.(iptablesCheckpoint)
	return ok && checkpoint.restored
}

// StopRestoredIPTablesReaper stops the timer of an abandoned restored stack.
func (s *Stack) StopRestoredIPTablesReaper() {
	if s.hasRestoredIPTables() {
		s.tables.stopReaper()
	}
}

func (e *stackExtState) saveCheckpointValues() map[string]any {
	e.mu.RLock()
	values := e.values
	checkpoint, enabled := values[iptablesCheckpointKey].(iptablesCheckpoint)
	if enabled {
		values = maps.Clone(values)
	}
	e.mu.RUnlock()
	if !enabled {
		return values
	}
	if tables := checkpoint.owner.tables; tables != nil {
		values[iptablesCheckpointKey] = tables.snapshotRules().encode()
	} else {
		delete(values, iptablesCheckpointKey)
	}
	return values
}

// Keep the previous layout, field order, and hook registration. They are part
// of the checkpoint fingerprint. Only the values map needs a custom saver.

func (*stackExtState) StateTypeName() string {
	return "pkg/tcpip/stack.stackExtState"
}

func (*stackExtState) StateFields() []string {
	return []string{"stack", "hasBridgeNetfilter", "bridgeIPv4", "bridgeIPv6", "values"}
}

func (e *stackExtState) StateSave(sink state.Sink) {
	sink.Save(0, &e.stack)
	sink.SaveBool(1, &e.hasBridgeNetfilter)
	sink.SaveBool(2, &e.bridgeIPv4)
	sink.SaveBool(3, &e.bridgeIPv6)
	sink.SaveValue(4, e.saveCheckpointValues())
}

func (e *stackExtState) StateLoad(_ context.Context, source state.Source) {
	source.Load(0, &e.stack)
	source.LoadBool(1, &e.hasBridgeNetfilter)
	source.LoadBool(2, &e.bridgeIPv4)
	source.LoadBool(3, &e.bridgeIPv6)
	source.Load(4, &e.values)
	source.AfterLoadTo(e)
}

func (e *stackExtState) StateAfterLoad(ctx context.Context) {
	e.afterLoad(ctx)
}

func init() {
	state.RegisterStruct((*stackExtState)(nil))
}
