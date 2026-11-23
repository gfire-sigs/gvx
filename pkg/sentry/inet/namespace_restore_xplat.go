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

package inet

import (
	"context"
	"fmt"
	"slices"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// NetworkCheckpointMode controls whether a sandbox checkpoint must contain
// saved firewall rules for every network namespace.
type NetworkCheckpointMode uint8

const (
	RequireNetworkCheckpoint NetworkCheckpointMode = iota
	ImportLegacyNetworkCheckpoint
)

type networkCheckpointLoad struct {
	mode       NetworkCheckpointMode
	namespaces []*Namespace
	activate   []checkpointActivation
	authorized map[any]struct{}
}

type checkpointActivation struct {
	object any
	run    func()
}

// WithNetworkCheckpointRestore stages the network state of a single kernel
// load without changing unrelated state.Load callers.
func WithNetworkCheckpointRestore(ctx gvcontext.Context, mode NetworkCheckpointMode) gvcontext.Context {
	return gvcontext.WithValue(ctx, stack.CheckpointRestoreKey{}, &networkCheckpointLoad{mode: mode})
}

func networkCheckpointFromContext(ctx context.Context) *networkCheckpointLoad {
	load, _ := ctx.Value(stack.CheckpointRestoreKey{}).(*networkCheckpointLoad)
	return load
}

// IsNetworkCheckpointRestore reports whether network activation is deferred.
func IsNetworkCheckpointRestore(ctx context.Context) bool {
	return networkCheckpointFromContext(ctx) != nil
}

func (load *networkCheckpointLoad) StageCheckpointActivation(object any, activate func()) {
	load.activate = append(load.activate, checkpointActivation{object: object, run: activate})
}

func (load *networkCheckpointLoad) AuthorizeCheckpointActivation(object any) {
	if load.authorized == nil {
		load.authorized = make(map[any]struct{})
	}
	load.authorized[object] = struct{}{}
}

type networkCheckpointStack interface {
	PrepareNetworkCheckpoint(context.Context, NetworkCheckpointMode) (*stack.Stack, func(), error)
	StageRecreatedNetworkCheckpoint() error
}

// PrepareNetworkCheckpointRestore validates every decoded namespace before
// installing any saved tables. Callers must run the returned activation after
// setting the kernel clocks but before configuring the root stack.
func PrepareNetworkCheckpointRestore(ctx context.Context, root *Namespace) (func(), error) {
	load := networkCheckpointFromContext(ctx)
	if load == nil {
		return nil, nil
	}
	if root == nil || !root.isRoot || root.root != nil || !slices.Contains(load.namespaces, root) {
		return nil, fmt.Errorf("invalid root network namespace in checkpoint")
	}
	install := make([]func(), 0, len(load.namespaces))
	seen := make(map[*stack.Stack]struct{}, len(load.namespaces))
	for i, n := range load.namespaces {
		if n != root && (n.isRoot || n.root != root) {
			return nil, fmt.Errorf("network namespace %d does not belong to the restored root", i)
		}
		if n != root && n.stack == nil && load.mode == ImportLegacyNetworkCheckpoint {
			continue
		}
		st, ok := n.stack.(networkCheckpointStack)
		if !ok {
			return nil, fmt.Errorf("network namespace %d is missing its saved netstack", i)
		}
		tcpipStack, apply, err := st.PrepareNetworkCheckpoint(ctx, load.mode)
		if err != nil {
			return nil, fmt.Errorf("network namespace %d: %w", i, err)
		}
		if _, exists := seen[tcpipStack]; exists {
			return nil, fmt.Errorf("network namespace %d shares another namespace's saved netstack", i)
		}
		seen[tcpipStack] = struct{}{}
		install = append(install, apply)
	}
	for st := range seen {
		if err := st.ValidateCheckpointLinks(ctx, seen); err != nil {
			return nil, err
		}
	}
	for _, activation := range load.activate {
		if _, ok := load.authorized[activation.object]; !ok {
			return nil, fmt.Errorf("unowned network checkpoint activation for %T", activation.object)
		}
	}
	for st := range seen {
		st.DetachCheckpointExtensions()
	}
	for _, apply := range install {
		apply()
	}
	for st := range seen {
		st.PrepareStagedRestore()
	}
	if err := root.restoreAfterLoad(); err != nil {
		return nil, fmt.Errorf("restoring root network namespace: %w", err)
	}
	for i, n := range load.namespaces {
		if n != root {
			recreated := n.stack == nil
			if err := n.restoreAfterLoad(); err != nil {
				return nil, fmt.Errorf("restoring legacy network namespace %d: %w", i, err)
			}
			if recreated {
				st, ok := n.stack.(networkCheckpointStack)
				if !ok {
					return nil, fmt.Errorf("legacy network namespace %d could not recreate a netstack", i)
				}
				if err := st.StageRecreatedNetworkCheckpoint(); err != nil {
					return nil, fmt.Errorf("legacy network namespace %d: %w", i, err)
				}
			}
		}
	}
	load.namespaces = nil
	activate := load.activate
	load.activate = nil
	load.authorized = nil
	return func() {
		for _, action := range activate {
			action.run()
		}
	}, nil
}

// StackCreatorProvider is an optional interface implemented by Stack values
// that supply a NetworkStackCreator during namespace creation or restore.
type StackCreatorProvider interface {
	RestoreNetworkNamespaceCreator() NetworkStackCreator
}

type stackConfigReplacer interface {
	ReplaceConfig(Stack)
}

type childStackRestorer interface {
	RestoreChildStack(rootStack Stack)
}

type interfaceEventSubscriberEnsurer interface {
	EnsureInterfaceEventSubscriber(InterfaceEventSubscriber)
}

type childStackCallbackSetter interface {
	SetChildStackCallbacks(pause, resume, restore func())
}

func (n *Namespace) bindStackCallbacks() {
	if n == nil || !n.isRoot || n.stack == nil {
		return
	}
	if setter, ok := n.stack.(childStackCallbackSetter); ok {
		setter.SetChildStackCallbacks(n.PauseChildStacks, n.ResumeChildStacks, n.RestoreChildStacks)
	}
}

func (n *Namespace) rootNamespace() *Namespace {
	if n == nil {
		return nil
	}
	if n.isRoot || n.root == nil {
		return n
	}
	return n.root
}

func (n *Namespace) registerChild(child *Namespace) {
	if n == nil || child == nil || child.isRoot {
		return
	}
	n.childMu.Lock()
	defer n.childMu.Unlock()
	if !slices.Contains(n.children, child) {
		n.children = append(n.children, child)
	}
}

func (n *Namespace) unregisterChild(child *Namespace) {
	if n == nil || child == nil {
		return
	}
	n.childMu.Lock()
	defer n.childMu.Unlock()
	for i, candidate := range n.children {
		if candidate == child {
			n.children = slices.Delete(n.children, i, i+1)
			return
		}
	}
}

func (n *Namespace) childrenSlice() []*Namespace {
	if n == nil {
		return nil
	}
	n.childMu.Lock()
	defer n.childMu.Unlock()
	return slices.Clone(n.children)
}

func (n *Namespace) markRestored() bool {
	if n == nil {
		return false
	}
	n.childMu.Lock()
	defer n.childMu.Unlock()
	if n.restored {
		return false
	}
	n.restored = true
	return true
}

// ForEachChildStack calls f for each child network namespace with a stack.
func (n *Namespace) ForEachChildStack(f func(Stack)) {
	for _, child := range n.childrenSlice() {
		if st := child.Stack(); st != nil {
			f(st)
		}
	}
}

// PauseChildStacks pauses all active child network namespace stacks registered
// under n.
func (n *Namespace) PauseChildStacks() {
	for _, child := range n.childrenSlice() {
		if st := child.Stack(); st != nil {
			st.Pause()
		}
	}
}

// ResumeChildStacks resumes all active child network namespace stacks
// registered under n.
func (n *Namespace) ResumeChildStacks() {
	for _, child := range n.childrenSlice() {
		if st := child.Stack(); st != nil {
			st.Resume()
		}
	}
}

// RestoreChildStacks restores all active child network namespace stacks
// registered under n.
func (n *Namespace) RestoreChildStacks() {
	for _, child := range n.childrenSlice() {
		child.restoreChildFromRoot(n.stack)
	}
}

func creatorFromStack(s Stack) NetworkStackCreator {
	if s == nil {
		return nil
	}
	if p, ok := s.(StackCreatorProvider); ok {
		if c := p.RestoreNetworkNamespaceCreator(); c != nil {
			return c
		}
	}
	if c, ok := s.(NetworkStackCreator); ok {
		return c
	}
	return nil
}

func (n *Namespace) effectiveCreator() NetworkStackCreator {
	if n == nil {
		return nil
	}
	if n.creator != nil {
		return n.creator
	}
	return creatorFromStack(n.stack)
}

// Creator returns the NetworkStackCreator configured for n.
func (n *Namespace) Creator() NetworkStackCreator {
	return n.effectiveCreator()
}

// NewNetworkNamespace creates a child network namespace from n.
func (n *Namespace) NewNetworkNamespace(userNS *auth.UserNamespace) *Namespace {
	if userNS == nil && n != nil {
		userNS = n.userNS
	}
	return NewNamespace(n, userNS)
}

func (n *Namespace) ensureInitialized() {
	if n.abstractSockets.endpoints == nil {
		n.abstractSockets.init()
	}
	if n.netlinkMcastTable == nil {
		n.netlinkMcastTable = NewNetlinkMcastTable()
	}
}

func (n *Namespace) subscribeInterfaceEvents() {
	if n.stack == nil || n.netlinkMcastTable == nil {
		return
	}
	if ensurer, ok := n.stack.(interfaceEventSubscriberEnsurer); ok {
		ensurer.EnsureInterfaceEventSubscriber(n.netlinkMcastTable)
		return
	}
	if pub, ok := n.stack.(InterfaceEventPublisher); ok {
		pub.AddInterfaceEventSubscriber(n.netlinkMcastTable)
	}
}

func (n *Namespace) restoreAfterLoad() error {
	n.ensureInitialized()
	if n.creator == nil && n.stack != nil {
		n.creator = creatorFromStack(n.stack)
	}
	if n.isRoot {
		if n.stack != nil {
			n.subscribeInterfaceEvents()
			n.bindStackCallbacks()
		}
		return nil
	}
	if n.root != nil {
		n.root.registerChild(n)
		if n.creator == nil {
			n.creator = n.root.effectiveCreator()
		}
	}
	if n.stack != nil {
		n.subscribeInterfaceEvents()
		return nil
	}
	if n.creator != nil {
		var (
			st  Stack
			err error
		)
		if rc, ok := n.creator.(RestoreNetworkStackCreator); ok {
			st, err = rc.CreateStackForRestore()
		} else {
			st, err = n.creator.CreateStack()
		}
		if err != nil {
			return err
		}
		n.stack = st
		n.subscribeInterfaceEvents()
	}
	return nil
}

func (n *Namespace) restoreRootStack(stack Stack) {
	n.ensureInitialized()
	if c := creatorFromStack(stack); c != nil && n.creator == nil {
		n.creator = c
	}
	if n.isRoot {
		switch {
		case n.stack == nil:
			n.stack = stack
			n.subscribeInterfaceEvents()
			if n.stack != nil {
				n.stack.Restore()
			}
		case stack != nil && n.stack != stack:
			if replacer, ok := n.stack.(stackConfigReplacer); ok {
				n.stack.ResetConfig()
				replacer.ReplaceConfig(stack)
				n.subscribeInterfaceEvents()
				n.stack.Restore()
			} else {
				n.stack = stack
				n.subscribeInterfaceEvents()
				n.stack.Restore()
			}
		default:
			n.subscribeInterfaceEvents()
			if n.stack != nil {
				n.stack.Restore()
			}
		}
		if c := creatorFromStack(n.stack); c != nil && n.creator == nil {
			n.creator = c
		}
		n.bindStackCallbacks()
		n.RestoreChildStacks()
		return
	}

	rootStack := stack
	if rootStack == nil && n.root != nil {
		rootStack = n.root.stack
	}
	n.restoreChildFromRoot(rootStack)
}

func (n *Namespace) restoreChildFromRoot(rootStack Stack) {
	if !n.markRestored() {
		return
	}
	n.ensureInitialized()
	if c := creatorFromStack(rootStack); c != nil && n.creator == nil {
		n.creator = c
	}
	if n.stack == nil && n.creator != nil {
		var (
			st  Stack
			err error
		)
		if rc, ok := n.creator.(RestoreNetworkStackCreator); ok {
			st, err = rc.CreateStackForRestore()
		} else {
			st, err = n.creator.CreateStack()
		}
		if err != nil {
			panic(err)
		}
		n.stack = st
	}
	if n.stack != nil {
		n.subscribeInterfaceEvents()
		n.stack.Restore()
		if restorer, ok := n.stack.(childStackRestorer); ok {
			restorer.RestoreChildStack(rootStack)
		}
		if n.creator == nil {
			n.creator = creatorFromStack(n.stack)
		}
	}
}

type testStackCreator struct{}

func (*testStackCreator) CreateStack() (Stack, error) {
	return NewTestStack(), nil
}

func (*testStackCreator) StateTypeName() string {
	return "pkg/sentry/inet.testStackCreator"
}

func (*testStackCreator) StateFields() []string {
	return nil
}

func (*testStackCreator) StateSave(state.Sink) {}

func (*testStackCreator) StateLoad(context.Context, state.Source) {}

// StateTypeName implements state.Type on Interface.
func (*Interface) StateTypeName() string {
	return "pkg/sentry/inet.Interface"
}

// StateFields implements state.Type on Interface.
func (*Interface) StateFields() []string {
	return []string{"Flags", "Name", "Addr", "MTU", "Master", "Kind"}
}

// StateSave implements state.SaverLoader on Interface.
func (iface *Interface) StateSave(sink state.Sink) {
	sink.SaveUint32(0, &iface.Flags)
	sink.SaveString(1, &iface.Name)
	sink.Save(2, &iface.Addr)
	sink.SaveUint32(3, &iface.MTU)
	sink.SaveUint32(4, &iface.Master)
	sink.SaveString(5, &iface.Kind)
}

// StateLoad implements state.SaverLoader on Interface.
func (iface *Interface) StateLoad(_ context.Context, src state.Source) {
	src.LoadUint32(0, &iface.Flags)
	src.LoadString(1, &iface.Name)
	src.Load(2, &iface.Addr)
	src.LoadUint32(3, &iface.MTU)
	src.LoadUint32(4, &iface.Master)
	src.LoadString(5, &iface.Kind)
}

// StateTypeName implements state.Type on TestStack.
func (*TestStack) StateTypeName() string {
	return "pkg/sentry/inet.TestStack"
}

// StateFields implements state.Type on TestStack.
func (*TestStack) StateFields() []string {
	return []string{"InterfacesMap"}
}

// StateSave implements state.SaverLoader on TestStack.
func (s *TestStack) StateSave(sink state.Sink) {
	sink.Save(0, &s.InterfacesMap)
}

// StateLoad implements state.SaverLoader on TestStack.
func (s *TestStack) StateLoad(_ context.Context, src state.Source) {
	src.Load(0, &s.InterfacesMap)
	if s.InterfaceAddrsMap == nil {
		s.InterfaceAddrsMap = make(map[int32][]InterfaceAddr)
	}
}

// RestoreNetworkNamespaceCreator implements StackCreatorProvider on TestStack.
func (*TestStack) RestoreNetworkNamespaceCreator() NetworkStackCreator {
	return &testStackCreator{}
}

func init() {
	state.RegisterNoHooks((*testStackCreator)(nil))
	state.RegisterNoHooks((*Interface)(nil))
	state.RegisterNoHooks((*TestStack)(nil))
}
