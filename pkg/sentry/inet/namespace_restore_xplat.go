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
	"slices"

	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/state"
)

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

func (n *Namespace) restoreAfterLoad() {
	n.ensureInitialized()
	if n.creator == nil && n.stack != nil {
		n.creator = creatorFromStack(n.stack)
	}
	if n.isRoot {
		if n.stack != nil {
			n.subscribeInterfaceEvents()
			n.bindStackCallbacks()
		}
		return
	}
	if n.root != nil {
		n.root.registerChild(n)
		if n.creator == nil {
			n.creator = n.root.effectiveCreator()
		}
	}
	if n.stack != nil {
		n.subscribeInterfaceEvents()
		return
	}
	if n.creator != nil {
		st, err := n.creator.CreateStack()
		if err != nil {
			panic(err)
		}
		n.stack = st
		n.subscribeInterfaceEvents()
	}
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
		st, err := n.creator.CreateStack()
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
