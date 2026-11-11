// Copyright 2020 The gVisor Authors.
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
	goContext "context"
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/nsfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
)

// Namespace represents a network namespace. See network_namespaces(7).
//
// +stateify savable
type Namespace struct {
	inode *nsfs.Inode

	// stack is the network stack implementation of this network namespace.
	stack Stack

	// creator allows kernel to create new network stack for network namespaces.
	// If nil, no networking will function if network is namespaced.
	//
	// At afterLoad(), creator will be used to create network stack. Stateify
	// needs to wait for this field to be loaded before calling afterLoad().
	creator NetworkStackCreator `state:"wait"`

	// root is the owning root network namespace for non-root namespaces.
	root *Namespace `state:"wait"`

	// isRoot indicates whether this is the root network namespace.
	isRoot bool

	userNS *auth.UserNamespace

	// abstractSockets tracks abstract sockets that are in use.
	abstractSockets AbstractSocketNamespace

	// netlinkMcastTable manages multicast group membership for netlink sockets.
	netlinkMcastTable *McastTable

	childMu  sync.Mutex   `state:"nosave"`
	children []*Namespace `state:"nosave"`
	restored bool         `state:"nosave"`
}

// NewRootNamespace creates the root network namespace, with creator
// allowing new network namespaces to be created. If creator is nil, no
// networking will function if the network is namespaced.
func NewRootNamespace(stack Stack, creator NetworkStackCreator, userNS *auth.UserNamespace) *Namespace {
	n := &Namespace{
		stack:             stack,
		creator:           creator,
		isRoot:            true,
		userNS:            userNS,
		netlinkMcastTable: NewNetlinkMcastTable(),
	}
	if eventPublishingStack, ok := stack.(InterfaceEventPublisher); ok {
		eventPublishingStack.AddInterfaceEventSubscriber(n.netlinkMcastTable)
	}
	n.bindStackCallbacks()
	n.abstractSockets.init()
	return n
}

// UserNamespace returns the user namespace associated with this namespace.
func (n *Namespace) UserNamespace() *auth.UserNamespace {
	return n.userNS
}

// SetInode sets the nsfs `inode` to the namespace.
func (n *Namespace) SetInode(inode *nsfs.Inode) {
	n.inode = inode
}

// GetInode returns the nsfs inode associated with this namespace.
func (n *Namespace) GetInode() *nsfs.Inode {
	return n.inode
}

// NewNamespace creates a new network namespace from the root.
func NewNamespace(root *Namespace, userNS *auth.UserNamespace) *Namespace {
	rootNS := root.rootNamespace()
	n := &Namespace{
		creator:           root.effectiveCreator(),
		root:              rootNS,
		userNS:            userNS,
		netlinkMcastTable: NewNetlinkMcastTable(),
	}
	n.init()
	rootNS.registerChild(n)
	return n
}

// Destroy implements nsfs.Namespace.Destroy.
func (n *Namespace) Destroy(ctx context.Context) {
	n.root.unregisterChild(n)
	if s := n.Stack(); s != nil {
		s.Destroy()
	}
}

// Type implements nsfs.Namespace.Type.
func (n *Namespace) Type() string {
	return "net"
}

// IncRef increments the Namespace's refcount.
func (n *Namespace) IncRef() {
	n.inode.IncRef()
}

// DecRef decrements the Namespace's refcount.
func (n *Namespace) DecRef(ctx context.Context) {
	n.inode.DecRef(ctx)
}

// Stack returns the network stack of n. Stack may return nil if no network
// stack is configured.
func (n *Namespace) Stack() Stack {
	return n.stack
}

// IsRoot returns whether n is the root network namespace.
func (n *Namespace) IsRoot() bool {
	return n.isRoot
}

// RestoreRootStack restores the network namespace with stack. This should
// only be called when restoring kernel.
func (n *Namespace) RestoreRootStack(stack Stack) {
	n.restoreRootStack(stack)
}

// ResetStack resets the stack in the network namespace to nil. This should
// only be called when restoring kernel.
func (n *Namespace) ResetStack() {
	n.stack = nil
}

func (n *Namespace) init() {
	// Root network namespace will have stack assigned later.
	if n.isRoot {
		return
	}
	if n.stack == nil && n.creator != nil {
		var err error
		n.stack, err = n.creator.CreateStack()
		if err != nil {
			panic(err)
		}
		n.subscribeInterfaceEvents()
	}
	n.ensureInitialized()
}

// afterLoad is invoked by stateify.
func (n *Namespace) afterLoad(goContext.Context) {
	n.restoreAfterLoad()
}

// AbstractSockets returns AbstractSocketNamespace.
func (n *Namespace) AbstractSockets() *AbstractSocketNamespace {
	return &n.abstractSockets
}

// NetlinkMcastTable returns the netlink multicast group table.
func (n *Namespace) NetlinkMcastTable() *McastTable {
	return n.netlinkMcastTable
}

// HasCapability checks if ctx has the given capability with respect to the network namespace n.
func (n *Namespace) HasCapability(ctx context.Context, cp linux.Capability) bool {
	creds := auth.CredentialsFromContext(ctx)
	return creds.HasCapabilityIn(cp, n.userNS)
}

// NetworkStackCreator allows new instances of a network stack to be created. It
// is used by the kernel to create new network namespaces when requested.
type NetworkStackCreator interface {
	// CreateStack creates a new network stack for a network namespace.
	CreateStack() (Stack, error)
}
