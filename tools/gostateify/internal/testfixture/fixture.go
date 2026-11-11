// Package testfixture exercises gostateify code generation with pkg/state round-trips.
package testfixture

import "context"

// Counter is a locally defined primitive type requiring a pointer cast in StateSave/StateLoad.
type Counter uint32

// Label is a type alias that uses SaveString/LoadString without a pointer cast.
type Label = string

// Payload exercises non-struct value registration via state.Register.
//
// +stateify savable
type Payload []byte

// BaseBox is the underlying savable struct for IdentBox.
//
// +stateify savable
type BaseBox struct {
	Code Counter
	Name Label
}

// IdentBox exercises +stateify identtype delegation to BaseBox.
//
// +stateify savable
// +stateify identtype
type IdentBox BaseBox

// EmbeddedMeta tests anonymous embedded struct field saving and loading.
//
// +stateify savable
type EmbeddedMeta struct {
	Version uint16
}

// LeafNode is referenced through a state:"wait" field on RootContainer so its
// afterLoad completes before RootContainer.afterLoad runs.
//
// +stateify savable
type LeafNode struct {
	Value       int64
	LoadedReady bool `state:"nosave"`
}

func (l *LeafNode) afterLoad(context.Context) {
	l.LoadedReady = true
}

// RootContainer exercises beforeSave, afterLoad, wait, nosave, zerovalue,
// custom value saver/loader methods, embedded fields, and interface polymorphism.
//
// +stateify savable
type RootContainer struct {
	EmbeddedMeta
	Count          Counter
	Title          Label
	Leaf           *LeafNode `state:"wait"`
	TransientCache string    `state:"nosave"`
	MustBeZero     int       `state:"zerovalue"`
	items          []string  `state:".([]string)"`
	AnyPayload     any
	SavedHookOrder []string
	LeafWasReady   bool `state:"nosave"`
}

func (rc *RootContainer) SetItems(items []string) {
	rc.items = append([]string(nil), items...)
}

func (rc *RootContainer) Items() []string {
	return rc.items
}

func (rc *RootContainer) beforeSave() {
	rc.SavedHookOrder = append(rc.SavedHookOrder, "beforeSave")
}

func (rc *RootContainer) saveItems() []string {
	out := make([]string, len(rc.items))
	copy(out, rc.items)
	return out
}

func (rc *RootContainer) loadItems(_ context.Context, v []string) {
	rc.items = append([]string(nil), v...)
}

func (rc *RootContainer) afterLoad(context.Context) {
	if rc.Leaf != nil {
		rc.LeafWasReady = rc.Leaf.LoadedReady
	}
}
