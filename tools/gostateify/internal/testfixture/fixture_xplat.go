package testfixture

import "context"

// XplatState exercises cross-file localTypes resolution and Tier 2 xplat partitioning.
//
// +stateify savable
type XplatState struct {
	Seq      Counter
	Tag      string
	Restored bool `state:"nosave"`
}

func (xs *XplatState) afterLoad(context.Context) {
	xs.Restored = true
}
