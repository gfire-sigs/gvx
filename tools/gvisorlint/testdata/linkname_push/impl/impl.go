package impl

import _ "unsafe"

//go:linkname push example.com/fixture/lib.hidden
func push() {}
