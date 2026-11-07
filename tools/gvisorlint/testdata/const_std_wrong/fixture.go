package fixture

import (
	_ "reflect"
	"unsafe"
)

type eface struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

const efaceSize = unsafe.Sizeof(eface{}) + 8 // +checksize internal/abi EmptyInterface
