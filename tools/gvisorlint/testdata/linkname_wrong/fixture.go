package main

import (
	_ "runtime"
	_ "unsafe"
)

//go:linkname nanotime runtime.nanotime
func nanotime() int32

func main() { nanotime() }
