package main

import (
	_ "runtime"
	_ "unsafe"
)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

func main() { nanotime() }
