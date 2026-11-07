package main

import (
	_ "unsafe"

	_ "example.com/fixture/impl"
)

//go:linkname hidden example.com/fixture/lib.hidden
func hidden()

func main() { hidden() }
