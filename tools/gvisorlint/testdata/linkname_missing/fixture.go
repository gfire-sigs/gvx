package main

import _ "unsafe"

//go:linkname missing runtime.gvxNoSuchFunction
func missing()

func main() { missing() }
