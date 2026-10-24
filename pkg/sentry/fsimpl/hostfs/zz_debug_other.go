//go:build !windows

package hostfs

func debugAccess(string) string { return "" }
