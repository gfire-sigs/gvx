//go:build windows

package syserr

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	maxErrno    = 256
	winsockBase = 10000
	winsockMax  = 11005
)

var (
	windowsHostTranslations    [maxErrno]*Error
	windowsWinsockTranslations [winsockMax - winsockBase]*Error
	windowsExtraTranslations   = make(map[unix.Errno]*Error)
)

func getHostTranslation(err unix.Errno) *Error {
	if uint64(err) < uint64(len(windowsHostTranslations)) {
		return windowsHostTranslations[err]
	}
	if err >= winsockBase && err < winsockMax {
		return windowsWinsockTranslations[err-winsockBase]
	}
	return windowsExtraTranslations[err]
}

func addHostTranslation(host unix.Errno, trans *Error) {
	if uint64(host) < uint64(len(windowsHostTranslations)) {
		if windowsHostTranslations[host] != nil {
			panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
		}
		windowsHostTranslations[host] = trans
		return
	}
	if host >= winsockBase && host < winsockMax {
		idx := host - winsockBase
		if windowsWinsockTranslations[idx] != nil {
			panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
		}
		windowsWinsockTranslations[idx] = trans
		return
	}
	if windowsExtraTranslations[host] != nil {
		panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
	}
	windowsExtraTranslations[host] = trans
}
