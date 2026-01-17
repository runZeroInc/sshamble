//go:build windows

package cmd

import (
	"fmt"
	"os"
	"syscall"
)

func increaseFileLimit() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to call _setmaxstdio: %v\n", r)
		}
	}()

	// Set the maximum runtime file descriptors to the upper limit (2048)
	m := syscall.NewLazyDLL("msvcrt.dll")
	s := m.NewProc("_setmaxstdio")
	s.Call(uintptr(2048))
}
