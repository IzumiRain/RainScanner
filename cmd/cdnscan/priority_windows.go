//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// Windows priority classes (winbase.h).
const (
	belowNormalPriorityClass = 0x00004000
	idlePriorityClass        = 0x00000040 // "low" — yields the most to the UI
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procSetPriorityClass  = kernel32.NewProc("SetPriorityClass")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
)

// lowerProcessPriority drops this process to below-normal priority so a running
// scan can never starve the desktop/UI — Windows always preempts below-normal
// threads in favour of the user's normal-priority foreground work. This is what
// keeps the mouse responsive while scanning.
func lowerProcessPriority() {
	h, _, _ := procGetCurrentProcess.Call() // pseudo-handle, no real handle to close
	r1, _, err := procSetPriorityClass.Call(h, uintptr(belowNormalPriorityClass))
	if r1 == 0 {
		fmt.Fprintf(os.Stderr, "lowerProcessPriority: SetPriorityClass failed (handle=%x): %v\n", h, err)
	}
}
