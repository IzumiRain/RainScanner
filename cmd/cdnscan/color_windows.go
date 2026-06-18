//go:build windows

package main

import "unsafe"

// Windows console-mode constants (consoleapi.h).
const (
	stdOutputHandle                 = ^uintptr(10) // STD_OUTPUT_HANDLE == -11 as an unsigned handle
	enableVirtualTerminalProcessing = 0x0004       // makes the console interpret ANSI escape sequences
)

// These procedures live in kernel32.dll, which is already loaded lazily in
// priority_windows.go (the kernel32 variable); we just bind the extra entry
// points we need for console-mode manipulation.
var (
	procGetStdHandle   = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// enableConsoleColors turns on virtual-terminal (ANSI) processing for stdout so
// the colour escape codes in the launch banner render as actual colours instead
// of literal "[91m" text. It reads the current console mode and ORs in the
// ENABLE_VIRTUAL_TERMINAL_PROCESSING flag. On any failure (e.g. stdout is a
// pipe, or a pre-Windows-10 console) it simply leaves colorEnabled false, and
// the colour helpers then emit plain, uncoloured text.
func enableConsoleColors() {
	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if h == 0 || h == ^uintptr(0) /* INVALID_HANDLE_VALUE */ {
		return
	}
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return // not a real console (redirected output) — leave colour off
	}
	if r, _, _ := procSetConsoleMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing)); r == 0 {
		return
	}
	colorEnabled = true
}
