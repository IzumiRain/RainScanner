//go:build !windows

package main

// enableConsoleColors is the non-Windows path. Unix-family terminals interpret
// ANSI colour escapes natively, so there is no console mode to flip — we simply
// declare colour usable. (If a user pipes output to a file the codes will be
// present, which matches the long-standing convention of CLI tools on these
// platforms; callers who care use a pager or strip them.)
func enableConsoleColors() { colorEnabled = true }
