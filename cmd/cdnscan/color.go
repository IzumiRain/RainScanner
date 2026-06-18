package main

// This file implements the small amount of terminal colouring used by the
// double-click launch banner. Colours are expressed as ANSI SGR escape
// sequences (the "\033[..m" codes). Every modern terminal understands them,
// and on Windows 10+ the classic CMD console understands them too once
// virtual-terminal processing has been switched on for the output handle —
// that switch is enableConsoleColors(), implemented per-OS in color_windows.go
// and color_other.go.
//
// We use the "bright" colour variants (90-series codes) rather than the base
// 30-series because plain blue in particular is nearly unreadable on the dark
// background CMD ships with.

const (
	ansiReset = "\033[0m"
	ansiWhite = "\033[97m" // bright white
	ansiGreen = "\033[92m" // bright green
	ansiBlue  = "\033[94m" // bright blue
)

// colorEnabled records whether colour output is actually safe to emit. It is
// set by enableConsoleColors() at startup: true once the console (or a native
// ANSI terminal) is ready, false if we couldn't enable it. When false the
// helpers below return the text unchanged so we never spray raw escape codes
// into a console that would show them literally.
var colorEnabled bool

// colorize wraps s in the given ANSI colour code (and a reset) when colour is
// enabled, and returns s untouched otherwise.
func colorize(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

func white(s string) string { return colorize(ansiWhite, s) }
func green(s string) string { return colorize(ansiGreen, s) }
func blue(s string) string  { return colorize(ansiBlue, s) }
