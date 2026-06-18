//go:build !windows

package xray

import "syscall"

// childSysProcAttr is a no-op off Windows (priority/window flags there are
// Windows-specific). Returning nil leaves the child with default attributes.
func childSysProcAttr() *syscall.SysProcAttr { return nil }
