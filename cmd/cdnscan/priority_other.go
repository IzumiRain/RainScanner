//go:build !windows

package main

// lowerProcessPriority is a no-op off Windows; the priority handling there is
// Windows-specific (SetPriorityClass). On Unix one could nice(2) instead.
func lowerProcessPriority() {}
