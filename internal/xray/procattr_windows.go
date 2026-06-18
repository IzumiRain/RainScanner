//go:build windows

package xray

import "syscall"

// Windows process creation flags (winbase.h).
const (
	belowNormalPriorityClass = 0x00004000
	createNoWindow           = 0x08000000
)

// childSysProcAttr launches each xray-core subprocess at below-normal priority
// (so the swarm of probes yields CPU to the user's desktop) and with no console
// window (no per-spawn flicker). This is the main lever that stops a scan from
// freezing the mouse.
func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: belowNormalPriorityClass | createNoWindow}
}
