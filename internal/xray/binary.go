package xray

import (
	"fmt"
	"os/exec"
	"runtime"
)

// FindBinary resolves the xray-core executable. An explicit path wins; otherwise
// it searches PATH and a couple of conventional local names.
func FindBinary(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	candidates = append(candidates, "xray")
	if runtime.GOOS == "windows" {
		candidates = append(candidates, "xray.exe", "./xray.exe")
	} else {
		candidates = append(candidates, "./xray")
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("xray-core not found (set --xray or put it on PATH)")
}
