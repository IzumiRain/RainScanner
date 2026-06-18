//go:build linux

package xray

import _ "embed"

// embeddedXrayZip is the xray-core release archive baked into this build. See the
// note in embedded_windows.go for how the placeholder is swapped for the real
// Xray-linux-64.zip at release-build time.
//
//go:embed assets/xray-linux-amd64.zip
var embeddedXrayZip []byte

// embeddedXrayName is the on-disk name the extracted binary is given.
const embeddedXrayName = "xray"
