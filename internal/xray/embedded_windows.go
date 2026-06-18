//go:build windows

package xray

import _ "embed"

// embeddedXrayZip is the xray-core release archive baked into this build. The CI
// release workflow (and scripts/fetch-xray.sh for local builds) overwrites the
// committed placeholder zip with the real Xray-windows-64.zip before compiling, so
// release binaries ship a working xray; a plain `go build` embeds the empty
// placeholder and falls back to a PATH/local xray at runtime.
//
//go:embed assets/xray-windows-amd64.zip
var embeddedXrayZip []byte

// embeddedXrayName is the on-disk name the extracted binary is given.
const embeddedXrayName = "xray.exe"
