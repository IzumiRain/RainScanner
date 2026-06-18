//go:build !windows && !linux

package xray

// No embedded xray for this platform; resolution falls back to a PATH/local xray.
var embeddedXrayZip []byte

const embeddedXrayName = "xray"
