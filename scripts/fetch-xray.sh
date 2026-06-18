#!/usr/bin/env bash
# Download the xray-core release asset for this OS and drop it where go:embed
# expects it (internal/xray/assets/), so a local `go build` bakes a working xray
# into the rainscan binary. CI does the equivalent step itself; this is only for
# building release-style (xray-embedded) binaries on your own machine.
#
# The committed assets/*.zip are tiny empty placeholders; a plain `go build`
# without running this embeds the placeholder and falls back to a PATH/local xray
# at runtime. After running this, consider:
#     git update-index --skip-worktree internal/xray/assets/*.zip
# so the ~15 MB real zip is never accidentally committed.
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -s)" in
  Linux*)               asset=Xray-linux-64.zip;   dest=internal/xray/assets/xray-linux-amd64.zip ;;
  MINGW*|MSYS*|CYGWIN*) asset=Xray-windows-64.zip; dest=internal/xray/assets/xray-windows-amd64.zip ;;
  *) echo "unsupported OS for embedding (only linux + windows are bundled)"; exit 1 ;;
esac

echo "resolving latest xray-core release for $asset ..."
url=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
  | grep -o "https://[^\"]*/${asset}" | head -1)
[ -n "$url" ] || { echo "could not find asset $asset in the latest release" >&2; exit 1; }

echo "downloading $asset ..."
curl -fL "$url" -o "$dest"
ls -l "$dest"
echo "done — 'go build ./cmd/cdnscan' will now embed xray into the binary."
