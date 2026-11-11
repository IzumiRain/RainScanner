# Testing RainScanner

## Go Regression Suite

Go 1.26 or newer is required. The standard tests use only the Go standard library
and local fixtures; they do not scan public CDNs or need an installed Xray core.

```sh
go vet ./...
go test -count=1 -timeout=120s ./...
go test -race -count=1 -timeout=120s ./...
```

The race detector requires CGO and a C compiler on supported platforms. The tests
include controlled helper subprocesses for Xray startup/exit/authentication,
local feed servers, concurrency schedules, persisted-state reopen checks,
bounded IPv4/IPv6 sampling, cancellation at result publication, and CLI output.

Useful repeated concurrency checks:

```sh
go test -race -count=10 -timeout=120s ./internal/xray ./internal/web
```

## Browser Regression Suite

Node.js 20 or newer and Chromium are required only for browser tests. They are
not application runtime dependencies; the shipped GUI remains self-contained.

```sh
npm ci --ignore-scripts --no-audit --no-fund
./node_modules/.bin/playwright-core install chromium
npm run test:browser
```

On a Linux machine missing browser system libraries, use Playwright's
`install --with-deps chromium` in an appropriate disposable test environment.
On Windows the executable is `node_modules\.bin\playwright-core.cmd`.

Existing installations can be reused without an install:

```sh
PLAYWRIGHT_MODULE=/path/to/playwright-core/index.mjs \
CHROMIUM_PATH=/path/to/chrome \
node tests/browser.mjs
```

The suite serves the committed HTML on loopback, blocks external requests, and
controls API responses, SSE IDs/errors, and clipboard permission rejection. It
checks desktop and mobile scan completion, pending-start exclusion, stop after
stream loss, editor request isolation, name collision prevention, prerequisite
save errors and truthful copy feedback. These are behavioral tests, not a claim
of complete accessibility or physical-device coverage.

## Real Xray Integration

Use a trusted local Linux Xray executable. The optional integration test uses a
dummy VLESS identity, a WebSocket virtual-host gate, local HTTP responses and a
TCP-open non-proxy control. It must never require production credentials.

```sh
RAINSCANNER_TEST_XRAY=/absolute/path/to/xray \
go test -count=1 -v -timeout=60s ./tests
```

Without the environment variable, real-core tests skip. They must exercise real
tunnel confirmation, replay of the exported profile and cancellation preserving
the previous successful result. New Xray versions may change accepted transport
configuration; record the core version with any failure before changing tests.

## Safe Execution

Prefer a disposable source copy and a network namespace with only loopback.
Keep credentials and the host home outside the test environment, make source and
toolchain read-only, and permit writes only to test scratch space. Apply CPU,
memory, process, file-size, disk and wall-clock limits. Downloads and dependency
preparation belong outside target execution; do not let a test fetch dependencies.
The 2026-11-02 audit used these boundaries in WSL Ubuntu 24.04.

## Compatibility Notes

- Existing ordinary builtin result paths remain readable.
- Previously sanitized custom result files are accepted only when their stored
  target identity matches; new noncanonical names have independent hashed paths.
- Old range caches without API override metadata continue to use the manifest URL.
- TCP-only scans expose reachable endpoints but do not overwrite confirmed files.
- Canceled or infrastructure-failed scans return errors and preserve completed files.
- Existing target names are read-only in the editor. Explicit rename/migration is
  intentionally not inferred from an upsert.

CI runs Go vet/tests with race detection, Linux/Windows amd64 cross-builds, and
the browser regression suite. Real-core tests are optional because a verified
external executable must be supplied explicitly.
