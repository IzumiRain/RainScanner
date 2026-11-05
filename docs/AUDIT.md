# RainScanner Correctness Audit

## Scope And Evidence

- Reviewed baseline: `cc5b1965ec9e39a55decc0502802ec524ee414ad` (2026-11-02).
- Scope: CLI, service, scanning, address expansion, Xray generation/processes,
  link parsing/export, provider feeds, persistence, HTTP/SSE API, browser UI,
  build/release workflows.
- Runtime environment: WSL Ubuntu 24.04, Go 1.26.9, Chromium/Playwright Core.
- Real-core validation: official Xray 26.10.31 Linux amd64; downloaded archive
  SHA-256 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214`.
- Execution used a separate source copy, an unprivileged process, read-only
  source/toolchain mounts, isolated loopback networking, and CPU, memory,
  process, file-size, disk and wall-clock limits. No public ranges were scanned.
- Regression failures below describe the baseline, not the corrected tree.
  Browser fault tests controlled API timing and transport errors; a separate
  real browser/server/TCP/SSE test validated the complete normal path and the
  rename overwrite against the actual backend.

P2 means a correctness, availability, or data-integrity defect worth fixing.
P3 means a narrower-condition or lower-impact defect. No P0/P1 was established.
Source references identify the baseline locations and may move during fixes.

## Findings

### A01 - P2 - Cancellation overwrites completed results

`internal/pipeline/pipeline.go:211-225,281-285`

Stop/Ctrl+C returns partial stage collections, then unconditionally replaces the
previous completed result. Reproduced with a canceled-context test and with Stop
during a real Xray-tunneled HTTP request: a file with one confirmed endpoint
became `count: 0, results: []`. Enforce cancellation before publication and
propagate it to callers. Partial data must not masquerade as a complete scan.

### A02 - P2 - TCP-only mode erases confirmed results and hides CLI addresses

`internal/pipeline/pipeline.go:217-225,264-266`; `cmd/cdnscan/main.go:234-239`

Without a link, stage 2 produces no confirmations but the result file is still
replaced. The CLI prints only counts, not `Summary.Endpoints`. Reproduced with an
actual TCP listener and CLI process: `tcp_open=1`, no IP in output, empty saved
results. Preserve confirmed output when confirmation is absent and print the
reachable endpoints explicitly.

### A03 - P2 - Infrastructure failure is treated as candidate rejection

`internal/xray/prober.go:118-156`; `internal/pipeline/pipeline.go:306-323`

Batch configuration, executable and startup errors populate `TestResult.Err`,
which the pipeline ignores. Reproduced invalid generated configuration and a
failing executable: both report successful zero-confirmation scans. Separate
infrastructure failure from normal failed network probes; do not publish it.

### A04 - P2 - Pipeline suppresses returned errors

`internal/pipeline/pipeline.go:123-141`

Single-target errors return `(nil, nil)`; provider errors are logged and skipped.
Reproduced an invalid output directory: callers receive no error. Return wrapped
single-target failures and joined errors alongside successful partial summaries.

### A05 - P2 - Export loses implicit Host/SNI

`internal/link/link.go:95-130,285-300`

Substitution replaces the address without materializing its effective original
Host/SNI. Reproduced round trips for VLESS, Trojan and VMess. Also reproduced with
real VLESS/WebSocket routing: the scanner confirmed the original profile with
two successes; its exported profile had zero successes; restoring the Host
produced two successes again. Preserve original routing identity before rewrite.

### A06 - P2 - Probe can trust the wrong listener

`internal/xray/prober.go:125-155,168-179,270-291`

Ports are released before child bind; readiness accepts any TCP listener. A
different batch/process can serve requests attributed to the original candidate.
Under an induced collision, a competing real Xray listener produced `OK=true`,
two successes for unreachable `127.0.0.9:1`. This validates the ownership defect,
not the natural probability of port reuse. Authenticate batch inbounds and
clients with unpredictable per-batch credentials and observe owned-child exit.

### A07 - P2 - IPv4 per-/24 sample limits are wrong

`internal/iprange/iprange.go:209-231`

`hostBits > 8` excludes /24; integer stride rounds down for other blocks.
Reproduced one sample on /24 returning 256 hosts, and three per /24 on /23
returning seven rather than six. Sample an explicit bounded count per /24.

### A08 - P2 - Broad-prefix preprocessing ignores cancellation

`internal/iprange/iprange.go:155-175,204-232`

`MaxTotal=1` still walks 2^32 addresses for /0. Expansion has no context. A bounded
real-server test acknowledged Stop but the next scan still received HTTP 409.
The test process was terminated promptly, not allowed to enumerate the Internet.
Add cancellation and bounded-work sampling rather than a full reservoir walk.

### A09 - P2 - Terminal SSE notification can be missed

`internal/web/server.go:542-558,613-644`

Snapshot and notification-channel acquisition are separate. A final push between
them leaves the subscriber waiting on an unused replacement channel. Reproduced
with a deterministic blocked-flush test; a real-Xray scan also stalled after its
confirmation log. Capture notification before snapshot or return both atomically.

### A10 - P2 - Stream failure loses active scan control

`internal/web/static/index.html:918,972`

The error callback closes EventSource and resets idle without stopping backend
work. Chromium fault injection reproduced a second Start receiving 409 while
Stop became inaccessible. Retain job state and reconnect with replay-safe IDs.

### A11 - P2 - Startup Stop races in browser and server

`internal/web/static/index.html:917-953`; `internal/web/server.go:434-487`

The browser displays Stop before `es` exists, so clicking it submits another
scan. Chromium reproduced two starts and no stop. Independently, the server
publishes its cancel function only in the worker after acknowledging creation;
this second race was established by a legal source schedule, not a runtime hit.
Represent starting/running/stopping explicitly and publish cancellation before
acknowledgment under the same ownership lock.

### A12 - P2 - Late reload corrupts another target's editor

`internal/web/static/index.html:982,992-1000,1045-1049`

Reload A, close the modal, open B, then receive A's response: the shared textarea
now contains A's ranges under B's name. Reproduced in Chromium. Invalidate pending
editor operations on close/open and ignore responses from older editor instances.

### A13 - P2 - Custom rename overwrites another record

`internal/web/static/index.html:996,1003-1015`

The UI allows a name change but sends only a name-keyed upsert. Renaming A to B
overwrites B and leaves A. Reproduced in mocked Chromium and against the actual
running registry API. Keep existing names immutable until a real collision-safe
rename operation exists.

### A14 - P2 - Distinct result names share filenames

`internal/output/output.go:112-150`

`A B` and `A-B` both map to `a-b.json`; non-ASCII-only names map to `custom`.
Reproduced writes and reads returning the other target's data. Use an unambiguous
key for noncanonical names; legacy reads must verify stored target identity.

### A15 - P2 - Scan refresh bypasses target registry

`internal/app/service.go:249-257`; `internal/providers/providers.go:494-515`

Force refresh routes custom names and builtin overrides through the manifest,
then updates disk without the live registry. Reproduced routing decisions and a
local-feed refresh whose next normal scan still used old CIDRs. Refresh through
registry semantics, preserving user feed overrides and updating the live record.

### A16 - P2 - Builtin feed overrides do not survive restart

`internal/targets/targets.go:67-76,300-307`

Builtin persistence omits API URL, and Open restores the manifest URL. Reproduced
save/reopen reverting the feed. Persist user-local override metadata while
remaining compatible with existing cache files that have no override field.

### A17 - P2 - Reload resurrects deletion and loses newer edits

`internal/targets/targets.go:259-285`

Reload snapshots a record, fetches unlocked, then unconditionally upserts it.
Reproduced local blocked feeds recreating deleted builtin and custom records,
including persisted state. Compare a record revision before applying the result;
do not recreate a missing record from stale asynchronous work.

### A18 - P2 - Clipboard failure is reported as success

`internal/web/static/index.html:1055-1061`

HTTP LAN pages lack the secure Clipboard API, and rejected promises are ignored.
Chromium permission rejection still displayed `copied!`. Await writes, detect
unsupported APIs, provide a fallback and report failure without claiming success.

### A19 - P3 - Embedded extraction shares a truncating temporary file

`internal/xray/embedded.go:97-113`

Concurrent first-use processes share `dst + ".new"` with O_TRUNC. One can consume
the other staging pathname or interfere with its writes. Source-confirmed; the
baseline race was not runtime-reproduced. Use unique temporary files, complete
validation and atomic publication; handle a competing completed extraction.

### A20 - P3 - Reload ignores prerequisite save rejection

`internal/web/static/index.html:1038-1044`

A rejected URL edit still triggers reload of the old saved feed and reports
success. Chromium reproduced save HTTP 400 followed by reload HTTP 200. Check
the first response and abort before reloading if persistence failed.

### A21 - P3 - Builtin casing changes split cache identity on Linux

`internal/targets/targets.go:210-217`

Case-insensitive lookup accepts `Cloudflare` but saves that casing, whereas Open
reads canonical `cloudflare`. Reproduced save/reopen returning old ranges on the
Linux case-sensitive filesystem. Preserve the manifest/existing canonical name.

## Excluded Or Unresolved Claims

- Early success at K probes is explicitly documented behavior, not reported as
  a defect merely because all N probes are not run.
- Non-amd64 embedding is outside the published release matrix; no supported
  platform regression was established.
- Feed TTL and partial-family refresh policies are not specified as stronger
  invariants, so they were not promoted to findings.
- No concrete race was found in the manifest's immutable pointer publication.
- Public feed ownership/currentness, censorship conditions, TLS/REALITY/ECH
  interoperability across all client versions, and external Actions behavior
  are not established by these local tests.

## Remediation Status

All 21 baseline findings have source fixes and permanent regression coverage.
The evidence level for each baseline claim remains as recorded above; a passing
fix test does not retroactively turn a source-only baseline claim into a natural
runtime reproduction.

| Findings | Remediation | Permanent coverage |
| --- | --- | --- |
| A01-A04 | Context-aware atomic result publication, error propagation, TCP-only preservation and CLI endpoint output | `internal/pipeline/pipeline_test.go`, `internal/output/output_test.go`, `cmd/cdnscan/main_test.go` |
| A05 | Materialize effective Host/SNI before substitution | `internal/link/link_test.go`, `tests/realxray_test.go` |
| A06 | Random authenticated batch inbounds, matching clients, port leases and owned-child/listener health checks | `internal/xray/prober_test.go`, `internal/xray/config_test.go` |
| A07-A08 | Exact per-/24 selection, context-aware virtual-pool sampling without full IPv4 traversal | `internal/iprange/iprange_test.go` |
| A09-A11 | Notification ordering, numbered SSE replay, separate UI state, synchronous cancel publication and terminal statuses | `internal/web/server_test.go`, `tests/browser.mjs` |
| A12-A13 | Editor generation/abort checks, collision prevention and immutable existing names | `tests/browser.mjs` |
| A14 | Independent namespaced result keys and identity-checked legacy reads | `internal/output/output_test.go` |
| A15-A17 | Registry-based refresh, persisted builtin override metadata and revision-checked reload commits | `internal/app/service_test.go`, `internal/targets/targets_test.go`, `internal/providers/persistence_test.go`, `internal/storage/storage_test.go` |
| A18 | Awaited clipboard writes, fallback and truthful failure feedback | `tests/browser.mjs` |
| A19 | Unique staging files, complete-content/permission validation and atomic publication | `internal/xray/embedded_test.go` |
| A20 | Abort reload when its prerequisite save fails | `tests/browser.mjs` |
| A21 | Canonical persisted builtin names | `internal/targets/targets_test.go` |

## Final Verification

Executed in the isolated WSL environment against the corrected tree on
2026-11-02:

```sh
go vet ./...
RAINSCANNER_TEST_XRAY=/source/tools/xray go test -race -count=1 -timeout=120s ./...
go test -race -count=10 -timeout=120s ./internal/xray ./internal/web
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /scratch/rainscan-linux ./cmd/cdnscan
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o /scratch/rainscan-windows.exe ./cmd/cdnscan
PLAYWRIGHT_MODULE=/playwright/node_modules/playwright-core/index.mjs \
CHROMIUM_PATH=/chromium/chrome-linux64/chrome node tests/browser.mjs
```

- Vet: passed.
- All Go packages, including opt-in real Xray integration, passed with `-race`.
- Xray process and SSE concurrency suites passed ten repeated race-enabled runs.
- Both supported-platform cross-builds passed.
- Browser suite: 12 passed, zero failed, including desktop/mobile normal flows,
  stream failure, pending creation, aborted editor requests, target name
  collisions, save rejection, clipboard denial, and consistent cleanup after
  stopped/error partial results and save/reload after first creating a feed.
- Real-core integration: TCP-open good/bad controls were distinguished by actual
  VLESS/WebSocket HTTP traffic; exported and explicit-host profiles both passed;
  cancellation during a tunneled request returned `context.Canceled` and
  preserved the prior completed file byte-for-byte.
- An independent source pass found stale derived copy controls in the initial
  stopped/error UI fix, new-feed creation not adopting its newly saved identity,
  and cancellation losing its sentinel through backup-feed failures. These were
  corrected with browser regressions and provider fallback-cancellation tests.
- `git diff --check` passed; Git may print existing LF/CRLF conversion warnings.

### PR Readiness Follow-Up

The final PR review caught a test-harness bookkeeping defect: the browser suite
had expanded from nine to twelve cases, but its exit check still required nine.
All twelve assertions passed while the process incorrectly exited 1. Earlier
assertion-only summaries therefore overstated the complete command's success.
The harness now counts scheduled cases rather than hardcoding their number;
the PR readiness rerun explicitly checks the process exit status.

That review also found that a successful primary feed followed by a canceled
IPv6 fetch could still be saved as a partial refresh. Fetch success now honors
cancellation, and registry reload checks cancellation after the fetch and again
under its commit lock. New regressions verify that a canceled dual feed does
not return partial success and a canceled reload preserves live and reopened
stored records.

Browser CI also uses a committed integrity-checked npm lockfile, `npm ci`, pinned
Node setup, Node 22 and bounded job timeouts. No hosted CI result is implied by
local execution.

The final readiness run passed vet, all-package race tests with real Xray,
ten repeated race runs of targets/providers/Xray/web, both cross-builds, and all
twelve browser checks. The command chain reached
`PR_READINESS_ALL_CHECKS_EXIT_ZERO`, explicitly confirming successful exit.
The npm lockfile also passed an offline `npm ci --dry-run` consistency check.

## Remaining Boundaries

- Public CDN scanning and censorship-dependent performance were not tested.
- Windows amd64 was cross-built, not runtime-tested on native Windows.
- Registry and output synchronization is process-local. Separate CLI processes
  writing the same directories can still race; no cross-process database or
  multi-file transaction journal was introduced.
- Re-adding a hidden builtin updates its range file before its hidden-envelope
  entry. A second-write failure leaves live hidden state intact but may update
  that hidden range cache.
- Atomic rename protects readers from partial writes; this is not a claim of
  power-loss durability or cross-file transactions.
- The UI retains the existing visual language. Contrast was improved for muted
  text and placeholders, but a full accessibility redesign, all browser engines,
  physical mobile devices and all TLS/REALITY/ECH combinations remain untested.
- CI configuration was added locally; hosted Actions have not been run here.

See [TESTING.md](TESTING.md) for reproducible commands and fixture requirements.
