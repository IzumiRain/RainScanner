# Changelog

All notable changes to **RainScanner** (`cdnscan`). Newest first.
Written by Claude (Anthropic).

---

## v2.1.0 — 2026-10-04 (unreleased)

### Added
- **IPv6 support, end to end** — provider feeds parse the IPv6 half (AWS
  `ipv6_prefixes`, a v6-aware scrape regex, a new `api_v6` manifest field for
  split feeds like Cloudflare), custom targets accept v6 CIDRs, and the scan
  pipeline gained a family selector (`auto|ipv4|ipv6|both`) with per-family
  expansion: IPv6 prefixes are sampled uniformly (bounded by
  `max-hosts-per-v6-cidr`, default 256) instead of strided. Each dial is pinned
  to the candidate's own address family, and `family=auto` falls back to IPv4
  on hosts without a global IPv6 address. Ranges/hosts report v4/v6 splits in
  the CLI, GUI and SSE payloads.

### Changed
- **GUI rebuilt** in the sample design language (single zero-build file behind
  `go:embed`): sidebar + KPI row + card grid, animated rain canvas, new IPv6
  controls (family selector, per-v6-prefix sample cap), v4/v6 sub-labels,
  off-canvas drawer under 768px, `prefers-reduced-motion` respected.

### Security
Hardening from the v2.1.0 security audit (15 confirmed findings; the items
below close the critical and high ones):
- **`xray_path` from the scan API can no longer point at a remote host** —
  UNC/`//` paths are rejected and separator-carrying paths must already exist
  as a local file (previously a cross-origin or LAN request could make the app
  authenticate to — or execute a binary from — an attacker host).
- **Mutating API endpoints reject cross-site requests** — an `Origin` header
  that does not match the serving host, or a non-JSON content type (the
  signature of a preflight-less CSRF "simple request"), is refused; request
  bodies are capped at 1 MiB.
- **Scan job IDs are random 128-bit tokens**, not sequential integers, and
  finished jobs (whose results can contain credential-bearing configs) are
  dropped after one hour — previously any local process or LAN peer could
  replay past scans' configs by walking `?id=1,2,3…`.
- **Request-supplied ceilings are clamped server-side** — TCP concurrency
  ≤ 4096, xray processes ≤ 32, batch ≤ 500, probes/confirm ≤ 64, ports ≤ 64
  (and each 1–65535), `max_hosts_per_v6_cidr` ≤ 100000, latency/probe timeouts
  bounded — so one unauthenticated request can no longer exhaust host
  resources or pin the scan lock forever.
- **The HTTP server runs with read-header/idle timeouts** (slowloris
  resistance; SSE streams are unaffected).

---

## v2.0.1 — 2026-06-21

### Added
- **Gcore CDN** — new built-in (`gcore`). 349 edge network ranges, fetched from
  `https://api.gcore.com/cdn/public-net-list`.

### Fixed
- **⟳ reload all no longer ignores newly added CDNs.** The manifest was fetched
  from the `v2.0.0` git ref, which resolved to the release *tag* (a frozen
  snapshot). Adding a CDN to `inside-api/index.json` had no effect until app
  restart. The source URL now points to `main`, so reload-all always reads the
  live manifest.
- **Daily range-refresh workflow** now checks out and commits to `main` instead
  of the deleted `v2.0.0` branch.

---

## v2.0.0 — 2026-06-21

A ground-up overhaul of how targets are managed and how the app is built, plus a
redesigned GUI.

### Added
- **Editable targets, right in the GUI.** Edit a built-in CDN's ranges, delete one
  you don't use, or **Add custom +** your own named set of CIDRs / bare IPs.
  Everything persists between runs.
- **Source switch — `github` ↔ `official api`.** Pull each CDN's ranges from the
  GitHub-hosted mirror or from the CDN's own API. Use `github` when a CDN's API is
  blocked in your region.
- **One-click `⟳ reload all`.** Re-fetches ranges for every CDN at once. GitHub owns
  the built-in set, so reloading **restores any built-in default you deleted** and
  refreshes its ranges — while your custom CDNs are left untouched.
- **Manifest-driven CDNs.** Built-ins are defined by a manifest (`inside-api/index.json`),
  not hardcoded. A daily GitHub Action re-fetches the mirrored ranges so they stay current.
- **Two new built-in CDNs:** `railway` and `vercel` (joining `cloudflare`, `fastly`,
  `cloudfront`, `arvan`) — six built-ins in total.
- **Multi-port scanning.** Scan several ports per IP (Advanced → *Ports to scan*).
- **Lite mode** for low-power machines — hard-caps concurrency so a scan won't peg a
  weak CPU.

### Changed
- **Redesigned GUI.** A live KPI dashboard (Hosts Scanned · TCP Open · Confirmed IPs ·
  Ranges Loaded), an animated progress bar with ETA, a responsive drawer sidebar for
  small screens, a live log, and copy buttons for each result list.
- **Faster Stage 2.** A batched Xray prober (v2rayN-style) tests many candidates per
  Xray process, cutting the process-spawn overhead that previously stalled the desktop.
- **Auto-tuned concurrency.** Concurrency now scales to your CPU by default, and scans
  run at below-normal priority (reserving cores for the UI) so the machine stays usable.
- **Internal refactor.** A storage port (`storage.Store` / `FileStore`) and a
  UI-agnostic core (`app.Service`) now back both the CLI and the GUI, so behavior lives
  in one place.

---

## v1.1.1 — 2026-06-18

### Added
- **Reload-all-CDNs button.** A `⟳` button in the Target section re-fetches the IP
  ranges for every CDN (and any custom target with an API URL) in one click, reporting
  per-CDN results.

---

## v1.1.0 — 2026-06-18

### Changed
- **Self-contained binary.** xray-core is now baked into the executable and extracted
  to a per-user cache dir on first use — nothing separate to install or update.
- Removed the old in-app xray updater (GUI button and `-update-xray` flag).

---

## v1.0.0 — 2026-06-18

- **Initial public release.** Multi-CDN clean-IP scanner: a high-concurrency TCP
  pre-filter followed by real Xray-proxied latency confirmation (not ICMP). CLI and
  browser GUI. Transports: VLESS / VMess / Trojan over `tcp`, `ws`, `grpc`, `http/h2`,
  and `xhttp`, with `tls` or `reality`.
