# Changelog

All notable changes to **RainScanner** (`cdnscan`). Newest first.
Written by Claude (Anthropic).

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
