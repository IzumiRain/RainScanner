<p align="center">
  <img src="imgs/logo/logo-radius250.png" alt="RainScanner logo" width="160" />
</p>

<h1 align="center">RainScanner</h1>
<p align="center"><em>unified CDN clean-IP scanner · real Xray latency</em><br/>
<sub>written by Claude (Anthropic) · binary: <code>rainscan.exe</code> · Go module: <code>cdnscan</code></sub></p>

<p align="center">
  <code>v2.0.0</code> ·
  <a href="changelog/CHANGELOG.md">Changelog</a> ·
  <strong>English</strong> · <a href="README.fa.md">🇮🇷 فارسی</a>
</p>

Finds CDN edge IPv4 addresses that actually work as Xray transports, ranked by
**real proxied latency** (not ICMP/ping). Two stages:

1. **TCP pre-filter** — high-concurrency connect sweep on the target port(s) discards dead IPs.
2. **Xray confirmation** — for each survivor, a generated Xray config dials the
   candidate IP directly while preserving the original SNI / WS-Host, then sends
   real HTTP requests through the proxy and measures end-to-end latency. Only IPs
   passing K-of-N probes within the latency budget are accepted.

IPv4-only. IPv6 ranges are dropped.

## 🌐 Supported CDNs

Six built-in defaults: `cloudflare`, `fastly`, `cloudfront` (AWS CloudFront),
`arvan` (ArvanCloud), `railway`, and `vercel`.

- The first four pull their official published ranges automatically and cache them
  as `ips/<cdn>.json`. `railway` and `vercel` have no public range API, so their
  ranges ship with the repo and are maintained manually.
- **Edit any built-in** (its ranges or API URL) or **delete** ones you don't use,
  right in the GUI. A deleted built-in comes back on the next *reload all*.
- **Add your own** from the GUI (**Add custom +**) — a named set of CIDRs or bare
  IPs, optionally with an API URL to reload from. Customs live in `ips/custom.json`
  and are never overwritten by a reload.
- **Source switch (`github` ↔ `official api`).** Fetch ranges from the GitHub-hosted
  mirror or from each CDN's own API — switch to `github` if a CDN's API is blocked
  in your region.
- The built-in set is defined by a **manifest** (`inside-api/index.json`), not
  hardcoded. A daily GitHub Action re-fetches the mirrored ranges so they stay
  current; add a new built-in by adding it to the manifest.

## 🔌 Transports

VLESS, VMess, and Trojan over `tcp` (incl. HTTP obfs), `ws`, `grpc` (incl.
`multi` mode), `http/h2`, and **`xhttp`** (incl. `mode` and `extra` like
`{"xPaddingBytes":"100-1000"}`), with `tls` or `reality`. Full TLS capabilities are
preserved on the probe so the confirmation matches a real client: `fingerprint`
(uTLS), `alpn`, `allowInsecure`, `flow`, and **ECH** (`echConfigList`). The candidate
IP is injected into the outbound while the original SNI / Host is preserved so the
CDN edge routes correctly.

## 🚀 Running the app

It's a single self-contained executable — nothing to install (xray is bundled inside).

```bash
# Windows: just double-click the .exe, or:
rainscan.exe -serve

# Linux:
./rainscan-linux-amd64 -serve
```

The browser then opens at:

```
http://127.0.0.1:8787
```

```bash
# reachable from a Windows host when run inside WSL — bind all interfaces:
./rainscan.exe -serve -addr 0.0.0.0:8787
```

> Stage 1 (TCP scanning) needs nothing else. You only need an Xray config link for
> **Stage 2** (real-latency confirmation).

## 🧭 Step by step: your first scan

**1) Pick a CDN.** In the **Targets** sidebar, click a CDN such as `cloudflare`. Its
ranges appear in the **Selected Ranges** panel. The GUI scans **one CDN per run**.

**2) (Optional) Choose the range source.** If a CDN's official API is blocked in your
region, set the **source switch** to `github` to read ranges from the GitHub mirror;
otherwise `official api` is fine.

**3) (Optional) Paste a config link.** To confirm IPs by **real latency**, paste a
share link (`vless://` or `vmess://`) into the **Optional config** box. Leave it empty
to run in **TCP-only** mode (reachability only, no latency measurement).

**4) (Optional) Advanced settings.** Open **⚙ Advanced settings** to set ports,
concurrency, and confirmation criteria (described below). The defaults are a good
starting point.

**5) Start the scan.** Click **Start scan**. While it runs, the dashboard cards, the
**Live Log**, and the progress bar (with ETA) update live. Click the same button —
now **Stop** — to cancel.

**6) Take the results.** When the scan finishes:
- **Valid IPs → TCP reachable** — IPs whose ports were open.
- **Xray confirmed** — IPs whose real latency passed (only if you gave a link).
- **Output configs** — your config link with the clean IP substituted in, ready to
  use. Grab it with the **copy** button.

## 🖥️ The GUI, panel by panel

### Header
Logo, app name and version (`v2.0.0`), and a link to the **GitHub** repo. On small
screens, the menu button (☰) opens the sidebar.

### Targets sidebar
- **Source switch (`github` / `official api`)** — where ranges are fetched from: the
  GitHub mirror or each CDN's official API.
- **`⟳` (reload all)** — re-fetches the ranges for every CDN at once. Because GitHub
  owns the default set, this **restores any built-in you deleted** and refreshes its
  ranges — while your custom CDNs are left untouched.
- **CDN list** — each entry shows its range count (`N range(s)`) and a pencil ✎ to
  **edit** it. Click a name to select it.
- **`+ Add custom`** — add a custom target: a name plus a list of CIDRs or IPs (and
  optionally an API URL to reload from).
- **`⚙ Advanced settings`** — see below.
- **`Start scan`** — start / stop the scan.

### Advanced settings
- **Network**
  - **Ports to scan** — comma-separated ports (e.g. `443,80`). Every IP is tested on
    each port. Default: `443`.
  - **Xray binary path** — path to the xray binary (blank = auto-detect).
- **Performance**
  - **Lite mode** — low-power mode; caps concurrency for weak machines.
  - **TCP concurrency / Xray procs / Batch size** — parallelism (blank = auto,
    scaled to your CPU).
- **Stage 2 · Xray confirm**
  - **Probes / Confirm** — how many successes out of N real requests are required
    (e.g. 3 of 5).
  - **Max latency (ms)** — the allowed median-latency budget.
  - **Probe timeout (ms)** — per-request timeout (blank = auto).
- **Sampling**
  - **Random sample** — max number of random IPs to scan (`0` = all).
  - **Sample per /24 / Max hosts/CIDR** — limit how many IPs are taken from each range.
  - **Force re-fetch** — re-fetch ranges from source before scanning.

### Dashboard & results
- **KPI cards** — live: **Hosts Scanned**, **TCP Open** (open ports), **Confirmed
  IPs** (Xray-confirmed), **Ranges Loaded**.
- **Progress bar** — percentage, elapsed time, and estimated time remaining (ETA).
- **Selected Ranges** — preview of the chosen CDN's ranges.
- **Live Log** — a live feed of scan events.
- **Valid IPs** — the good IPs: a **TCP reachable** section and an **Xray confirmed**
  section, each with a **copy IPs** button.
- **Optional config** — the box for pasting your share link (for real-latency confirm).
- **Output configs (clean IP inside)** — your config link with the clean IP
  substituted in, ready to use; grab it with **copy all**.

### CDN editor dialog
Opens from the pencil ✎ or **Add custom**:
- **name** — the target name (not editable for built-in CDNs).
- **api url** — an address to fetch ranges from (optional). **⟳ Reload range IPs**
  pulls them right then.
- **ip ranges** — the list of CIDRs / IPs, one per line.
- **Save / Cancel / Delete** — save, discard, or remove the target.

## 📦 Setup

RainScanner runs on **Windows** and **Linux** (tested on **WSL Ubuntu 24.04**).

### Use a release (recommended)

Download the binary for your OS from the [Releases](https://github.com/IzumiRain/RainScanner/releases)
page and run it — **xray-core is bundled inside the binary**, so there's nothing
else to install. It's extracted to a per-user cache dir on first use.

```powershell
.\rainscan-windows-amd64.exe          # GUI at http://127.0.0.1:8787 (also opens on bare double-click)
```

```bash
./rainscan-linux-amd64 -serve         # GUI at http://127.0.0.1:8787
# from a Windows browser against a WSL instance, bind all interfaces:
./rainscan-linux-amd64 -serve -addr 0.0.0.0:8787
```

### Build from source

You need [Go 1.26+](https://go.dev/dl/). A plain `go build` bakes in an empty
placeholder for xray; run `scripts/fetch-xray.sh` first to embed the real
xray-core (as the release build does), **or** just keep an `xray` / `xray.exe`
binary on `PATH` (or pass `--xray /path/to/xray`) and skip the fetch.

```bash
git clone https://github.com/IzumiRain/RainScanner.git && cd RainScanner
./scripts/fetch-xray.sh               # optional: embed xray into the binary
go build -o rainscan ./cmd/cdnscan    # rainscan.exe on Windows
./rainscan -serve
```

> Stage-1 (TCP scanning) works with no xray at all; xray is only needed for the
> Stage-2 real-latency confirmation. The probe configs don't use geo routing, so
> `geoip.dat` / `geosite.dat` are **not** required.

## ⌨️ Command-line usage

The GUI scans one CDN; the CLI can scan several (`-cdn a,b`).

```bash
# list providers
./rainscan.exe -list

# full scan with Xray latency confirmation
./rainscan.exe \
  --cdn cloudflare,fastly \
  --link "vless://UUID@domain:443?security=tls&type=ws&host=cdn.domain&path=%2Fws&sni=cdn.domain" \
  --port 443 \
  --tcp-concurrency 1000 \
  --xray-concurrency 32 \
  --probes 5 --confirm 3 --max-latency 800ms

# huge ranges: sample instead of full enumeration
./rainscan.exe --cdn cloudflare --link "vmess://..." --sample-per-24 4

# TCP-only mode (no link) — just reachability, no latency confirmation
./rainscan.exe --cdn fastly --sample-per-24 1
```

Cached ranges live in `ips/<cdn>.json`; confirmed results in `results/<cdn>.json`.

> **Note:** the on-disk `results/<cdn>.json` stores the ranked clean IPs (`ip`,
> `port`, `median_ms`, `successes`, `total`) — **not** the full share-links. The
> ready-to-use configs with the clean IP substituted in are generated in the GUI
> and grabbed via the copy buttons; they aren't written to that JSON file.

## ⚡ Speed & progress

- **Fail-fast probing:** Stage 2 stops a candidate as soon as the verdict is
  decided — accept once `--confirm` successes land, reject once failures make
  that impossible. Dead-but-reachable IPs no longer burn the full probe budget
  (~3.5× faster in practice).
- **Live progress bar + ETA** in both the CLI (in-place bar with elapsed/ETA) and
  the GUI (animated bar). Raise `--xray-concurrency` for more parallelism.

## 🎯 Accuracy controls

- `--probes` / `--confirm` — require K successes out of N real proxied requests.
- A discarded warmup request removes tunnel-setup cost from the median.
- Median latency (not mean) resists jitter; `--max-latency` is the budget.
- Accept requires real proxied success (kills false positives); retries across
  probes suppress transient false negatives.

## 🚩 Key flags

| flag | default | meaning |
|------|---------|---------|
| `--cdn` | — | CDNs to scan (`a,b` or `all`) |
| `--link` | — | `vless://` / `vmess://` share link; omit for TCP-only |
| `--xray` | PATH | xray-core binary path |
| `--port` | 443 | target TCP port |
| `--ports` | — | comma-separated ports to scan, e.g. `443,80,8080` (overrides `--port`) |
| `--tcp-concurrency` | 1000 | stage1 parallel dials |
| `--xray-concurrency` | 32 | stage2 parallel xray processes |
| `--probes` / `--confirm` | 5 / 3 | K-of-N latency confirmation |
| `--max-latency` | 800ms | median latency budget |
| `--sample-per-24` | 0 | sample N hosts per /24 (0 = full) |
| `--refresh` | false | force re-fetch provider ranges |

## 🗒️ Changelog

Full history is in **[`changelog/CHANGELOG.md`](changelog/CHANGELOG.md)**.

**v2.0.0** — editable targets in the GUI, a `github ↔ official api` source switch,
one-click `⟳ reload all` (restores deleted built-ins, keeps your customs),
manifest-driven CDNs with a daily refresh, two new built-ins (`railway`, `vercel`),
multi-port scanning, and a redesigned KPI dashboard.

## 🤝 Contributing

Issues and pull requests are welcome. Found a bug, hit a CDN whose ranges look
wrong, or have an idea? [Open an issue](https://github.com/IzumiRain/RainScanner/issues)
or send a [pull request](https://github.com/IzumiRain/RainScanner/pulls) — adding a
new built-in CDN can be as small as one manifest entry.

## 💝 Donate

If RainScanner is useful to you, donations are appreciated 🙏

| Network | Address |
|---------|---------|
| **TRC20** (Tron) | `TKBHWNoeygcaCK8N78e7dQX5Yco3WTb6ZN` |
| **BEP20** (BNB Smart Chain) | `0x0F982640a69D3B9FB944840D7DA8bECCfcF0bb9E` |
| **TON** | `UQAyLUyxew-eggwhxbzsAZZZ9ULM8MYOk-3IXFh7tNC33LNt` |

## 📄 License

[MIT](LICENSE) © IzumiRain. Written by Claude (Anthropic).
