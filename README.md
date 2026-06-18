<p align="center">
  <img src="imgs/logo/logo-radius250.png" alt="RainScanner logo" width="160" />
</p>

<h1 align="center">RainScanner</h1>
<p align="center"><em>unified CDN clean-IP scanner · real Xray latency</em><br/>
<sub>written by Claude (Anthropic) · binary: <code>rainscan.exe</code> · Go module: <code>cdnscan</code></sub></p>

Finds CDN edge IPv4 addresses that actually work as Xray transports, ranked by
**real proxied latency** (not ICMP/ping). Two stages:

1. **TCP pre-filter** — high-concurrency connect sweep on `:443` discards dead IPs.
2. **Xray confirmation** — for each survivor, a generated Xray config dials the
   candidate IP directly while preserving the original SNI / WS-Host, then sends
   real HTTP requests through the proxy and measures end-to-end latency. Only IPs
   passing K-of-N probes within the latency budget are accepted.

IPv4-only. IPv6 ranges are dropped.

## Supported CDNs

Built-in defaults: `cloudflare`, `fastly`, `cloudfront` (AWS CloudFront), `arvan` (ArvanCloud).

- Each built-in pulls its official published ranges automatically and caches them
  as `ips/<cdn>.json`.
- Add your own CDNs/ranges from the GUI ("Add custom +"); customs are stored
  together in `ips/custom.json`.
- Add more built-in CDNs by registering a fetcher in
  `internal/providers/providers.go`.

## Transports

VLESS, VMess, and Trojan over `tcp` (incl. HTTP obfs), `ws`, `grpc` (incl.
`multi` mode), `http/h2`, and **`xhttp`** (incl. `mode` and `extra` like
`{"xPaddingBytes":"100-1000"}`), with `tls` or `reality`. Full TLS capabilities are
preserved on the probe so the confirmation matches a real client: `fingerprint`
(uTLS), `alpn`, `allowInsecure`, `flow`, and **ECH** (`echConfigList`). The candidate
IP is injected into the outbound while the original SNI / Host is preserved so the
CDN edge routes correctly.

## GUI

```bash
./rainscan.exe -serve              # then open http://127.0.0.1:8787
./rainscan.exe -serve -addr 0.0.0.0:8787   # reachable from Windows host when run in WSL
# (bare double-click with no flags also defaults to -serve and opens the browser)
```

The browser app (single-CDN per run) lets you:

- pick **one** CDN, or **Add custom +** a named set of CIDR ranges to scan;
- preview the selected ranges, watch live logs and a progress bar;
- scan **TCP-only by default**, optionally pasting an Xray share link to enable
  real-delay confirmation;
- multi-port scan via the **Advanced** panel (default `443`);
- copy the **TCP-reachable IPs**, the **Xray-confirmed IPs**, and ready-to-use
  **configs with each clean IP substituted in**.

Cached ranges live in `ips/<cdn>.json`; confirmed results in `results/<cdn>.json`.

> **Note:** the on-disk `results/<cdn>.json` stores the ranked clean IPs (`ip`,
> `port`, `median_ms`, `successes`, `total`) — **not** the full share-links. The
> ready-to-use configs with the clean IP substituted in are generated in the GUI
> and grabbed via the copy buttons; they aren't written to that JSON file.

## Setup

RainScanner runs on **Windows** and **Linux** (tested on **WSL Ubuntu 24.04**).
You need [Go 1.26+](https://go.dev/dl/) to build, and `xray-core` for Stage-2
latency confirmation (Stage-1 TCP scanning works without it).

### Windows

```powershell
git clone https://github.com/IzumiRain/RainScanner.git ; cd RainScanner
go build -o rainscan.exe ./cmd/cdnscan

.\rainscan.exe -update-xray     # downloads xray-core + geoip/geosite into the project folder
.\rainscan.exe -serve           # GUI at http://127.0.0.1:8787 (also opens on bare double-click)
```

### Linux / WSL

```bash
git clone https://github.com/IzumiRain/RainScanner.git && cd RainScanner
go build -o rainscan ./cmd/cdnscan

./rainscan -update-xray         # downloads the linux/amd64 (or arm64) xray-core + geo data
./rainscan -serve               # GUI at http://127.0.0.1:8787
# from a Windows browser against a WSL instance, bind all interfaces:
./rainscan -serve -addr 0.0.0.0:8787
```

> `-update-xray` auto-picks the right OS/arch build. To use an existing
> `xray-core` instead, put it on `PATH` (or pass `--xray /path/to/xray`); the
> `geoip.dat` / `geosite.dat` files must sit alongside the xray binary.

## Usage

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

## Speed & progress

- **Fail-fast probing:** Stage 2 stops a candidate as soon as the verdict is
  decided — accept once `--confirm` successes land, reject once failures make
  that impossible. Dead-but-reachable IPs no longer burn the full probe budget
  (~3.5× faster in practice).
- **Live progress bar + ETA** in both the CLI (in-place bar with elapsed/ETA) and
  the GUI (animated bar). Raise `--xray-concurrency` for more parallelism.

## Accuracy controls

- `--probes` / `--confirm` — require K successes out of N real proxied requests.
- A discarded warmup request removes tunnel-setup cost from the median.
- Median latency (not mean) resists jitter; `--max-latency` is the budget.
- Accept requires real proxied success (kills false positives); retries across
  probes suppress transient false negatives.

## Key flags

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

## Donate

If RainScanner is useful to you, donations are appreciated 🙏

| Network | Address |
|---------|---------|
| **TRC20** (Tron) | `TKBHWNoeygcaCK8N78e7dQX5Yco3WTb6ZN` |
| **BEP20** (BNB Smart Chain) | `0x0F982640a69D3B9FB944840D7DA8bECCfcF0bb9E` |
| **TON** | `UQAyLUyxew-eggwhxbzsAZZZ9ULM8MYOk-3IXFh7tNC33LNt` |

## License

[MIT](LICENSE) © IzumiRain. Written by Claude (Anthropic).
