package xray

import (
	"encoding/json"
	"fmt"

	"cdnscan/internal/link"
)

// GenerateConfig builds a minimal Xray config whose outbound dials candidateIP
// directly while preserving the original SNI / WS-Host from the share link, so
// the CDN edge at candidateIP routes the connection to the correct backend. The
// inbound is a local HTTP proxy on inboundPort used to drive a real request.
func GenerateConfig(o *link.Outbound, candidateIP string, candidatePort, inboundPort int) ([]byte, error) {
	ob, err := buildOutbound(o, candidateIP, candidatePort, "")
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"listen":   "127.0.0.1",
			"port":     inboundPort,
			"protocol": "http",
			"settings": map[string]any{},
		}},
		"outbounds": []any{ob},
	}
	return json.Marshal(cfg)
}

// BatchTarget is one candidate in a batched config: its IP/port plus the local
// inbound port wired to it.
type BatchTarget struct {
	IP          string
	Port        int
	InboundPort int
}

// GenerateBatchConfig builds ONE Xray config that tests many candidates at once
// (the v2rayN approach): each target gets its own local HTTP inbound and its own
// outbound, joined by a routing rule (inboundTag -> outboundTag). A single xray
// process then serves the whole batch, so we pay one process spawn per ~50
// candidates instead of one per candidate — the big Stage-2 speed/lag win.
func GenerateBatchConfig(o *link.Outbound, targets []BatchTarget) ([]byte, error) {
	inbounds := make([]any, 0, len(targets))
	outbounds := make([]any, 0, len(targets))
	rules := make([]any, 0, len(targets))

	for i, t := range targets {
		inTag := "in-" + itoa(i)
		outTag := "out-" + itoa(i)

		inbounds = append(inbounds, map[string]any{
			"listen":   "127.0.0.1",
			"port":     t.InboundPort,
			"protocol": "http",
			"settings": map[string]any{},
			"tag":      inTag,
		})

		ob, err := buildOutbound(o, t.IP, t.Port, outTag)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, ob)

		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []any{inTag},
			"outboundTag": outTag,
		})
	}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"rules": rules},
	}
	return json.Marshal(cfg)
}

// buildOutbound constructs one outbound object dialing candidateIP while keeping
// the share link's protocol + stream (SNI/WS/REALITY/etc). tag is optional.
func buildOutbound(o *link.Outbound, candidateIP string, candidatePort int, tag string) (map[string]any, error) {
	stream, err := streamSettings(o)
	if err != nil {
		return nil, err
	}

	// Protocol-specific "settings" block. Each proxy protocol names its server
	// list differently (vless/vmess use "vnext", trojan uses "servers") and
	// carries different credentials, so we build the right shape per protocol.
	var settings map[string]any
	switch o.Protocol {
	case "vless":
		// VLESS authenticates with a UUID and uses no transport-level cipher
		// ("encryption":"none"). flow (e.g. xtls-rprx-vision) is optional.
		user := map[string]any{"id": o.ID, "encryption": "none"}
		if o.Flow != "" {
			user["flow"] = o.Flow
		}
		settings = map[string]any{
			"vnext": []any{map[string]any{
				"address": candidateIP,
				"port":    candidatePort,
				"users":   []any{user},
			}},
		}
	case "vmess":
		// VMess authenticates with a UUID + alterId and DOES apply a cipher
		// ("security"); "auto" lets xray pick a sensible default.
		cipher := o.Cipher
		if cipher == "" {
			cipher = "auto"
		}
		settings = map[string]any{
			"vnext": []any{map[string]any{
				"address": candidateIP,
				"port":    candidatePort,
				"users": []any{map[string]any{
					"id":       o.ID,
					"alterId":  o.AlterID,
					"security": cipher,
				}},
			}},
		}
	case "trojan":
		// Trojan authenticates with a password (carried in the link's user-info
		// slot) rather than a UUID, and lists servers under "servers".
		server := map[string]any{
			"address":  candidateIP,
			"port":     candidatePort,
			"password": o.Password,
		}
		if o.Flow != "" {
			server["flow"] = o.Flow
		}
		settings = map[string]any{"servers": []any{server}}
	default:
		return nil, fmt.Errorf("unsupported protocol %q", o.Protocol)
	}

	ob := map[string]any{
		"protocol":       o.Protocol,
		"settings":       settings,
		"streamSettings": stream,
	}
	if tag != "" {
		ob["tag"] = tag
	}
	return ob, nil
}

func streamSettings(o *link.Outbound) (map[string]any, error) {
	network := o.Network
	if network == "" {
		network = "tcp"
	}
	ss := map[string]any{"network": network}

	switch o.Security {
	case "", "none":
		ss["security"] = "none"
	case "tls":
		// Standard TLS. serverName carries the original SNI so that, even though
		// we are dialing a raw candidate IP, the CDN edge sees the hostname it
		// needs to route by. allowInsecure mirrors the share link's setting:
		// when true the proxy will accept a certificate that doesn't match the
		// SNI (some setups rely on this); when false (the safe default) the cert
		// must validate, exactly as a real client would require.
		ss["security"] = "tls"
		tls := map[string]any{"serverName": o.SNI, "allowInsecure": o.AllowInsecure}
		if o.FP != "" {
			// uTLS fingerprint (e.g. "chrome"): makes the TLS ClientHello mimic a
			// real browser so the handshake isn't trivially distinguishable.
			tls["fingerprint"] = o.FP
		}
		if len(o.ALPN) > 0 {
			// Application-layer protocol negotiation list (e.g. h2, http/1.1).
			tls["alpn"] = o.ALPN
		}
		if o.ECH != "" {
			// Encrypted Client Hello. The share link supplies an "ECH query"
			// string such as "ip.gs+udp://8.8.8.8", which names the domain whose
			// published ECH config list should be used together with the DNS
			// server to fetch it from. xray resolves and applies that config at
			// connect time, encrypting the real SNI inside the ClientHello. We
			// must pass this through verbatim: if we dropped it, our probe would
			// perform a *different* (plaintext-SNI) handshake than the real
			// client and could wrongly accept or reject an edge IP.
			tls["echConfigList"] = o.ECH
		}
		ss["tlsSettings"] = tls
	case "reality":
		// REALITY is an anti-censorship TLS variant that borrows a real external
		// site's certificate. It needs the server's public key (pbk), a short ID
		// (sid), and a "spider" path (spx) from the link; the fingerprint defaults
		// to chrome when the link omits it. These are passed straight through so
		// the probe negotiates REALITY identically to the real client.
		ss["security"] = "reality"
		ss["realitySettings"] = map[string]any{
			"serverName":  o.SNI,
			"fingerprint": firstNonEmpty(o.FP, "chrome"),
			"publicKey":   o.PublicKey,
			"shortId":     o.ShortID,
			"spiderX":     o.SpiderX,
		}
	default:
		return nil, fmt.Errorf("unsupported security %q", o.Security)
	}

	// Per-transport settings. Each CDN-frontable transport carries the original
	// Host header / path so the edge routes to the correct backend even though
	// the TCP connection is opened to a bare candidate IP.
	switch network {
	case "ws":
		// WebSocket: the Host header is what the CDN routes on (it is the real
		// hostname, not the candidate IP), and path selects the backend route.
		ss["wsSettings"] = map[string]any{
			"path":    o.Path,
			"headers": map[string]any{"Host": o.Host},
		}
	case "grpc":
		// gRPC transport. serviceName is the gRPC path; multiMode is an xray
		// option that multiplexes streams and must be enabled only when the link
		// requested it ("mode=multi"), otherwise the handshake won't match.
		grpc := map[string]any{"serviceName": o.Service}
		if o.Mode == "multi" {
			grpc["multiMode"] = true
		}
		ss["grpcSettings"] = grpc
	case "http", "h2":
		// HTTP/2 transport. xray calls this network "http"; the link may spell it
		// "h2", which applyDefaults() in the link package normalises to "http".
		ss["network"] = "http"
		ss["httpSettings"] = map[string]any{
			"host": []any{o.Host},
			"path": o.Path,
		}
	case "xhttp", "splithttp":
		// xhttp (formerly "splithttp"). Beyond host/path it supports a "mode"
		// (auto/packet-up/stream-up/stream-one) and an "extra" settings object.
		ss["network"] = "xhttp"
		xs := map[string]any{
			"host": o.Host,
			"path": o.Path,
		}
		if o.Mode != "" {
			xs["mode"] = o.Mode
		}
		if o.Extra != "" {
			// "extra" arrives as a raw JSON object string in the link
			// (e.g. {"xPaddingBytes":"100-1000"}). We embed it with
			// json.RawMessage so it nests as a real JSON object in the config
			// rather than being escaped into a quoted string.
			xs["extra"] = json.RawMessage(o.Extra)
		}
		ss["xhttpSettings"] = xs
	case "tcp":
		// Raw TCP needs no stream settings at all, EXCEPT when the link requests
		// HTTP obfuscation (headerType=http): then xray wraps the stream in a
		// fake HTTP request whose Host/path we copy from the link so the
		// obfuscation header matches what the server expects.
		if o.HeaderType == "http" {
			ss["tcpSettings"] = map[string]any{
				"header": map[string]any{
					"type": "http",
					"request": map[string]any{
						"headers": map[string]any{"Host": []any{o.Host}},
						"path":    []any{o.Path},
					},
				},
			}
		}
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	return ss, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
