// Package link parses vless:// and vmess:// share links into a normalized
// outbound description that the xray config generator can consume.
package link

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Outbound is the normalized, protocol-agnostic description of a proxy server
// extracted from a share link. The candidate CDN IP is NOT stored here; it is
// injected at config-generation time while Address/SNI/Host are preserved so the
// CDN edge routes the connection to the correct backend.
type Outbound struct {
	Protocol string // "vless" | "vmess" | "trojan"
	Address  string // original server hostname (kept as SNI/Host)
	Port     int
	ID       string // user UUID (vless/vmess)
	Password string // credential (trojan)

	// stream
	Network    string // "tcp" | "ws" | "grpc" | "h2"/"http" | "xhttp"
	Security   string // "none" | "tls" | "reality"
	SNI        string
	Host       string // ws/h2 Host header (defaults to Address)
	Path       string // ws/h2/xhttp path
	Service    string // grpc serviceName
	Mode       string // grpc mode (gun|multi) or xhttp mode (auto|packet-up|stream-up|stream-one)
	Extra      string // xhttp extra settings (raw JSON object)
	HeaderType string // tcp obfuscation header type (e.g. "http")
	ALPN       []string

	// TLS capabilities
	FP            string // uTLS fingerprint
	ECH           string // echConfigList (ECH; e.g. "domain+udp://1.1.1.1")
	AllowInsecure bool   // skip certificate verification

	// vless specifics
	Flow string

	// reality
	PublicKey string
	ShortID   string
	SpiderX   string

	// vmess specifics
	AlterID int
	Cipher  string // vmess security ("auto","aes-128-gcm","none",...)

	Remark string
}

// Parse dispatches on the share-link scheme.
func Parse(raw string) (*Outbound, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESS(raw)
	case strings.HasPrefix(raw, "vmess://"):
		return parseVMess(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojan(raw)
	default:
		return nil, fmt.Errorf("unsupported link scheme (want vless://, vmess:// or trojan://)")
	}
}

// Substitute rewrites a share link so it dials the given clean CDN IP directly,
// while leaving the SNI / Host / path / UUID untouched so the CDN edge still
// routes to the original backend. If port <= 0 the link's original port is kept.
// The result is a ready-to-use link with the candidate IP in the address slot:
//
//	vless://UUID@<ip>:<port>?...   (or vmess:// with "add" replaced)
func Substitute(raw, ip string, port int) (string, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return substituteURLHost(raw, ip, port, "vless")
	case strings.HasPrefix(raw, "trojan://"):
		return substituteURLHost(raw, ip, port, "trojan")
	case strings.HasPrefix(raw, "vmess://"):
		return substituteVMess(raw, ip, port)
	default:
		return "", fmt.Errorf("unsupported link scheme (want vless://, vmess:// or trojan://)")
	}
}

// substituteURLHost rewrites the host of a URL-style share link (vless/trojan),
// preserving the user credential, query, and fragment.
func substituteURLHost(raw, ip string, port int, scheme string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", scheme, err)
	}
	p := u.Port()
	if port > 0 {
		p = strconv.Itoa(port)
	}
	if p == "" {
		return "", fmt.Errorf("%s: missing port", scheme)
	}
	u.Host = net.JoinHostPort(ip, p) // preserves u.User, query, fragment
	return u.String(), nil
}

func substituteVMess(raw, ip string, port int) (string, error) {
	payload := strings.TrimPrefix(raw, "vmess://")
	data, err := decodeBase64(payload)
	if err != nil {
		return "", fmt.Errorf("vmess: base64 decode: %w", err)
	}
	// Decode into a generic map so fields we don't model are preserved on re-encode.
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("vmess: json: %w", err)
	}
	m["add"] = ip
	if port > 0 {
		m["port"] = strconv.Itoa(port)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("vmess: re-encode: %w", err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(out), nil
}

func parseVLESS(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless: missing UUID")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("vless: bad port %q", u.Port())
	}
	q := u.Query()

	o := &Outbound{
		Protocol:      "vless",
		Address:       u.Hostname(),
		Port:          port,
		ID:            u.User.Username(),
		Network:       first(q.Get("type"), "tcp"),
		Security:      first(q.Get("security"), "none"),
		SNI:           q.Get("sni"),
		Host:          q.Get("host"),
		Path:          first(q.Get("path"), "/"),
		Service:       q.Get("serviceName"),
		Mode:          q.Get("mode"),
		Extra:         q.Get("extra"),
		HeaderType:    q.Get("headerType"),
		FP:            q.Get("fp"),
		ECH:           q.Get("ech"),
		AllowInsecure: parseBool(q.Get("allowInsecure")) || parseBool(q.Get("insecure")),
		Flow:          q.Get("flow"),
		PublicKey:     q.Get("pbk"),
		ShortID:       q.Get("sid"),
		SpiderX:       q.Get("spx"),
		Remark:        decodeFragment(u.Fragment),
	}
	if a := q.Get("alpn"); a != "" {
		o.ALPN = splitCSV(a)
	}
	applyDefaults(o)
	return o, validate(o)
}

// parseTrojan parses a trojan:// share link. Trojan uses the same query layout
// as vless, with the password in the user-info slot and TLS on by default.
func parseTrojan(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("trojan: missing password")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("trojan: bad port %q", u.Port())
	}
	q := u.Query()

	o := &Outbound{
		Protocol:      "trojan",
		Address:       u.Hostname(),
		Port:          port,
		Password:      u.User.Username(),
		Network:       first(q.Get("type"), "tcp"),
		Security:      first(q.Get("security"), "tls"), // trojan implies TLS
		SNI:           q.Get("sni"),
		Host:          q.Get("host"),
		Path:          first(q.Get("path"), "/"),
		Service:       q.Get("serviceName"),
		Mode:          q.Get("mode"),
		Extra:         q.Get("extra"),
		HeaderType:    q.Get("headerType"),
		FP:            q.Get("fp"),
		ECH:           q.Get("ech"),
		AllowInsecure: parseBool(q.Get("allowInsecure")) || parseBool(q.Get("insecure")),
		Flow:          q.Get("flow"),
		Remark:        decodeFragment(u.Fragment),
	}
	if a := q.Get("alpn"); a != "" {
		o.ALPN = splitCSV(a)
	}
	applyDefaults(o)
	return o, validate(o)
}

// vmessJSON is the standard v2rayN base64 payload format.
type vmessJSON struct {
	V    any    `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
	ECH  string `json:"ech"`
}

func parseVMess(raw string) (*Outbound, error) {
	payload := strings.TrimPrefix(raw, "vmess://")
	data, err := decodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("vmess: base64 decode: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("vmess: json: %w", err)
	}
	port, err := toInt(v.Port)
	if err != nil {
		return nil, fmt.Errorf("vmess: bad port: %w", err)
	}
	if v.ID == "" {
		return nil, fmt.Errorf("vmess: missing id")
	}
	aid, _ := toInt(v.Aid)

	o := &Outbound{
		Protocol: "vmess",
		Address:  v.Add,
		Port:     port,
		ID:       v.ID,
		Network:  first(v.Net, "tcp"),
		Security: first(v.TLS, "none"),
		SNI:      v.SNI,
		Host:     v.Host,
		Path:     first(v.Path, "/"),
		FP:       v.FP,
		ECH:      v.ECH,
		AlterID:  aid,
		Cipher:   first(v.Scy, "auto"),
		Remark:   v.PS,
	}
	if v.Net == "grpc" {
		o.Service = v.Path
	}
	if v.ALPN != "" {
		o.ALPN = splitCSV(v.ALPN)
	}
	applyDefaults(o)
	return o, validate(o)
}

// applyDefaults fills in derived fields. Critically, when Host/SNI are absent
// they fall back to the server Address so direct-IP dialing still presents the
// correct CDN-routing identity.
func applyDefaults(o *Outbound) {
	if o.Security == "" || o.Security == "0" {
		o.Security = "none"
	}
	if o.Security == "1" {
		o.Security = "tls"
	}
	if o.Host == "" {
		o.Host = o.Address
	}
	if o.SNI == "" {
		o.SNI = o.Host
	}
	if o.Network == "h2" {
		o.Network = "http"
	}
	if o.Network == "splithttp" {
		o.Network = "xhttp" // Xray renamed splithttp -> xhttp
	}
}

func validate(o *Outbound) error {
	if o.Address == "" {
		return fmt.Errorf("%s: missing server address", o.Protocol)
	}
	if o.Port <= 0 || o.Port > 65535 {
		return fmt.Errorf("%s: invalid port %d", o.Protocol, o.Port)
	}
	return nil
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseBool reads the truthy share-link flag conventions ("1", "true", "yes").
func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func decodeFragment(f string) string {
	if dec, err := url.QueryUnescape(f); err == nil {
		return dec
	}
	return f
}

func toInt(v any) (int, error) {
	switch t := v.(type) {
	case float64:
		return int(t), nil
	case string:
		if t == "" {
			return 0, nil
		}
		return strconv.Atoi(t)
	case int:
		return t, nil
	case nil:
		return 0, nil
	default:
		return 0, fmt.Errorf("unexpected number type %T", v)
	}
}

// decodeBase64 tolerates standard/url encodings, with and without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encs := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, e := range encs {
		if d, err := e.DecodeString(s); err == nil {
			return d, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}
