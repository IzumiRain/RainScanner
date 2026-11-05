package link

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

func vmessLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func TestSubstitutePreservesOutbound(t *testing.T) {
	cases := map[string]string{
		"vless implicit":   "vless://uuid@origin.example:443?security=tls&type=ws&path=%2Fproxy#original",
		"trojan implicit":  "trojan://secret%3A%40%2F@origin.example:443?type=ws&path=%2Fproxy#original",
		"host-derived sni": "vless://uuid@origin.example:443?security=tls&type=ws&host=route.example",
		"explicit sni":     "vless://uuid@origin.example:443?security=tls&type=ws&sni=cert.example",
		"explicit ipv6":    "vless://uuid@[2001:db8::1]:443?security=reality&type=grpc&host=route.example&sni=cert.example&serviceName=svc&mode=multi&pbk=key&sid=abcd&spx=%2Ftest&fp=chrome",
		"xhttp":            "vless://uuid@origin.example:443?security=tls&type=xhttp&path=%2Fproxy&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&alpn=h2&ech=example%2Budp%3A%2F%2F1.1.1.1&insecure=1",
		"trojan explicit":  "trojan://secret@origin.example:443?type=ws&host=route.example&sni=cert.example&path=%2Fproxy#original",
	}
	for _, explicit := range []bool{false, true} {
		fields := map[string]any{
			"v": "2", "add": "origin.example", "port": "443", "id": "uuid", "aid": "2",
			"net": "tcp", "type": "http", "tls": "tls", "path": "/proxy", "ps": "original", "scy": "aes-128-gcm",
		}
		name := "vmess implicit"
		if explicit {
			fields["host"], fields["sni"] = "route.example", "cert.example"
			name = "vmess explicit"
		}
		cases[name] = vmessLink(t, fields)
	}
	for name, raw := range cases {
		for _, port := range []int{0, 8443} {
			t.Run(name+"/"+strconv.Itoa(port), func(t *testing.T) {
				before, err := Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				rewritten, err := Substitute(raw, "2001:db8::10", port)
				if err != nil {
					t.Fatal(err)
				}
				after, err := Parse(rewritten)
				if err != nil {
					t.Fatal(err)
				}
				wantPort := before.Port
				if port > 0 {
					wantPort = port
				}
				if after.Address != "2001:db8::10" || after.Port != wantPort {
					t.Fatalf("endpoint = %s:%d", after.Address, after.Port)
				}
				after.Address, after.Port = before.Address, before.Port
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("outbound changed beyond endpoint:\ngot  %+v\nwant %+v", after, before)
				}
			})
		}
	}
}

func TestSubstitutePreservesUnmodeledFields(t *testing.T) {
	raw := "trojan://secret%3A%40%2F@origin.example:443?type=ws&unknown=a&unknown=b#remark"
	rewritten, err := Substitute(raw, "192.0.2.10", 0)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if u.User.Username() != "secret:@/" || u.Fragment != "remark" || !reflect.DeepEqual(u.Query()["unknown"], []string{"a", "b"}) {
		t.Fatalf("lost URL fields: %s", rewritten)
	}
	raw = vmessLink(t, map[string]any{"add": "origin.example", "port": 443, "id": "uuid", "custom": map[string]any{"enabled": true}})
	rewritten, err = Substitute(raw, "192.0.2.10", 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := decodeBase64(rewritten[len("vmess://"):])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields["custom"], map[string]any{"enabled": true}) || fields["port"] != float64(443) {
		t.Fatalf("lost VMess fields: %s", data)
	}
}

func TestVMessTCPHeaderType(t *testing.T) {
	for _, network := range []string{"tcp", "", "ws"} {
		o, err := Parse(vmessLink(t, map[string]any{"add": "origin.example", "port": "80", "id": "uuid", "net": network, "type": "http"}))
		if err != nil {
			t.Fatal(err)
		}
		want := "http"
		if network == "ws" {
			want = ""
		}
		if o.HeaderType != want {
			t.Errorf("net=%q HeaderType=%q, want %q", network, o.HeaderType, want)
		}
	}
}
