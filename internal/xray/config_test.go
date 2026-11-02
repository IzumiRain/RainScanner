package xray

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"cdnscan/internal/link"
)

func TestVMessTCPHTTPObfuscationConfig(t *testing.T) {
	for _, headerType := range []string{"http", "none"} {
		t.Run(headerType, func(t *testing.T) {
			payload := `{"add":"origin.example","port":"80","id":"uuid","net":"tcp","type":"` + headerType + `","host":"route.example","path":"/proxy"}`
			o, err := link.Parse("vmess://" + base64.StdEncoding.EncodeToString([]byte(payload)))
			if err != nil {
				t.Fatal(err)
			}
			data, err := GenerateConfig(o, "192.0.2.10", 8080, 18080)
			if err != nil {
				t.Fatal(err)
			}
			var cfg struct {
				Outbounds []struct {
					Stream struct {
						TCP *struct {
							Header struct {
								Type    string
								Request struct {
									Headers struct{ Host []string }
									Path    []string
								}
							}
						} `json:"tcpSettings"`
					} `json:"streamSettings"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			tcp := cfg.Outbounds[0].Stream.TCP
			if headerType == "none" {
				if tcp != nil {
					t.Fatal("plain TCP gained obfuscation")
				}
				return
			}
			if tcp == nil || tcp.Header.Type != "http" || len(tcp.Header.Request.Headers.Host) != 1 || tcp.Header.Request.Headers.Host[0] != "route.example" || len(tcp.Header.Request.Path) != 1 || tcp.Header.Request.Path[0] != "/proxy" {
				t.Fatalf("missing HTTP obfuscation: %s", data)
			}
		})
	}
}

func TestBatchConfigAuthentication(t *testing.T) {
	o := &link.Outbound{Protocol: "vless", ID: "uuid", Network: "ws", Host: "route.example", SNI: "cert.example", Security: "tls", Path: "/proxy"}
	targets := []BatchTarget{{IP: "192.0.2.1", Port: 443, InboundPort: 18080}, {IP: "2001:db8::1", Port: 8443, InboundPort: 18081}}
	for _, authenticated := range []bool{false, true} {
		var data []byte
		var err error
		if authenticated {
			data, err = generateBatchConfig(o, targets, "batch-user", "batch-password")
		} else {
			data, err = GenerateBatchConfig(o, targets)
		}
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Inbounds []struct {
				Port     int
				Tag      string
				Settings struct{ Accounts []struct{ User, Pass string } }
			}
			Routing struct {
				Rules []struct {
					InboundTag  []string
					OutboundTag string
				}
			}
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		if len(cfg.Inbounds) != len(targets) || len(cfg.Routing.Rules) != len(targets) {
			t.Fatalf("batch routes missing: %s", data)
		}
		for i, inbound := range cfg.Inbounds {
			if inbound.Port != targets[i].InboundPort || inbound.Tag != "in-"+itoa(i) || cfg.Routing.Rules[i].OutboundTag != "out-"+itoa(i) || len(cfg.Routing.Rules[i].InboundTag) != 1 || cfg.Routing.Rules[i].InboundTag[0] != inbound.Tag {
				t.Fatalf("incorrect route: %s", data)
			}
			if authenticated {
				if len(inbound.Settings.Accounts) != 1 || inbound.Settings.Accounts[0].User != "batch-user" || inbound.Settings.Accounts[0].Pass != "batch-password" {
					t.Fatalf("credentials missing: %s", data)
				}
			} else if len(inbound.Settings.Accounts) != 0 {
				t.Fatal("public GenerateBatchConfig changed authentication behavior")
			}
		}
	}
}
