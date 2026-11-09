package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSOCKS5HandshakeRejection(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	logger := log.New(io.Discard, "", 0)
	go socksHandle(c2, logger)

	// 1. Client greeting: SOCKS5, 1 method: No Auth (0x00)
	if _, err := c1.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(c1, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("unexpected greeting reply: %v", reply)
	}

	// 2. Request connect to non-Telegram IP on a non-Telegram port (8.8.8.8:53)
	// CMD=1 (CONNECT), RSV=0, ATYP=1 (IPv4), IP=8.8.8.8, Port=53 (0x0035)
	req := []byte{5, 1, 0, 1, 8, 8, 8, 8, 0, 53}
	if _, err := c1.Write(req); err != nil {
		t.Fatalf("write connect req: %v", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(c1, resp); err != nil {
		t.Fatalf("read connect resp: %v", err)
	}
	// Expect REP=2 (Connection not allowed)
	if resp[1] != 2 {
		t.Fatalf("expected REP=2 (Connection not allowed) for non-Telegram port, got %d", resp[1])
	}
}

func TestSOCKS5RejectionOnStandardPort(t *testing.T) {
	// A non-Telegram destination must be rejected even on Telegram-standard
	// ports (443): the speculative port-based allowance let forged DC203
	// inits reach handleCDN203 and turned the daemon into an open proxy.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	logger := log.New(io.Discard, "", 0)
	go socksHandle(c2, logger)

	if _, err := c1.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c1, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("unexpected greeting reply: %v", reply)
	}

	// CMD=1 (CONNECT), ATYP=1 (IPv4), IP=8.8.8.8, Port=443 (0x01BB)
	req := []byte{5, 1, 0, 1, 8, 8, 8, 8, 0x01, 0xBB}
	if _, err := c1.Write(req); err != nil {
		t.Fatalf("write connect req: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c1, resp); err != nil {
		t.Fatalf("read connect resp: %v", err)
	}
	if resp[1] != 2 {
		t.Fatalf("expected REP=2 (Connection not allowed) for non-Telegram IP:443, got %d", resp[1])
	}
}

func TestSOCKS5NonTelegramDomainRejection(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	logger := log.New(io.Discard, "", 0)
	go socksHandle(c2, logger)

	if _, err := c1.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c1, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("unexpected greeting reply: %v", reply)
	}

	// ATYP=3 (domain), domain="example.com", port=443
	domain := "example.com"
	req := append([]byte{5, 1, 0, 3, byte(len(domain))}, []byte(domain)...)
	req = append(req, 0x01, 0xBB)
	if _, err := c1.Write(req); err != nil {
		t.Fatalf("write connect req: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c1, resp); err != nil {
		t.Fatalf("read connect resp: %v", err)
	}
	if resp[1] != 2 {
		t.Fatalf("expected REP=2 (Connection not allowed) for non-Telegram domain %q, got %d", domain, resp[1])
	}
}

func TestSOCKS5TelegramDomainResolvingToNonTelegramIPRejection(t *testing.T) {
	// A domain matching isTelegramDomain() that resolves to a non-Telegram IP
	// must be rejected (REP=2), preventing open-proxy tunneling via DNS spoofing.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		resp := dohResponse{
			Status: 0,
			Answer: []dohAnswer{
				{Name: "spoofed.telegram.org", Type: 1, TTL: 120, Data: "8.8.8.8"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	origEndpoints := getDoHEndpoints()
	setDoHEndpoints([]string{server.URL})
	defer func() { setDoHEndpoints(origEndpoints) }()

	tmpDir := t.TempDir()
	origBase := getBaseDir()
	setBaseDir(tmpDir)
	defer func() { setBaseDir(origBase) }()

	if err := writeDoHEnabled(true); err != nil {
		t.Fatalf("failed to enable DoH: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	logger := log.New(io.Discard, "", 0)
	go socksHandle(c2, logger)

	if _, err := c1.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c1, reply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("unexpected greeting reply: %v", reply)
	}

	domain := "spoofed.telegram.org"
	req := append([]byte{5, 1, 0, 3, byte(len(domain))}, []byte(domain)...)
	req = append(req, 0x01, 0xBB)
	if _, err := c1.Write(req); err != nil {
		t.Fatalf("write connect req: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c1, resp); err != nil {
		t.Fatalf("read connect resp: %v", err)
	}
	if resp[1] != 2 {
		t.Fatalf("expected REP=2 (Connection not allowed) for spoofed domain resolving to non-Telegram IP, got %d", resp[1])
	}
}
