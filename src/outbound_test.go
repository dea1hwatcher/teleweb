package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShouldBypassOutboundProxy(t *testing.T) {
	tests := []struct {
		target  string
		noProxy string
		bypass  bool
	}{
		{"127.0.0.1:443", "", true},
		{"localhost:8080", "", true},
		{"[::1]:443", "", true},
		{"1.1.1.1:443", "*", true},
		{"192.168.1.50:443", "192.168.0.0/16", true},
		{"10.1.2.3:443", "192.168.0.0/16", false},
		{"api.telegram.org:443", "telegram.org", true},
		{"api.telegram.org:443", ".telegram.org", true},
		{"api.telegram.org:443", "*.telegram.org", true},
		{"api.telegram.org:443", "example.com", false},
		{"kws2.cloudflare.com:443", "google.com,cloudflare.com", true},
		{"kws2.cloudflare.com:443", "google.com,10.0.0.0/8", false},
	}

	for _, tt := range tests {
		got := shouldBypassOutboundProxy(tt.target, tt.noProxy)
		if got != tt.bypass {
			t.Errorf("shouldBypassOutboundProxy(%q, %q) = %v, want %v", tt.target, tt.noProxy, got, tt.bypass)
		}
	}
}

func TestReadOutboundProxyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origDir := getBaseDir()
	setBaseDir(tmpDir)
	defer setBaseDir(origDir)

	// Environment variable fallback
	t.Setenv("ALL_PROXY", "socks5://proxy.example.com:1080")
	t.Setenv("NO_PROXY", "localhost,127.0.0.1")

	pURL, np := readOutboundProxyConfig()
	if pURL != "socks5://proxy.example.com:1080" {
		t.Fatalf("expected proxy URL socks5://proxy.example.com:1080, got %q", pURL)
	}
	if np != "localhost,127.0.0.1" {
		t.Fatalf("expected no_proxy localhost,127.0.0.1, got %q", np)
	}

	// File override takes precedence
	configFile := filepath.Join(tmpDir, "outbound_proxy")
	if err := os.WriteFile(configFile, []byte("http://192.168.1.1:3128\n*.lan,10.0.0.0/8\n"), 0600); err != nil {
		t.Fatal(err)
	}

	pURL, np = readOutboundProxyConfig()
	if pURL != "http://192.168.1.1:3128" {
		t.Fatalf("expected file override http://192.168.1.1:3128, got %q", pURL)
	}
	if np != "*.lan,10.0.0.0/8" {
		t.Fatalf("expected file override no_proxy *.lan,10.0.0.0/8, got %q", np)
	}

	// Direct marker in file disables proxy
	if err := os.WriteFile(configFile, []byte("direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pURL, _ = readOutboundProxyConfig()
	if pURL != "" {
		t.Fatalf("expected direct marker to disable proxy, got %q", pURL)
	}
}

func TestDialViaOutboundProxy_HTTPConnect(t *testing.T) {
	// Start a mock HTTP CONNECT proxy
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	proxyAddr := l.Addr().String()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				if !strings.HasPrefix(req, "CONNECT") {
					return
				}
				// Reply 200 Connection Established
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				// Echo test byte
				var one [1]byte
				if _, err := c.Read(one[:]); err == nil {
					_, _ = c.Write(one[:])
				}
			}(conn)
		}
	}()

	tmpDir := t.TempDir()
	origDir := getBaseDir()
	setBaseDir(tmpDir)
	defer setBaseDir(origDir)

	configFile := filepath.Join(tmpDir, "outbound_proxy")
	if err := os.WriteFile(configFile, []byte("http://"+proxyAddr+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, used, err := dialViaOutboundProxy(ctx, "tcp", "target.telegram.org:443", 2*time.Second)
	if !used {
		t.Fatal("expected proxy to be used")
	}
	if err != nil {
		t.Fatalf("dialViaOutboundProxy failed: %v", err)
	}
	defer conn.Close()

	// Verify data transit
	if _, err := conn.Write([]byte("X")); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := conn.Read(reply[:]); err != nil || reply[0] != 'X' {
		t.Fatalf("expected echo 'X', got %v (err=%v)", reply, err)
	}
}
