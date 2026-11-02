package main

import (
	"bytes"
	"io"
	"log"
	"net"
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
