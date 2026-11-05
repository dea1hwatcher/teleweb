//go:build windows

package main

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/windows"
)

// lingerOf reads the real SO_LINGER value, a four byte struct linger
// {u_short l_onoff; u_short l_linger}. syscall.Linger and windows.Linger are
// documented as wrong for direct use on Windows, so the bytes are parsed here.
func lingerOf(t *testing.T, raw interface {
	Control(func(fd uintptr)) error
}) (onoff, linger uint16) {
	t.Helper()
	var buf [4]byte
	var length int32 = int32(len(buf))
	var readErr error
	if err := raw.Control(func(fd uintptr) {
		readErr = windows.Getsockopt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_LINGER, &buf[0], &length)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if readErr != nil {
		t.Fatalf("Getsockopt(SO_LINGER): %v", readErr)
	}
	return binary.LittleEndian.Uint16(buf[0:2]), binary.LittleEndian.Uint16(buf[2:4])
}

// TestSetDialSockOptsSetsLinger guards the Windows dial sockets against the SYN
// retransmit storm: with SO_LINGER(0) an aborted dial terminates with RST at
// once, without it the TCP stack keeps retransmitting in the background for
// tens of seconds. The option was already dropped once by an unrelated commit,
// so the value is asserted instead of trusted.
func TestSetDialSockOptsSetsLinger(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("dial returned %T, want *net.TCPConn", conn)
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	// Control: a fresh socket leaves linger disabled, so this proves the
	// assertion below is observing our own syscall and not a Windows default.
	if onoff, _ := lingerOf(t, raw); onoff != 0 {
		t.Fatalf("fresh socket has linger enabled (onoff=%d); test would pass vacuously", onoff)
	}

	if err := setDialSockOpts(raw); err != nil {
		t.Fatalf("setDialSockOpts: %v", err)
	}
	onoff, linger := lingerOf(t, raw)
	if onoff != 1 || linger != 0 {
		t.Fatalf("SO_LINGER = {onoff:%d, linger:%d}, want {1, 0}: aborted dials would retransmit SYNs", onoff, linger)
	}
}
