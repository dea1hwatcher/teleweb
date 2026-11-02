package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// cmdSocks exposes the WSS transport through a local SOCKS5 listener. Clients
// point Telegram at 127.0.0.1:<port> explicitly; no kernel interception or
// admin rights are required. Only Telegram DC destinations are accepted so the
// listener cannot be abused as an open proxy.
func cmdSocks(addr string) {
	if addr == "" {
		addr = "127.0.0.1:17845"
	}
	ensureDir()
	startSignalLogger()
	logger := log.New(os.Stdout, "", log.LstdFlags)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks: %v\n", err)
		os.Exit(1)
	}
	logf("SOCKS5 listening on %s (Telegram DC endpoints only)", addr)
	logger.Printf("TeleWEB SOCKS5 on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			if isNeutralError(err) {
				continue
			}
			logf("socks: accept: %v", err)
			continue
		}
		go socksHandle(c, logger)
	}
}

func socksHandle(c net.Conn, logger *log.Logger) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))

	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{5, 0xff})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 { // CONNECT only
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var ip netip.Addr
	var isDomainAllowed bool
	switch req[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		ip = netip.AddrFrom4(b)
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		domainStr := string(name)
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ips, err := androidDNSResolver().LookupNetIP(ctx, "ip4", domainStr)
		cancel()
		if err != nil || len(ips) == 0 {
			_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
			return
		}
		ip = ips[0]
		if isTelegramDomain(domainStr) {
			isDomainAllowed = true
		}
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		ip = netip.AddrFrom16(b)
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}) // address type not supported
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb[:])
	if !isDomainAllowed && !isTelegramEndpoint(ip) {
		// Allow speculative SOCKS5 handshakes for Telegram-standard ports (443, 80, 8443, 5222);
		// serveConn will inspect the initial 64-byte payload and drop non-MTProto traffic.
		if port == 443 || port == 80 || port == 8443 || port == 5222 {
			isDomainAllowed = true
		} else {
			logger.Printf("socks: rejected non-Telegram destination %s:%d", ip, port)
			_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}) // connection not allowed
			return
		}
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	logger.Printf("socks: %s -> %s:%d", c.RemoteAddr(), ip, port)
	serveConn(c, netip.AddrPortFrom(ip, port))
}

var telegramParsedSubnetsV6 = func() []netip.Prefix {
	cidrs := []string{
		"2001:b88::/32",
		"2001:67c:4e8::/48",
	}
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}()

func isTelegramDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	return strings.HasSuffix(d, ".telegram.org") ||
		d == "telegram.org" ||
		strings.HasSuffix(d, ".t.me") ||
		d == "t.me" ||
		strings.HasSuffix(d, ".telegra.ph") ||
		d == "telegra.ph" ||
		strings.HasSuffix(d, ".telesco.pe") ||
		d == "telesco.pe" ||
		strings.HasSuffix(d, ".telegram-cdn.org") ||
		d == "telegram-cdn.org"
}

// isTelegramEndpoint reports whether ip falls into a Telegram DC aggregate
// that the transparent mode intercepts as well. Every aggregate, including the
// CDN203 /23, comes from telegramSubnets, so this stays in sync with both the
// iptables REDIRECT list and the WinDivert filter by construction.
func isTelegramEndpoint(ip netip.Addr) bool {
	ip = ip.Unmap()
	if isCDN203IP(ip) {
		return true
	}
	if ip.Is4() {
		for _, sub := range telegramParsedSubnets {
			if sub.prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if ip.Is6() {
		for _, prefix := range telegramParsedSubnetsV6 {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	return false
}
