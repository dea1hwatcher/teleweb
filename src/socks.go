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
	loadRouteCache()
	loadLearnedDCs()
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
			// EMFILE/ENFILE return immediately and would busy-spin; pause
			// briefly. A closed listener stops the loop.
			if pause := acceptPause(err); pause < 0 {
				return
			} else if pause > 0 {
				time.Sleep(pause)
			}
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
		if isTelegramDomain(domainStr) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			var ips []netip.Addr
			var err error
			if doHEnabledCached() {
				dohCtx, dohCancel := context.WithTimeout(ctx, 2*time.Second)
				ips, err = resolveDoHRace(dohCtx, domainStr)
				dohCancel()
			}
			if err != nil || len(ips) == 0 {
				ips, err = systemDNSResolver().LookupNetIP(ctx, "ip", domainStr)
			}
			cancel()
			if err != nil || len(ips) == 0 {
				_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // host unreachable
				return
			}
			for _, resolved := range ips {
				u := resolved.Unmap()
				if isTelegramAggregate(u) {
					ip = u
					break
				}
			}
		} else if parsedIP, err := netip.ParseAddr(domainStr); err == nil {
			ip = parsedIP.Unmap()
		}
		// When domainStr is not a Telegram domain or does not resolve to an
		// allowable Telegram endpoint, ip remains the zero value and is rejected below.
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
	if !isTelegramAggregate(ip) {
		// The SOCKS listener is a Telegram transport, not a general proxy:
		// any other destination is rejected regardless of port. Speculative
		// port-based allowances previously let forged DC203 inits through to
		// handleCDN203, turning the daemon into an open TCP proxy.
		logger.Printf("socks: rejected non-Telegram destination %s:%d", ip, port)
		_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}) // connection not allowed
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	logger.Printf("socks: %s -> %s:%d", c.RemoteAddr(), ip, port)
	serveConn(c, netip.AddrPortFrom(ip, port))
}

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
	if !ip.Is4() {
		return false
	}
	if isCDN203IP(ip) {
		return true
	}
	for _, sub := range telegramParsedSubnets {
		if sub.prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// isTelegramAggregate reports whether ip (either address family) belongs to a
// Telegram network aggregate. It guards learned-DC bookkeeping against
// pollution from forged init packets.
func isTelegramAggregate(ip netip.Addr) bool {
	return isTelegramEndpoint(ip) || isTelegramEndpointV6(ip)
}

func isTelegramEndpointV6(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is6() {
		return false
	}
	for _, prefix := range telegramV6Prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
