package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// selfDialPorts tracks local ports of connections opened by the daemon itself
// towards Telegram. On Windows the WinDivert redirector must not re-capture
// those flows, otherwise every WSS dial would loop back into our own listener.
//
// Entries are kept for a grace period after the socket closes: a blocked
// destination makes the kernel retransmit the SYN for tens of seconds, and a
// retransmit landing after unregistration would be intercepted as client
// traffic, creating a self-connecting cascade.
var (
	selfDialMu    sync.RWMutex
	selfDialPorts = map[uint16]time.Time{}
)

const selfDialGrace = 4 * time.Minute

func selfDialRegister(port uint16) {
	selfDialMu.Lock()
	selfDialPorts[port] = time.Now().Add(selfDialGrace)
	selfDialMu.Unlock()
}

func selfDialExpire(port uint16) {
	selfDialMu.Lock()
	selfDialPorts[port] = time.Now().Add(selfDialGrace)
	selfDialMu.Unlock()
}

func isSelfDialPort(port uint16) bool {
	selfDialMu.RLock()
	exp, ok := selfDialPorts[port]
	selfDialMu.RUnlock()
	return ok && time.Now().Before(exp)
}

func selfDialJanitor() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for now := range t.C {
		selfDialMu.Lock()
		for p, exp := range selfDialPorts {
			if now.After(exp) {
				delete(selfDialPorts, p)
			}
		}
		selfDialMu.Unlock()
	}
}

type selfPortConn struct {
	net.Conn
	port uint16
}

func (s *selfPortConn) Close() error {
	selfDialExpire(s.port)
	return s.Conn.Close()
}

func trackSelfDial(c net.Conn) net.Conn {
	if c == nil {
		return c
	}
	if ta, ok := c.LocalAddr().(*net.TCPAddr); ok && ta.Port > 0 {
		port := uint16(ta.Port)
		selfDialRegister(port)
		return &selfPortConn{Conn: c, port: port}
	}
	return c
}

// isTelegramTarget reports whether addr names a Telegram endpoint that the
// platform redirector will intercept; such dials must reserve their local port
// first so the redirector never captures the daemon's own connection.
func isTelegramTarget(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return isTelegramEndpoint(ip)
}

func isLocalAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "only one usage of each socket address") ||
		strings.Contains(s, "10048")
}

// trackedDial reserves and registers the local port before the SYN leaves, so
// the Windows redirector never mistakes our own outbound connection for
// client traffic even in the first packet. The timeout budgets the WHOLE
// call: an unreachable destination fails immediately without retrying or
// cascading into WinDivert loopback.
func trackedDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	overall, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// External destinations (Cloudflare, Workers, DoH) are never intercepted by
	// WinDivert because its filter only captures telegramSubnets. Dialing them
	// through standard ephemeral ports skips the Listen/Close/selfDial overhead.
	if !isTelegramTarget(addr) {
		d := net.Dialer{KeepAlive: 30 * time.Second}
		return d.DialContext(overall, network, addr)
	}

	for attempt := 0; attempt < 3; attempt++ {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		port := uint16(l.Addr().(*net.TCPAddr).Port)
		_ = l.Close()

		selfDialRegister(port)
		d := net.Dialer{
			LocalAddr: &net.TCPAddr{Port: int(port)},
			Control: func(network, address string, c syscall.RawConn) error {
				return setDialSockOpts(c)
			},
		}
		c, err := d.DialContext(overall, network, addr)
		if err == nil {
			return &selfPortConn{Conn: c, port: port}, nil
		}
		selfDialExpire(port)
		if overall.Err() != nil {
			return nil, err
		}
		if !isLocalAddrInUse(err) {
			// Remote endpoint is unreachable/refused/reset; do not retry.
			return nil, err
		}
	}
	return nil, fmt.Errorf("trackedDial: local port conflict across attempts for %s", addr)
}

// runDesktop is the long-lived foreground supervisor used by systemd on Linux
// and by the Windows service (svc-run). The daemon child owns the platform
// redirector on Windows; on Linux this process installs iptables rules.
func runDesktop() error {
	ensureDir()
	if err := writeEnabled(true); err != nil {
		return err
	}
	if err := ensureServer(); err != nil {
		return fmt.Errorf("start tgws: %w", err)
	}
	if !waitForListener(6 * time.Second) {
		return fmt.Errorf("tgws failed to listen on port %d", defaultPort)
	}
	if err := setupRules(); err != nil {
		stopServer()
		return err
	}
	if err := ensureWatchdog(); err != nil {
		logf("watchdog: failed to start: %v", err)
	}
	logf("desktop runtime active (platform=%s, dir=%s)", runtime.GOOS, baseDir)
	updateModuleDescription(currentStatusDesc())
	return nil
}

// cmdRun blocks until a termination signal, then tears everything down.
// It installs its own signal handler instead of startSignalLogger: that
// helper exits on the first signal, which would race this graceful teardown
// and leave the REDIRECT rules pointing at a dead port.
func cmdRun() {
	ensureDir()
	// Register before startup so a signal arriving mid-boot is queued and
	// still triggers the teardown below.
	ch := make(chan os.Signal, 1)
	notifySignals(ch)
	fmt.Println("TeleWEB desktop runtime starting; Ctrl+C to stop")
	if err := runDesktop(); err != nil {
		logf("run: %v", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig := <-ch
	logf("run: signal %v received, stopping", sig)
	stopWatchdog()
	stopServer()
	fmt.Println("TeleWEB stopped")
}

func openInBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		logf("gui: cannot open browser: %v", err)
		fmt.Printf("TeleWEB GUI: open %s manually\n", url)
		return
	}
	_ = cmd.Process.Release()
}
