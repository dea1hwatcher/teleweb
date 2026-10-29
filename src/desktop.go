package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// selfDialPorts tracks local ports of connections opened by the daemon itself
// towards Telegram. On Windows the WinDivert redirector must not re-capture
// those flows, otherwise every WSS dial would loop back into our own listener.
var selfDialPorts sync.Map // uint16 -> struct{}

type selfPortConn struct {
	net.Conn
	port uint16
}

func (s *selfPortConn) Close() error {
	selfDialPorts.Delete(s.port)
	return s.Conn.Close()
}

func trackSelfDial(c net.Conn) net.Conn {
	if c == nil {
		return c
	}
	if ta, ok := c.LocalAddr().(*net.TCPAddr); ok && ta.Port > 0 {
		port := uint16(ta.Port)
		selfDialPorts.Store(port, struct{}{})
		return &selfPortConn{Conn: c, port: port}
	}
	return c
}

func isSelfDialPort(port uint16) bool {
	_, ok := selfDialPorts.Load(port)
	return ok
}

// trackedDial reserves and registers the local port before the SYN leaves, so
// the Windows redirector never mistakes our own outbound connection for
// client traffic even in the first packet.
func trackedDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	for attempt := 0; attempt < 3; attempt++ {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			break
		}
		port := uint16(l.Addr().(*net.TCPAddr).Port)
		_ = l.Close()
		selfDialPorts.Store(port, struct{}{})
		d.LocalAddr = &net.TCPAddr{Port: int(port)}
		c, err := d.DialContext(ctx, network, addr)
		if err == nil {
			return &selfPortConn{Conn: c, port: port}, nil
		}
		selfDialPorts.Delete(port)
		if ctx.Err() != nil {
			return nil, err
		}
	}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return trackSelfDial(c), nil
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
func cmdRun() {
	ensureDir()
	startSignalLogger()
	fmt.Println("TeleWEB desktop runtime starting; Ctrl+C to stop")
	if err := runDesktop(); err != nil {
		logf("run: %v", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ch := make(chan os.Signal, 1)
	notifySignals(ch)
	sig := <-ch
	logf("run: signal %v received, stopping", sig)
	stopWatchdog()
	stopServer()
	fmt.Println("TeleWEB stopped")
}

// cmdGui serves the embedded WebUI on loopback and opens it in the default
// browser. This is what a bare double-click on tgws.exe runs on desktop.
func cmdGui(addr string) {
	if addr == "" {
		addr = "127.0.0.1:17842"
	}
	ensureDir()
	startSignalLogger()
	go func() {
		time.Sleep(300 * time.Millisecond)
		openInBrowser("http://" + addr + "/")
	}()
	cmdWebUI(addr)
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
