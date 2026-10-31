//go:build !linux && !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func defaultBaseDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "teleweb")
	}
	return "teleweb-data"
}

func isAndroidRuntime() bool { return false }

func setDaemonProcAttr(cmd *exec.Cmd) {
	// setsid is not supported on non-linux OS
}

func isPidAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	p, err := os.FindProcess(pid)
	return err == nil && p != nil
}

func killProcess(pid int) error {
	if pid <= 1 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

// killProcessForce mirrors killProcess on non-Linux platforms where p.Kill()
// is already unconditional.
func killProcessForce(pid int) error {
	return killProcess(pid)
}

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func originalDestination(c net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST is only supported on Linux")
}

func serverListening() bool {
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", defaultPort), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func setDialSockOpts(c syscall.RawConn) error { return nil }
