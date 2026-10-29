//go:build windows

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

	"golang.org/x/sys/windows"
)

func defaultBaseDir() string {
	if d := os.Getenv("ProgramData"); d != "" {
		dir := filepath.Join(d, "teleweb")
		// Portable single-file exe run without admin rights cannot write to
		// ProgramData; fall back to the per-user app data directory.
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir
		}
	}
	if d := os.Getenv("LocalAppData"); d != "" {
		return filepath.Join(d, "teleweb")
	}
	return "teleweb-data"
}

func isAndroidRuntime() bool { return false }

func setDaemonProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
}

func isPidAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	if pid == os.Getpid() {
		return true
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
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

func killProcessForce(pid int) error {
	return killProcess(pid)
}

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

// originalDestination is resolved through the NAT table published by the
// WinDivert redirector: clients are rewritten to 127.0.0.1:<natPort>, and the
// original Telegram endpoint is recovered from the accepted socket's port.
func originalDestination(c net.Conn) (netip.AddrPort, error) {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok && ta.Port > 0 {
		if ap, ok := natLookup(uint16(ta.Port)); ok {
			return ap, nil
		}
	}
	return netip.AddrPort{}, errNoOriginalDst
}

func serverListening() bool {
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", defaultPort), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

var errAdminRequired = errors.New("administrator privileges are required for transparent interception on Windows (run from an elevated console)")

func setDialSockOpts(c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		// Set SO_LINGER with zero timeout so aborted/cancelled dials terminate
		// immediately with RST instead of having the Windows TCP stack retransmit
		// SYN packets for tens of seconds in the background.
		l := windows.Linger{Onoff: 1, Linger: 0}
		_ = windows.SetsockoptLinger(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_LINGER, &l)
	})
}
