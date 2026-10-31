//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// androidRuntime is resolved once at startup: Android exposes the platform
// build description and the property area, which no other Linux distribution
// has. Every Android-specific behaviour (package UID discovery, cgroup/LMK
// protection, carrier DNS, the pre-warmed socket pool) is gated on it, so a
// wrong answer silently disables the whole interception stack.
var androidRuntime = detectAndroidRuntime()

func detectAndroidRuntime() bool {
	for _, marker := range []string{"/system/build.prop", "/dev/__properties__"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return os.Getenv("ANDROID_ROOT") != ""
}

func isAndroidRuntime() bool { return androidRuntime }

// defaultBaseDir keeps the Magisk/KernelSU module directory on Android so a
// bare `tgws status` from a root shell reads the same state as service.sh;
// desktop Linux follows the XDG config directory.
func defaultBaseDir() string {
	if isAndroidRuntime() {
		return "/data/adb/teleweb"
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "teleweb")
	}
	return "teleweb-data"
}

func attachParentConsole() {}

func setCmdNoWindow(cmd *exec.Cmd) {}

// setDaemonProcAttr detaches the daemon from the caller's process group so
// Magisk restarting service.sh cannot take the transport down with it.
func setDaemonProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func isPidAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// killProcess asks the daemon to terminate gracefully; killProcessForce is the
// last-resort SIGKILL used by stopPID after the grace period, so a stuck
// daemon cannot squat the listen port forever.
func killProcess(pid int) error {
	if pid <= 1 {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}

func killProcessForce(pid int) error {
	if pid <= 1 {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

// originalDestination recovers the pre-REDIRECT Telegram endpoint from the
// netfilter conntrack entry. Failures are reported through errNoOriginalDst so
// the caller classifies them as neutral instead of counting a client fault.
func originalDestination(c net.Conn) (netip.AddrPort, error) {
	addr, err := originalDestinationV4(c)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w (%v)", errNoOriginalDst, err)
	}
	return addr, nil
}

func originalDestinationV4(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not TCP")
	}
	raw, e := tc.SyscallConn()
	if e != nil {
		return netip.AddrPort{}, e
	}
	var addr netip.AddrPort
	var inner error
	e = raw.Control(func(fd uintptr) {
		var sa [128]byte
		l := uint32(16)
		if err := getOriginalDst(fd, unsafe.Pointer(&sa[0]), &l); err != nil {
			inner = err
			return
		}
		port := binary.BigEndian.Uint16(sa[2:4])
		ip := net.IPv4(sa[4], sa[5], sa[6], sa[7])
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			inner = errors.New("bad original IPv4 address")
			return
		}
		a = a.Unmap()
		addr = netip.AddrPortFrom(a, port)
	})
	if e != nil {
		return netip.AddrPort{}, e
	}
	if inner != nil {
		return netip.AddrPort{}, inner
	}
	if !addr.IsValid() {
		return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST did not return address")
	}
	return addr, nil
}

// serverListening inspects the kernel socket table instead of opening a probe
// connection: a probe would be accepted as a fake MTProto client, inflate the
// failure counter and pollute the log on every watchdog tick.
func serverListening() bool {
	b, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return false
	}
	want := fmt.Sprintf(":%04X", defaultPort)
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.HasSuffix(strings.ToUpper(fields[1]), want) && fields[3] == "0A" {
			return true // TCP_LISTEN
		}
	}
	return false
}

func setDialSockOpts(c syscall.RawConn) error { return nil }

// The desktop window/tray integration is Windows-only; Linux desktop builds use
// the browser WebUI, so these stay inert.
func acquireSingleInstance() (func(), bool) { return func() {}, true }

func applyWindowsDarkTheme(title string) {}

func showMainWindow(restore bool) {}

func hideMainWindow() {}

func restartElevated() error { return nil }

func setupSystemTray(title string, onToggle func(), onOpenWebUI func(), onQuit func()) func() {
	return func() {}
}

func updateSystemTray(active bool, tip string) {}
