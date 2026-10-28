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
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var androidDetection = struct {
	once sync.Once
	val  bool
}{}

// isAndroidRuntime separates the Android module from the Linux desktop port:
// both build with GOOS=linux, so the distinction must be made at runtime.
func isAndroidRuntime() bool {
	androidDetection.once.Do(func() {
		if _, err := os.Stat("/system/build.prop"); err == nil {
			androidDetection.val = true
			return
		}
		if _, err := os.Stat("/system/bin/app_process"); err == nil {
			androidDetection.val = true
		}
	})
	return androidDetection.val
}

func defaultBaseDir() string {
	if isAndroidRuntime() {
		return "/data/adb/teleweb"
	}
	return "/var/lib/teleweb"
}

func serverListening() bool {
	// Inspect the kernel socket table instead of opening a probe connection:
	// a probe would be accepted as a fake MTProto client and pollute the log.
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

func setDaemonProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func isPidAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func killProcess(pid int) error {
	if pid <= 1 {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}

// killProcessForce is the last-resort SIGKILL used by stopPID after the grace
// period, so a stuck daemon cannot squat the listen port forever.
func killProcessForce(pid int) error {
	if pid <= 1 {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

func originalDestination(c net.Conn) (netip.AddrPort, error) {
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
