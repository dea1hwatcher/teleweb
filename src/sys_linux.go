//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"
)

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
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.SOL_IP), uintptr(80), uintptr(unsafe.Pointer(&sa[0])), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			inner = errno
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
