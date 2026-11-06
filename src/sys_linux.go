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

// androidGate memoizes the Android detection for the process lifetime.
type androidGate struct {
	once sync.Once
	val  bool
}

var androidDetection = &androidGate{}

// androidProbe answers whether this Linux build is running inside Android. It
// is a variable so a test can pin the answer instead of having to fake
// /system/build.prop and /system/bin/app_process on the test machine.
var androidProbe = func() bool {
	if _, err := os.Stat("/system/build.prop"); err == nil {
		return true
	}
	if _, err := os.Stat("/system/bin/app_process"); err == nil {
		return true
	}
	return false
}

// isAndroidRuntime separates the Android module from the Linux desktop port:
// both build with GOOS=linux, so the distinction must be made at runtime.
func isAndroidRuntime() bool {
	androidDetection.once.Do(func() { androidDetection.val = androidProbe() })
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

// decodeOriginalDst reads the struct sockaddr that IP(6)T_SO_ORIGINAL_DST
// filled in. The port sits right after the family in both layouts; IPv4 puts
// the address in the next four bytes, while IPv6 has the flow label in between
// and then a sixteen byte address.
func decodeOriginalDst(sa []byte, v6 bool) (netip.AddrPort, bool) {
	if len(sa) < 8 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(sa[2:4])
	if v6 {
		if len(sa) < 24 {
			return netip.AddrPort{}, false
		}
		a, ok := netip.AddrFromSlice(sa[8:24])
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(a.Unmap(), port), true
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{sa[4], sa[5], sa[6], sa[7]}), port), true
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
	// The socket's own family is asked first and the other one after it: some
	// kernels answer a single one of the two options.
	v6First := false
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok && ta.IP != nil && ta.IP.To4() == nil {
		v6First = true
	}
	var addr netip.AddrPort
	var inner error
	e = raw.Control(func(fd uintptr) {
		var sa [128]byte
		for _, wantV6 := range []bool{v6First, !v6First} {
			length := uint32(16)
			if wantV6 {
				length = 28
			}
			var err error
			if wantV6 {
				err = getOriginalDstV6(fd, unsafe.Pointer(&sa[0]), &length)
			} else {
				err = getOriginalDst(fd, unsafe.Pointer(&sa[0]), &length)
			}
			if err != nil {
				inner = err
				continue
			}
			if ap, ok := decodeOriginalDst(sa[:], wantV6); ok {
				addr = ap
				return
			}
		}
	})
	if e != nil {
		return netip.AddrPort{}, e
	}
	if addr.IsValid() {
		return addr, nil
	}
	if inner != nil {
		return netip.AddrPort{}, inner
	}
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST did not return address")
}

func setReuseAddr(raw syscall.RawConn) error {
	var err error
	controlErr := raw.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if controlErr != nil {
		return controlErr
	}
	return err
}

func setDialSockOpts(c syscall.RawConn) error { return setReuseAddr(c) }
