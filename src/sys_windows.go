//go:build windows

package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// stillActive is STILL_ACTIVE from the Windows process status codes.
const stillActive = 259

func setDaemonProcAttr(cmd *exec.Cmd) {
	// setsid is not supported on Windows
}

// isPidAlive opens the process and reads its exit code: os.FindProcess
// succeeds for any pid on Windows, so it cannot answer liveness and would
// make stopPID wait out its full grace period and log a false SIGKILL
// survivor for an already-dead daemon.
func isPidAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	if pid == os.Getpid() {
		return true
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
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
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func originalDestination(c net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST is only supported on Linux")
}
