//go:build !linux && !windows

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
