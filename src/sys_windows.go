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

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole = kernel32.NewProc("AttachConsole")
)

// attachParentConsole attaches standard I/O to the parent console if tgws was
// executed from Command Prompt or PowerShell, so CLI commands print their
// output even when compiled with -H=windowsgui. If launched by double-clicking
// in Explorer, this is a silent no-op and never allocates a console window.
func attachParentConsole() {
	if len(os.Args) > 1 {
		// If stdout/stderr was already redirected to a pipe or file by the caller,
		// preserve that stream so CLI piping and automation work seamlessly.
		h, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		ft, _ := windows.GetFileType(h)
		if ft == windows.FILE_TYPE_PIPE || ft == windows.FILE_TYPE_DISK {
			return
		}
		const attachParentProcess = ^uintptr(0) // DWORD -1
		r, _, _ := procAttachConsole.Call(attachParentProcess)
		if r != 0 {
			if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
				os.Stdout = f
				os.Stderr = f
			}
		}
	}
}

func setCmdNoWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}

func setDaemonProcAttr(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
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
