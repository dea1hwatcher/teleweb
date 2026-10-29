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
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

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
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	user32              = windows.NewLazySystemDLL("user32.dll")
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	dwmapi              = windows.NewLazySystemDLL("dwmapi.dll")

	procAttachConsole   = kernel32.NewProc("AttachConsole")
	procCreateMutex     = kernel32.NewProc("CreateMutexW")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")

	procFindWindow       = user32.NewProc("FindWindowW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetFgWindow      = user32.NewProc("SetForegroundWindow")
	procLoadIcon         = user32.NewProc("LoadIconW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procPostMessage      = user32.NewProc("PostMessageW")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenu       = user32.NewProc("AppendMenuW")
	procTrackPopupMenuEx = user32.NewProc("TrackPopupMenuEx")
	procDestroyMenu      = user32.NewProc("DestroyMenu")

	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")
	procShellExecute    = shell32.NewProc("ShellExecuteW")

	procDwmSetAttr      = dwmapi.NewProc("DwmSetWindowAttribute")
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

// ---------------------- Windows Modern Integration -------------------------

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     uintptr
}

var (
	trayMu         sync.Mutex
	trayNID        notifyIconDataW
	trayHwnd       uintptr
	trayActive     bool
	trayTipText    = "TeleWEB: прозрачный WSS транспорт"
	trayOnToggleFn func()
	trayOnWebUIFn  func()
	trayOnQuitFn   func()
	singleMutexH   uintptr
)

func findMainWindow() uintptr {
	title, _ := windows.UTF16PtrFromString("TeleWEB")
	class, _ := windows.UTF16PtrFromString("GioWindow")
	hwnd, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		hwnd, _, _ = procFindWindow.Call(0, uintptr(unsafe.Pointer(title)))
	}
	return hwnd
}

// applyWindowsDarkTheme sets the DWM non-client attributes for dark mode,
// custom caption color matching Material 3 Expressive Dark (#101418), and rounded
// corners on Windows 11.
func applyWindowsDarkTheme(title string) {
	hwnd := findMainWindow()
	if hwnd == 0 {
		return
	}
	var darkMode uint32 = 1
	// DWMWA_USE_IMMERSIVE_DARK_MODE (20 on Win10 1903+/Win11, 19 on Win10 1809)
	r, _, _ := procDwmSetAttr.Call(hwnd, 20, uintptr(unsafe.Pointer(&darkMode)), unsafe.Sizeof(darkMode))
	if r != 0 {
		procDwmSetAttr.Call(hwnd, 19, uintptr(unsafe.Pointer(&darkMode)), unsafe.Sizeof(darkMode))
	}
	// DWMWA_CAPTION_COLOR (35) = 0x00181410 (#101418 in BGR)
	var captionColor uint32 = 0x00181410
	procDwmSetAttr.Call(hwnd, 35, uintptr(unsafe.Pointer(&captionColor)), unsafe.Sizeof(captionColor))

	// DWMWA_BORDER_COLOR (34) = 0x002F2A26 (#262A2F in BGR)
	var borderColor uint32 = 0x002F2A26
	procDwmSetAttr.Call(hwnd, 34, uintptr(unsafe.Pointer(&borderColor)), unsafe.Sizeof(borderColor))

	// DWMWA_WINDOW_CORNER_PREFERENCE (33) = DWMWCP_ROUND (2)
	var cornerPref uint32 = 2
	procDwmSetAttr.Call(hwnd, 33, uintptr(unsafe.Pointer(&cornerPref)), unsafe.Sizeof(cornerPref))
}

func showMainWindow(restore bool) {
	hwnd := findMainWindow()
	if hwnd == 0 {
		return
	}
	const (
		SW_NORMAL  = 1
		SW_RESTORE = 9
	)
	cmd := uintptr(SW_NORMAL)
	if restore {
		cmd = uintptr(SW_RESTORE)
	}
	procShowWindow.Call(hwnd, cmd)
	procSetFgWindow.Call(hwnd)
}

func hideMainWindow() {
	hwnd := findMainWindow()
	if hwnd == 0 {
		return
	}
	const SW_HIDE = 0
	procShowWindow.Call(hwnd, uintptr(SW_HIDE))
}

func restartElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString("gui")
	const SW_SHOWNORMAL = 1
	r, _, _ := procShellExecute.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(args)), 0, uintptr(SW_SHOWNORMAL))
	if r > 32 {
		os.Exit(0)
	}
	return fmt.Errorf("elevation failed or was cancelled (code %d)", r)
}

func acquireSingleInstance() (func(), bool) {
	name, _ := windows.UTF16PtrFromString("Local\\TeleWEB_SingleInstance_Mutex")
	h, _, err := procCreateMutex.Call(0, 1, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return func() {}, true
	}
	const ERROR_ALREADY_EXISTS = 183
	if err == syscall.Errno(ERROR_ALREADY_EXISTS) {
		showMainWindow(true)
		procCloseHandle.Call(h)
		return nil, false
	}
	singleMutexH = h
	return func() {
		if singleMutexH != 0 {
			procCloseHandle.Call(singleMutexH)
			singleMutexH = 0
		}
	}, true
}

const (
	wmUserTray     = 0x0400 + 101
	nimAdd         = 0
	nimModify      = 1
	nimDelete      = 2
	nifMessage     = 0x00000001
	nifIcon        = 0x00000002
	nifTip         = 0x00000004
	wmLButtonUp    = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp    = 0x0205
	tpmReturnCmd   = 0x0100
	tpmRightButton = 0x0002
	mfString       = 0x00000000
	mfSeparator    = 0x00000800
	mfGrayed       = 0x00000001
)

func setupSystemTray(title string, onToggle func(), onOpenWebUI func(), onQuit func()) func() {
	trayMu.Lock()
	trayOnToggleFn = onToggle
	trayOnWebUIFn = onOpenWebUI
	trayOnQuitFn = onQuit
	trayMu.Unlock()

	ready := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		className, _ := windows.UTF16PtrFromString("TeleWEB_Tray_Window_Class")
		hMod, _, _ := procGetModuleHandle.Call(0)
		hIcon, _, _ := procLoadIcon.Call(hMod, 1)
		if hIcon == 0 {
			hIcon, _, _ = procLoadIcon.Call(0, 32512)
		}

		wndProc := syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
			switch msg {
			case wmUserTray:
				switch lParam {
				case wmLButtonUp, wmLButtonDblClk:
					showMainWindow(true)
					return 0
				case wmRButtonUp:
					var pt struct{ x, y int32 }
					procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
					procSetFgWindow.Call(hwnd)
					hMenu, _, _ := procCreatePopupMenu.Call()
					if hMenu == 0 {
						return 0
					}

					mTitle, _ := windows.UTF16PtrFromString("Показать TeleWEB")
					procAppendMenu.Call(hMenu, mfString, 101, uintptr(unsafe.Pointer(mTitle)))
					procAppendMenu.Call(hMenu, mfSeparator, 0, 0)

					trayMu.Lock()
					curTip := trayTipText
					act := trayActive
					trayMu.Unlock()

					mStatus, _ := windows.UTF16PtrFromString(curTip)
					procAppendMenu.Call(hMenu, mfString|mfGrayed, 102, uintptr(unsafe.Pointer(mStatus)))

					toggleLabel := "Запустить"
					if act {
						toggleLabel = "Остановить"
					}
					mToggle, _ := windows.UTF16PtrFromString(toggleLabel)
					procAppendMenu.Call(hMenu, mfString, 103, uintptr(unsafe.Pointer(mToggle)))

					mWebUI, _ := windows.UTF16PtrFromString("Открыть WebUI в браузере")
					procAppendMenu.Call(hMenu, mfString, 104, uintptr(unsafe.Pointer(mWebUI)))

					procAppendMenu.Call(hMenu, mfSeparator, 0, 0)
					mQuit, _ := windows.UTF16PtrFromString("Выход")
					procAppendMenu.Call(hMenu, mfString, 105, uintptr(unsafe.Pointer(mQuit)))

					cmd, _, _ := procTrackPopupMenuEx.Call(hMenu, tpmReturnCmd|tpmRightButton, uintptr(pt.x), uintptr(pt.y), hwnd, 0)
					procDestroyMenu.Call(hMenu)

					switch cmd {
					case 101:
						showMainWindow(true)
					case 103:
						trayMu.Lock()
						fn := trayOnToggleFn
						trayMu.Unlock()
						if fn != nil {
							go fn()
						}
					case 104:
						trayMu.Lock()
						fn := trayOnWebUIFn
						trayMu.Unlock()
						if fn != nil {
							go fn()
						}
					case 105:
						trayMu.Lock()
						fn := trayOnQuitFn
						trayMu.Unlock()
						if fn != nil {
							fn()
						}
					}
					return 0
				}
			case 0x0010: // WM_CLOSE
				procDestroyWindow.Call(hwnd)
				return 0
			case 0x0002: // WM_DESTROY
				procPostQuitMessage.Call(0)
				return 0
			}
			r, _, _ := procDefWindowProc.Call(hwnd, msg, wParam, lParam)
			return r
		})

		wc := wndClassExW{
			cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			lpfnWndProc:   wndProc,
			hInstance:     hMod,
			lpszClassName: className,
		}
		procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))

		const hwndMessage = ^uintptr(2)
		hwnd, _, _ := procCreateWindowEx.Call(
			0,
			uintptr(unsafe.Pointer(className)),
			uintptr(unsafe.Pointer(className)),
			0, 0, 0, 0, 0,
			hwndMessage,
			0,
			hMod,
			0,
		)

		trayMu.Lock()
		trayHwnd = hwnd
		trayNID.cbSize = uint32(unsafe.Sizeof(trayNID))
		trayNID.hWnd = hwnd
		trayNID.uID = 1
		trayNID.uFlags = nifMessage | nifIcon | nifTip
		trayNID.uCallbackMessage = wmUserTray
		trayNID.hIcon = hIcon
		copy(trayNID.szTip[:], windows.StringToUTF16(title))
		procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&trayNID)))
		trayMu.Unlock()

		close(ready)

		var msg struct {
			hwnd    uintptr
			message uint32
			wParam  uintptr
			lParam  uintptr
			time    uint32
			pt      struct{ x, y int32 }
		}
		for {
			res, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(res) <= 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}()

	<-ready
	return func() {
		trayMu.Lock()
		if trayHwnd != 0 {
			procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&trayNID)))
			procPostMessage.Call(trayHwnd, 0x0010, 0, 0)
			trayHwnd = 0
		}
		trayMu.Unlock()
	}
}

func updateSystemTray(active bool, tip string) {
	trayMu.Lock()
	defer trayMu.Unlock()
	trayActive = active
	trayTipText = tip
	if trayHwnd != 0 {
		var sz [128]uint16
		copy(sz[:], windows.StringToUTF16(tip))
		trayNID.szTip = sz
		procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&trayNID)))
	}
}

