//go:build windows && nativegui

package main

// Win32 integration for the native desktop window: the single instance mutex,
// the system tray icon and its menu, the DWM dark title bar, the window
// show/hide helpers and the elevation restart. It lives apart from
// sys_windows.go, which holds what the daemon needs, and is compiled only for
// the GUI variant so a service build carries none of it.

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	dwmapi              = windows.NewLazySystemDLL("dwmapi.dll")
	procCreateMutex     = kernel32.NewProc("CreateMutexW")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
	procGetModuleHandle = kernel32.NewProc("GetModuleHandleW")

	procFindWindow               = user32.NewProc("FindWindowW")
	procShowWindow               = user32.NewProc("ShowWindow")
	procSetFgWindow              = user32.NewProc("SetForegroundWindow")
	procLoadIcon                 = user32.NewProc("LoadIconW")
	procDefWindowProc            = user32.NewProc("DefWindowProcW")
	procRegisterClassEx          = user32.NewProc("RegisterClassExW")
	procCreateWindowEx           = user32.NewProc("CreateWindowExW")
	procDestroyWindow            = user32.NewProc("DestroyWindow")
	procGetMessage               = user32.NewProc("GetMessageW")
	procTranslateMessage         = user32.NewProc("TranslateMessage")
	procDispatchMessage          = user32.NewProc("DispatchMessageW")
	procPostQuitMessage          = user32.NewProc("PostQuitMessage")
	procPostMessage              = user32.NewProc("PostMessageW")
	procGetCursorPos             = user32.NewProc("GetCursorPos")
	procCreatePopupMenu          = user32.NewProc("CreatePopupMenu")
	procAppendMenu               = user32.NewProc("AppendMenuW")
	procTrackPopupMenuEx         = user32.NewProc("TrackPopupMenuEx")
	procDestroyMenu              = user32.NewProc("DestroyMenu")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procIsWindow                 = user32.NewProc("IsWindow")

	procShellNotifyIcon = shell32.NewProc("Shell_NotifyIconW")
	procShellExecute    = shell32.NewProc("ShellExecuteW")

	procDwmSetAttr = dwmapi.NewProc("DwmSetWindowAttribute")
)

// attachParentConsole attaches standard I/O to the parent console if tgws was
// executed from Command Prompt or PowerShell, so CLI commands print their
// output even when compiled with -H=windowsgui. If launched by double-clicking
// in Explorer, this is a silent no-op and never allocates a console window.

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
	mainHwnd       uintptr
	mainHwndMu     sync.Mutex
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
	mainHwndMu.Lock()
	defer mainHwndMu.Unlock()
	if mainHwnd != 0 {
		r, _, _ := procIsWindow.Call(mainHwnd)
		if r != 0 {
			return mainHwnd
		}
		mainHwnd = 0
	}
	pid := windows.GetCurrentProcessId()
	procEnumWindows.Call(syscall.NewCallback(func(hwnd, lParam uintptr) uintptr {
		var wndPid uint32
		procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&wndPid)))
		trayMu.Lock()
		isTray := (hwnd == trayHwnd)
		trayMu.Unlock()
		if wndPid == pid && !isTray {
			mainHwnd = hwnd
			return 0 // stop enumeration
		}
		return 1 // continue
	}), 0)
	if mainHwnd == 0 {
		title, _ := windows.UTF16PtrFromString("TeleWEB")
		h, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(title)))
		mainHwnd = h
	}
	return mainHwnd
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
	go func(h, c uintptr) {
		procShowWindow.Call(h, c)
		procSetFgWindow.Call(h)
	}(hwnd, cmd)
}

func hideMainWindow() {
	hwnd := findMainWindow()
	if hwnd == 0 {
		return
	}
	const SW_HIDE = 0
	go procShowWindow.Call(hwnd, uintptr(SW_HIDE))
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
	wmUserTray      = 0x0400 + 101
	nimAdd          = 0
	nimModify       = 1
	nimDelete       = 2
	nifMessage      = 0x00000001
	nifIcon         = 0x00000002
	nifTip          = 0x00000004
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	tpmReturnCmd    = 0x0100
	tpmRightButton  = 0x0002
	mfString        = 0x00000000
	mfSeparator     = 0x00000800
	mfGrayed        = 0x00000001
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
		copyUTF16(trayNID.szTip[:], title)
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
	if trayActive == active && trayTipText == tip {
		return
	}
	trayActive = active
	trayTipText = tip
	if trayHwnd != 0 {
		copyUTF16(trayNID.szTip[:], tip)
		procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&trayNID)))
	}
}

// copyUTF16 fills a fixed-size shell string field, always leaving the NUL
// terminator: Shell_NotifyIcon treats these fields as C strings, and a
// truncated tip without a terminator would be read past its end.
func copyUTF16(dst []uint16, s string) {
	if len(dst) == 0 {
		return
	}
	if n := copy(dst, windows.StringToUTF16(s)); n == len(dst) {
		dst[len(dst)-1] = 0
	}
}
