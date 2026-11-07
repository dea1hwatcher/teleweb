//go:build windows && nativegui

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gioui.org/app"
	"gioui.org/op"
	"golang.org/x/sys/windows"
)

func TestCopyUTF16AlwaysTerminates(t *testing.T) {
	var dst [8]uint16
	copyUTF16(dst[:], "TeleWEB")
	if dst[7] != 0 {
		t.Fatalf("short string not NUL-terminated: %v", dst)
	}
	if got := windows.UTF16ToString(dst[:]); got != "TeleWEB" {
		t.Fatalf("decoded %q, want TeleWEB", got)
	}

	var long [8]uint16
	copyUTF16(long[:], "TeleWEB: a very long status tip that overflows the field")
	if long[len(long)-1] != 0 {
		t.Fatalf("truncated string lost its NUL terminator: %v", long)
	}
	decoded := windows.UTF16ToString(long[:])
	if decoded == "" || !strings.HasPrefix("TeleWEB: a very long status tip that overflows the field", decoded) {
		t.Fatalf("decoded prefix %q", decoded)
	}

	var empty [4]uint16
	copyUTF16(empty[:], "")
	if empty[0] != 0 {
		t.Fatalf("empty string must be an empty C string: %v", empty)
	}
	copyUTF16(nil, "ignored")
}

func TestCreateIconFromPNG(t *testing.T) {
	for _, sz := range []int{16, 32, 48, 64} {
		hIcon := loadAppIcon(sz)
		if hIcon == 0 {
			t.Fatalf("loadAppIcon failed for size %d", sz)
		}
	}
}

func TestGetAppIconCached(t *testing.T) {
	icon16a := getAppIcon(16)
	icon16b := getAppIcon(16)
	if icon16a == 0 || icon16a != icon16b {
		t.Fatalf("expected cached 16px icon, got %v and %v", icon16a, icon16b)
	}
	icon32a := getAppIcon(32)
	icon32b := getAppIcon(32)
	if icon32a == 0 || icon32a != icon32b {
		t.Fatalf("expected cached 32px icon, got %v and %v", icon32a, icon32b)
	}
}

func TestSetMainHwnd(t *testing.T) {
	mainHwndMu.Lock()
	orig := mainHwnd
	mainHwndMu.Unlock()
	defer func() {
		mainHwndMu.Lock()
		mainHwnd = orig
		mainHwndMu.Unlock()
	}()

	dummy := uintptr(0xDEADBEEF)
	setMainHwnd(dummy)
	mainHwndMu.Lock()
	got := mainHwnd
	mainHwndMu.Unlock()
	if got != dummy {
		t.Fatalf("setMainHwnd got %v, want %v", got, dummy)
	}

	// setMainWindowIcon on a dummy handle should return immediately without blocking or panicking
	setMainWindowIcon(dummy)
	setMainWindowIcon(0)
}

func TestWindowStartup(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		w := new(app.Window)
		w.Option(app.Title("TeleWEB_Test"), app.Size(100, 100))
		timer := time.After(5 * time.Second)
		for {
			select {
			case <-timer:
				done <- fmt.Errorf("timeout waiting for frame")
				return
			default:
				e := w.Event()
				t.Logf("Received event: %T", e)
				switch e := e.(type) {
				case app.DestroyEvent:
					done <- e.Err
					return
				case app.ViewEvent:
					if we, ok := e.(app.Win32ViewEvent); ok {
						t.Logf("Win32ViewEvent HWND: 0x%x", we.HWND)
					}
				case app.FrameEvent:
					t.Logf("FrameEvent received! Calling applyWindowsDarkTheme...")
					applyWindowsDarkTheme("TeleWEB_Test")
					t.Logf("applyWindowsDarkTheme completed!")
					var ops op.Ops
					e.Frame(&ops)
					done <- nil
					return
				}
			}
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Window startup failed: %v", err)
		}
		t.Log("Frame rendered successfully!")
	case <-time.After(6 * time.Second):
		t.Fatal("TestWindowStartup overall timeout")
	}
}

func TestSetupSystemTray(t *testing.T) {
	cleanup := setupSystemTray("TeleWEB Test", nil, nil)
	defer cleanup()

	trayMu.Lock()
	hwnd := trayHwnd
	trayMu.Unlock()
	if hwnd == 0 {
		t.Fatal("trayHwnd is 0!")
	}

	// Post tray click message; must handle smoothly without stalling
	procPostMessage.Call(hwnd, wmUserTray, 1, wmLButtonUp)
}

func TestApplyWindowsDarkThemeNoHwnd(t *testing.T) {
	// Should gracefully return without panic when no window is present
	applyWindowsDarkTheme("NonExistentWindow")
}
