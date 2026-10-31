//go:build windows

package main

import (
	"strings"
	"testing"

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
