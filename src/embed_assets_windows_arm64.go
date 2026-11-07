//go:build windows && arm64

package main

import "io/fs"

// WinDivert ships no ARM64 driver, so transparent mode is unavailable there.
func embeddedDriverFS() fs.FS { return nil }

func embeddedWebrootFS() fs.FS { return nil }
