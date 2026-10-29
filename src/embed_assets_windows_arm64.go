//go:build windows && arm64

package main

import (
	"embed"
	"io/fs"
)

//go:embed webui_fallback/*
var embeddedFiles embed.FS

// WinDivert ships no ARM64 driver, so transparent mode is unavailable there;
// the embedded WebUI still makes the SOCKS mode self-contained.
func embeddedDriverFS() fs.FS { return nil }

func embeddedWebrootFS() fs.FS { return subEmbedded(embeddedFiles, "webui_fallback") }

func subEmbedded(f embed.FS, dir string) fs.FS {
	s, err := fs.Sub(f, dir)
	if err != nil {
		return nil
	}
	return s
}
