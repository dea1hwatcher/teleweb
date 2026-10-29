//go:build windows && 386

package main

import (
	"embed"
	"io/fs"
)

//go:embed drivers/386/* webui_fallback/*
var embeddedFiles embed.FS

func embeddedDriverFS() fs.FS { return subEmbedded(embeddedFiles, "drivers/386") }

func embeddedWebrootFS() fs.FS { return subEmbedded(embeddedFiles, "webui_fallback") }

func subEmbedded(f embed.FS, dir string) fs.FS {
	s, err := fs.Sub(f, dir)
	if err != nil {
		return nil
	}
	return s
}
