//go:build windows && amd64

package main

import (
	"embed"
	"io/fs"
)

//go:embed drivers/amd64/* webui_fallback/*
var embeddedFiles embed.FS

func embeddedDriverFS() fs.FS { return subEmbedded(embeddedFiles, "drivers/amd64") }

func embeddedWebrootFS() fs.FS { return subEmbedded(embeddedFiles, "webui_fallback") }

func subEmbedded(f embed.FS, dir string) fs.FS {
	s, err := fs.Sub(f, dir)
	if err != nil {
		return nil
	}
	return s
}
