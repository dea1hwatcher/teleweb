//go:build windows && 386

package main

import (
	"embed"
	"io/fs"
)

//go:embed drivers/386/*
var embeddedFiles embed.FS

func embeddedDriverFS() fs.FS { return subEmbedded(embeddedFiles, "drivers/386") }

func embeddedWebrootFS() fs.FS { return nil }
