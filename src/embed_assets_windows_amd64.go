//go:build windows && amd64

package main

import (
	"embed"
	"io/fs"
)

//go:embed drivers/amd64/*
var embeddedFiles embed.FS

func embeddedDriverFS() fs.FS { return subEmbedded(embeddedFiles, "drivers/amd64") }

func embeddedWebrootFS() fs.FS { return nil }
