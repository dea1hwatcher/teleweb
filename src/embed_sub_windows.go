//go:build windows

package main

import (
	"embed"
	"io/fs"
)

// subEmbedded exposes dir inside an embedded filesystem, or nil when the
// subtree is missing. Shared by the per-architecture embed files, which used
// to carry three verbatim copies of this helper.
func subEmbedded(f embed.FS, dir string) fs.FS {
	s, err := fs.Sub(f, dir)
	if err != nil {
		return nil
	}
	return s
}
