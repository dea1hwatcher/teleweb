//go:build !windows

package main

import "io/fs"

func embeddedDriverFS() fs.FS { return nil }
