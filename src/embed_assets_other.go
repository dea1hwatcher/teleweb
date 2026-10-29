package main

import "io/fs"

func embeddedDriverFS() fs.FS { return nil }

func embeddedWebrootFS() fs.FS { return nil }
