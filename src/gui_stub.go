//go:build !nativegui

package main

import "time"

// cmdGui falls back to the browser panel for builds without the native GUI
// tag (Android module, engine-only builds and CI engine builds).
func cmdGui(addr string) {
	if addr == "" {
		addr = "127.0.0.1:17842"
	}
	ensureDir()
	startSignalLogger()
	go func() {
		time.Sleep(300 * time.Millisecond)
		openInBrowser("http://" + addr + "/")
	}()
	cmdWebUI(addr)
}
