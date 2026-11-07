//go:build !nativegui

package main

import "fmt"

// cmdGui is invoked when the application is launched without arguments on
// platforms where the native GUI is not available (Linux / headless).
func cmdGui(_ string) {
	fmt.Println("TeleWEB transparent WebSocket engine\ncommands: boot | ensure | status | stop | watchdog | run | socks [addr] | api BASE64_JSON | check")
}
