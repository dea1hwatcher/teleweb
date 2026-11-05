//go:build !windows

package main

import "errors"

// Transparent redirection is implemented only on Windows (WinDivert) and on
// Linux/Android (iptables); other platforms reject the commands explicitly.
func redirectorSupported() bool    { return false }
func startRedirector() error       { return nil }
func stopRedirector()              {}
func ensureRedirector() error      { return nil }
func redirectorHealthy() bool      { return false }
func localRedirectorHealthy() bool { return false }

func redirectorUnsupportedReason() error { return nil }

var errWindowsOnly = errors.New("this command is only supported on Windows")

func svcInstall() error   { return errWindowsOnly }
func svcUninstall() error { return errWindowsOnly }
func svcRun() error       { return errWindowsOnly }
