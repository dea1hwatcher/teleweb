//go:build linux

package main

import (
	"errors"
	"net"
	"testing"
)

func TestLinuxDefaultBaseDirFollowsAndroidGate(t *testing.T) {
	orig := androidRuntime
	t.Cleanup(func() { androidRuntime = orig })

	androidRuntime = true
	if got := defaultBaseDir(); got != "/data/adb/teleweb" {
		t.Fatalf("android baseDir=%q, want /data/adb/teleweb", got)
	}
	androidRuntime = false
	if got := defaultBaseDir(); got == "/data/adb/teleweb" {
		t.Fatal("desktop Linux must not use the module directory")
	}
}

// A socket that was never NAT-redirected has no original destination. The
// failure must carry errNoOriginalDst so handleClient treats it as neutral
// instead of counting a client fault and logging it.
func TestLinuxOriginalDestinationWrapsSentinel(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	if _, err := originalDestination(client); !errors.Is(err, errNoOriginalDst) {
		t.Fatalf("expected errNoOriginalDst, got %v", err)
	}
}
