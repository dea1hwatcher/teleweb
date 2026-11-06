//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestLinuxDefaultBaseDirFollowsAndroidGate pins the one decision that separates
// the Android module from the Linux desktop port: the two share GOOS=linux, so a
// wrong answer sends the daemon to the wrong state directory. The probe is
// replaced rather than faked, because the machine running the tests is not
// expected to carry /system/build.prop.
func TestLinuxDefaultBaseDirFollowsAndroidGate(t *testing.T) {
	origProbe, origGate := androidProbe, androidDetection
	t.Cleanup(func() { androidProbe, androidDetection = origProbe, origGate })

	androidProbe = func() bool { return true }
	androidDetection = &androidGate{}
	if got := defaultBaseDir(); got != "/data/adb/teleweb" {
		t.Fatalf("android baseDir=%q, want /data/adb/teleweb", got)
	}

	androidProbe = func() bool { return false }
	androidDetection = &androidGate{}
	if got := defaultBaseDir(); got == "/data/adb/teleweb" {
		t.Fatal("desktop Linux must not use the module directory")
	}
}

// TestDecodeOriginalDst covers the two sockaddr layouts that
// IP(6)T_SO_ORIGINAL_DST writes. The parse used to be written out four times
// inside originalDestination, which is how a wrong offset would survive review.
func TestDecodeOriginalDst(t *testing.T) {
	v4 := make([]byte, 28)
	binary.BigEndian.PutUint16(v4[0:2], 2) // AF_INET
	binary.BigEndian.PutUint16(v4[2:4], 443)
	copy(v4[4:8], netip.MustParseAddr("149.154.167.51").AsSlice())

	got4, ok := decodeOriginalDst(v4, false)
	if !ok {
		t.Fatal("decodeOriginalDst rejected a valid sockaddr_in")
	}
	if want := netip.MustParseAddrPort("149.154.167.51:443"); got4 != want {
		t.Errorf("IPv4 layout decoded as %s, want %s", got4, want)
	}

	v6 := make([]byte, 28)
	binary.BigEndian.PutUint16(v6[0:2], 10) // AF_INET6
	binary.BigEndian.PutUint16(v6[2:4], 443)
	copy(v6[8:24], netip.MustParseAddr("2001:b28:f23d:f001::a").AsSlice())

	got6, ok := decodeOriginalDst(v6, true)
	if !ok {
		t.Fatal("decodeOriginalDst rejected a valid sockaddr_in6")
	}
	if want := netip.MustParseAddrPort("[2001:b28:f23d:f001::a]:443"); got6 != want {
		t.Errorf("IPv6 layout decoded as %s, want %s", got6, want)
	}

	if _, ok := decodeOriginalDst(make([]byte, 4), false); ok {
		t.Error("decodeOriginalDst accepted a buffer with no address")
	}
	if _, ok := decodeOriginalDst(make([]byte, 16), true); ok {
		t.Error("decodeOriginalDst accepted a truncated IPv6 address")
	}
}
