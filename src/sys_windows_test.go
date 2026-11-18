//go:build windows

package main

import "testing"

func TestLocalProxyPointsAtOurPort(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"127.0.0.1:8080", false}, // someone else's local proxy
		{"localhost:8080", false},
		{"127.0.0.1:17841", true},
		{"localhost:17841;socks=127.0.0.1:1080", true},
		{"127.0.0.1", false},
		{"192.168.1.10:17841", false},
	}
	for _, tc := range tests {
		if got := localProxyPointsAtOurPort(tc.value); got != tc.want {
			t.Errorf("localProxyPointsAtOurPort(%q) = %t, want %t", tc.value, got, tc.want)
		}
	}
}
