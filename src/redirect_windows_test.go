//go:build windows

package main

import (
	"net/netip"
	"testing"
)

func TestNatGetOrCreate_SynPurgesStale(t *testing.T) {
	orig := netip.MustParseAddrPort("149.154.167.51:443")
	flow := natFlowKey{
		srcIP:   [4]byte{192, 168, 1, 50},
		srcPort: 54321,
		dstIP:   [4]byte{149, 154, 167, 51},
		dstPort: 443,
	}

	// 1. Initial connection with SYN
	e1 := natGetOrCreate(flow, orig, true)
	if e1 == nil {
		t.Fatal("expected natEntry to be created")
	}
	port1 := e1.natPort

	// 2. Mid-connection packet (ACK/PSH) without SYN
	e2 := natGetOrCreate(flow, orig, false)
	if e2 != e1 || e2.natPort != port1 {
		t.Fatalf("expected same entry for non-SYN packet, got port %d != %d", e2.natPort, port1)
	}

	// 3. Reconnect with new SYN (after previous connection closed)
	e3 := natGetOrCreate(flow, orig, true)
	if e3 == nil {
		t.Fatal("expected new natEntry to be created for SYN")
	}
	if e3.natPort == port1 {
		t.Fatalf("expected fresh natPort on SYN to avoid TIME_WAIT collision, got %d", e3.natPort)
	}

	// Lookup for new port must resolve to orig
	resolved, ok := natLookup(e3.natPort)
	if !ok || resolved != orig {
		t.Fatalf("natLookup(%d) = %v, %v; want %v, true", e3.natPort, resolved, ok, orig)
	}
}

func TestPrefixLast_Subnets(t *testing.T) {
	cases := []struct {
		cidr string
		want string
	}{
		{"149.154.160.0/20", "149.154.175.255"},
		{"91.108.4.0/22", "91.108.7.255"},
		{"91.108.8.0/22", "91.108.11.255"},
		{"91.108.12.0/22", "91.108.15.255"},
		{"91.108.16.0/22", "91.108.19.255"},
		{"91.108.20.0/22", "91.108.23.255"},
		{"91.108.56.0/22", "91.108.59.255"},
		{"185.76.151.0/24", "185.76.151.255"},
		{"91.105.192.0/23", "91.105.193.255"},
	}

	for _, tc := range cases {
		p := netip.MustParsePrefix(tc.cidr)
		got := prefixLast(p)
		if got.String() != tc.want {
			t.Errorf("prefixLast(%s) = %s; want %s", tc.cidr, got, tc.want)
		}
	}
}
