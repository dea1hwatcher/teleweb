//go:build windows

package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"
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

func TestV6CoverageNoticeNamesEveryRange(t *testing.T) {
	withV6 := v6CoverageNotice(true)
	for _, p := range telegramV6Prefixes {
		if !strings.Contains(withV6, p.String()) {
			t.Errorf("notice omits %s: %s", p, withV6)
		}
	}
	if !strings.Contains(withV6, "not intercepted") || !strings.Contains(withV6, "unproxied") {
		t.Errorf("notice does not spell out that the ranges bypass the tunnel: %s", withV6)
	}
	withoutV6 := v6CoverageNotice(false)
	if withoutV6 == withV6 {
		t.Error("a host without IPv6 reads the same notice as one that has it")
	}
	if !strings.Contains(withoutV6, "no global IPv6") {
		t.Errorf("notice for a v4-only host does not explain why nothing can bypass: %s", withoutV6)
	}
}

func TestNatEntryTouchMarksEstablished(t *testing.T) {
	cases := []struct {
		name  string
		flags byte
		want  bool
	}{
		{"SYN alone starts the handshake", 0x02, false},
		{"SYN-ACK is not completion", 0x12, false},
		{"bare ACK completes it", 0x10, true},
		{"PSH-ACK carries data", 0x18, true},
		{"FIN-ACK closes an established flow", 0x11, true},
	}

	for _, tc := range cases {
		var e natEntry
		e.touch(tc.flags, 12345)
		if got := e.established.Load(); got != tc.want {
			t.Errorf("%s: flags %#x -> established=%t, want %t", tc.name, tc.flags, got, tc.want)
		}
		if e.lastSeen.Load() != 12345 {
			t.Errorf("%s: lastSeen=%d, want the value passed in", tc.name, e.lastSeen.Load())
		}
	}
}

func TestPruneFlowsTwoPhaseTimeouts(t *testing.T) {
	natTable.mu.Lock()
	oldFlows, oldPorts, oldNext := natTable.flows, natTable.ports, natTable.next
	natTable.flows, natTable.ports, natTable.next = map[natFlowKey]*natEntry{}, map[uint16]*natEntry{}, 20000
	natTable.mu.Unlock()
	t.Cleanup(func() {
		natTable.mu.Lock()
		natTable.flows, natTable.ports, natTable.next = oldFlows, oldPorts, oldNext
		natTable.mu.Unlock()
	})

	now := time.Now()
	add := func(port uint16, established bool, age time.Duration) {
		e := &natEntry{natPort: port}
		e.lastSeen.Store(now.Add(-age).UnixNano())
		e.established.Store(established)
		key := natFlowKey{srcPort: port}
		natTable.mu.Lock()
		natTable.flows[key] = e
		natTable.ports[port] = e
		natTable.mu.Unlock()
	}
	add(20001, true, time.Hour)       // established, quiet for an hour: keep
	add(20002, true, 3*time.Hour)     // established but past the RFC timeout: drop
	add(20003, false, time.Minute)    // handshake in flight: keep
	add(20004, false, 10*time.Minute) // never completed, stale: drop

	pruneFlows(now)

	natTable.mu.RLock()
	defer natTable.mu.RUnlock()
	kept := map[uint16]bool{}
	for _, e := range natTable.flows {
		kept[e.natPort] = true
	}
	for _, port := range []uint16{20001, 20003} {
		if !kept[port] {
			t.Errorf("port %d was pruned, want it kept", port)
			continue
		}
		if _, ok := natTable.ports[port]; !ok {
			t.Errorf("port index lost %d while its flow survived", port)
		}
	}
	for _, port := range []uint16{20002, 20004} {
		if kept[port] {
			t.Errorf("port %d survived pruning, want it dropped", port)
		}
		if _, ok := natTable.ports[port]; ok {
			t.Errorf("port index still holds %d after the flow was dropped", port)
		}
	}
}
