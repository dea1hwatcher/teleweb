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

func TestNAT_NonSYN_NoPortAlloc_AndEviction(t *testing.T) {
	flow := natFlowKey{
		srcIP:   [4]byte{10, 0, 0, 1},
		srcPort: 54321,
		dstIP:   [4]byte{149, 154, 167, 51},
		dstPort: 443,
	}
	orig := netip.AddrPortFrom(netip.AddrFrom4(flow.dstIP), flow.dstPort)

	// 1. Non-SYN packet for untracked flow MUST return nil and not allocate a port.
	if e := natGetOrCreate(flow, orig, false); e != nil {
		t.Fatalf("expected nil for non-SYN packet on untracked flow, got natPort=%d", e.natPort)
	}

	// 2. SYN packet initiates the connection and allocates a port.
	entry1 := natGetOrCreate(flow, orig, true)
	if entry1 == nil {
		t.Fatal("expected valid natEntry on SYN")
	}
	port1 := entry1.natPort
	if port1 < 20000 || port1 >= 32000 {
		t.Fatalf("natPort out of range: %d", port1)
	}

	// 3. Subsequent mid-stream non-SYN packet finds the existing flow.
	entry2 := natGetOrCreate(flow, orig, false)
	if entry2 == nil || entry2.natPort != port1 {
		t.Fatalf("expected existing entry with port %d, got %v", port1, entry2)
	}

	// 4. Return entry lookup by natPort.
	lookupOrig, ok := natLookup(port1)
	if !ok || lookupOrig != orig {
		t.Fatalf("natLookup(%d) = %v, %v; want %v, true", port1, lookupOrig, ok, orig)
	}

	// 5. Subsequent SYN replaces the stale mapping with a fresh port (TIME_WAIT protection).
	entry3 := natGetOrCreate(flow, orig, true)
	if entry3 == nil {
		t.Fatal("expected valid entry on new SYN")
	}
	if entry3.natPort == port1 {
		t.Fatalf("expected new port on fresh SYN, got identical port %d", entry3.natPort)
	}

	// Clean up test entry
	natTable.mu.Lock()
	delete(natTable.flows, flow)
	delete(natTable.ports, port1)
	delete(natTable.ports, entry3.natPort)
	natTable.mu.Unlock()
}
