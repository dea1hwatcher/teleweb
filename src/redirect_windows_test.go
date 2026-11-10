//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
		{"95.161.64.0/20", "95.161.79.255"},
		{"172.121.110.0/24", "172.121.110.255"},
		{"142.252.58.0/24", "142.252.58.255"},
	}

	for _, tc := range cases {
		p := netip.MustParsePrefix(tc.cidr)
		got := prefixLast(p)
		if got.String() != tc.want {
			t.Errorf("prefixLast(%s) = %s; want %s", tc.cidr, got, tc.want)
		}
	}
}

// buildV6TCPPacket lays out a minimal IPv6 + TCP header, which is all the
// parser and the rewrites look at.
func buildV6TCPPacket(src, dst netip.Addr, sport, dport uint16, flags byte) []byte {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20) // payload length: the TCP header
	pkt[6] = 6                               // next header: TCP
	pkt[7] = 64
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	binary.BigEndian.PutUint16(pkt[40:], sport)
	binary.BigEndian.PutUint16(pkt[42:], dport)
	pkt[40+12] = 0x50 // data offset: five words
	pkt[40+13] = flags
	return pkt
}

func addr16From(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}

func TestParseTCPv6(t *testing.T) {
	src := netip.MustParseAddr("2a02:1234:5678::42")
	dst := netip.MustParseAddr("2001:b28:f23d:f001::a")
	pkt := buildV6TCPPacket(src, dst, 54321, 443, 0x12)

	meta, ok := parseTCPv6(pkt)
	if !ok {
		t.Fatal("parseTCPv6 rejected a well formed IPv6/TCP packet")
	}
	if addr16From(meta.srcIP[:]) != src || addr16From(meta.dstIP[:]) != dst {
		t.Errorf("addresses parsed as %s -> %s, want %s -> %s", addr16From(meta.srcIP[:]), addr16From(meta.dstIP[:]), src, dst)
	}
	if meta.sport != 54321 || meta.dport != 443 || meta.flags != 0x12 || meta.tcpOff != 40 {
		t.Errorf("meta = %+v, want sport 54321, dport 443, flags 0x12, tcpOff 40", meta)
	}

	v4 := make([]byte, 60)
	v4[0] = 0x45
	v4[9] = 6
	if _, ok := parseTCPv6(v4); ok {
		t.Error("parseTCPv6 accepted an IPv4 packet")
	}
	udp := buildV6TCPPacket(src, dst, 1, 2, 0)
	udp[6] = 17
	if _, ok := parseTCPv6(udp); ok {
		t.Error("parseTCPv6 accepted an IPv6/UDP packet")
	}

	// F14: an extension-header chain must not make the packet escape.
	hop := append([]byte(nil), pkt[:40]...)
	hop = append(hop, make([]byte, 8)...) // Hop-by-Hop: 8*(0+1) = 8 bytes
	hop = append(hop, pkt[40:]...)        // then the TCP header
	hop[6] = 0                            // next after IPv6 header: Hop-by-Hop
	hop[40] = 6                           // next after options: TCP
	metaH, okH := parseTCPv6(hop)
	if !okH {
		t.Fatal("parseTCPv6 rejected an IPv6 packet with a Hop-by-Hop header")
	}
	if metaH.dport != meta.dport || metaH.tcpOff != 48 {
		t.Errorf("hop-by-hop parse: tcpOff=%d dport=%d, want 48/%d", metaH.tcpOff, metaH.dport, meta.dport)
	}

	frag := append([]byte(nil), pkt[:40]...)
	frag = append(frag, make([]byte, 8)...) // Fragment: fixed 8 bytes
	frag = append(frag, pkt[40:]...)        // then the TCP header
	frag[6] = 44                            // next after IPv6 header: Fragment
	frag[40] = 6                            // next after fragment header: TCP
	if metaF, okF := parseTCPv6(frag); !okF || metaF.tcpOff != 48 {
		t.Fatalf("fragment chain: ok=%v tcpOff=%d, want true/48", okF, metaF.tcpOff)
	}
	if _, ok := parseTCPv6(pkt[:59]); ok {
		t.Error("parseTCPv6 accepted a truncated packet")
	}
}

func TestV6LoopbackRewriteBothDirections(t *testing.T) {
	client := netip.MustParseAddr("2a02:1234:5678::42")
	telegram := netip.MustParseAddr("2001:b28:f23d:f001::a")
	const natPort = 23456

	// Request: the client's packet is redirected onto the listener.
	req := buildV6TCPPacket(client, telegram, 54321, 443, 0x02)
	meta, ok := parseTCPv6(req)
	if !ok {
		t.Fatal("parseTCPv6 rejected the packet under test")
	}
	v6ToLoopback(req, meta, natPort)
	if got := addr16From(req[8:24]); got != netip.IPv6Loopback() {
		t.Errorf("request source address = %s, want ::1", got)
	}
	if got := addr16From(req[24:40]); got != netip.IPv6Loopback() {
		t.Errorf("request destination address = %s, want ::1", got)
	}
	if sp := binary.BigEndian.Uint16(req[40:]); sp != natPort {
		t.Errorf("request source port = %d, want the NAT port %d, which is what maps the accepted socket back to Telegram", sp, natPort)
	}
	if dp := binary.BigEndian.Uint16(req[42:]); dp != defaultPort {
		t.Errorf("request destination port = %d, want the listener port %d", dp, defaultPort)
	}
	if req[40+13] != 0x02 {
		t.Errorf("request flags changed to %#x", req[40+13])
	}

	// Reply: what the listener sends back has to reach the client as the
	// Telegram endpoint.
	reply := buildV6TCPPacket(netip.IPv6Loopback(), netip.IPv6Loopback(), defaultPort, natPort, 0x12)
	rmeta, ok := parseTCPv6(reply)
	if !ok {
		t.Fatal("parseTCPv6 rejected the reply packet")
	}
	v6FromLoopback(reply, rmeta, netip.AddrPortFrom(telegram, 443), client, 54321)
	if got := addr16From(reply[8:24]); got != telegram {
		t.Errorf("reply source address = %s, want %s", got, telegram)
	}
	if got := addr16From(reply[24:40]); got != client {
		t.Errorf("reply destination address = %s, want %s", got, client)
	}
	if sp := binary.BigEndian.Uint16(reply[40:]); sp != 443 {
		t.Errorf("reply source port = %d, want 443", sp)
	}
	if dp := binary.BigEndian.Uint16(reply[42:]); dp != 54321 {
		t.Errorf("reply destination port = %d, want the client port 54321", dp)
	}
	if reply[40+13] != 0x12 {
		t.Errorf("reply flags changed to %#x", reply[40+13])
	}
}

func TestNatTableV6AllocationAndPrune(t *testing.T) {
	natTable.mu.Lock()
	oldFlows, oldFlowsV6, oldPorts, oldNext := natTable.flows, natTable.flowsV6, natTable.ports, natTable.next
	natTable.flows = map[natFlowKey]*natEntry{}
	natTable.flowsV6 = map[natFlowKeyV6]*natEntry{}
	natTable.ports = map[uint16]*natEntry{}
	natTable.next = natPortFirst
	natTable.mu.Unlock()
	t.Cleanup(func() {
		natTable.mu.Lock()
		natTable.flows, natTable.flowsV6, natTable.ports, natTable.next = oldFlows, oldFlowsV6, oldPorts, oldNext
		natTable.mu.Unlock()
	})

	client := netip.MustParseAddr("2a02:1234:5678::42")
	telegram1 := netip.MustParseAddr("2001:b28:f23d:f001::a")
	telegram2 := netip.MustParseAddr("2a0a:f280::1")
	key1 := natFlowKeyV6{srcIP: client.As16(), srcPort: 54321, dstIP: telegram1.As16(), dstPort: 443}
	key2 := natFlowKeyV6{srcIP: client.As16(), srcPort: 54322, dstIP: telegram2.As16(), dstPort: 443}

	e1 := natGetOrCreateV6(key1, netip.AddrPortFrom(telegram1, 443), true)
	if e1 == nil {
		t.Fatal("no mapping allocated for an IPv6 flow")
	}
	if got := natLookupFlowV6(key1); got != e1 {
		t.Error("the flow lookup did not return the mapping just created")
	}
	if ap, ok := natLookup(e1.natPort); !ok || ap != netip.AddrPortFrom(telegram1, 443) {
		t.Errorf("natLookup(%d) = %v, %t; want the Telegram endpoint", e1.natPort, ap, ok)
	}
	if e1.clientAddr != client || e1.clientPort != 54321 {
		t.Errorf("mapping recorded the client as %s:%d", e1.clientAddr, e1.clientPort)
	}

	e2 := natGetOrCreateV6(key2, netip.AddrPortFrom(telegram2, 443), true)
	if e2 == nil {
		t.Fatal("second IPv6 flow got no mapping")
	}
	if e2.natPort == e1.natPort {
		t.Fatalf("two flows share local port %d", e1.natPort)
	}

	// A SYN for an existing tuple rebinds a fresh port and drops the old one.
	before := e1.natPort
	e1b := natGetOrCreateV6(key1, netip.AddrPortFrom(telegram1, 443), true)
	if e1b == nil || e1b.natPort == before {
		t.Errorf("SYN reuse kept local port %d, want a fresh one", before)
	}
	if _, busy := natTable.ports[before]; busy {
		t.Errorf("port %d stayed indexed after the mapping was replaced", before)
	}

	// Established but long idle: pruned. Fresh: kept.
	e2.lastSeen.Store(time.Now().Add(-3 * time.Hour).UnixNano())
	e2.established.Store(true)
	pruneFlows(time.Now())
	if natLookupFlowV6(key2) != nil {
		t.Error("a stale IPv6 mapping survived pruning")
	}
	if _, busy := natTable.ports[e2.natPort]; busy {
		t.Error("the port index kept a pruned IPv6 mapping")
	}
	if natLookupFlowV6(key1) == nil {
		t.Error("a fresh IPv6 mapping was pruned")
	}
}

func TestV6FiltersAndInterceptDecision(t *testing.T) {
	out := buildOutboundFilterV6()
	if !strings.Contains(out, "ipv6") || !strings.Contains(out, "tcp") || !strings.Contains(out, "not loopback") {
		t.Errorf("outbound v6 filter is missing a guard: %s", out)
	}
	if strings.Contains(out, "ipv6.DstAddr") {
		t.Errorf("the outbound v6 filter cannot test a range, so it must capture all IPv6 TCP: %s", out)
	}
	ret := buildReturnFilterV6()
	for _, want := range []string{"ipv6.SrcAddr == ::1", "ipv6.DstAddr == ::1", fmt.Sprintf("tcp.SrcPort == %d", defaultPort)} {
		if !strings.Contains(ret, want) {
			t.Errorf("return v6 filter %q is missing %q", ret, want)
		}
	}

	telegram := netip.MustParseAddr("2001:b28:f23d:f001::a").As16()
	other := netip.MustParseAddr("2606:4700::1111").As16()
	if !v6InterceptTarget(telegram, 49152) {
		t.Error("a Telegram IPv6 destination was not taken into the tunnel")
	}
	if v6InterceptTarget(other, 49152) {
		t.Error("a non-Telegram IPv6 destination was taken into the tunnel")
	}
	selfDialRegister(49222)
	defer selfDialExpire(49222)
	if v6InterceptTarget(telegram, 49222) {
		t.Error("the daemon's own dial was taken into the tunnel")
	}
}

func TestProcessOut6AndRet6Pipeline(t *testing.T) {
	natTable.mu.Lock()
	oldFlows, oldFlowsV6, oldPorts, oldNext := natTable.flows, natTable.flowsV6, natTable.ports, natTable.next
	natTable.flows = map[natFlowKey]*natEntry{}
	natTable.flowsV6 = map[natFlowKeyV6]*natEntry{}
	natTable.ports = map[uint16]*natEntry{}
	natTable.next = natPortFirst
	natTable.mu.Unlock()
	t.Cleanup(func() {
		natTable.mu.Lock()
		natTable.flows, natTable.flowsV6, natTable.ports, natTable.next = oldFlows, oldFlowsV6, oldPorts, oldNext
		natTable.mu.Unlock()
	})

	client := netip.MustParseAddr("2a02:1234:5678::42")
	telegram := netip.MustParseAddr("2001:b28:f23d:f001::a")

	req := buildV6TCPPacket(client, telegram, 40000, 443, 0x02)
	if processOut6(req) != v6Rewritten {
		t.Fatal("a Telegram IPv6 flow was not folded into the tunnel")
	}
	meta, ok := parseTCPv6(req)
	if !ok {
		t.Fatal("the folded packet no longer parses")
	}
	if addr16From(req[24:40]) != netip.IPv6Loopback() || meta.dport != defaultPort {
		t.Errorf("folded packet targets %s:%d, want ::1:%d", addr16From(req[24:40]), meta.dport, defaultPort)
	}
	flow := natFlowKeyV6{srcIP: client.As16(), srcPort: 40000, dstIP: telegram.As16(), dstPort: 443}
	e := natLookupFlowV6(flow)
	if e == nil {
		t.Fatal("no mapping was created for the folded flow")
	}
	if e.orig != netip.AddrPortFrom(telegram, 443) {
		t.Errorf("mapping points at %s, want the Telegram endpoint", e.orig)
	}
	if meta.sport != e.natPort {
		t.Errorf("folded packet source port = %d, want the NAT port %d so the accepted socket maps back", meta.sport, e.natPort)
	}

	other := netip.MustParseAddr("2606:4700::1111")
	pass := buildV6TCPPacket(client, other, 40001, 443, 0x02)
	before := append([]byte(nil), pass...)
	if processOut6(pass) != v6PassThrough {
		t.Error("a non-Telegram IPv6 flow was folded into the tunnel")
	}
	if !bytes.Equal(pass, before) {
		t.Error("a packet that is not tunnel material was modified")
	}

	selfDialRegister(40002)
	defer selfDialExpire(40002)
	self := buildV6TCPPacket(client, telegram, 40002, 443, 0x02)
	if processOut6(self) != v6PassThrough {
		t.Error("the daemon's own dial was folded into the tunnel")
	}

	reply := buildV6TCPPacket(netip.IPv6Loopback(), netip.IPv6Loopback(), defaultPort, e.natPort, 0x12)
	if !processRet6(reply) {
		t.Fatal("a reply with a live mapping was not rewritten")
	}
	rm, ok := parseTCPv6(reply)
	if !ok {
		t.Fatal("the rewritten reply no longer parses")
	}
	if addr16From(reply[8:24]) != telegram || rm.sport != 443 {
		t.Errorf("reply source = %s:%d, want the Telegram endpoint", addr16From(reply[8:24]), rm.sport)
	}
	if addr16From(reply[24:40]) != client || rm.dport != 40000 {
		t.Errorf("reply destination = %s:%d, want the client's address and port", addr16From(reply[24:40]), rm.dport)
	}

	stray := buildV6TCPPacket(netip.IPv6Loopback(), netip.IPv6Loopback(), defaultPort, 32001, 0x12)
	if processRet6(stray) {
		t.Error("a reply without a mapping was rewritten")
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
