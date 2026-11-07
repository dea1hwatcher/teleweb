//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ------------------------------ WinDivert FFI ------------------------------
//
// The library is called through LazyDLL so the binary stays pure Go (no cgo)
// and cross-compiles from any host. The DLL is looked up next to tgws.exe
// first; a single-file build falls back to the copy embedded at build time,
// extracted into the state directory. WinDivert64.sys / WinDivert32.sys must
// sit next to the DLL — WinDivert loads them from its own directory.

var (
	wdDLL     *syscall.LazyDLL
	wdOpen    *syscall.LazyProc
	wdRecv    *syscall.LazyProc
	wdSend    *syscall.LazyProc
	wdClose   *syscall.LazyProc
	wdCalcSum *syscall.LazyProc
)

const (
	wdLayerNetwork = 0
	wdInvalid      = ^uintptr(0)
)

func loadWinDivert(dir string) error {
	wdDLL = syscall.NewLazyDLL(filepath.Join(dir, "WinDivert.dll"))
	if err := wdDLL.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not loadable from %s: %w", dir, err)
	}
	wdOpen = wdDLL.NewProc("WinDivertOpen")
	wdRecv = wdDLL.NewProc("WinDivertRecv")
	wdSend = wdDLL.NewProc("WinDivertSend")
	wdClose = wdDLL.NewProc("WinDivertClose")
	wdCalcSum = wdDLL.NewProc("WinDivertHelperCalcChecksums")
	return nil
}

// resolveDriverDir returns a directory containing WinDivert.dll and the
// matching .sys driver: the exe directory when the files ship alongside, or a
// per-user state directory populated from the embedded driver assets.
func resolveDriverDir() (string, error) {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, "WinDivert.dll")); err == nil {
			return dir, nil
		}
	}
	fsys := embeddedDriverFS()
	if fsys == nil {
		return "", fmt.Errorf("WinDivert.dll not found next to tgws.exe and no embedded driver for windows/%s", runtime.GOARCH)
	}
	dir := filepath.Join(baseDir, "driver")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		want, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, want) {
			continue
		}
		if err := os.WriteFile(path, want, 0700); err != nil {
			return "", fmt.Errorf("extract %s: %w", e.Name(), err)
		}
	}
	return dir, nil
}

// wdAddr mirrors WINDIVERT_ADDRESS (64 bytes). Byte 10 holds the flag bits:
// 0 Sniffed, 1 Outbound, 2 Loopback, 3 Impostor, 4 IPv6, 5-7 checksum-valid.
type wdAddr [64]byte

func (a *wdAddr) clearLoopback() { a[10] &^= 0x04 }

func explainWinDivertError(err error) error {
	if err == nil {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == 433 {
			return fmt.Errorf("WinDivertOpen failed (ERROR_NO_SUCH_DEVICE 433): driver is hung or held by another bypass tool (GoodbyeDPI, Zapret). Try closing them or rebooting: %w", err)
		}
		if uint32(errno) == 0x8032000A {
			return fmt.Errorf("WinDivertOpen failed (FWP_E_IN_USE 0x8032000A): WFP filter object is still in use by Windows. Wait a few seconds or reboot: %w", err)
		}
	}
	return fmt.Errorf("WinDivertOpen failed: %v (administrator rights and WinDivert.dll/.sys required)", err)
}

func wdOpenHandle(filter string) (uintptr, error) {
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	// WinDivertOpen(filter, layer, INT16 priority, UINT64 flags): on 386 the
	// trailing UINT64 occupies two 32-bit stdcall slots; passing a single
	// uintptr leaves garbage in the high half and WinDivertOpen rejects it
	// with ERROR_INVALID_PARAMETER.
	var h uintptr
	var callErr error
	if unsafe.Sizeof(uintptr(0)) == 4 {
		h, _, callErr = wdOpen.Call(uintptr(unsafe.Pointer(f)), wdLayerNetwork, 0, 0, 0)
	} else {
		h, _, callErr = wdOpen.Call(uintptr(unsafe.Pointer(f)), wdLayerNetwork, 0, 0)
	}
	if h == wdInvalid || h == 0 {
		return 0, explainWinDivertError(callErr)
	}
	return h, nil
}

func wdRecvPacket(h uintptr, pkt []byte) (int, wdAddr, error) {
	var addr wdAddr
	var recvLen uint32
	ok, _, callErr := wdRecv.Call(h,
		uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&recvLen)), uintptr(unsafe.Pointer(&addr)))
	if ok == 0 {
		return 0, addr, callErr
	}
	return int(recvLen), addr, nil
}

func wdSendPacket(h uintptr, pkt []byte, addr *wdAddr) error {
	var sendLen uint32
	ok, _, callErr := wdSend.Call(h,
		uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&sendLen)), uintptr(unsafe.Pointer(addr)))
	if ok == 0 {
		return callErr
	}
	return nil
}

func wdCalcChecksums(pkt []byte, addr *wdAddr) {
	// WinDivertHelperCalcChecksums(packet, len, addr, UINT64 flags): same
	// two-slot UINT64 rule on 386 as WinDivertOpen.
	if unsafe.Sizeof(uintptr(0)) == 4 {
		_, _, _ = wdCalcSum.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0, 0)
		return
	}
	_, _, _ = wdCalcSum.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0)
}

// ------------------------------ NAT table ----------------------------------

type natEntry struct {
	orig       netip.AddrPort
	clientAddr netip.Addr
	clientPort uint16
	natPort    uint16
	lastSeen   atomic.Int64
	// established turns true once a packet carrying ACK but not SYN crosses the
	// flow, which is the handshake completing. Established flows are kept for
	// the RFC 5382 idle timeout instead of a couple of minutes: dropping a live
	// mapping leaves the replies forwarded to the client unrewritten.
	established atomic.Bool
}

// TCP control bits, as they appear in the flags octet.
const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
)

// touch records traffic on the flow and upgrades it to established when the
// flags show a completed handshake.
func (e *natEntry) touch(flags byte, now int64) {
	e.lastSeen.Store(now)
	if flags&tcpFlagACK != 0 && flags&tcpFlagSYN == 0 {
		e.established.Store(true)
	}
}

type natFlowKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

// natFlowKeyV6 is the same tuple for a native IPv6 flow.
type natFlowKeyV6 struct {
	srcIP   [16]byte
	srcPort uint16
	dstIP   [16]byte
	dstPort uint16
}

const (
	natPortFirst = 20000
	natPortLast  = 32000
)

var natTable = struct {
	mu      sync.RWMutex
	flows   map[natFlowKey]*natEntry
	flowsV6 map[natFlowKeyV6]*natEntry
	ports   map[uint16]*natEntry
	next    uint16
}{
	flows:   map[natFlowKey]*natEntry{},
	flowsV6: map[natFlowKeyV6]*natEntry{},
	ports:   map[uint16]*natEntry{},
	next:    natPortFirst,
}

// allocNatEntry claims a free local port for a mapping and indexes it there.
// The caller holds natTable.mu and files the entry in its own flow map, so both
// address families share one port space and one lookup for accepted sockets.
func allocNatEntry(orig netip.AddrPort, clientAddr netip.Addr, clientPort uint16) *natEntry {
	for i := 0; i < natPortLast-natPortFirst; i++ {
		p := natTable.next
		natTable.next++
		if natTable.next >= natPortLast {
			natTable.next = natPortFirst
		}
		if _, busy := natTable.ports[p]; busy {
			continue
		}
		e := &natEntry{orig: orig, clientAddr: clientAddr, clientPort: clientPort, natPort: p}
		e.lastSeen.Store(time.Now().UnixNano())
		natTable.ports[p] = e
		return e
	}
	return nil
}

func natGetOrCreate(flow natFlowKey, orig netip.AddrPort, isSYN bool) *natEntry {
	natTable.mu.Lock()
	defer natTable.mu.Unlock()
	if !isSYN {
		if e := natTable.flows[flow]; e != nil {
			return e
		}
	} else if old := natTable.flows[flow]; old != nil {
		// New TCP connection initiated with SYN: purge the stale mapping so
		// this connection receives a fresh local port and does not collide
		// with a previous socket in TIME_WAIT.
		delete(natTable.ports, old.natPort)
		delete(natTable.flows, flow)
	}
	e := allocNatEntry(orig, netip.AddrFrom4(flow.srcIP), flow.srcPort)
	if e == nil {
		return nil
	}
	natTable.flows[flow] = e
	return e
}

// natGetOrCreateV6 mirrors natGetOrCreate for native IPv6 flows.
func natGetOrCreateV6(flow natFlowKeyV6, orig netip.AddrPort, isSYN bool) *natEntry {
	natTable.mu.Lock()
	defer natTable.mu.Unlock()
	if !isSYN {
		if e := natTable.flowsV6[flow]; e != nil {
			return e
		}
	} else if old := natTable.flowsV6[flow]; old != nil {
		delete(natTable.ports, old.natPort)
		delete(natTable.flowsV6, flow)
	}
	e := allocNatEntry(orig, netip.AddrFrom16(flow.srcIP), flow.srcPort)
	if e == nil {
		return nil
	}
	natTable.flowsV6[flow] = e
	return e
}

func natReturnEntry(port uint16) *natEntry {
	natTable.mu.RLock()
	defer natTable.mu.RUnlock()
	return natTable.ports[port]
}

// natLookup resolves the original Telegram endpoint for an accepted socket
// whose remote is 127.0.0.1:<natPort>. The port space is shared by both address
// families, so this answers for IPv6 flows as well.
func natLookup(port uint16) (netip.AddrPort, bool) {
	e := natReturnEntry(port)
	if e == nil {
		return netip.AddrPort{}, false
	}
	return e.orig, true
}

func natLookupFlow(flow natFlowKey) *natEntry {
	natTable.mu.RLock()
	defer natTable.mu.RUnlock()
	return natTable.flows[flow]
}

func natLookupFlowV6(flow natFlowKeyV6) *natEntry {
	natTable.mu.RLock()
	defer natTable.mu.RUnlock()
	return natTable.flowsV6[flow]
}

// Idle timeouts from RFC 5382: a connection that never finished its handshake
// goes stale after four minutes, an established one only after two hours and
// four minutes. The single 360 s cutoff that was here before dropped connections
// that were alive but quiet, and a dropped mapping sends the replies to the
// client unrewritten, which the client sees as a broken connection.
const (
	natIdleTimeout        = 4 * time.Minute
	natEstablishedTimeout = 2*time.Hour + 4*time.Minute
)

// pruneFlowMap drops stale mappings from one family's flow map. The caller
// holds natTable.mu.
func pruneFlowMap[K comparable](flows map[K]*natEntry, now time.Time) {
	idleCutoff := now.Add(-natIdleTimeout).UnixNano()
	establishedCutoff := now.Add(-natEstablishedTimeout).UnixNano()
	for k, e := range flows {
		cutoff := idleCutoff
		if e.established.Load() {
			cutoff = establishedCutoff
		}
		if e.lastSeen.Load() < cutoff {
			delete(flows, k)
			delete(natTable.ports, e.natPort)
		}
	}
}

// pruneFlows drops stale mappings. now is a parameter so the rules can be
// exercised without waiting on a clock.
func pruneFlows(now time.Time) {
	natTable.mu.Lock()
	defer natTable.mu.Unlock()
	pruneFlowMap(natTable.flows, now)
	pruneFlowMap(natTable.flowsV6, now)
}

func natJanitor(stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			pruneFlows(time.Now())
		}
	}
}

// ------------------------------ Filters ------------------------------------

func prefixLast(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return p.Addr()
	}
	a := p.Masked().Addr().As4()
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		b := bits - i*8
		if b >= 8 {
			continue
		}
		if b <= 0 {
			a[i] = 0xff
			continue
		}
		// b network bits remain in this octet, so the remaining (8 - b) host bits must be 1.
		a[i] |= byte(0xff >> b)
	}
	return netip.AddrFrom4(a)
}

func buildOutboundFilter() string {
	parts := make([]string, 0, len(telegramSubnets))
	for _, sub := range telegramSubnets {
		p, err := netip.ParsePrefix(sub.cidr)
		if err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("(ip.DstAddr >= %s and ip.DstAddr <= %s)", p.Masked().Addr(), prefixLast(p)))
	}
	return "outbound and ip and tcp and not loopback and (" + strings.Join(parts, " or ") + ")"
}

func buildReturnFilter() string {
	return fmt.Sprintf("loopback and outbound and ip and tcp and ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == %d and ip.DstAddr == 127.0.0.1", defaultPort)
}

// buildOutboundFilterV6 captures every outbound IPv6 TCP packet. A range test is
// not available for IPv6 fields in the WinDivert filter language - the
// documented workaround for IPv6 is to capture all of it - so the address is
// matched per packet instead, and everything that is not a Telegram aggregate
// leaves the loop untouched within one iteration.
func buildOutboundFilterV6() string {
	return "outbound and ipv6 and tcp and not loopback"
}

func buildReturnFilterV6() string {
	return fmt.Sprintf("loopback and outbound and ipv6 and tcp and ipv6.SrcAddr == ::1 and tcp.SrcPort == %d and ipv6.DstAddr == ::1", defaultPort)
}

// v6InterceptTarget reports whether an outbound IPv6 packet belongs to the
// tunnel: the daemon's own dials are excluded, and a destination outside
// Telegram's aggregates is handed straight back to the stack.
func v6InterceptTarget(dst [16]byte, sport uint16) bool {
	if isSelfDialPort(sport) {
		return false
	}
	return isTelegramEndpointV6(netip.AddrFrom16(dst))
}

// ------------------------------ Packet parsing -----------------------------

type tcpMeta struct {
	ihl          int
	srcIP, dstIP [4]byte
	sport, dport uint16
	flags        byte
}

func parseTCPv4(pkt []byte) (tcpMeta, bool) {
	var m tcpMeta
	if len(pkt) < 40 || pkt[0]>>4 != 4 {
		return m, false
	}
	m.ihl = int(pkt[0]&0x0f) * 4
	if m.ihl < 20 || len(pkt) < m.ihl+20 || pkt[9] != 6 {
		return m, false
	}
	copy(m.srcIP[:], pkt[12:16])
	copy(m.dstIP[:], pkt[16:20])
	m.sport = binary.BigEndian.Uint16(pkt[m.ihl:])
	m.dport = binary.BigEndian.Uint16(pkt[m.ihl+2:])
	m.flags = pkt[m.ihl+13]
	return m, true
}

// tcpMetaV6 mirrors tcpMeta for native IPv6 packets. A packet whose IPv6 Next
// Header is not TCP is rejected here and forwarded untouched: WinDivert's
// filter language cannot express a test for IPv6 extension headers, so they are
// sorted out per packet instead.
type tcpMetaV6 struct {
	tcpOff       int
	srcIP, dstIP [16]byte
	sport, dport uint16
	flags        byte
}

func parseTCPv6(pkt []byte) (tcpMetaV6, bool) {
	var m tcpMetaV6
	off := ipv6TCPHeaderOffset(pkt)
	if off < 0 {
		return m, false
	}
	m.tcpOff = off
	copy(m.srcIP[:], pkt[8:24])
	copy(m.dstIP[:], pkt[24:40])
	m.sport = binary.BigEndian.Uint16(pkt[m.tcpOff:])
	m.dport = binary.BigEndian.Uint16(pkt[m.tcpOff+2:])
	m.flags = pkt[m.tcpOff+13]
	return m, true
}

// ipv6TCPHeaderOffset walks the IPv6 extension-header chain and returns the
// offset of the TCP header, or -1 when the packet carries no TCP payload we
// can act on. Without the walk a single Hop-by-Hop or Destination-Options
// header made the old pkt[6] != 6 check reject the packet and let it escape
// the tunnel untouched.
func ipv6TCPHeaderOffset(pkt []byte) int {
	const ipv6HeaderLen = 40
	if len(pkt) < ipv6HeaderLen+20 || pkt[0]>>4 != 6 {
		return -1
	}
	next := int(pkt[6])
	off := ipv6HeaderLen
	for hops := 0; hops < 8; hops++ {
		switch next {
		case 6: // TCP
			if off+20 > len(pkt) {
				return -1
			}
			return off
		case 0, 60, 43: // Hop-by-Hop, Destination Options, Routing: 8*(len+1) bytes
			if off+2 > len(pkt) {
				return -1
			}
			extLen := 8 * (int(pkt[off+1]) + 1)
			if off+extLen > len(pkt) {
				return -1
			}
			next = int(pkt[off])
			off += extLen
		case 44: // Fragment: fixed 8 bytes, next header first
			if off+8 > len(pkt) {
				return -1
			}
			next = int(pkt[off])
			off += 8
		case 51: // Authentication Header: 4*(len+2) bytes, next header first
			if off+2 > len(pkt) {
				return -1
			}
			extLen := 4 * (int(pkt[off+1]) + 2)
			if off+extLen > len(pkt) {
				return -1
			}
			next = int(pkt[off])
			off += extLen
		default: // No-next-header, UDP, ICMPv6 and anything else: not our business.
			return -1
		}
	}
	return -1
}

// v6ToLoopback rewrites a client -> Telegram IPv6 packet so the daemon's
// listener accepts it: the packet is addressed to [::1]:defaultPort and appears
// to come from [::1]:natPort, which is how the accepted socket later maps back
// to the Telegram endpoint. It mirrors the rewrite the IPv4 loop applies.
func v6ToLoopback(p []byte, meta tcpMetaV6, natPort uint16) {
	loop := netip.IPv6Loopback().As16()
	copy(p[8:24], loop[:])
	copy(p[24:40], loop[:])
	binary.BigEndian.PutUint16(p[meta.tcpOff:], natPort)
	binary.BigEndian.PutUint16(p[meta.tcpOff+2:], defaultPort)
}

// v6FromLoopback restores the client's view of a reply: the source becomes the
// Telegram endpoint again and the destination the client that opened the flow.
func v6FromLoopback(p []byte, meta tcpMetaV6, orig netip.AddrPort, client netip.Addr, clientPort uint16) {
	src := orig.Addr().As16()
	dst := client.As16()
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	binary.BigEndian.PutUint16(p[meta.tcpOff:], orig.Port())
	binary.BigEndian.PutUint16(p[meta.tcpOff+2:], clientPort)
}

// ------------------------------ Redirector ---------------------------------

type wdRedirector struct {
	hOut, hRet   uintptr
	hOut6, hRet6 uintptr
	running      atomic.Bool
	stopJanitor  chan struct{}
}

var (
	redirectorMu     sync.Mutex
	activeRedirector *wdRedirector
)

func redirectorSupported() bool { return runtime.GOARCH == "amd64" || runtime.GOARCH == "386" }

// redirectorUnsupportedReason explains why transparent mode is unavailable on
// this architecture (ARM64 has no WinDivert driver build).
func redirectorUnsupportedReason() error {
	if runtime.GOARCH == "arm64" {
		return errors.New("WinDivert ships no ARM64 driver: transparent mode is unavailable on Windows ARM64; use `tgws socks <addr>` instead")
	}
	return nil
}

func localRedirectorHealthy() bool {
	redirectorMu.Lock()
	defer redirectorMu.Unlock()
	return activeRedirector != nil && activeRedirector.running.Load()
}

// hostHasGlobalIPv6 reports whether this machine holds a routable IPv6 address,
// which is what decides whether the coverage gap below can actually be hit.
func hostHasGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.Is6() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
				return true
			}
		}
	}
	return false
}

// v6CoverageNotice explains the coverage gap on devices where IPv6 capture is
// unavailable or disabled: the filter language offers no range test for an
// IPv6 field (its documented escape hatch is to capture all IPv6 traffic,
// which is not something to impose on every machine), so without the IPv6
// handles those connections leave unproxied. Logged only on the failure and
// disabled paths -- when the handles are up, the ranges are intercepted.
func v6CoverageNotice(hasIPv6 bool) string {
	ranges := make([]string, 0, len(telegramV6Prefixes))
	for _, p := range telegramV6Prefixes {
		ranges = append(ranges, p.String())
	}
	detail := "this host has no global IPv6 address, so nothing can bypass it"
	if hasIPv6 {
		detail = "Telegram traffic to them leaves the machine unproxied"
	}
	return fmt.Sprintf("redirector: IPv4 only; %s is not intercepted (%s)", strings.Join(ranges, ", "), detail)
}

func startRedirector() error {
	redirectorMu.Lock()
	defer redirectorMu.Unlock()
	if activeRedirector != nil && activeRedirector.running.Load() {
		return nil
	}
	if !isElevated() {
		return errAdminRequired
	}
	driverDir, err := resolveDriverDir()
	if err != nil {
		return err
	}
	if err := loadWinDivert(driverDir); err != nil {
		return err
	}
	hOut, err := wdOpenHandle(buildOutboundFilter())
	if err != nil {
		return err
	}
	hRet, err := wdOpenHandle(buildReturnFilter())
	if err != nil {
		_, _, _ = wdClose.Call(hOut)
		return err
	}
	stopCh := make(chan struct{})
	r := &wdRedirector{hOut: hOut, hRet: hRet, stopJanitor: stopCh}
	r.running.Store(true)
	activeRedirector = r
	go r.outLoop()
	go r.retLoop()
	go natJanitor(stopCh)
	logf("redirector: WinDivert active; Telegram TCP -> 127.0.0.1:%d", defaultPort)

	// IPv6 rides on its own pair of handles, so a failure here leaves the IPv4
	// path exactly as it was, and the coverage notice explains the gap.
	if readFlag("ipv6_capture", true) {
		switch hOut6, err6 := wdOpenHandle(buildOutboundFilterV6()); {
		case err6 != nil:
			logf("redirector: IPv6 capture unavailable: %v", err6)
			logf("%s", v6CoverageNotice(hostHasGlobalIPv6()))
		default:
			hRet6, err6b := wdOpenHandle(buildReturnFilterV6())
			if err6b != nil {
				_, _, _ = wdClose.Call(hOut6)
				logf("redirector: IPv6 capture unavailable: %v", err6b)
				logf("%s", v6CoverageNotice(hostHasGlobalIPv6()))
				break
			}
			r.hOut6, r.hRet6 = hOut6, hRet6
			go r.out6Loop()
			go r.ret6Loop()
			logf("redirector: Telegram IPv6 -> [::1]:%d; other IPv6 TCP passes through", defaultPort)
		}
	} else {
		logf("redirector: IPv6 capture disabled by the ipv6_capture flag")
		logf("%s", v6CoverageNotice(hostHasGlobalIPv6()))
	}
	return nil
}

func tryUnloadWinDivertService() {
	// Attempt to stop the WinDivert service gracefully so the Windows kernel
	// unloads the driver and unlocks the .sys file from disk.
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		for _, name := range []string{"WinDivert", "WinDivert14", "Monkey"} {
			if s, err := m.OpenService(name); err == nil {
				_, _ = s.Control(svc.Stop)
				s.Close()
			}
		}
		return
	}
	for _, name := range []string{"WinDivert", "WinDivert14", "Monkey"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = exec.CommandContext(ctx, "sc.exe", "stop", name).Run()
		cancel()
	}
}

func stopRedirector() {
	redirectorMu.Lock()
	if activeRedirector != nil {
		activeRedirector.running.Store(false)
		if activeRedirector.stopJanitor != nil {
			close(activeRedirector.stopJanitor)
		}
		_, _, _ = wdClose.Call(activeRedirector.hOut)
		_, _, _ = wdClose.Call(activeRedirector.hRet)
		if activeRedirector.hOut6 != 0 {
			_, _, _ = wdClose.Call(activeRedirector.hOut6)
		}
		if activeRedirector.hRet6 != 0 {
			_, _, _ = wdClose.Call(activeRedirector.hRet6)
		}
		activeRedirector = nil
		logf("redirector: WinDivert stopped")
	}
	redirectorMu.Unlock()
	// Unloading the driver talks to the service control manager (or runs
	// sc.exe up to three times). Doing that while holding redirectorMu
	// stalled startRedirector and every status/watchdog probe for seconds on
	// every stop, even when no redirector was ever started.
	tryUnloadWinDivertService()
}

func (r *wdRedirector) outLoop() {
	defer func() {
		if rec := recover(); rec != nil {
			logStack(fmt.Sprintf("FATAL panic in WinDivert outLoop: %v", rec))
			r.running.Store(false)
		}
	}()
	pkt := make([]byte, 65535)
	for r.running.Load() {
		n, addr, err := wdRecvPacket(r.hOut, pkt)
		if err != nil {
			if r.running.Load() {
				logf("redirector: recv: %v", err)
				r.running.Store(false)
			}
			return
		}
		p := pkt[:n]
		m, ok := parseTCPv4(p)
		if !ok || isSelfDialPort(m.sport) {
			_ = wdSendPacket(r.hOut, p, &addr)
			continue
		}
		isSYN := (m.flags & (tcpFlagSYN | tcpFlagACK)) == tcpFlagSYN
		flow := natFlowKey{srcIP: m.srcIP, srcPort: m.sport, dstIP: m.dstIP, dstPort: m.dport}
		// Fast path: established flows are resolved under a read lock. A SYN
		// (new or retransmitted) may carry a stale TIME_WAIT mapping, so it
		// falls through to natGetOrCreate which purges and rebinds a fresh
		// local port for the new connection.
		e := natLookupFlow(flow)
		if e == nil || isSYN {
			e = natGetOrCreate(flow, netip.AddrPortFrom(netip.AddrFrom4(m.dstIP), m.dport), isSYN)
			if e == nil {
				// Every local port is taken: fail closed by dropping the packet
				// so it does not leak directly outside the tunnel, matching the
				// IPv6 v6Drop invariant.
				natTable.mu.RLock()
				flows := len(natTable.ports)
				natTable.mu.RUnlock()
				logf("redirector: NAT port range exhausted (%d flows); %s:%d -> %s:%d dropped instead of escaping the tunnel", flows, netip.AddrFrom4(m.srcIP), m.sport, netip.AddrFrom4(m.dstIP), m.dport)
				continue
			}
		}
		e.touch(m.flags, time.Now().UnixNano())
		p[12], p[13], p[14], p[15] = 127, 0, 0, 1
		p[16], p[17], p[18], p[19] = 127, 0, 0, 1
		binary.BigEndian.PutUint16(p[m.ihl:], e.natPort)
		binary.BigEndian.PutUint16(p[m.ihl+2:], defaultPort)
		wdCalcChecksums(p, &addr)
		_ = wdSendPacket(r.hOut, p, &addr)
	}
}

func (r *wdRedirector) retLoop() {
	defer func() {
		if rec := recover(); rec != nil {
			logStack(fmt.Sprintf("FATAL panic in WinDivert retLoop: %v", rec))
			r.running.Store(false)
		}
	}()
	pkt := make([]byte, 65535)
	for r.running.Load() {
		n, addr, err := wdRecvPacket(r.hRet, pkt)
		if err != nil {
			if r.running.Load() {
				logf("redirector: ret recv: %v", err)
				r.running.Store(false)
			}
			return
		}
		p := pkt[:n]
		m, ok := parseTCPv4(p)
		if !ok {
			_ = wdSendPacket(r.hRet, p, &addr)
			continue
		}
		e := natReturnEntry(m.dport)
		if e == nil {
			_ = wdSendPacket(r.hRet, p, &addr)
			continue
		}
		e.touch(m.flags, time.Now().UnixNano())
		if !e.orig.Addr().Is4() {
			_ = wdSendPacket(r.hRet, p, &addr)
			continue
		}
		o := e.orig.Addr().As4()
		client := e.clientAddr.As4()
		copy(p[12:16], o[:])
		copy(p[16:20], client[:])
		binary.BigEndian.PutUint16(p[m.ihl:], e.orig.Port())
		binary.BigEndian.PutUint16(p[m.ihl+2:], e.clientPort)
		addr.clearLoopback()
		wdCalcChecksums(p, &addr)
		_ = wdSendPacket(r.hRet, p, &addr)
	}
}

// v6Verdict classifies what processOut6 decided about a captured packet.
type v6Verdict int

const (
	// v6PassThrough: not tunnel material, reinject unchanged.
	v6PassThrough v6Verdict = iota
	// v6Rewritten: folded into the tunnel.
	v6Rewritten
	// v6Drop: tunnel material we cannot serve. Fail closed -- a Telegram
	// packet we cannot map must not silently leak direct, which on a filtered
	// network means the connection appears half-alive to the client. Dropping
	// a SYN is TCP-correct: the client retransmits and the flow succeeds once
	// a NAT port frees up.
	v6Drop
)

// processOut6 folds one captured outbound IPv6 packet into the tunnel in place
// and reports what it did with it. Pulled out of the loop so the whole decision
// chain - parse, range check, mapping, rewrite - can be exercised without
// WinDivert and without a routed IPv6 stack.
func processOut6(p []byte) v6Verdict {
	m, ok := parseTCPv6(p)
	if !ok || !v6InterceptTarget(m.dstIP, m.sport) {
		return v6PassThrough
	}
	isSYN := (m.flags & (tcpFlagSYN | tcpFlagACK)) == tcpFlagSYN
	flow := natFlowKeyV6{srcIP: m.srcIP, srcPort: m.sport, dstIP: m.dstIP, dstPort: m.dport}
	e := natLookupFlowV6(flow)
	if e == nil || isSYN {
		orig := netip.AddrPortFrom(netip.AddrFrom16(m.dstIP), m.dport)
		e = natGetOrCreateV6(flow, orig, isSYN)
		if e == nil {
			natTable.mu.RLock()
			flows := len(natTable.ports)
			natTable.mu.RUnlock()
			logf("redirector: NAT port range exhausted (%d flows); %s:%d -> %s:%d dropped instead of escaping the tunnel", flows, netip.AddrFrom16(m.srcIP), m.sport, orig.Addr(), m.dport)
			return v6Drop
		}
	}
	e.touch(m.flags, time.Now().UnixNano())
	v6ToLoopback(p, m, e.natPort)
	return v6Rewritten
}

// processRet6 restores the client's view of one reply from the listener and
// reports whether it rewrote the packet.
func processRet6(p []byte) bool {
	m, ok := parseTCPv6(p)
	if !ok {
		return false
	}
	e := natReturnEntry(m.dport)
	if e == nil || !e.orig.Addr().Is6() {
		// No mapping, or the shared port belongs to an IPv4 flow: hand it back.
		return false
	}
	e.touch(m.flags, time.Now().UnixNano())
	v6FromLoopback(p, m, e.orig, e.clientAddr, e.clientPort)
	return true
}

// out6Loop is the IPv6 twin of outLoop. Every outbound IPv6 TCP packet passes
// through here because the filter cannot be narrowed to a range; a packet that
// is not tunnel material is injected back unchanged in the same iteration.
func (r *wdRedirector) out6Loop() {
	defer func() {
		if rec := recover(); rec != nil {
			logStack(fmt.Sprintf("FATAL panic in WinDivert out6Loop: %v", rec))
			r.running.Store(false)
		}
	}()
	pkt := make([]byte, 65535)
	for r.running.Load() {
		n, addr, err := wdRecvPacket(r.hOut6, pkt)
		if err != nil {
			if r.running.Load() {
				logf("redirector: v6 recv: %v", err)
				r.running.Store(false)
			}
			return
		}
		p := pkt[:n]
		switch processOut6(p) {
		case v6Rewritten:
			wdCalcChecksums(p, &addr)
		case v6Drop:
			continue
		}
		_ = wdSendPacket(r.hOut6, p, &addr)
	}
}

// ret6Loop rewrites the listener's replies back into the Telegram endpoint, the
// IPv6 counterpart of retLoop.
func (r *wdRedirector) ret6Loop() {
	defer func() {
		if rec := recover(); rec != nil {
			logStack(fmt.Sprintf("FATAL panic in WinDivert ret6Loop: %v", rec))
			r.running.Store(false)
		}
	}()
	pkt := make([]byte, 65535)
	for r.running.Load() {
		n, addr, err := wdRecvPacket(r.hRet6, pkt)
		if err != nil {
			if r.running.Load() {
				logf("redirector: v6 ret recv: %v", err)
				r.running.Store(false)
			}
			return
		}
		p := pkt[:n]
		if processRet6(p) {
			addr.clearLoopback()
			wdCalcChecksums(p, &addr)
		}
		_ = wdSendPacket(r.hRet6, p, &addr)
	}
}

func redirectorHealthy() bool {
	if localRedirectorHealthy() {
		return true
	}
	// Cross-process view: consult the daemon's fresh status snapshot.
	st, err := os.Stat(path("status.json"))
	if err != nil || time.Since(st.ModTime()) > 30*time.Second {
		return false
	}
	b, err := os.ReadFile(path("status.json"))
	if err != nil {
		return false
	}
	var s Status
	if json.Unmarshal(b, &s) != nil {
		return false
	}
	return s.Redirector && pidAlive()
}

func ensureRedirector() error {
	if redirectorHealthy() {
		return nil
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if redirectorHealthy() {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("WinDivert redirector is not active (check WinDivert.dll/.sys next to tgws.exe and administrator rights)")
}

func isElevated() bool {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	t := windows.GetCurrentProcessToken()
	member, err := t.IsMember(sid)
	return err == nil && member
}

// ------------------------------ Windows service ----------------------------

const serviceName = "TeleWEB"

func svcInstall() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open service manager: %w", err)
	}
	defer m.Disconnect()
	cfg := mgr.Config{
		DisplayName: "TeleWEB WSS transport",
		Description: "Transparent WSS transport for Telegram (DC1-DC5)",
		StartType:   mgr.StartAutomatic,
	}
	s, err := m.CreateService(serviceName, exe, cfg, "svc-run")
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
			s, err = m.OpenService(serviceName)
		}
		if err != nil {
			return err
		}
	}
	defer s.Close()
	fmt.Printf("service %q installed: %s svc-run\n", serviceName, exe)
	return nil
}

func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("service %q removed\n", serviceName)
	return nil
}

type telewebService struct{}

func (s *telewebService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	errCh := make(chan error, 1)
	go func() { errCh <- runDesktop() }()
	select {
	case err := <-errCh:
		if err != nil {
			logf("service: start failed: %v", err)
			return false, 1
		}
	case <-time.After(20 * time.Second):
		go func() {
			if err := <-errCh; err != nil {
				logf("service: runtime error: %v", err)
			}
		}()
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			stopWatchdog()
			stopServer()
			runShutdownHooks()
			return false, 0
		}
	}
	return false, 0
}

func svcRun() error { return svc.Run(serviceName, &telewebService{}) }
