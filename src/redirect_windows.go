//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
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
// and cross-compiles from any host. WinDivert.dll and WinDivert64.sys must be
// placed next to tgws.exe; opening a handle as administrator installs and
// starts the signed driver service automatically.

var (
	wdDLL     = syscall.NewLazyDLL("WinDivert.dll")
	wdOpen    = wdDLL.NewProc("WinDivertOpen")
	wdRecv    = wdDLL.NewProc("WinDivertRecv")
	wdSend    = wdDLL.NewProc("WinDivertSend")
	wdClose   = wdDLL.NewProc("WinDivertClose")
	wdCalcSum = wdDLL.NewProc("WinDivertHelperCalcChecksums")
)

const (
	wdLayerNetwork = 0
	wdInvalid      = ^uintptr(0)
)

// wdAddr mirrors WINDIVERT_ADDRESS (64 bytes). Byte 10 holds the flag bits:
// 0 Sniffed, 1 Outbound, 2 Loopback, 3 Impostor, 4 IPv6, 5-7 checksum-valid.
type wdAddr [64]byte

func (a *wdAddr) clearLoopback() { a[10] &^= 0x04 }

func wdOpenHandle(filter string) (uintptr, error) {
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	h, _, callErr := wdOpen.Call(uintptr(unsafe.Pointer(f)), wdLayerNetwork, 0, 0)
	if h == wdInvalid || h == 0 {
		return 0, fmt.Errorf("WinDivertOpen failed: %v (administrator rights and WinDivert.dll/.sys required)", callErr)
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
	_, _, _ = wdCalcSum.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0)
}

// ------------------------------ NAT table ----------------------------------

type natEntry struct {
	orig       netip.AddrPort
	clientIP   [4]byte
	clientPort uint16
	natPort    uint16
	lastSeen   atomic.Int64
}

type natFlowKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

var natTable = struct {
	mu    sync.RWMutex
	flows map[natFlowKey]*natEntry
	ports map[uint16]*natEntry
	next  uint16
}{flows: map[natFlowKey]*natEntry{}, ports: map[uint16]*natEntry{}, next: 20000}

func natGetOrCreate(flow natFlowKey, orig netip.AddrPort) *natEntry {
	natTable.mu.Lock()
	defer natTable.mu.Unlock()
	if e := natTable.flows[flow]; e != nil {
		return e
	}
	for i := 0; i < 12000; i++ {
		p := natTable.next
		natTable.next++
		if natTable.next >= 32000 {
			natTable.next = 20000
		}
		if p == defaultPort {
			continue
		}
		if _, busy := natTable.ports[p]; busy {
			continue
		}
		e := &natEntry{orig: orig, clientIP: flow.srcIP, clientPort: flow.srcPort, natPort: p}
		e.lastSeen.Store(time.Now().UnixNano())
		natTable.flows[flow] = e
		natTable.ports[p] = e
		return e
	}
	return nil
}

func natReturnEntry(port uint16) *natEntry {
	natTable.mu.RLock()
	defer natTable.mu.RUnlock()
	return natTable.ports[port]
}

// natLookup resolves the original Telegram endpoint for an accepted socket
// whose remote is 127.0.0.1:<natPort>.
func natLookup(port uint16) (netip.AddrPort, bool) {
	e := natReturnEntry(port)
	if e == nil {
		return netip.AddrPort{}, false
	}
	return e.orig, true
}

func natJanitor() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-180 * time.Second).UnixNano()
		natTable.mu.Lock()
		for k, e := range natTable.flows {
			if e.lastSeen.Load() < cutoff {
				delete(natTable.flows, k)
				delete(natTable.ports, e.natPort)
			}
		}
		natTable.mu.Unlock()
	}
}

// ------------------------------ Filters ------------------------------------

func prefixLast(p netip.Prefix) netip.Addr {
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
		a[i] |= byte(0xff << b)
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

// ------------------------------ Packet parsing -----------------------------

type tcpMeta struct {
	ihl          int
	srcIP, dstIP [4]byte
	sport, dport uint16
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
	return m, true
}

// ------------------------------ Redirector ---------------------------------

type wdRedirector struct {
	hOut, hRet uintptr
	running    atomic.Bool
}

var (
	redirectorMu     sync.Mutex
	activeRedirector *wdRedirector
)

func redirectorSupported() bool { return true }

func localRedirectorHealthy() bool {
	redirectorMu.Lock()
	defer redirectorMu.Unlock()
	return activeRedirector != nil && activeRedirector.running.Load()
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
	if err := wdDLL.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not loadable (place WinDivert.dll and WinDivert64.sys next to tgws.exe): %w", err)
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
	r := &wdRedirector{hOut: hOut, hRet: hRet}
	r.running.Store(true)
	activeRedirector = r
	go r.outLoop()
	go r.retLoop()
	go natJanitor()
	logf("redirector: WinDivert active; Telegram TCP -> 127.0.0.1:%d", defaultPort)
	return nil
}

func stopRedirector() {
	redirectorMu.Lock()
	defer redirectorMu.Unlock()
	if activeRedirector == nil {
		return
	}
	activeRedirector.running.Store(false)
	_, _, _ = wdClose.Call(activeRedirector.hOut)
	_, _, _ = wdClose.Call(activeRedirector.hRet)
	activeRedirector = nil
	logf("redirector: WinDivert stopped")
}

func (r *wdRedirector) outLoop() {
	pkt := make([]byte, 65535)
	for r.running.Load() {
		n, addr, err := wdRecvPacket(r.hOut, pkt)
		if err != nil {
			if r.running.Load() {
				logf("redirector: recv: %v", err)
			}
			return
		}
		p := pkt[:n]
		m, ok := parseTCPv4(p)
		if !ok || isSelfDialPort(m.sport) {
			_ = wdSendPacket(r.hOut, p, &addr)
			continue
		}
		flow := natFlowKey{srcIP: m.srcIP, srcPort: m.sport, dstIP: m.dstIP, dstPort: m.dport}
		e := natGetOrCreate(flow, netip.AddrPortFrom(netip.AddrFrom4(m.dstIP), m.dport))
		if e == nil {
			_ = wdSendPacket(r.hOut, p, &addr)
			continue
		}
		e.lastSeen.Store(time.Now().UnixNano())
		copy(p[12:16], []byte{127, 0, 0, 1})
		copy(p[16:20], []byte{127, 0, 0, 1})
		binary.BigEndian.PutUint16(p[m.ihl:], e.natPort)
		binary.BigEndian.PutUint16(p[m.ihl+2:], defaultPort)
		wdCalcChecksums(p, &addr)
		_ = wdSendPacket(r.hOut, p, &addr)
	}
}

func (r *wdRedirector) retLoop() {
	pkt := make([]byte, 65535)
	for r.running.Load() {
		n, addr, err := wdRecvPacket(r.hRet, pkt)
		if err != nil {
			if r.running.Load() {
				logf("redirector: ret recv: %v", err)
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
		e.lastSeen.Store(time.Now().UnixNano())
		o := e.orig.Addr().As4()
		copy(p[12:16], o[:])
		copy(p[16:20], e.clientIP[:])
		binary.BigEndian.PutUint16(p[m.ihl:], e.orig.Port())
		binary.BigEndian.PutUint16(p[m.ihl+2:], e.clientPort)
		addr.clearLoopback()
		wdCalcChecksums(p, &addr)
		_ = wdSendPacket(r.hRet, p, &addr)
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
			return false, 0
		}
	}
	return false, 0
}

func svcRun() error { return svc.Run(serviceName, &telewebService{}) }
