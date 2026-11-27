// TeleWEB L5 TLS ClientHello evasion & adaptive DPI escalation.
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	tlsEvasionModeAuto       = "auto"
	tlsEvasionModeSplit      = "split"
	tlsEvasionModeAggressive = "aggressive"
	tlsEvasionModeOff        = "off"

	// 4 KiB Pre-SNI padding exceeds standard IPv4 MTUs and first-packet DPI
	// windows while staying comfortably inside the 16 KiB TLS record limit.
	preSNIPaddingBytes = 4096
	maxTLSEvasionHosts = 128
	tlsEvasionHostTTL  = 15 * time.Minute
)

// tlsEvasionProfile identifies how an outgoing TLS ClientHello record is transformed.
type tlsEvasionProfile uint8

const (
	tlsSplitNone tlsEvasionProfile = iota
	tlsSplitMidSNI
	tlsSplitBeforeSNI
	tlsSplitSubHeader
	tlsSplitPreSNIPadding
)

func (p tlsEvasionProfile) String() string {
	switch p {
	case tlsSplitMidSNI:
		return "mid-sni"
	case tlsSplitBeforeSNI:
		return "before-sni"
	case tlsSplitSubHeader:
		return "sub-header"
	case tlsSplitPreSNIPadding:
		return "pre-sni-pad"
	default:
		return "none"
	}
}

type tlsFailureKind uint8

const (
	tlsFailNone tlsFailureKind = iota
	tlsFailReset
	tlsFailTimeout
	tlsFailOther
)

// tlsHandshakeError preserves the underlying error while exposing a DPI-aware failure class.
type tlsHandshakeError struct {
	Kind tlsFailureKind
	Err  error
}

func (e *tlsHandshakeError) Error() string {
	if e == nil || e.Err == nil {
		return "TLS handshake failed"
	}
	return e.Err.Error()
}

func (e *tlsHandshakeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type hostEvasionEntry struct {
	profile tlsEvasionProfile
	updated time.Time
}

var (
	tlsEvasionMu    sync.RWMutex
	tlsEvasionHosts = make(map[string]hostEvasionEntry)
)

func normalizeTLSEvasionMode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", tlsEvasionModeAuto:
		return tlsEvasionModeAuto, true
	case tlsEvasionModeSplit, "always", "1", "true":
		return tlsEvasionModeSplit, true
	case tlsEvasionModeAggressive, "pad", "padding":
		return tlsEvasionModeAggressive, true
	case tlsEvasionModeOff, "0", "false", "none", "disable":
		return tlsEvasionModeOff, true
	default:
		return tlsEvasionModeAuto, false
	}
}

func readTLSEvasionMode() string {
	b, err := os.ReadFile(path("tls_evasion"))
	if err != nil {
		return tlsEvasionModeAuto
	}
	mode, _ := normalizeTLSEvasionMode(string(b))
	return mode
}

func writeTLSEvasionMode(raw string) error {
	mode, ok := normalizeTLSEvasionMode(raw)
	if !ok {
		return fmt.Errorf("invalid tls_evasion mode: %q", raw)
	}
	ensureDir()
	if err := os.WriteFile(path("tls_evasion"), []byte(mode+"\n"), 0600); err != nil {
		return err
	}
	clearTLSEvasionState()
	return nil
}

func tlsEvasionModeCached() string {
	return cachedFileRead("tls_evasion", func() any { return readTLSEvasionMode() }).(string)
}

func clearTLSEvasionState() {
	tlsEvasionMu.Lock()
	clear(tlsEvasionHosts)
	tlsEvasionMu.Unlock()
	cfgFileCache.mu.Lock()
	delete(cfgFileCache.entries, "tls_evasion")
	cfgFileCache.mu.Unlock()
}

func tlsEvasionHostKey(host string, honorFrontingSNI bool) string {
	sni, _ := tlsHandshakeForHost(host, honorFrontingSNI)
	if sni = strings.ToLower(strings.TrimSpace(sni)); sni != "" {
		return sni
	}
	return strings.ToLower(strings.TrimSpace(host))
}

// tlsProfileForHost returns the active evasion profile for host, combining the
// global tls_evasion setting with any per-host escalation triggered by DPI resets.
func tlsProfileForHost(host string) tlsEvasionProfile {
	mode := tlsEvasionModeCached()
	if mode == tlsEvasionModeOff {
		return tlsSplitNone
	}
	var floor tlsEvasionProfile
	switch mode {
	case tlsEvasionModeSplit:
		floor = tlsSplitMidSNI
	case tlsEvasionModeAggressive:
		return tlsSplitPreSNIPadding
	}

	key := strings.ToLower(strings.TrimSpace(host))
	if key == "" {
		return floor
	}
	now := time.Now()
	tlsEvasionMu.RLock()
	entry, ok := tlsEvasionHosts[key]
	tlsEvasionMu.RUnlock()
	if ok && now.Sub(entry.updated) <= tlsEvasionHostTTL && entry.profile > floor {
		return entry.profile
	}
	return floor
}

// effectiveStdTLSProfile adapts uTLS-specific profiles for Go's standard crypto/tls
// used by HTTP/2 media and DoH transports where extension injection is unavailable.
func effectiveStdTLSProfile(p tlsEvasionProfile) tlsEvasionProfile {
	if p == tlsSplitPreSNIPadding {
		return tlsSplitBeforeSNI
	}
	return p
}

// wrapStdTLSConn wraps a dialed TCP connection for stdlib crypto/tls paths when
// TLS evasion is active for the target host.
func wrapStdTLSConn(conn net.Conn, host string) net.Conn {
	if conn == nil {
		return nil
	}
	prof := effectiveStdTLSProfile(tlsProfileForHost(host))
	return newTLSSplitConn(conn, prof)
}

func classifyTLSHandshakeErr(err error) tlsFailureKind {
	if err == nil {
		return tlsFailNone
	}
	if isTimeout(err) || isTimeoutText(strings.ToLower(err.Error())) {
		return tlsFailTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNABORTED) {
		return tlsFailReset
	}
	// Winsock errors on non-English Windows localize err.Error(), so match
	// WSAECONNRESET (10054) and WSAECONNABORTED (10053) by numeric errno too.
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == 10054 || errno == 10053 || errno == 10057) {
		return tlsFailReset
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "connection was aborted") ||
		strings.Contains(msg, "aborted by the software") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "wsaeconnreset") ||
		strings.Contains(msg, "unexpected eof") {
		return tlsFailReset
	}
	return tlsFailOther
}

func nextTLSEvasionProfile(cur tlsEvasionProfile) (tlsEvasionProfile, bool) {
	switch cur {
	case tlsSplitNone:
		return tlsSplitMidSNI, true
	case tlsSplitMidSNI, tlsSplitBeforeSNI:
		return tlsSplitSubHeader, true
	case tlsSplitSubHeader:
		return tlsSplitPreSNIPadding, true
	default:
		return cur, false
	}
}

// escalateTLSEvasion advances the per-host evasion profile after a post-connect
// DPI reset or handshake stall so subsequent attempts can bypass SNI filters.
func escalateTLSEvasion(host string, kind tlsFailureKind) (tlsEvasionProfile, bool) {
	if kind != tlsFailReset && kind != tlsFailTimeout {
		return tlsSplitNone, false
	}
	if tlsEvasionModeCached() == tlsEvasionModeOff {
		return tlsSplitNone, false
	}
	key := strings.ToLower(strings.TrimSpace(host))
	if key == "" {
		return tlsSplitNone, false
	}

	now := time.Now()
	floor := tlsSplitNone
	switch tlsEvasionModeCached() {
	case tlsEvasionModeSplit:
		floor = tlsSplitMidSNI
	case tlsEvasionModeAggressive:
		floor = tlsSplitPreSNIPadding
	}

	tlsEvasionMu.Lock()
	defer tlsEvasionMu.Unlock()

	cur := floor
	if e, ok := tlsEvasionHosts[key]; ok && now.Sub(e.updated) <= tlsEvasionHostTTL && e.profile > cur {
		cur = e.profile
	}
	next, changed := nextTLSEvasionProfile(cur)
	if !changed {
		return cur, false
	}
	if len(tlsEvasionHosts) >= maxTLSEvasionHosts {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range tlsEvasionHosts {
			if now.Sub(v.updated) > tlsEvasionHostTTL {
				delete(tlsEvasionHosts, k)
				continue
			}
			if oldestKey == "" || v.updated.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.updated
			}
		}
		if len(tlsEvasionHosts) >= maxTLSEvasionHosts && oldestKey != "" {
			delete(tlsEvasionHosts, oldestKey)
		}
	}
	tlsEvasionHosts[key] = hostEvasionEntry{profile: next, updated: now}
	return next, true
}

// handleTLSHandshakeFailure inspects a failed dial/handshake error and, when it
// matches a DPI reset or post-connect stall under an active context, escalates
// the host's evasion profile and reports whether an escalated retry is warranted.
func handleTLSHandshakeFailure(ctx context.Context, hostKey string, err error) bool {
	if err == nil || !shouldPenalizeRoute(ctx, err) {
		return false
	}
	var tlsErr *tlsHandshakeError
	if !errors.As(err, &tlsErr) {
		return false
	}
	next, escalated := escalateTLSEvasion(hostKey, tlsErr.Kind)
	if escalated {
		reason := "reset"
		if tlsErr.Kind == tlsFailTimeout {
			reason = "handshake timeout"
		}
		logf("tls-evasion: %s hit %s -> escalating to %s", hostKey, reason, next)
	}
	return escalated
}

func remainingDialBudget(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		return time.Until(deadline)
	}
	return 5 * time.Second
}

type clientHelloSNIOffsets struct {
	beforeExtLenOff int // offset within handshake payload right before 2-byte extensions_length
	beforeSNIOff    int // offset within handshake payload at extension type 0x0000
	sniHostMidOff   int // offset splitting SNI host_name ASCII bytes in half
}

// parseClientHelloSNIOffsets locates extension and SNI hostname split offsets
// within a single TLS ClientHello record payload (offsets relative to payload[0]).
func parseClientHelloSNIOffsets(record []byte) (clientHelloSNIOffsets, bool) {
	var out clientHelloSNIOffsets
	if len(record) < 5+42 || record[0] != 0x16 {
		return out, false
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recLen < 42 || 5+recLen > len(record) {
		return out, false
	}
	payload := record[5 : 5+recLen]
	if payload[0] != 0x01 {
		return out, false
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if hsLen < 38 || 4+hsLen > len(payload) {
		return out, false
	}
	hsEnd := 4 + hsLen

	off := 4 + 2 + 32 // HandshakeHdr(4) + LegacyVersion(2) + Random(32)
	if off >= hsEnd {
		return out, false
	}
	sidLen := int(payload[off])
	off += 1 + sidLen
	if off+2 > hsEnd {
		return out, false
	}
	csLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2 + csLen
	if off >= hsEnd {
		return out, false
	}
	cmLen := int(payload[off])
	off += 1 + cmLen
	if off+2 > hsEnd {
		return out, false
	}
	out.beforeExtLenOff = off
	extTotal := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	extEnd := off + extTotal
	if extEnd > hsEnd {
		return out, false
	}

	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[off : off+2])
		extLen := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		if extLen < 0 || off+4+extLen > extEnd {
			return out, false
		}
		if extType == 0x0000 {
			out.beforeSNIOff = off
			sni := payload[off+4 : off+4+extLen]
			if len(sni) >= 5 {
				listLen := int(binary.BigEndian.Uint16(sni[0:2]))
				nameType := sni[2]
				nameLen := int(binary.BigEndian.Uint16(sni[3:5]))
				if 2+listLen <= len(sni) && nameType == 0x00 && nameLen >= 2 && 5+nameLen <= len(sni) {
					out.sniHostMidOff = off + 4 + 5 + nameLen/2
				}
			}
			return out, true
		}
		off += 4 + extLen
	}
	return out, out.beforeExtLenOff > 0
}

func chooseTLSSplitOffset(record []byte, profile tlsEvasionProfile) int {
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	off, ok := parseClientHelloSNIOffsets(record)
	switch profile {
	case tlsSplitSubHeader:
		return 2
	case tlsSplitMidSNI:
		if ok && off.sniHostMidOff > 0 && off.sniHostMidOff < recLen {
			return off.sniHostMidOff
		}
		if ok && off.beforeSNIOff > 0 && off.beforeSNIOff < recLen {
			return off.beforeSNIOff
		}
	case tlsSplitBeforeSNI, tlsSplitPreSNIPadding:
		if ok && off.beforeSNIOff > 0 && off.beforeSNIOff < recLen {
			return off.beforeSNIOff
		}
		if ok && off.beforeExtLenOff > 0 && off.beforeExtLenOff < recLen {
			return off.beforeExtLenOff
		}
	}
	mid := recLen / 2
	if mid < 1 {
		mid = 1
	}
	return mid
}

func writeAllBytes(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		buf = buf[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// tlsSplitConn fragments only the initial outgoing TLS ClientHello plaintext
// record, then flips passThrough to become a zero-allocation relay pass-through.
type tlsSplitConn struct {
	net.Conn
	profile     tlsEvasionProfile
	passThrough atomic.Bool
	mu          sync.Mutex
}

func newTLSSplitConn(conn net.Conn, profile tlsEvasionProfile) net.Conn {
	if conn == nil || profile == tlsSplitNone {
		return conn
	}
	return &tlsSplitConn{Conn: conn, profile: profile}
}

func (c *tlsSplitConn) Write(b []byte) (int, error) {
	if c.passThrough.Load() {
		return c.Conn.Write(b)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.passThrough.Load() {
		return c.Conn.Write(b)
	}
	// Permanently disable splitting after evaluating the first outgoing write
	// so encrypted HTTP upgrades and hot WebSocket/H2 frames take the fast path.
	c.passThrough.Store(true)

	if len(b) < 12 || b[0] != 0x16 || b[5] != 0x01 {
		return c.Conn.Write(b)
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 8 || recLen > 16384 || 5+recLen > len(b) {
		return c.Conn.Write(b)
	}

	splitAt := chooseTLSSplitOffset(b[:5+recLen], c.profile)
	if splitAt < 1 || splitAt >= recLen {
		return c.Conn.Write(b)
	}

	payload := b[5 : 5+recLen]
	part1 := payload[:splitAt]
	part2 := payload[splitAt:]
	trailing := b[5+recLen:]

	ver1Hi, ver1Lo := b[1], b[2]
	if c.profile == tlsSplitSubHeader {
		// CircumVolve heterogeneous record version pair across split boundary (RFC 8446 §5.1 safe).
		ver1Hi, ver1Lo = 0x03, 0x01
	}

	rec1 := make([]byte, 5+len(part1))
	rec1[0] = 0x16
	rec1[1] = ver1Hi
	rec1[2] = ver1Lo
	binary.BigEndian.PutUint16(rec1[3:5], uint16(len(part1)))
	copy(rec1[5:], part1)

	rec2 := make([]byte, 5+len(part2)+len(trailing))
	rec2[0] = 0x16
	rec2[1] = 0x03
	rec2[2] = 0x03
	binary.BigEndian.PutUint16(rec2[3:5], uint16(len(part2)))
	copy(rec2[5:], part2)
	copy(rec2[5+len(part2):], trailing)

	if err := writeAllBytes(c.Conn, rec1); err != nil {
		return 0, err
	}
	if err := writeAllBytes(c.Conn, rec2); err != nil {
		return 0, err
	}
	return len(b), nil
}

// applyPreSNIPadding places a single RFC 7685 padding extension right before
// SNIExtension when Pre-SNI padding is active, dropping any existing Chrome padding
// extension to avoid RFC 8446 duplicate-extension rejection.
func applyPreSNIPadding(conn *utls.UConn, profile tlsEvasionProfile) {
	if conn == nil || profile != tlsSplitPreSNIPadding {
		return
	}
	hasSNI := false
	for _, ext := range conn.Extensions {
		if _, ok := ext.(*utls.SNIExtension); ok {
			hasSNI = true
			break
		}
	}
	if !hasSNI {
		return
	}

	rebuilt := make([]utls.TLSExtension, 0, len(conn.Extensions)+1)
	inserted := false
	for _, ext := range conn.Extensions {
		if _, isPad := ext.(*utls.UtlsPaddingExtension); isPad {
			continue
		}
		if _, isSNI := ext.(*utls.SNIExtension); isSNI && !inserted {
			padLen := preSNIPaddingBytes
			rebuilt = append(rebuilt, &utls.UtlsPaddingExtension{
				PaddingLen: padLen,
				WillPad:    true,
				GetPaddingLen: func(int) (int, bool) {
					return padLen, true
				},
			})
			inserted = true
		}
		rebuilt = append(rebuilt, ext)
	}
	conn.Extensions = rebuilt
}
