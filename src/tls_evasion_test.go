package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func isolateTLSEvasionEnv(t *testing.T) string {
	t.Helper()
	logMu.Lock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
	logMu.Unlock()

	oldBase := getBaseDir()
	tmp := t.TempDir()
	setBaseDir(tmp)
	clearTLSEvasionState()
	cfgFileCache.mu.Lock()
	delete(cfgFileCache.entries, "fronting-sni")
	cfgFileCache.mu.Unlock()
	t.Cleanup(func() {
		logMu.Lock()
		if logFile != nil {
			_ = logFile.Close()
			logFile = nil
		}
		logMu.Unlock()
		clearTLSEvasionState()
		setBaseDir(oldBase)
		cfgFileCache.mu.Lock()
		delete(cfgFileCache.entries, "tls_evasion")
		delete(cfgFileCache.entries, "fronting-sni")
		cfgFileCache.mu.Unlock()
	})
	return tmp
}

func makeTestEphemeralCAAndCert(t *testing.T, dnsName string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TeleWEB Unit CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	leafCert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("load keypair: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, leafCert
}

type writeRecorderConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (w *writeRecorderConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	w.mu.Lock()
	w.writes = append(w.writes, cp)
	w.mu.Unlock()
	return w.Conn.Write(b)
}

func (w *writeRecorderConn) snapshotWrites() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.writes))
	copy(out, w.writes)
	return out
}

func countTLSExtension(record []byte, wantType uint16) (count int, firstOff int) {
	firstOff = -1
	if len(record) < 5+42 || record[0] != 0x16 {
		return 0, -1
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if 5+recLen > len(record) {
		return 0, -1
	}
	p := record[5 : 5+recLen]
	off := 4 + 2 + 32
	if off >= len(p) {
		return 0, -1
	}
	off += 1 + int(p[off])
	if off+2 > len(p) {
		return 0, -1
	}
	off += 2 + int(binary.BigEndian.Uint16(p[off:off+2]))
	if off >= len(p) {
		return 0, -1
	}
	off += 1 + int(p[off])
	if off+2 > len(p) {
		return 0, -1
	}
	extEnd := off + 2 + int(binary.BigEndian.Uint16(p[off:off+2]))
	off += 2
	if extEnd > len(p) {
		return 0, -1
	}
	for off+4 <= extEnd {
		t := binary.BigEndian.Uint16(p[off : off+2])
		l := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		if off+4+l > extEnd {
			break
		}
		if t == wantType {
			count++
			if firstOff < 0 {
				firstOff = off
			}
		}
		off += 4 + l
	}
	return count, firstOff
}

func TestTLSEvasionModeConfigAndAPI(t *testing.T) {
	isolateTLSEvasionEnv(t)

	if got := readTLSEvasionMode(); got != tlsEvasionModeAuto {
		t.Fatalf("expected default auto mode, got %q", got)
	}
	if err := writeTLSEvasionMode("bad-mode"); err == nil {
		t.Fatal("expected error for invalid tls_evasion mode")
	}

	splitVal := "always"
	if _, err := executeAPICommand(apiRequest{Cmd: "setConfig", TLSEvasion: &splitVal}); err != nil {
		t.Fatalf("setConfig always->split failed: %v", err)
	}
	if got := tlsEvasionModeCached(); got != tlsEvasionModeSplit {
		t.Fatalf("expected normalized split mode, got %q", got)
	}
	st := buildStatus(nil)
	if st.TLSEvasion != tlsEvasionModeSplit {
		t.Fatalf("expected Status.TLSEvasion=split, got %q", st.TLSEvasion)
	}

	offVal := "off"
	if _, err := executeAPICommand(apiRequest{Cmd: "setConfig", TLSEvasion: &offVal}); err != nil {
		t.Fatalf("setConfig off failed: %v", err)
	}
	if got := tlsProfileForHost("kws2.web.telegram.org"); got != tlsSplitNone {
		t.Fatalf("expected tlsSplitNone in off mode, got %v", got)
	}
}

func TestParseClientHelloSNIOffsetsAndBounds(t *testing.T) {
	host := "kws2.web.telegram.org"
	for _, id := range []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto} {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		rec := &writeRecorderConn{Conn: c1}
		uConn := utls.UClient(rec, &utls.Config{ServerName: host, NextProtos: []string{"http/1.1"}}, id)
		if err := prepareUTLSForHTTP1WithProfile(uConn, tlsSplitNone); err != nil {
			t.Fatalf("prepareUTLS failed for %v: %v", id, err)
		}

		go func() {
			_ = c2.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 4096)
			_, _ = c2.Read(buf)
			_ = c2.Close()
		}()
		_ = uConn.Handshake()

		writes := rec.snapshotWrites()
		if len(writes) == 0 {
			t.Fatalf("no ClientHello bytes captured for %v", id)
		}
		rawHello := writes[0]
		off, ok := parseClientHelloSNIOffsets(rawHello)
		if !ok {
			t.Fatalf("parseClientHelloSNIOffsets returned false for %v", id)
		}
		if off.beforeExtLenOff <= 40 || off.beforeSNIOff < off.beforeExtLenOff+2 || off.sniHostMidOff <= off.beforeSNIOff+9 {
			t.Fatalf("unexpected offsets for %v: %+v", id, off)
		}
		recLen := int(binary.BigEndian.Uint16(rawHello[3:5]))
		if off.sniHostMidOff >= recLen {
			t.Fatalf("sniHostMidOff=%d >= recLen=%d", off.sniHostMidOff, recLen)
		}
		payload := rawHello[5 : 5+recLen]
		halfHost := host[:len(host)/2]
		if !bytes.HasSuffix(payload[:off.sniHostMidOff], []byte(halfHost)) {
			t.Fatalf("expected midpoint split after %q, got tail %q", halfHost, payload[off.sniHostMidOff-len(halfHost):off.sniHostMidOff])
		}
	}

	// Malformed / truncated / missing SNI inputs must never panic.
	badInputs := [][]byte{
		nil,
		{},
		{0x17, 0x03, 0x03, 0x00, 0x10},
		make([]byte, 64),
	}
	badInputs[3][0] = 0x16
	badInputs[3][3] = 0x00
	badInputs[3][4] = 0x50 // declared length > buffer length
	badInputs[3][5] = 0x01
	for i, in := range badInputs {
		if _, ok := parseClientHelloSNIOffsets(in); ok {
			t.Fatalf("bad input #%d unexpectedly parsed as valid", i)
		}
	}
}

func TestTLSSplitConnWireAndHandshakeAllProfiles(t *testing.T) {
	isolateTLSEvasionEnv(t)
	const testHost = "kws2.dpi-test.internal"
	caPool, leafCert := makeTestEphemeralCAAndCert(t, testHost)

	profiles := []tlsEvasionProfile{
		tlsSplitNone,
		tlsSplitMidSNI,
		tlsSplitBeforeSNI,
		tlsSplitSubHeader,
		tlsSplitPreSNIPadding,
	}

	for _, prof := range profiles {
		t.Run(prof.String(), func(t *testing.T) {
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{leafCert},
				NextProtos:   []string{"http/1.1"},
			})
			if err != nil {
				t.Fatalf("tls.Listen failed: %v", err)
			}
			defer ln.Close()

			srvErr := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					srvErr <- err
					return
				}
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err != nil {
					srvErr <- err
					return
				}
				_, err = c.Write(buf)
				srvErr <- err
			}()

			raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer raw.Close()

			rec := &writeRecorderConn{Conn: raw}
			wrapped := newTLSSplitConn(rec, prof)
			uConn := utls.UClient(wrapped, &utls.Config{
				ServerName:         testHost,
				MinVersion:         utls.VersionTLS12,
				RootCAs:            caPool,
				InsecureSkipVerify: false,
				NextProtos:         []string{"http/1.1"},
				CurvePreferences:   []utls.CurveID{utls.X25519, utls.CurveP256},
			}, utls.HelloChrome_Auto)

			if err := prepareUTLSForHTTP1WithProfile(uConn, prof); err != nil {
				t.Fatalf("prepareUTLS failed: %v", err)
			}
			_ = uConn.SetDeadline(time.Now().Add(3 * time.Second))
			if err := uConn.HandshakeContext(context.Background()); err != nil {
				t.Fatalf("TLS handshake failed under profile %s: %v", prof, err)
			}
			if _, err := uConn.Write([]byte("PING")); err != nil {
				t.Fatalf("post-handshake write failed: %v", err)
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(uConn, echo); err != nil || string(echo) != "PING" {
				t.Fatalf("unexpected echo=%q err=%v", echo, err)
			}
			if err := <-srvErr; err != nil {
				t.Fatalf("server failed: %v", err)
			}

			writes := rec.snapshotWrites()
			if prof == tlsSplitNone {
				if len(writes) < 2 || writes[0][0] != 0x16 {
					t.Fatalf("unexpected non-split writes: %d", len(writes))
				}
				return
			}

			// First two wire writes must be split ClientHello TLS records.
			if len(writes) < 3 {
				t.Fatalf("expected >= 3 wire writes (2 ClientHello fragments + later AppData), got %d", len(writes))
			}
			rec1, rec2 := writes[0], writes[1]
			if rec1[0] != 0x16 || rec2[0] != 0x16 {
				t.Fatalf("expected 0x16 Handshake records, got 0x%02x / 0x%02x", rec1[0], rec2[0])
			}
			len1 := int(binary.BigEndian.Uint16(rec1[3:5]))
			if 5+len1 != len(rec1) {
				t.Fatalf("rec1 declared len %d != wire len %d", 5+len1, len(rec1))
			}
			if prof == tlsSplitSubHeader {
				if len1 != 2 {
					t.Fatalf("expected sub-header rec1 payload=2B, got %d", len1)
				}
				if rec1[1] != 0x03 || rec1[2] != 0x01 || rec2[1] != 0x03 || rec2[2] != 0x03 {
					t.Fatalf("unexpected heterogeneous record versions (%x %x / %x %x)", rec1[1], rec1[2], rec2[1], rec2[2])
				}
			}
			if prof == tlsSplitMidSNI {
				if bytes.Contains(rec1, []byte(testHost)) || bytes.Contains(rec2, []byte(testHost)) {
					t.Fatalf("full SNI %q leaked intact into one fragment", testHost)
				}
			}
			if prof == tlsSplitPreSNIPadding {
				if bytes.Contains(rec1, []byte(testHost)) {
					t.Fatalf("SNI %q must follow Pre-SNI padding in rec2, found in rec1", testHost)
				}
				len2 := int(binary.BigEndian.Uint16(rec2[3:5]))
				if 5+len2 != len(rec2) {
					t.Fatalf("rec2 declared len %d != wire len %d", 5+len2, len(rec2))
				}
				combined := make([]byte, 5+len1+len2)
				combined[0] = 0x16
				combined[1], combined[2] = rec1[1], rec1[2]
				binary.BigEndian.PutUint16(combined[3:5], uint16(len1+len2))
				copy(combined[5:], rec1[5:])
				copy(combined[5+len1:], rec2[5:])
				padCount, padOff := countTLSExtension(combined, 0x0015)
				sniCount, sniOff := countTLSExtension(combined, 0x0000)
				if padCount != 1 || sniCount != 1 {
					t.Fatalf("expected exactly 1 padding (0x0015) and 1 SNI (0x0000), got %d and %d", padCount, sniCount)
				}
				if padOff >= sniOff || sniOff < preSNIPaddingBytes {
					t.Fatalf("expected Pre-SNI padding before SNI with >=4096B shift: padOff=%d sniOff=%d", padOff, sniOff)
				}
			}
		})
	}
}

func TestDPIResetTriggersAutoEscalationAndBypass(t *testing.T) {
	isolateTLSEvasionEnv(t)
	const blockedHost = "kws2.dpi-e2e-unit.internal"
	caPool, leafCert := makeTestEphemeralCAAndCert(t, blockedHost)

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer tlsLn.Close()

	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err == nil {
					_, _ = conn.Write(buf)
				}
			}(c)
		}
	}()

	// Simulated DPI middlebox: resets connection when record 1 carries unfragmented SNI < 2048B.
	dpiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dpi listen failed: %v", err)
	}
	defer dpiLn.Close()

	go func() {
		for {
			cli, err := dpiLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 16384)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					_ = c.Close()
					return
				}
				pkt := buf[:n]
				if len(pkt) >= 9 && pkt[0] == 0x16 {
					recLen := int(binary.BigEndian.Uint16(pkt[3:5]))
					if 5+recLen <= len(pkt) {
						off, ok := parseClientHelloSNIOffsets(pkt[:5+recLen])
						if ok && off.beforeSNIOff > 0 && off.beforeSNIOff < 2048 && off.beforeSNIOff+4+len(blockedHost)+5 <= recLen && bytes.Contains(pkt[5:5+recLen], []byte(blockedHost)) {
							if tc, ok := c.(*net.TCPConn); ok {
								_ = tc.SetLinger(0)
							}
							_ = c.Close()
							return
						}
					}
				}
				backend, err := net.DialTimeout("tcp", tlsLn.Addr().String(), 2*time.Second)
				if err != nil {
					_ = c.Close()
					return
				}
				_, _ = backend.Write(pkt)
				go func() { _, _ = io.Copy(backend, c); _ = backend.Close() }()
				_, _ = io.Copy(c, backend)
				_ = c.Close()
			}(cli)
		}
	}()

	// Canceled caller context must never escalate host state.
	canceledCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn()
	<-canceledCtx.Done()
	if handleTLSHandshakeFailure(canceledCtx, blockedHost, &tlsHandshakeError{Kind: tlsFailReset, Err: syscall.ECONNRESET}) {
		t.Fatal("canceled context must not escalate TLS evasion")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var bypassed bool
	for attempt := 0; attempt < 2; attempt++ {
		prof := tlsProfileForHost(blockedHost)
		raw, err := net.DialTimeout("tcp", dpiLn.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial DPI middlebox failed: %v", err)
		}
		setConnSockOpts(raw)
		uConn := utls.UClient(newTLSSplitConn(raw, prof), &utls.Config{
			ServerName:         blockedHost,
			MinVersion:         utls.VersionTLS12,
			RootCAs:            caPool,
			InsecureSkipVerify: false,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_Auto)
		if err := prepareUTLSForHTTP1WithProfile(uConn, prof); err != nil {
			_ = raw.Close()
			t.Fatalf("prepareUTLS failed: %v", err)
		}
		_ = uConn.SetDeadline(time.Now().Add(2 * time.Second))
		err = uConn.HandshakeContext(ctx)
		if err == nil {
			if attempt == 0 {
				_ = uConn.Close()
				t.Fatal("attempt 0 unexpectedly bypassed DPI without escalation")
			}
			_, _ = uConn.Write([]byte("OKAY"))
			echo := make([]byte, 4)
			if _, rerr := io.ReadFull(uConn, echo); rerr != nil || string(echo) != "OKAY" {
				_ = uConn.Close()
				t.Fatalf("post-bypass echo failed: %q %v", echo, rerr)
			}
			_ = uConn.Close()
			bypassed = true
			break
		}
		_ = raw.Close()
		wrapped := &tlsHandshakeError{Kind: classifyTLSHandshakeErr(err), Err: err}
		if !errors.Is(wrapped, err) {
			t.Fatal("tlsHandshakeError must unwrap underlying error")
		}
		if !handleTLSHandshakeFailure(ctx, blockedHost, wrapped) {
			t.Fatalf("expected auto-escalation on DPI reset error (%v)", err)
		}
	}
	if !bypassed {
		t.Fatal("expected attempt 1 to bypass simulated DPI after escalation")
	}
}

func TestStdTLSWrapperAndCandidateRetention(t *testing.T) {
	isolateTLSEvasionEnv(t)

	// Nil and clean connections must pass through unmodified.
	if wrapStdTLSConn(nil, "example.com") != nil {
		t.Fatal("expected nil pass-through")
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if got := wrapStdTLSConn(c1, "example.com"); got != c1 {
		t.Fatal("expected unwrapped net.Conn when profile is tlsSplitNone")
	}
	if got := effectiveStdTLSProfile(tlsSplitPreSNIPadding); got != tlsSplitBeforeSNI {
		t.Fatalf("expected PreSNIPadding to adapt to BeforeSNI for stdlib crypto/tls, got %v", got)
	}
	if err := writeTLSEvasionMode(tlsEvasionModeSplit); err != nil {
		t.Fatalf("write split failed: %v", err)
	}
	if got := wrapStdTLSConn(c1, "example.com"); got == c1 {
		t.Fatal("expected tlsSplitConn wrapper when tls_evasion=split")
	}

	// Non-English Windows socket reset errnos (WSAECONNRESET=10054) must classify deterministically.
	if got := classifyTLSHandshakeErr(syscall.Errno(10054)); got != tlsFailReset {
		t.Fatalf("expected WSAECONNRESET(10054) -> tlsFailReset, got %v", got)
	}

	// AGENTS.md §5.3: Exhausted TLS reset parked via noteRouteHTTPFailure must still
	// preserve at least 1 candidate from frontCandidatesForRace.
	domains := []string{"front-a.example.com", "front-b.example.com"}
	routeKeys := []string{"kws2.front-a.example.com", "kws2.front-b.example.com"}
	routeHealthMu.Lock()
	oldHealth := make(map[string]routeHealthState, len(routeKeys))
	for _, h := range routeKeys {
		if st, ok := routeHealth[h]; ok {
			oldHealth[h] = st
		}
		delete(routeHealth, h)
	}
	routeHealthMu.Unlock()
	defer func() {
		routeHealthMu.Lock()
		for _, h := range routeKeys {
			if st, ok := oldHealth[h]; ok {
				routeHealth[h] = st
			} else {
				delete(routeHealth, h)
			}
		}
		routeHealthMu.Unlock()
	}()

	for _, h := range routeKeys {
		noteRouteHTTPFailure(h, &tlsHandshakeError{Kind: tlsFailReset, Err: syscall.ECONNRESET})
	}
	cands := frontCandidatesForRace(2, domains, 0, maxFrontsPerRace)
	if len(cands) == 0 {
		t.Fatal("frontCandidatesForRace returned 0 candidates after TLS reset parks (violates Invariant 3)")
	}
	if !strings.HasPrefix(cands[0], "kws2.front-") {
		t.Fatalf("unexpected candidate %q", cands[0])
	}
}
