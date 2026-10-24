package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestParseProcCgroups(t *testing.T) {
	input := "12:cpuset:/top-app\n0::/uid_10123/pid_456\n7:freezer:/apps\ninvalid\n"
	got := parseProcCgroups(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 cgroup entries, got %d: %#v", len(got), got)
	}
	if got[0].hierarchy != "12" || got[0].controllers != "cpuset" || got[0].path != "/top-app" {
		t.Fatalf("unexpected cpuset entry: %#v", got[0])
	}
	if got[1].hierarchy != "0" || got[1].controllers != "" || got[1].path != "/uid_10123/pid_456" {
		t.Fatalf("unexpected unified entry: %#v", got[1])
	}
	if got[2].controllers != "freezer" || got[2].path != "/apps" {
		t.Fatalf("unexpected freezer entry: %#v", got[2])
	}
}

func TestParseProcCgroupsNormalizesRootAndPath(t *testing.T) {
	got := parseProcCgroups("0::/\n1:cpuset:////system/../top-app\n")
	if len(got) != 2 || got[0].path != "/" || got[1].path != "/top-app" {
		t.Fatalf("unexpected normalized entries: %#v", got)
	}
}

func TestWebSocketHostForDC(t *testing.T) {
	want := map[int]string{
		1: "kws1.web.telegram.org",
		2: "kws2.web.telegram.org",
		3: "kws3.web.telegram.org",
		4: "kws4.web.telegram.org",
		5: "kws5.web.telegram.org",
	}
	for dc, host := range want {
		if got := wsHostForDC(dc); got != host {
			t.Errorf("wsHostForDC(%d)=%q, want %q", dc, got, host)
		}
	}
	if got := wsHostForDC(0); got != "" {
		t.Errorf("invalid DC host=%q, want empty", got)
	}
	if got := wsHostsForDC(4, true); len(got) != 2 || got[0] != "kws4-1.web.telegram.org" || got[1] != "kws4.web.telegram.org" {
		t.Errorf("media hosts=%v, want kws4-1 then kws4", got)
	}
	if got := wsHostsForDC(5, true); len(got) != 2 || got[0] != "kws5-1.web.telegram.org" || got[1] != "kws5.web.telegram.org" {
		t.Errorf("DC5 media hosts=%v, want kws5-1 then kws5", got)
	}
}

func TestPreferredIngressForDC(t *testing.T) {
	want := map[int]string{1: "149.154.175.50", 2: "149.154.167.220", 3: "", 4: "149.154.167.220", 5: ""}
	for dc, expected := range want {
		if got := preferredIngressForDC(dc); got != expected {
			t.Errorf("preferredIngressForDC(%d)=%q, want %q", dc, got, expected)
		}
	}
}

func TestDCMappingKnownAddresses(t *testing.T) {
	cases := map[string]int{
		"149.154.175.54":  1,
		"149.154.167.51":  2,
		"149.154.175.211": 1,
		"91.108.56.100":   5,
		"91.108.56.193":   5,
		"149.154.167.41":  2,
		"149.154.167.35":  2,
		"149.154.167.222": 2,
		"149.154.167.223": 2,
		"149.154.167.255": 4,
		"149.154.166.120": 4,
		"149.154.164.250": 4,
		"149.154.171.5":   5,
		"149.154.171.255": 5,
		"149.154.168.1":   5,
		"149.154.170.100": 5,
		"149.154.165.136": 4,
		"149.154.160.1":   2,
		"149.154.161.10":  2,
		"149.154.162.1":   2,
		"149.154.163.254": 2,
		"185.76.151.10":   2,
		"91.105.192.50":   2,
	}
	for raw, want := range cases {
		if got := dcFor(netip.MustParseAddr(raw)); got != want {
			t.Errorf("dcFor(%s)=%d, want %d", raw, got, want)
		}
	}
	// Linux SO_ORIGINAL_DST can represent an IPv4 destination as an
	// IPv4-mapped IPv6 address. Verify normalization for every DC.
	mapped := map[string]int{
		"::ffff:149.154.175.54":  1,
		"::ffff:149.154.167.51":  2,
		"::ffff:149.154.175.211": 1,
		"::ffff:149.154.167.223": 2,
		"::ffff:91.108.56.193":   5,
		"::ffff:149.154.171.5":   5,
		"::ffff:149.154.171.255": 5,
	}
	for raw, want := range mapped {
		if got := dcFor(netip.MustParseAddr(raw)); got != want {
			t.Errorf("dcFor(%s)=%d, want %d", raw, got, want)
		}
	}
}

func TestMediaIPClassification(t *testing.T) {
	cases := map[string]bool{
		"149.154.165.136": true,
		"149.154.165.111": true,
		"149.154.171.255": true,
		"149.154.167.41":  false,
		"149.154.175.211": true,
	}
	for raw, want := range cases {
		if got := mediaForIP(netip.MustParseAddr(raw)); got != want {
			t.Errorf("mediaForIP(%s)=%t, want %t", raw, got, want)
		}
	}
}

func TestMTProtoPacketFramerAbridgedPacketBoundaries(t *testing.T) {
	// Construct an obfuscated2 header whose decrypted tag is abridged. The
	// header bytes 0:56 are the key/IV material; bytes 56:64 are CTR-encrypted.
	init := make([]byte, 64)
	for i := 0; i < 56; i++ {
		init[i] = byte(i + 1)
	}
	key := init[8:40]
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ctr := cipher.NewCTR(block, init[40:56])
	ctr.XORKeyStream(make([]byte, 56), make([]byte, 56))
	plainTail := make([]byte, 8)
	binary.LittleEndian.PutUint32(plainTail[:4], 0xEFEFEFEF)
	// Use random DC bytes, as WSS relay hostnames carry the DC identity.
	plainTail[4], plainTail[5] = 0x12, 0x34
	ctr.XORKeyStream(init[56:], plainTail)

	f, err := newMTProtoPacketFramer(init)
	if err != nil {
		t.Fatal(err)
	}
	// Two abridged packets: one 4-byte payload (1 word), then two words.
	packets := []byte{1, 1, 2, 3, 4, 2, 5, 6, 7, 8, 9, 10, 11, 12}
	key = init[8:40]
	block, _ = aes.NewCipher(key)
	stream := cipher.NewCTR(block, init[40:56])
	stream.XORKeyStream(make([]byte, 64), make([]byte, 64))
	encrypted := make([]byte, len(packets))
	stream.XORKeyStream(encrypted, packets)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ws := &wsConn{conn: client, r: bufio.NewReader(client)}
	feedDone := make(chan error, 1)
	go func() { feedDone <- f.feed(encrypted, ws) }()
	br := bufio.NewReader(server)
	readFrame := func() []byte {
		h := make([]byte, 2)
		if _, err := io.ReadFull(br, h); err != nil {
			t.Fatal(err)
		}
		n := int(h[1] & 0x7f)
		if n == 126 {
			var x [2]byte
			if _, err := io.ReadFull(br, x[:]); err != nil {
				t.Fatal(err)
			}
			n = int(binary.BigEndian.Uint16(x[:]))
		}
		var mask [4]byte
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			t.Fatal(err)
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(br, p); err != nil {
			t.Fatal(err)
		}
		for i := range p {
			p[i] ^= mask[i&3]
		}
		return p
	}
	first := readFrame()
	if len(first) != 69 || string(first[:64]) != string(init) || string(first[64:]) != string(encrypted[:5]) {
		t.Fatalf("first frame length/content mismatch: %d", len(first))
	}
	second := readFrame()
	if string(second) != string(encrypted[5:]) {
		t.Fatalf("second frame content mismatch: %x", second)
	}
	client.Close()
	if err := <-feedDone; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestAbridgedQuickAckLengthMarkers(t *testing.T) {
	tests := []struct {
		name  string
		plain []byte
		want  int
	}{
		{name: "short quick ack", plain: []byte{0x81, 1, 2, 3, 4}, want: 5},
		{name: "short max quick ack", plain: append([]byte{0xfe}, make([]byte, 126*4)...), want: 1 + 126*4},
		{name: "extended quick ack", plain: append([]byte{0xff, 127, 0, 0}, make([]byte, 127*4)...), want: 4 + 127*4},
		{name: "extended ordinary", plain: append([]byte{0x7f, 127, 0, 0}, make([]byte, 127*4)...), want: 4 + 127*4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &mtprotoPacketFramer{proto: 0xEFEFEFEF, plain: tt.plain}
			got, ready, err := f.nextPacketSize()
			if err != nil {
				t.Fatalf("nextPacketSize() error: %v", err)
			}
			if !ready || got != tt.want {
				t.Fatalf("nextPacketSize()=(%d, %t), want (%d, true)", got, ready, tt.want)
			}
		})
	}
}

func TestWebSocketClientFrameAndServerFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	w := &wsConn{conn: client, r: bufio.NewReader(client)}
	payload := []byte("telegram-frame-payload")
	writeDone := make(chan error, 1)
	go func() { writeDone <- w.writeFrame(2, payload) }()
	br := bufio.NewReader(server)
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x82 || h[1]&0x80 == 0 {
		t.Fatalf("unexpected client frame header: %x", h)
	}
	n := uint64(h[1] & 0x7f)
	if n == 126 {
		var x [2]byte
		if _, err := io.ReadFull(br, x[:]); err != nil {
			t.Fatal(err)
		}
		n = uint64(binary.BigEndian.Uint16(x[:]))
	}
	if n != uint64(len(payload)) {
		t.Fatalf("length=%d, want %d", n, len(payload))
	}
	var mask [4]byte
	if _, err := io.ReadFull(br, mask[:]); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i] ^= mask[i&3]
	}
	if string(got) != string(payload) {
		t.Fatalf("payload=%q, want %q", got, payload)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	// A server-to-client frame is not masked.
	go func() { _, _ = server.Write([]byte{0x82, byte(len(payload))}); _, _ = server.Write(payload) }()
	op, got, err := w.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if op != 2 || string(got) != string(payload) {
		t.Fatalf("got opcode=%d payload=%q", op, got)
	}
}

func TestWebSocketFragmentedServerMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	w := &wsConn{conn: client, r: bufio.NewReader(client)}
	go func() {
		_, _ = server.Write([]byte{0x02, 0x03, 'a', 'b', 'c'}) // non-final binary
		_, _ = server.Write([]byte{0x80, 0x03, 'd', 'e', 'f'}) // final continuation
	}()
	op, payload, err := w.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if op != 2 || string(payload) != "abcdef" {
		t.Fatalf("got opcode=%d payload=%q", op, payload)
	}
}

func TestWebSocketUpgradeHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		r := bufio.NewReader(server)
		req, err := http.ReadRequest(r)
		if err != nil {
			serverErr <- err
			return
		}
		if req.URL.Path != "/apiws" || req.Header.Get("Sec-WebSocket-Protocol") != "binary" || req.Header.Get("Origin") != "https://web.telegram.org" {
			serverErr <- fmt.Errorf("bad request: %s, protocol=%q", req.URL.Path, req.Header.Get("Sec-WebSocket-Protocol"))
			return
		}
		accept := base64.StdEncoding.EncodeToString(sha1Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID)))
		_, err = fmt.Fprintf(server, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: binary\r\n\r\n", accept)
		serverErr <- err
	}()
	ws, err := websocketUpgrade(client, "pluto.web.telegram.org")
	if err != nil {
		t.Fatal(err)
	}
	if ws == nil {
		t.Fatal("websocketUpgrade returned nil")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestParseMTProtoDCAndMediaFlag(t *testing.T) {
	makeInit := func(dcIndex int16) []byte {
		init := make([]byte, 64)
		for i := range init {
			init[i] = byte(i*13 + 7)
		}
		key := init[8:40]
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		stream := cipher.NewCTR(block, init[40:56])
		stream.XORKeyStream(make([]byte, 56), make([]byte, 56))
		keystream := make([]byte, 8)
		stream.XORKeyStream(keystream, make([]byte, 8))
		plainTail := make([]byte, 8)
		binary.LittleEndian.PutUint32(plainTail[:4], 0xEEEEEEEE)
		binary.LittleEndian.PutUint16(plainTail[4:6], uint16(dcIndex))
		for i := 0; i < 8; i++ {
			init[56+i] = plainTail[i] ^ keystream[i]
		}
		return init
	}
	if dc, media, ok := parseMTProtoDC(makeInit(2)); !ok || dc != 2 || media {
		t.Fatalf("normal DC parse=(%d,%t,%t)", dc, media, ok)
	}
	if dc, media, ok := parseMTProtoDC(makeInit(-4)); !ok || dc != 4 || !media {
		t.Fatalf("media DC parse=(%d,%t,%t)", dc, media, ok)
	}
}

func TestCFDomainListValidation(t *testing.T) {
	oldDir := baseDir
	tmp := t.TempDir()
	baseDir = tmp
	defer func() { baseDir = oldDir }()
	if err := os.WriteFile(filepath.Join(tmp, "cf-domains"), []byte("# comment\nexample.org\ninvalid domain\nexample.org\nweb.telegram.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := cfDomains()
	if len(got) != 1 || got[0] != "example.org" {
		t.Fatalf("cfDomains()=%v, want [example.org]", got)
	}
}

func TestRepeatedEarlyEOFTemporarilyCoolsRoute(t *testing.T) {
	host := "kws2.test-route-cooldown.invalid"
	key := "2:false:test-route-cooldown"
	routeHealthMu.Lock()
	delete(routeHealth, host)
	routeHealthMu.Unlock()
	defer func() {
		routeHealthMu.Lock()
		delete(routeHealth, host)
		routeHealthMu.Unlock()
	}()
	if routeCoolingDown(host) {
		t.Fatal("route should not start in cooldown")
	}
	noteEarlyRemoteClose(key, host, io.EOF, 5*time.Second, 300, 178)
	if routeCoolingDown(host) {
		t.Fatal("route should not cool down after only one early EOF")
	}
	noteEarlyRemoteClose(key, host, io.EOF, 5*time.Second, 300, 178)
	if !routeCoolingDown(host) {
		t.Fatal("two early EOFs should cool down route")
	}
}

func TestAppProcessMatches(t *testing.T) {
	cases := []struct {
		cmd, pkg string
		want     bool
	}{
		{"com.exteragram.messenger\x00", "com.exteragram.messenger", true},
		{"com.exteragram.messenger:push\x00", "com.exteragram.messenger", true},
		{"com.exteragram.messenger2", "com.exteragram.messenger", false},
		{"org.telegram.messenger", "com.exteragram.messenger", false},
		{"org.nemogram.messenger\x00", "org.nemogram.messenger", true},
		{"org.nemogram\x00", "org.nemogram", true},
	}
	for _, tc := range cases {
		if got := appProcessMatches(tc.cmd, tc.pkg); got != tc.want {
			t.Errorf("appProcessMatches(%q,%q)=%t want %t", tc.cmd, tc.pkg, got, tc.want)
		}
	}
}

func TestDecodeCFProxyDomain(t *testing.T) {
	cases := map[string]string{
		"virkgj.com":     "pclead.co.uk",
		"vmmzovy.com":    "offshor.co.uk",
		"mkuosckvso.com": "cakeisalie.co.uk",
		"custom.org":     "custom.org",
	}
	for in, want := range cases {
		if got := decodeCFProxyDomain(in); got != want {
			t.Errorf("decodeCFProxyDomain(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestDC203Normalization(t *testing.T) {
	makeInit := func(dcIndex int16) []byte {
		init := make([]byte, 64)
		for i := range init {
			init[i] = byte(i*13 + 7)
		}
		key := init[8:40]
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		stream := cipher.NewCTR(block, init[40:56])
		stream.XORKeyStream(make([]byte, 56), make([]byte, 56))
		keystream := make([]byte, 8)
		stream.XORKeyStream(keystream, make([]byte, 8))
		plainTail := make([]byte, 8)
		binary.LittleEndian.PutUint32(plainTail[:4], 0xEEEEEEEE)
		binary.LittleEndian.PutUint16(plainTail[4:6], uint16(dcIndex))
		for i := 0; i < 8; i++ {
			init[56+i] = plainTail[i] ^ keystream[i]
		}
		return init
	}
	dc, isMedia, ok := parseMTProtoDC(makeInit(203))
	if !ok || dc != 203 || isMedia {
		t.Fatalf("DC 203 detection failed: dc=%d isMedia=%t ok=%t", dc, isMedia, ok)
	}
	dc, isMedia, ok = parseMTProtoDC(makeInit(-203))
	if !ok || dc != 203 || !isMedia {
		t.Fatalf("DC -203 media detection failed: dc=%d isMedia=%t ok=%t", dc, isMedia, ok)
	}
}

func TestFrontingSNIConfig(t *testing.T) {
	oldDir := baseDir
	tmp := t.TempDir()
	baseDir = tmp
	defer func() { baseDir = oldDir }()

	if got := configuredFrontingSNI(); got != "" {
		t.Errorf("expected empty fronting SNI, got %q", got)
	}
	_ = os.WriteFile(filepath.Join(tmp, "fronting-sni"), []byte("sprinthost.ru\n"), 0600)
	if got := configuredFrontingSNI(); got != "sprinthost.ru" {
		t.Errorf("expected sprinthost.ru, got %q", got)
	}
	_ = os.WriteFile(filepath.Join(tmp, "fronting-sni"), []byte("disable\n"), 0600)
	if got := configuredFrontingSNI(); got != "" {
		t.Errorf("expected disabled fronting SNI, got %q", got)
	}
}

func TestPackageNamesValidity(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range packageNames {
		if p.Pkg == "" || p.Name == "" {
			t.Errorf("empty package or name: %#v", p)
		}
		if seen[p.Pkg] {
			t.Errorf("duplicate package in packageNames: %s", p.Pkg)
		}
		seen[p.Pkg] = true
		if strings.ContainsAny(p.Pkg, " ,;:/\\") {
			t.Errorf("invalid character in package name: %s", p.Pkg)
		}
	}
	if len(packageNames) < 15 {
		t.Errorf("expected at least 15 supported packages, got %d", len(packageNames))
	}
}

func TestSystemRootCAs(t *testing.T) {
	pool := getSystemRootCAs()
	if pool == nil {
		t.Fatal("expected non-nil system root CA pool")
	}
}

func TestAndroidDNSServersCaching(t *testing.T) {
	servers1 := androidDNSServers()
	if len(servers1) == 0 {
		t.Fatal("expected at least fallback DNS servers")
	}
	foundYandex := false
	for _, s := range servers1 {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.IsValid() {
			t.Errorf("invalid DNS server IP: %s", s)
		}
		if s == "77.88.8.8" {
			foundYandex = true
		}
	}
	if !foundYandex {
		t.Error("expected 77.88.8.8 in DNS server list")
	}

	servers2 := androidDNSServers()
	if len(servers1) != len(servers2) {
		t.Errorf("cached server list length mismatch: %d vs %d", len(servers1), len(servers2))
	}
}

func TestMTProtoIntermediateAndPaddedTransport(t *testing.T) {
	for _, proto := range []uint32{0xEEEEEEEE, 0xDDDDDDDD} {
		// Valid intermediate packet: 4 bytes length (e.g., 16) + 16 bytes payload = 20 bytes total
		payloadLen := uint32(16)
		plain := make([]byte, 4+payloadLen)
		binary.LittleEndian.PutUint32(plain[:4], payloadLen)
		for i := 4; i < len(plain); i++ {
			plain[i] = byte(i)
		}

		f := &mtprotoPacketFramer{proto: proto, plain: plain}
		total, ready, err := f.nextPacketSize()
		if err != nil {
			t.Fatalf("proto %#x: nextPacketSize error: %v", proto, err)
		}
		if !ready {
			t.Fatalf("proto %#x: expected ready=true", proto)
		}
		if total != 20 {
			t.Fatalf("proto %#x: expected total=20, got %d", proto, total)
		}

		// Partial packet (< 4 bytes)
		fPartial := &mtprotoPacketFramer{proto: proto, plain: plain[:2]}
		total, ready, err = fPartial.nextPacketSize()
		if err != nil || ready || total != 0 {
			t.Fatalf("proto %#x partial: expected ready=false, got ready=%t, total=%d, err=%v", proto, ready, total, err)
		}

		// Zero length packet must return error
		zeroPlain := make([]byte, 4)
		fZ := &mtprotoPacketFramer{proto: proto, plain: zeroPlain}
		_, _, err = fZ.nextPacketSize()
		if err == nil {
			t.Fatalf("proto %#x: expected error on zero-length packet", proto)
		}
	}
}

func TestNoteRouteHTTPFailureCooldown(t *testing.T) {
	testHost := "badhost-test.invalid"
	if routeCoolingDown(testHost) {
		t.Fatalf("host %s should not be cooling down initially", testHost)
	}

	// Non-5xx error should NOT trigger cooldown
	noteRouteHTTPFailure(testHost, errors.New("HTTP 404 Not Found"))
	if routeCoolingDown(testHost) {
		t.Fatalf("host %s should not cool down on HTTP 404", testHost)
	}

	// HTTP 502 Bad Gateway MUST trigger cooldown
	noteRouteHTTPFailure(testHost, errors.New("HTTP 502 Bad Gateway: upstream connect error"))
	if !routeCoolingDown(testHost) {
		t.Fatalf("host %s must cool down after HTTP 502", testHost)
	}

	// HTTP 503 Service Unavailable MUST trigger cooldown
	testHost503 := "badhost-503.invalid"
	noteRouteHTTPFailure(testHost503, errors.New("HTTP 503 Service Unavailable"))
	if !routeCoolingDown(testHost503) {
		t.Fatalf("host %s must cool down after HTTP 503", testHost503)
	}
}

func TestRouteCachePersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "teleweb-route-cache-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origBase := baseDir
	baseDir = tmpDir
	defer func() { baseDir = origBase }()

	testKey := "2"
	testHost := "kws2.testpersist.co.uk"
	testCandidates := []routeCandidate{
		{host: "kws2.testpersist.co.uk", latency: 45 * time.Millisecond},
		{host: "kws2.fallbackpersist.co.uk", latency: 70 * time.Millisecond},
	}

	saveRouteCache(testKey, testHost, testCandidates)

	cacheFile := filepath.Join(tmpDir, "route-cache.json")
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("expected route-cache.json to exist: %v", err)
	}

	// Clear memory state before load
	cfHostCache.Delete(testKey)
	routeChoice.Delete(testKey)
	routePool.Delete(testKey)

	loadRouteCache()

	v, ok := cfHostCache.Load(testKey)
	if !ok || v.(string) != testHost {
		t.Fatalf("expected cached host %s, got %#v", testHost, v)
	}

	pooled, ok := routePool.Load(testKey)
	if !ok {
		t.Fatalf("expected routePool for %s", testKey)
	}
	candidates, ok := pooled.([]routeCandidate)
	if !ok || len(candidates) != 2 {
		t.Fatalf("expected 2 candidates in routePool, got %#v", pooled)
	}
	if candidates[0].host != testCandidates[0].host || candidates[0].latency != testCandidates[0].latency {
		t.Errorf("candidate 0 mismatch: %#v vs %#v", candidates[0], testCandidates[0])
	}
}

func TestCustomCFDomainPrecedence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "teleweb-custom-domain-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origBase := baseDir
	baseDir = tmpDir
	defer func() { baseDir = origBase }()

	if got := readCustomCFDomain(); got != "" {
		t.Errorf("expected empty custom domain initially, got %s", got)
	}

	custom := "my-custom-cf.workers.dev"
	if err := writeCustomCFDomain(custom); err != nil {
		t.Fatalf("failed to write custom domain: %v", err)
	}

	if got := readCustomCFDomain(); got != custom {
		t.Fatalf("readCustomCFDomain() = %q, want %q", got, custom)
	}

	domains := cfDomains()
	if len(domains) == 0 {
		t.Fatal("expected non-empty domains list")
	}
	if domains[0] != custom {
		t.Errorf("expected custom domain %q as first element, got %q", custom, domains[0])
	}

	// Clearing custom domain
	if err := writeCustomCFDomain(""); err != nil {
		t.Fatalf("failed to clear custom domain: %v", err)
	}
	if got := readCustomCFDomain(); got != "" {
		t.Errorf("expected empty domain after clear, got %s", got)
	}
}

func TestDCOverridesParsing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "teleweb-dc-overrides-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origBase := baseDir
	baseDir = tmpDir
	defer func() { baseDir = origBase }()

	input := "1:149.154.175.55, 2:149.154.167.50, 4:149.154.167.99"
	if err := writeDCOverrides(input); err != nil {
		t.Fatalf("writeDCOverrides failed: %v", err)
	}

	overrides := readDCOverrides()
	if len(overrides) != 3 {
		t.Fatalf("expected 3 overrides, got %d: %#v", len(overrides), overrides)
	}
	if overrides[1] != "149.154.175.55" || overrides[2] != "149.154.167.50" || overrides[4] != "149.154.167.99" {
		t.Errorf("overrides mismatch: %#v", overrides)
	}

	// Check preferredIngressForDC respects override
	if got := preferredIngressForDC(1); got != "149.154.175.55" {
		t.Errorf("preferredIngressForDC(1) = %q, want %q", got, "149.154.175.55")
	}

	// Invalid input format validation
	badInput := "99:not-an-ip"
	if err := writeDCOverrides(badInput); err == nil {
		t.Error("expected error on invalid DC override input")
	}
}

func TestCFPriorityAndBalanceStorage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "teleweb-flags-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origBase := baseDir
	baseDir = tmpDir
	defer func() { baseDir = origBase }()

	if readCFPriority() {
		t.Error("expected cfPriority to be false by default")
	}
	if err := writeCFPriority(true); err != nil {
		t.Fatal(err)
	}
	if !readCFPriority() {
		t.Error("expected cfPriority to be true after write")
	}

	if readCFBalance() {
		t.Error("expected cfBalance to be false by default")
	}
	if err := writeCFBalance(true); err != nil {
		t.Fatal(err)
	}
	if !readCFBalance() {
		t.Error("expected cfBalance to be true after write")
	}
}

func TestApiMainSetConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "teleweb-api-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origBase := baseDir
	baseDir = tmpDir
	defer func() { baseDir = origBase }()

	cfPri := true
	cfBal := true
	customDom := "worker.test-api.co.uk"
	dcOver := "1:149.154.175.50, 2:149.154.167.220"

	req := apiRequest{
		Cmd:            "setConfig",
		CFPriority:     &cfPri,
		CFBalance:      &cfBal,
		CustomCFDomain: &customDom,
		DCOverrides:    &dcOver,
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(b)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	apiMain(encoded)

	w.Close()
	os.Stdout = oldStdout
	outBytes, _ := io.ReadAll(r)

	var resp struct {
		OK   bool   `json:"ok"`
		Data Status `json:"data"`
	}
	if err := json.Unmarshal(outBytes, &resp); err != nil {
		t.Fatalf("failed to parse API response: %v, raw: %s", err, string(outBytes))
	}
	if !resp.OK {
		t.Fatalf("expected ok=true in API response, got: %s", string(outBytes))
	}
	if !resp.Data.CFPriority || !resp.Data.CFBalance || resp.Data.CustomCFDomain != customDom || resp.Data.DCOverrides != dcOver {
		t.Errorf("status data mismatch in API response: %#v", resp.Data)
	}

	if !readCFPriority() || !readCFBalance() || readCustomCFDomain() != customDom || readDCOverridesRaw() != dcOver {
		t.Errorf("persisted configuration mismatch: cfPriority=%t cfBalance=%t customDomain=%s dcOverrides=%s",
			readCFPriority(), readCFBalance(), readCustomCFDomain(), readDCOverridesRaw())
	}
}

func TestCandidateIngressesForDC(t *testing.T) {
	dc2Candidates := candidateIngressesForDC(2)
	if len(dc2Candidates) < 4 {
		t.Fatalf("expected at least 4 candidates for DC2, got %d: %#v", len(dc2Candidates), dc2Candidates)
	}
	expectedDC2 := []string{"149.154.167.220", "149.154.167.51", "149.154.167.50", "149.154.167.41"}
	for _, exp := range expectedDC2 {
		found := false
		for _, cand := range dc2Candidates {
			if cand == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DC2 candidates missing expected IP %s: got %#v", exp, dc2Candidates)
		}
	}

	dc1Candidates := candidateIngressesForDC(1)
	if len(dc1Candidates) < 3 || dc1Candidates[0] != "149.154.175.50" {
		t.Errorf("unexpected DC1 candidates: %#v", dc1Candidates)
	}
}

func TestIsNeutralError(t *testing.T) {
	neutralErrors := []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		net.ErrClosed,
		context.Canceled,
		errors.New("read: connection reset by peer"),
		errors.New("wsarecv: An existing connection was forcibly closed by the remote host."),
		errors.New("write: broken pipe"),
		errors.New("use of closed network connection"),
		errors.New("client_eof"),
	}
	for _, err := range neutralErrors {
		if !isNeutralError(err) {
			t.Errorf("expected error %v (%T) to be classified as neutral", err, err)
		}
	}

	fatalErrors := []error{
		nil,
		errors.New("HTTP 502 Bad Gateway"),
		errors.New("HTTP 429 Too Many Requests"),
		errors.New("dial tcp: lookup fail.example.com: no such host"),
		errors.New("TLS handshake failed: remote error: tls: handshake failure"),
	}
	for _, err := range fatalErrors {
		if isNeutralError(err) {
			t.Errorf("did not expect error %v to be classified as neutral", err)
		}
	}
}

func TestDynamicCloudflareCooldown(t *testing.T) {
	// Test HTTP 429 triggers 3-minute cooldown
	host429 := "cooldown-429.invalid"
	noteRouteHTTPFailure(host429, errors.New("HTTP 429 Too Many Requests: error code: 1015"))
	if !routeCoolingDown(host429) {
		t.Fatalf("host %s must cool down after HTTP 429", host429)
	}

	// Test HTTP 403 triggers 3-minute cooldown
	host403 := "cooldown-403.invalid"
	noteRouteHTTPFailure(host403, errors.New("HTTP 403 Forbidden: Cloudflare 1020 access denied"))
	if !routeCoolingDown(host403) {
		t.Fatalf("host %s must cool down after HTTP 403", host403)
	}

	// Test Timeout triggers 45-second cooldown
	hostTimeout := "cooldown-timeout.invalid"
	noteRouteHTTPFailure(hostTimeout, errors.New("dial tcp4 104.21.1.1:443: i/o timeout"))
	if !routeCoolingDown(hostTimeout) {
		t.Fatalf("host %s must cool down after dial timeout", hostTimeout)
	}
}

func TestSetConnSockOpts(t *testing.T) {
	// Must not panic on nil
	setConnSockOpts(nil)

	// Must handle non-TCP (pipe) gracefully without panic
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	setConnSockOpts(c1)
	setConnSockOpts(c2)
}

func TestPrepareUTLSForHTTP1(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uConfig := &utls.Config{
		ServerName:         "test.example.com",
		InsecureSkipVerify: true,
	}
	uConn := utls.UClient(c1, uConfig, utls.HelloChrome_Auto)
	if err := prepareUTLSForHTTP1(uConn); err != nil {
		t.Fatalf("prepareUTLSForHTTP1 failed: %v", err)
	}

	found := false
	for _, ext := range uConn.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			found = true
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("unexpected ALPN protocols: %#v", alpn.AlpnProtocols)
			}
		}
	}
	if !found {
		t.Fatal("ALPNExtension not found on UConn after prepareUTLSForHTTP1")
	}
}

func TestAppsCachePersistence(t *testing.T) {
	tempDir := t.TempDir()
	origBaseDir := baseDir
	baseDir = tempDir
	defer func() { baseDir = origBaseDir }()

	// Initially no cache
	apps, uids := loadCachedApps()
	if len(apps) != 0 || len(uids) != 0 {
		t.Fatalf("expected empty cache initially, got %#v, %#v", apps, uids)
	}

	testApps := []App{
		{Name: "Telegram", Pkg: "org.telegram.messenger", UID: 10123},
		{Name: "exteraGram", Pkg: "com.exteragram.messenger", UID: 10124},
	}
	saveCachedApps(testApps)

	loadedApps, loadedUIDs := loadCachedApps()
	if len(loadedApps) != 2 || len(loadedUIDs) != 2 {
		t.Fatalf("expected 2 apps and 2 UIDs, got %#v, %#v", loadedApps, loadedUIDs)
	}
	if loadedApps[0].UID != 10123 || loadedApps[1].UID != 10124 {
		t.Errorf("UID mismatch in loaded apps: %#v", loadedApps)
	}
	if loadedUIDs[0] != 10123 || loadedUIDs[1] != 10124 {
		t.Errorf("UID mismatch in loaded UIDs: %#v", loadedUIDs)
	}
}

func TestCustomCFWorkerConfig(t *testing.T) {
	oldDir := baseDir
	tmp := t.TempDir()
	baseDir = tmp
	defer func() { baseDir = oldDir }()

	if got := readCustomCFWorker(); got != "" {
		t.Errorf("expected empty worker initially, got %q", got)
	}

	workerURL := "https://my-tg-worker.example.workers.dev/"
	if err := writeCustomCFWorker(workerURL); err != nil {
		t.Fatalf("failed to write worker: %v", err)
	}

	expected := "my-tg-worker.example.workers.dev"
	if got := readCustomCFWorker(); got != expected {
		t.Errorf("worker mismatch: got %q, want %q", got, expected)
	}

	// Clearing
	if err := writeCustomCFWorker(""); err != nil {
		t.Fatalf("failed to clear worker: %v", err)
	}
	if got := readCustomCFWorker(); got != "" {
		t.Errorf("expected empty worker after clear, got %q", got)
	}
}

func TestCloudflareWorkerContract(t *testing.T) {
	cases := []struct {
		dc       int
		expected string
	}{
		{1, "149.154.175.50"},
		{2, "149.154.167.51"},
		{3, "149.154.175.100"},
		{4, "149.154.167.91"},
		{5, "149.154.171.5"},
		{203, "91.105.192.100"},
	}
	for _, tc := range cases {
		dst := workerDstForDC(tc.dc)
		if dst != tc.expected {
			t.Errorf("workerDstForDC(%d)=%q, want %q", tc.dc, dst, tc.expected)
		}
	}
}

func TestRaceCandidatesFastWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var startedCount atomic.Int32
	candidates := []dialCandidate{
		{
			name: "cand-slow-failing",
			dial: func(c context.Context) (*wsConn, error) {
				startedCount.Add(1)
				select {
				case <-time.After(500 * time.Millisecond):
					return nil, errors.New("timeout")
				case <-c.Done():
					return nil, c.Err()
				}
			},
		},
		{
			name: "cand-fast-winner",
			dial: func(c context.Context) (*wsConn, error) {
				startedCount.Add(1)
				// Return a fake wsConn
				return &wsConn{host: "winner.test"}, nil
			},
		},
	}

	// 50ms stagger
	ws, winner, err := raceCandidates(ctx, candidates, 50*time.Millisecond, 2)
	if err != nil {
		t.Fatalf("raceCandidates failed: %v", err)
	}
	if ws == nil {
		t.Fatal("expected non-nil ws")
	}
	if winner != "cand-fast-winner" {
		t.Errorf("expected winner cand-fast-winner, got %q", winner)
	}
}

func TestPipeTCPToTCPBidirectional(t *testing.T) {
	clientSide, c := net.Pipe()
	remote, serverSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		pipeTCPToTCP(c, remote, 999, 203)
		close(done)
	}()

	msg1 := []byte("hello from client to server")
	go func() {
		_, _ = clientSide.Write(msg1)
	}()

	buf1 := make([]byte, len(msg1))
	if _, err := io.ReadFull(serverSide, buf1); err != nil {
		t.Fatalf("failed to read on serverSide: %v", err)
	}
	if string(buf1) != string(msg1) {
		t.Fatalf("expected %q, got %q", string(msg1), string(buf1))
	}

	msg2 := []byte("reply from server to client")
	go func() {
		_, _ = serverSide.Write(msg2)
	}()

	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(clientSide, buf2); err != nil {
		t.Fatalf("failed to read on clientSide: %v", err)
	}
	if string(buf2) != string(msg2) {
		t.Fatalf("expected %q, got %q", string(msg2), string(buf2))
	}

	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeTCPToTCP did not shut down within 2s after socket close")
	}
	_ = serverSide.Close()
}

func TestRaceCandidatesContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	candidates := []dialCandidate{
		{
			name: "cand-slow-1",
			dial: func(c context.Context) (*wsConn, error) {
				<-c.Done()
				return nil, c.Err()
			},
		},
		{
			name: "cand-slow-2",
			dial: func(c context.Context) (*wsConn, error) {
				<-c.Done()
				return nil, c.Err()
			},
		},
	}

	ws, _, err := raceCandidates(ctx, candidates, 20*time.Millisecond, 2)
	if err == nil {
		if ws != nil {
			_ = ws.Close()
		}
		t.Fatal("expected error on context timeout")
	}
}

func TestWorkerCooldownAndRateLimit(t *testing.T) {
	host := "test-worker-rate-limit.workers.dev"
	clearWorkerCooldown(host)
	defer clearWorkerCooldown(host)

	if isWorkerInCooldown(host) {
		t.Fatal("worker should not start in cooldown")
	}

	rle := &RateLimitError{StatusCode: 429, RetryAfter: 5 * time.Second, Message: "error code: 1015"}
	if !strings.Contains(rle.Error(), "HTTP 429") || !strings.Contains(rle.Error(), "retry after 5s") {
		t.Fatalf("unexpected RateLimitError string: %s", rle.Error())
	}

	markWorkerCooldown(host, rle.RetryAfter)
	if !isWorkerInCooldown(host) {
		t.Fatal("worker should be in cooldown after markWorkerCooldown")
	}

	clearWorkerCooldown(host)
	if isWorkerInCooldown(host) {
		t.Fatal("worker should not be in cooldown after clearWorkerCooldown")
	}

	// Exponential backoff test (strike 1 -> 30s)
	markWorkerCooldown(host, 0)
	v, ok := workerCooldowns.Load(host)
	if !ok {
		t.Fatal("workerCooldowns entry missing")
	}
	state := v.(workerCooldownState)
	if state.strikes != 1 {
		t.Fatalf("expected strike 1, got %d", state.strikes)
	}
	rem := time.Until(state.until)
	if rem < 25*time.Second || rem > 35*time.Second {
		t.Fatalf("expected cooldown ~30s, got %v", rem)
	}

	// Strike 2 -> 60s
	markWorkerCooldown(host, 0)
	v, ok = workerCooldowns.Load(host)
	if !ok {
		t.Fatal("workerCooldowns entry missing")
	}
	state = v.(workerCooldownState)
	if state.strikes != 2 {
		t.Fatalf("expected strike 2, got %d", state.strikes)
	}
	rem = time.Until(state.until)
	if rem < 55*time.Second || rem > 65*time.Second {
		t.Fatalf("expected cooldown ~60s, got %v", rem)
	}
}

func TestDCLearnAndPersistence(t *testing.T) {
	oldBase := baseDir
	tmp := t.TempDir()
	baseDir = tmp
	defer func() { baseDir = oldBase }()

	ip := "198.51.100.99"
	learnedDCs.Delete(ip)
	defer learnedDCs.Delete(ip)

	if _, _, ok := lookupLearnedDC(ip); ok {
		t.Fatal("IP should not be learned yet")
	}

	learnDC(ip, 4, true)

	dc, isMedia, ok := lookupLearnedDC(ip)
	if !ok || dc != 4 || !isMedia {
		t.Fatalf("learnDC failed: got dc=%d isMedia=%t ok=%t", dc, isMedia, ok)
	}

	addr := netip.MustParseAddr(ip)
	if got := dcFor(addr); got != 4 {
		t.Fatalf("dcFor(%s) = %d; want 4", ip, got)
	}
	if got := mediaForIP(addr); !got {
		t.Fatalf("mediaForIP(%s) = false; want true", ip)
	}

	// Trigger persistence and reload
	persistLearnedDCs()

	// Clear memory map
	learnedDCs.Delete(ip)
	if _, _, ok := lookupLearnedDC(ip); ok {
		t.Fatal("IP should be cleared from memory")
	}

	// Reload from disk
	loadLearnedDCs()
	dc, isMedia, ok = lookupLearnedDC(ip)
	if !ok || dc != 4 || !isMedia {
		t.Fatalf("loadLearnedDCs failed to restore: got dc=%d isMedia=%t ok=%t", dc, isMedia, ok)
	}
}

func TestRaceCandidatesFastFailureRecoversSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	candidates := []dialCandidate{
		{
			name: "cand-slow",
			dial: func(c context.Context) (*wsConn, error) {
				select {
				case <-time.After(300 * time.Millisecond):
					return nil, errors.New("slow failed")
				case <-c.Done():
					return nil, c.Err()
				}
			},
		},
		{
			name: "cand-fast-fail",
			dial: func(c context.Context) (*wsConn, error) {
				time.Sleep(5 * time.Millisecond)
				return nil, errors.New("fast error")
			},
		},
		{
			name: "cand-fast-winner",
			dial: func(c context.Context) (*wsConn, error) {
				time.Sleep(5 * time.Millisecond)
				return &wsConn{host: "winner.test"}, nil
			},
		},
	}

	ws, winner, err := raceCandidates(ctx, candidates, 20*time.Millisecond, 2)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("raceCandidates failed: %v", err)
	}
	if ws == nil {
		t.Fatal("expected non-nil ws")
	}
	if winner != "cand-fast-winner" {
		t.Fatalf("expected cand-fast-winner, got %q", winner)
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("race took too long (%v > 150ms), slot recovery stalled", elapsed)
	}
}


func TestScoreDensity(t *testing.T) {
	if scoreDensity("res/mipmap-xxxhdpi/ic_launcher.png") <= scoreDensity("res/mipmap-mdpi/ic_launcher.png") {
		t.Error("xxxhdpi should score higher than mdpi")
	}
	if scoreDensity("res/mipmap-xxhdpi/ic_launcher.png") <= scoreDensity("res/drawable-xxhdpi/ic_launcher.png") {
		t.Error("mipmap should score higher than drawable")
	}
}

func TestExtractAPKIconsMock(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Add normal icon
	f1, err := zw.Create("res/mipmap-xxhdpi/ic_launcher.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f1.Write([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a})

	// Add monet icon
	f2, err := zw.Create("res/drawable/ic_launcher_monochrome.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.Write([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x01})

	_ = zw.Close()

	tmpFile := filepath.Join(t.TempDir(), "test_mock.apk")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	normal, monet := extractAPKIcons(tmpFile)
	if !strings.HasPrefix(normal, "data:image/png;base64,") {
		t.Errorf("expected normal icon, got %s", normal)
	}
	if !strings.HasPrefix(monet, "data:image/png;base64,") {
		t.Errorf("expected monet icon, got %s", monet)
	}
}
func TestUpdateModuleDescription(t *testing.T) {
	tmpDir := t.TempDir()
	propFile := filepath.Join(tmpDir, "module.prop")
	initialContent := "id=teleweb\nname=TeleWEB\nversion=0.1.0\nversionCode=100\nauthor=TeleWEB\ndescription=Initial description\nwebuiIcon=webroot/module_icon.png\n"
	if err := os.WriteFile(propFile, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TELEWEB_MOD", tmpDir)

	// Test updating to running
	updateModuleDescription("✅ Работает · WSS")
	content, err := os.ReadFile(propFile)
	if err != nil {
		t.Fatal(err)
	}
	expectedRunning := "description=✅ Работает · WSS | " + defaultDescBase
	if !strings.Contains(string(content), expectedRunning) {
		t.Errorf("expected %q in module.prop, got:\n%s", expectedRunning, string(content))
	}

	// Test updating to stopped
	updateModuleDescription("⛔ Остановлено")
	content, err = os.ReadFile(propFile)
	if err != nil {
		t.Fatal(err)
	}
	expectedStopped := "description=⛔ Остановлено | " + defaultDescBase
	if !strings.Contains(string(content), expectedStopped) {
		t.Errorf("expected %q in module.prop, got:\n%s", expectedStopped, string(content))
	}

	// Verify idempotence (calling again doesn't alter content or duplicate)
	updateModuleDescription("⛔ Остановлено")
	content2, _ := os.ReadFile(propFile)
	if string(content2) != string(content) {
		t.Errorf("idempotent call altered file content")
	}

	// Verify currentStatusDesc when disabled
	t.Setenv("TELEWEB_DIR", tmpDir)
	_ = writeEnabled(false)
	desc := currentStatusDesc()
	if desc != "⛔ Остановлено" {
		t.Errorf("expected ⛔ Остановлено when disabled, got %s", desc)
	}
}

func TestWsPool_Lifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TELEWEB_DIR", tmpDir)

	if err := writePoolSize(3); err != nil {
		t.Fatalf("failed to write pool size: %v", err)
	}
	if sz := readPoolSize(); sz != 3 {
		t.Fatalf("expected pool size 3, got %d", sz)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWsPool(ctx, 3)
	defer pool.Close()

	// 1. Initial Get on empty pool should miss
	ws := pool.Get(2, false)
	if ws != nil {
		t.Fatalf("expected nil from empty pool, got %v", ws)
	}
	hits, misses, idle := pool.Stats()
	if hits != 0 || misses != 1 || idle != 0 {
		t.Fatalf("expected 0 hits, 1 miss, 0 idle; got hits=%d misses=%d idle=%d", hits, misses, idle)
	}

	// 2. Put a live mock connection into slot
	c1, c2 := net.Pipe()
	defer c2.Close()
	mockWS := &wsConn{conn: c1, host: "mock-host.invalid"}

	slot := poolSlot{dc: 2, isMedia: false}
	q, _ := pool.getQueue(slot)
	q <- &poolEntry{ws: mockWS, createdAt: time.Now()}

	if pool.IdleCount() != 1 {
		t.Fatalf("expected 1 idle connection, got %d", pool.IdleCount())
	}

	// 3. Get should hit
	retrieved := pool.Get(2, false)
	if retrieved == nil {
		t.Fatalf("expected valid connection from pool, got nil")
	}
	if retrieved.host != "mock-host.invalid" {
		t.Fatalf("expected mock-host.invalid, got %s", retrieved.host)
	}
	_ = retrieved.Close()

	hits, misses, _ = pool.Stats()
	if hits != 1 || misses != 1 {
		t.Fatalf("expected 1 hit, 1 miss; got hits=%d misses=%d", hits, misses)
	}

	// 4. Stale connection should be discarded
	c3, c4 := net.Pipe()
	defer c4.Close()
	staleWS := &wsConn{conn: c3, host: "stale-host.invalid"}
	q <- &poolEntry{ws: staleWS, createdAt: time.Now().Add(-200 * time.Second)}

	staleRetrieved := pool.Get(2, false)
	if staleRetrieved != nil {
		t.Fatalf("expected stale entry to be dropped, got %v", staleRetrieved)
	}
}

func TestDoH_ParsingAndCache(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TELEWEB_DIR", tmpDir)

	if err := writeDoHEnabled(true); err != nil {
		t.Fatalf("failed to write doh enabled: %v", err)
	}
	if !readDoHEnabled() {
		t.Fatalf("expected dohEnabled to be true")
	}

	// Mock DoH server returning DNS JSON
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name != "kws2.test.invalid" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		resp := dohResponse{
			Status: 0,
			Answer: []dohAnswer{
				{Name: "kws2.test.invalid", Type: 1, TTL: 120, Data: "104.21.12.34"},
				{Name: "kws2.test.invalid", Type: 1, TTL: 120, Data: "172.67.56.78"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	origEndpoints := dohEndpoints
	dohEndpoints = []string{server.URL}
	defer func() { dohEndpoints = origEndpoints }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := resolveDoHRace(ctx, "kws2.test.invalid")
	if err != nil {
		t.Fatalf("resolveDoHRace failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs from mock DoH, got %d (%v)", len(ips), ips)
	}
	if ips[0].String() != "104.21.12.34" || ips[1].String() != "172.67.56.78" {
		t.Fatalf("unexpected IPs returned: %v", ips)
	}

	// Verify cached
	cachedVal, ok := dohCache.Load("kws2.test.invalid")
	if !ok {
		t.Fatalf("expected kws2.test.invalid in dohCache")
	}
	cachedEntry := cachedVal.(dohCacheEntry)
	if len(cachedEntry.ips) != 2 {
		t.Fatalf("expected 2 cached IPs, got %d", len(cachedEntry.ips))
	}

	// Test DoH disabled
	_ = writeDoHEnabled(false)
	_, err = resolveDoHRace(ctx, "another.test.invalid")
	if err == nil {
		t.Fatalf("expected error when DoH disabled, got nil")
	}
}

func TestApiMain_PoolSize_And_DoH_Config(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := baseDir
	baseDir = tmpDir
	defer func() { baseDir = origBase }()

	poolSz := 4
	dohEn := false
	req := apiRequest{
		Cmd:        "setConfig",
		PoolSize:   &poolSz,
		DoHEnabled: &dohEn,
	}
	b, _ := json.Marshal(req)
	encoded := base64.StdEncoding.EncodeToString(b)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	apiMain(encoded)

	_ = w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	var resp struct {
		OK   bool   `json:"ok"`
		Data Status `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("failed to parse api response: %v, raw: %s", err, string(out))
	}
	if !resp.OK {
		t.Fatalf("expected api response OK=true, got false")
	}

	if readPoolSize() != 4 {
		t.Fatalf("expected poolSize 4, got %d", readPoolSize())
	}
	if readDoHEnabled() != false {
		t.Fatalf("expected dohEnabled false, got %t", readDoHEnabled())
	}
}
