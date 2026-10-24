package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if !ok || dc != 2 || isMedia {
		t.Fatalf("DC 203 normalization failed: dc=%d isMedia=%t ok=%t", dc, isMedia, ok)
	}
	dc, isMedia, ok = parseMTProtoDC(makeInit(-203))
	if !ok || dc != 2 || !isMedia {
		t.Fatalf("DC -203 media normalization failed: dc=%d isMedia=%t ok=%t", dc, isMedia, ok)
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
