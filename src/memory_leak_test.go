package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func createFramerForTest(t testing.TB) (*mtprotoPacketFramer, cipher.Stream) {
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
	plainTail[4], plainTail[5] = 0x12, 0x34
	ctr.XORKeyStream(init[56:], plainTail)

	f, err := newMTProtoPacketFramer(init)
	if err != nil {
		t.Fatal(err)
	}

	key = init[8:40]
	block, _ = aes.NewCipher(key)
	clientStream := cipher.NewCTR(block, init[40:56])
	clientStream.XORKeyStream(make([]byte, 64), make([]byte, 64))
	return f, clientStream
}

// TestMemoryLeak_MTProtoFramer streams 20,000 packets through the framer
// and verifies that slice compaction prevents memory runaway and buffer retention.
func TestMemoryLeak_MTProtoFramer(t *testing.T) {
	f, clientStream := createFramerForTest(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain server side in background
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	ws := &wsConn{conn: client, r: bufio.NewReader(client)}

	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	// Stream 20,000 packets with varying sizes
	payloadSample := make([]byte, 1024)
	for i := range payloadSample {
		payloadSample[i] = byte(i % 251)
	}

	for i := 0; i < 20000; i++ {
		// Abridged packet: 1 byte len (words) + payload
		words := (i % 60) + 1
		pLen := words * 4
		pkt := make([]byte, 1+pLen)
		pkt[0] = byte(words)
		copy(pkt[1:], payloadSample[:pLen])

		enc := make([]byte, len(pkt))
		clientStream.XORKeyStream(enc, pkt)

		if err := f.feed(enc, ws); err != nil {
			t.Fatalf("feed failed at packet %d: %v", i, err)
		}

		// Verify cap stays within memory bounds (less than 256KB)
		if cap(f.raw) > 256*1024 {
			t.Fatalf("packet %d: f.raw capacity ballooned to %d bytes without compaction", i, cap(f.raw))
		}
	}

	// Large media chunk test: feed a 256KB packet to force slice expansion,
	// then verify that on complete drain (len==0), the oversized capacity is reclaimed.
	largeWords := 65536 // 256KB payload
	largePkt := make([]byte, 4+largeWords*4)
	largePkt[0] = 0x7f
	largePkt[1] = byte(largeWords & 0xff)
	largePkt[2] = byte((largeWords >> 8) & 0xff)
	largePkt[3] = byte((largeWords >> 16) & 0xff)
	largeEnc := make([]byte, len(largePkt))
	clientStream.XORKeyStream(largeEnc, largePkt)

	if err := f.feed(largeEnc, ws); err != nil {
		t.Fatalf("feed large packet failed: %v", err)
	}

	if len(f.raw) != 0 {
		t.Fatalf("expected len(f.raw) == 0 after large packet dispatch, got %d", len(f.raw))
	}
	if cap(f.raw) > 128*1024 {
		t.Fatalf("f.raw capacity remained %d bytes (> 128KB) after drain; memory compaction failed", cap(f.raw))
	}

	runtime.GC()
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	growth := int64(mAfter.HeapAlloc) - int64(mBefore.HeapAlloc)
	t.Logf("Framer 20k packets + 256KB media chunk: HeapAlloc before=%d KB, after=%d KB, growth=%d KB, final raw cap=%d, plain cap=%d",
		mBefore.HeapAlloc/1024, mAfter.HeapAlloc/1024, growth/1024, cap(f.raw), cap(f.plain))

	if growth > 1024*1024 {
		t.Errorf("potential memory leak in framer: heap growth %d bytes (> 1MB)", growth)
	}
}

// TestMemoryLeak_WsPool_Churn ensures that creating, cycling, and closing connections
// in WsPool leaves zero leaked goroutines or open sockets.
func TestMemoryLeak_WsPool_Churn(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	// Pre-cancel the pool context: Get() kicks off Refill, and a live Refill
	// would dial real Telegram WSS endpoints from a unit test and leave its
	// goroutines running past the leak check.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer cancel()

	pool := newWsPool(ctx, 2)
	slot := poolSlot{dc: 2, isMedia: false, isTest: false}
	q, _ := pool.getQueue(slot)

	// Cycle 1,000 connections through the queue
	for i := 0; i < 1000; i++ {
		c1, c2 := net.Pipe()
		ws := &wsConn{conn: c1, host: "test-pool.invalid"}
		entry := &poolEntry{ws: ws, createdAt: time.Now()}

		select {
		case q <- entry:
		default:
			_ = ws.Close()
			_ = c2.Close()
			continue
		}

		// Retrieve from queue
		got := pool.Get(2, false, false)
		if got != nil {
			_ = got.Close()
			_ = c2.Close()
		}
	}

	// The daemon never tears the pool down; mirror a shutdown the way the
	// runtime would: stop the rotation goroutine and drain queued sockets.
	pool.cancel()
	pool.drainAll()
	time.Sleep(50 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	t.Logf("WsPool churn: initial goroutines=%d, final goroutines=%d", initialGoroutines, finalGoroutines)

	// Allow a tolerance of +/- 2 for standard Go background runtime threads
	if finalGoroutines > initialGoroutines+3 {
		t.Errorf("goroutine leak detected in WsPool: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// TestMemoryLeak_DoHCache_Churn verifies that the DoH cache evicts expired entries
// and enforces a hard ceiling of 256 items under continuous churn.
func TestMemoryLeak_DoHCache_Churn(t *testing.T) {
	// Store 1,000 expired entries
	for i := 0; i < 1000; i++ {
		host := fmt.Sprintf("expired-%d.example.com", i)
		storeDoHCache(host, dohCacheEntry{
			ips:     []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			expires: time.Now().Add(-1 * time.Minute), // expired
		})
	}

	// Store 100 fresh entries
	for i := 0; i < 100; i++ {
		host := fmt.Sprintf("fresh-%d.example.com", i)
		storeDoHCache(host, dohCacheEntry{
			ips:     []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			expires: time.Now().Add(5 * time.Minute), // valid
		})
	}

	// Verify total count is bounded and <= 256
	count := 0
	dohCache.Range(func(key, val any) bool {
		count++
		return true
	})

	if count > 256 {
		t.Fatalf("dohCache exceeded bound: got %d, max allowed 256", count)
	}
	t.Logf("dohCache bounded count after 1,100 inserts: %d entries (bound=256)", count)

	// Clean up cache after test
	dohCache.Range(func(key, _ any) bool {
		dohCache.Delete(key)
		return true
	})
}

// TestMemoryLeak_H2Clients_PoolBound verifies that H2 client map never exceeds 8
// hosts and cleans up idle connections.
func TestMemoryLeak_H2Clients_PoolBound(t *testing.T) {
	h2ClientsMu.Lock()
	// Reset map for clean test
	for k, c := range h2Clients {
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		delete(h2Clients, k)
	}
	h2ClientsMu.Unlock()

	// Request 50 different hosts
	for i := 0; i < 50; i++ {
		host := fmt.Sprintf("cf-host-%d.cloudflare.com", i)
		clt := getH2Client(host)
		if clt == nil {
			t.Fatalf("getH2Client returned nil for %s", host)
		}
	}

	h2ClientsMu.RLock()
	count := len(h2Clients)
	h2ClientsMu.RUnlock()

	if count > 8 {
		t.Fatalf("h2Clients map exceeded bound: got %d, max allowed 8", count)
	}
	t.Logf("h2Clients pool count after 50 distinct requests: %d (bound=8)", count)
}

// TestMemoryLeak_BoundedMaps_ProtectAndLearnedDCs ensures warnProtect and learnedDCs
// maintain hard upper bounds on mobile devices.
func TestMemoryLeak_BoundedMaps_ProtectAndLearnedDCs(t *testing.T) {
	// 1. warnProtect churn with 1,000 PIDs
	for pid := 20000; pid < 21000; pid++ {
		warnProtect(pid, "protect test warning")
	}

	warnCount := 0
	protectWarnings.Range(func(_, _ any) bool {
		warnCount++
		return true
	})
	if warnCount > 128 {
		t.Fatalf("protectWarnings exceeded hard cap: got %d, max allowed 128", warnCount)
	}
	t.Logf("protectWarnings count after 1,000 calls: %d (bound=128)", warnCount)

	// 2. learnedDCs churn with 1,000 IPs
	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i%250)
		learnDC(ip, (i%5)+1, i%2 == 0)
	}

	dcCount := 0
	learnedDCs.Range(func(_, _ any) bool {
		dcCount++
		return true
	})
	if dcCount > 256 {
		t.Fatalf("learnedDCs exceeded hard cap: got %d, max allowed 256", dcCount)
	}
	t.Logf("learnedDCs count after 1,000 calls: %d (bound=256)", dcCount)
}

// TestMemoryLeak_RaceCandidates_GoroutineCleanup ensures all losing/slow candidates
// promptly terminate when one candidate wins, preventing goroutine leaks.
func TestMemoryLeak_RaceCandidates_GoroutineCleanup(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var slowGoroutinesTerminated atomic.Int32

	candidates := []dialCandidate{
		{
			name: "slow-loser-1",
			dial: func(c context.Context) (*wsConn, error) {
				defer slowGoroutinesTerminated.Add(1)
				<-c.Done()
				return nil, c.Err()
			},
		},
		{
			name: "slow-loser-2",
			dial: func(c context.Context) (*wsConn, error) {
				defer slowGoroutinesTerminated.Add(1)
				<-c.Done()
				return nil, c.Err()
			},
		},
		{
			name: "fast-winner",
			dial: func(c context.Context) (*wsConn, error) {
				time.Sleep(15 * time.Millisecond)
				return &wsConn{host: "fast.winner"}, nil
			},
		},
	}

	wonWS, _, err := raceCandidates(ctx, candidates, 2*time.Millisecond, 4)
	if err != nil || wonWS == nil {
		t.Fatalf("expected winner, got err=%v", err)
	}

	// Wait 50ms for context cancellation to propagate to slow candidates
	time.Sleep(50 * time.Millisecond)

	if slowGoroutinesTerminated.Load() < 2 {
		t.Errorf("not all slow candidates terminated: got %d, want 2", slowGoroutinesTerminated.Load())
	}

	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("raceCandidates goroutine cleanup: initial=%d, final=%d, terminated=%d",
		initialGoroutines, finalGoroutines, slowGoroutinesTerminated.Load())

	if finalGoroutines > initialGoroutines+3 {
		t.Errorf("goroutine leak in raceCandidates: initial=%d, final=%d", initialGoroutines, finalGoroutines)
	}
}

// Benchmarks for hot-path allocations and memory overhead
func BenchmarkMTProtoFramer_Feed(b *testing.B) {
	f, clientStream := createFramerForTest(b)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 64*1024)
		for {
			_, err := c2.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	ws := &wsConn{conn: c1, r: bufio.NewReader(c1)}

	payload := make([]byte, 256)
	enc := make([]byte, 1+len(payload))
	enc[0] = byte(len(payload) / 4)
	copy(enc[1:], payload)
	clientStream.XORKeyStream(enc, enc)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = f.feed(enc, ws)
	}
}

func BenchmarkEncodeH2Reply(b *testing.B) {
	body := make([]byte, 1024)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = encodeH2Reply(body, 0xEFEFEFEF)
	}
}

// TestMemoryLeak_WsPool_DisabledDrain ensures that disabling the pool at
// runtime (poolSize=0) releases every queued socket instead of leaking FDs.
func TestMemoryLeak_WsPool_DisabledDrain(t *testing.T) {
	pool := newWsPool(context.Background(), 2)
	q, _ := pool.getQueue(poolSlot{dc: 1, isMedia: false, isTest: false})

	type pipedEntry struct {
		conn net.Conn // peer end; readable error signals our side closed
	}
	peers := make([]pipedEntry, 0, 3)
	for i := 0; i < 3; i++ {
		c1, c2 := net.Pipe()
		entry := &poolEntry{ws: &wsConn{conn: c1, host: "drain-test"}, createdAt: time.Now()}
		select {
		case q <- entry:
		default:
			_ = c1.Close()
			_ = c2.Close()
			continue
		}
		peers = append(peers, pipedEntry{conn: c2})
	}
	if len(peers) == 0 {
		t.Fatal("queue empty before drain; test setup broken")
	}

	// Disabling the pool must close every queued connection.
	globalWsPool = pool
	t.Cleanup(func() { globalWsPool = nil })
	if err := writePoolSize(0); err != nil {
		t.Fatalf("writePoolSize(0): %v", err)
	}
	if pool.IdleCount() != 0 {
		t.Fatalf("expected empty queues after drain, got %d idle", pool.IdleCount())
	}
	for i, p := range peers {
		_ = p.conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1)
		if _, err := p.conn.Read(buf); err == nil {
			t.Errorf("peer %d: expected read error after drain, got data", i)
		}
		p.conn.Close()
	}
}

// TestPipeWSTunnelRoundTrip drives the production WSS relay loop end to end
// against an in-process fake relay: the 64-byte init must ride the first frame,
// subsequent MTProto packets must be framed one per message, the downlink must
// be relayed verbatim, server pings must be answered, and a server close must
// tear both directions down without leaking goroutines.
func TestPipeWSTunnelRoundTrip(t *testing.T) {
	oldDir := baseDir
	baseDir = t.TempDir()
	t.Cleanup(func() {
		baseDir = oldDir
		logMu.Lock()
		if logFile != nil {
			_ = logFile.Close()
			logFile = nil
		}
		logMu.Unlock()
	})

	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	init := make([]byte, 64)
	for i := 0; i < 56; i++ {
		init[i] = byte(i + 1)
	}
	block, err := aes.NewCipher(init[8:40])
	if err != nil {
		t.Fatal(err)
	}
	ctr := cipher.NewCTR(block, init[40:56])
	ctr.XORKeyStream(make([]byte, 56), make([]byte, 56))
	plainTail := make([]byte, 8)
	binary.LittleEndian.PutUint32(plainTail[:4], 0xEFEFEFEF)
	plainTail[4], plainTail[5] = 0x01, 0x00
	ctr.XORKeyStream(init[56:], plainTail)

	clientConn, clientPeer := net.Pipe()
	defer clientPeer.Close()
	serverConn, serverPeer := net.Pipe()

	serverErr := make(chan error, 1)
	go func() {
		defer close(serverErr)
		defer serverPeer.Close()
		sr := bufio.NewReader(serverPeer)
		req, err := http.ReadRequest(sr)
		if err != nil {
			serverErr <- err
			return
		}
		if req.URL.Path != "/apiws" || req.Header.Get("Sec-WebSocket-Protocol") != "binary" {
			serverErr <- fmt.Errorf("bad upgrade request: path=%q", req.URL.Path)
			return
		}
		accept := base64.StdEncoding.EncodeToString(sha1Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID)))
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
		if _, err := serverPeer.Write([]byte(resp)); err != nil {
			serverErr <- err
			return
		}

		serverWS := &wsConn{conn: serverPeer, r: sr}
		op, payload, err := serverWS.readFrame()
		if err != nil {
			serverErr <- err
			return
		}
		if op != 2 || len(payload) != 69 || string(payload[:64]) != string(init) {
			serverErr <- fmt.Errorf("first frame: op=%d len=%d (want 2/69 with init prefix)", op, len(payload))
			return
		}
		op, payload, err = serverWS.readFrame()
		if err != nil {
			serverErr <- err
			return
		}
		if op != 2 || len(payload) != 9 {
			serverErr <- fmt.Errorf("second frame: op=%d len=%d (want 2/9)", op, len(payload))
			return
		}

		reply := []byte("relay-downlink-bytes!!")
		if err := serverWS.writeFrame(2, reply); err != nil {
			serverErr <- err
			return
		}
		if err := serverWS.writeFrame(9, []byte("ping")); err != nil {
			serverErr <- err
			return
		}
		op, payload, err = serverWS.readFrame()
		if err != nil {
			serverErr <- err
			return
		}
		if op != 10 || string(payload) != "ping" {
			serverErr <- fmt.Errorf("expected pong 'ping', got op=%d payload=%q", op, payload)
			return
		}
		_ = serverWS.writeFrame(8, nil)
	}()

	ws, err := websocketUpgradePath(serverConn, "fake-relay.test", "/apiws")
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		pipeWSTunnel(clientConn, ws, init, 1, 1, false)
	}()

	// Emulate the Telegram client: two abridged packets back to back. The
	// first rides the init frame, the second arrives as its own message.
	clientCTR := cipher.NewCTR(block, init[40:56])
	skip := make([]byte, 64)
	clientCTR.XORKeyStream(skip, skip)
	encrypt := func(words int) []byte {
		pkt := make([]byte, 1+words*4)
		pkt[0] = byte(words)
		out := make([]byte, len(pkt))
		clientCTR.XORKeyStream(out, pkt)
		return out
	}
	uplink := append(encrypt(1), encrypt(2)...)
	if _, err := clientPeer.Write(uplink); err != nil {
		t.Fatalf("client uplink write: %v", err)
	}

	down := make([]byte, len("relay-downlink-bytes!!"))
	if _, err := io.ReadFull(clientPeer, down); err != nil {
		t.Fatalf("client downlink read: %v", err)
	}
	if string(down) != "relay-downlink-bytes!!" {
		t.Fatalf("downlink payload %q", down)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("fake relay: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the fake relay")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pipeWSTunnel did not shut down after server close")
	}
	clientPeer.Close()

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	if final := runtime.NumGoroutine(); final > initialGoroutines+3 {
		t.Errorf("goroutine leak after tunnel teardown: initial=%d final=%d", initialGoroutines, final)
	}
}
