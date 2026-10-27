package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	h2ClientsMu sync.RWMutex
	h2Clients   = make(map[string]*http.Client)
	h2FailsMu   sync.RWMutex
	h2Fails     = make(map[string]time.Time)
)

func readH2MediaEnabled() bool {
	b, err := os.ReadFile(path("h2_media_enabled"))
	if err != nil {
		return false // optional experimental feature, off by default
	}
	return strings.TrimSpace(string(b)) == "1"
}

func writeH2MediaEnabled(v bool) error {
	ensureDir()
	val := "0"
	if v {
		val = "1"
	}
	return os.WriteFile(path("h2_media_enabled"), []byte(val), 0600)
}

func getH2Client(host string) *http.Client {
	h2ClientsMu.RLock()
	if c, ok := h2Clients[host]; ok {
		h2ClientsMu.RUnlock()
		return c
	}
	h2ClientsMu.RUnlock()

	h2ClientsMu.Lock()
	defer h2ClientsMu.Unlock()
	if c, ok := h2Clients[host]; ok {
		return c
	}

	// Bound cache to 8 hosts to avoid socket/memory leaks
	if len(h2Clients) >= 8 {
		for h, clt := range h2Clients {
			if tr, ok := clt.Transport.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
			delete(h2Clients, h)
			break
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: host,
			RootCAs:    getSystemRootCAs(),
			// ServerName always equals the dialed host here (no fronting-SNI
			// override in the H2 path), so certificate verification stays on.
			InsecureSkipVerify: false,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   65 * time.Second,
	}
	h2Clients[host] = c
	return c
}

func encodeH2Reply(body []byte, proto uint32) []byte {
	if len(body) == 0 {
		return nil
	}
	switch proto {
	case 0xEFEFEFEF: // Abridged
		words := len(body) / 4
		if words < 0x7f {
			out := make([]byte, 1+len(body))
			out[0] = byte(words)
			copy(out[1:], body)
			return out
		}
		out := make([]byte, 4+len(body))
		out[0] = 0x7f
		out[1] = byte(words)
		out[2] = byte(words >> 8)
		out[3] = byte(words >> 16)
		copy(out[4:], body)
		return out
	case 0xEEEEEEEE, 0xDDDDDDDD: // Intermediate / Padded Intermediate
		out := make([]byte, 4+len(body))
		binary.LittleEndian.PutUint32(out[:4], uint32(len(body)))
		copy(out[4:], body)
		return out
	default:
		return body
	}
}

func createClientEncryptor(initial []byte) (cipher.Stream, error) {
	if len(initial) < 56 {
		return nil, fmt.Errorf("initial header too short")
	}
	// Reverse bytes 8..56 for server->client encryption stream
	var rev [48]byte
	for i := 0; i < 48; i++ {
		rev[i] = initial[8+47-i]
	}
	key := rev[:32]
	iv := rev[32:48]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	var zero64 [64]byte
	stream.XORKeyStream(zero64[:], zero64[:])
	return stream, nil
}

// h2Reply carries one HTTP/2 response to the ordered writer. A nil data field
// means the request failed: the sequence slot is consumed without writing so
// later replies are not blocked behind it.
type h2Reply struct {
	seq  uint64
	data []byte
}

// h2ReplySequencer reassembles HTTP/2 responses in dispatch order. MTProto's
// server->client CTR stream is strictly sequential, so a response that arrives
// out of order must wait for its predecessors before being encrypted: writing
// keystream blocks in arrival order would desynchronize the whole session.
type h2ReplySequencer struct {
	next     uint64
	buffered map[uint64][]byte
	write    func(body []byte) error
}

func newH2ReplySequencer(write func(body []byte) error) *h2ReplySequencer {
	return &h2ReplySequencer{buffered: make(map[uint64][]byte), write: write}
}

// push hands one reply to the sequencer. A nil body marks a failed request:
// it consumes its sequence slot without writing so later replies still flow.
// Only a single goroutine (the reply writer) may call push.
func (s *h2ReplySequencer) push(seq uint64, body []byte) error {
	s.buffered[seq] = body
	for {
		data, ok := s.buffered[s.next]
		if !ok {
			return nil
		}
		delete(s.buffered, s.next)
		s.next++
		if data == nil {
			continue
		}
		if err := s.write(data); err != nil {
			return err
		}
	}
}

// h2PostPacket performs one MTProto-over-HTTP/2 POST and returns the decoded
// response body, or nil when the request failed for any reason.
func h2PostPacket(ctx context.Context, client *http.Client, apiURL, host string, body []byte) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Capture CF-Ray & CF-PoP telemetry from response
	if cfRay := strings.TrimSpace(resp.Header.Get("CF-Ray")); cfRay != "" {
		lastCFRay.Store(&cfRay)
		if pop := parseCFRayPoP(cfRay); pop != "" {
			lastCFPoP.Store(&pop)
		}
	}

	if resp.StatusCode != http.StatusOK {
		h2FailsMu.Lock()
		h2Fails[host] = time.Now().Add(30 * time.Second)
		h2FailsMu.Unlock()
		return nil
	}

	// Reject HTML error pages
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil
	}

	respData, err := io.ReadAll(io.LimitReader(resp.Body, maxWSFrame))
	if err != nil || len(respData) == 0 || len(respData)%4 != 0 {
		return nil
	}
	return respData
}

func tryBridgeH2Media(c net.Conn, init []byte, id int64, dc int, isTest bool) bool {
	// Cloudflare does not front Telegram Test DCs; only production DCs 1-5
	if isTest || !h2MediaEnabledCached() {
		return false
	}

	// 1. Pick candidate host for DC from active Cloudflare domains
	domains := cfDomainsCached()
	if len(domains) == 0 {
		return false
	}
	var hosts []string
	for _, d := range domains {
		hosts = append(hosts, fmt.Sprintf("kws%d.%s", dc, d))
	}

	now := time.Now()
	var selectedHost string
	for _, h := range hosts {
		h2FailsMu.RLock()
		until := h2Fails[h]
		h2FailsMu.RUnlock()
		if now.After(until) {
			selectedHost = h
			break
		}
	}
	if selectedHost == "" {
		return false
	}

	client := getH2Client(selectedHost)
	apiURL := fmt.Sprintf("https://%s/api", selectedHost)

	// 2. Preflight check: HEAD request with 3s timeout to verify HTTP/2 support
	preflightCtx, preCancel := context.WithTimeout(context.Background(), 3*time.Second)
	headReq, err := http.NewRequestWithContext(preflightCtx, http.MethodHead, apiURL, nil)
	if err != nil {
		preCancel()
		return false
	}
	headReq.Header.Set("User-Agent", "Mozilla/5.0")
	headResp, err := client.Do(headReq)
	preCancel() // release context timer immediately after request completes
	if err != nil {
		h2FailsMu.Lock()
		h2Fails[selectedHost] = time.Now().Add(60 * time.Second)
		h2FailsMu.Unlock()
		return false
	}
	_ = headResp.Body.Close()

	// Must negotiate HTTP/2 and return 2xx / 405 / 501
	if headResp.ProtoMajor < 2 || !(headResp.StatusCode >= 200 && headResp.StatusCode < 300 || headResp.StatusCode == http.StatusMethodNotAllowed || headResp.StatusCode == http.StatusNotImplemented) {
		h2FailsMu.Lock()
		h2Fails[selectedHost] = time.Now().Add(60 * time.Second)
		h2FailsMu.Unlock()
		return false
	}

	// 3. Initialize MTProto framer and client encryptor
	framer, err := newMTProtoPacketFramer(init)
	if err != nil {
		return false
	}
	cltEnc, err := createClientEncryptor(init)
	if err != nil {
		return false
	}

	logf("conn #%d DC%d media bridged via HTTP/2 host=%s (%s)", id, dc, selectedHost, apiURL)

	// 4. Run HTTP/2 pipeline
	bridgeCtx, bridgeCancel := context.WithCancel(context.Background())
	defer bridgeCancel()

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	// Single reply writer: response bodies are handed over out of band and
	// reassembled in dispatch order before touching the shared CTR stream.
	replyCh := make(chan h2Reply, 8)
	go func() {
		seq := newH2ReplySequencer(func(body []byte) error {
			encoded := encodeH2Reply(body, framer.proto)
			encrypted := make([]byte, len(encoded))
			cltEnc.XORKeyStream(encrypted, encoded)
			if err := writeFull(c, encrypted); err != nil {
				return err
			}
			atomic.AddInt64(&trafficDownBytes, int64(len(body)))
			lastActivity.Store(time.Now().UnixNano())
			return nil
		})
		for {
			select {
			case r := <-replyCh:
				if err := seq.push(r.seq, r.data); err != nil {
					bridgeCancel()
					return
				}
			case <-bridgeCtx.Done():
				return
			}
		}
	}()

	postSeq := uint64(0)
	// Read loop from client
	buf := make([]byte, 32*1024)
	for {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Minute))
		nr, err := c.Read(buf)
		if nr > 0 {
			lastActivity.Store(time.Now().UnixNano())
			prevPlain := len(framer.plain)
			chunk := buf[:nr]
			framer.plain = append(framer.plain, chunk...)
			framer.stream.XORKeyStream(framer.plain[prevPlain:], chunk)

			for {
				n, ready, ferr := framer.nextPacketSize()
				if ferr != nil || !ready {
					break
				}
				packetBody := append([]byte(nil), framer.plain[:n]...)
				framer.plain = framer.plain[n:]
				if len(framer.plain) == 0 {
					framer.plain = framer.plain[:0]
				} else if cap(framer.plain) > 128*1024 && len(framer.plain) < 32*1024 {
					// Shrink an oversized buffer like mtprotoPacketFramer.feed does.
					compacted := make([]byte, len(framer.plain))
					copy(compacted, framer.plain)
					framer.plain = compacted
				}

				// Strip length prefix from packetBody before HTTP/2 POST
				var rawMTProto []byte
				switch framer.proto {
				case 0xEFEFEFEF:
					if len(packetBody) > 0 {
						if (packetBody[0] & 0x7f) == 0x7f {
							if len(packetBody) >= 4 {
								rawMTProto = packetBody[4:]
							}
						} else {
							rawMTProto = packetBody[1:]
						}
					}
				case 0xEEEEEEEE, 0xDDDDDDDD:
					if len(packetBody) >= 4 {
						rawMTProto = packetBody[4:]
					}
				default:
					rawMTProto = packetBody
				}

				if len(rawMTProto) == 0 {
					continue
				}

				// Asynchronous HTTP/2 POST stream; every dispatched packet owns
				// one sequence slot, even when its request ultimately fails.
				seq := postSeq
				postSeq++
				go func(seq uint64, body []byte) {
					postCtx, postCancel := context.WithTimeout(bridgeCtx, 45*time.Second)
					defer postCancel()
					data := h2PostPacket(postCtx, client, apiURL, selectedHost, body)
					select {
					case replyCh <- h2Reply{seq: seq, data: data}:
					case <-bridgeCtx.Done():
					}
				}(seq, rawMTProto)
			}
		}

		if err != nil {
			break
		}
	}

	return true
}
