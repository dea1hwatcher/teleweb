package main

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type poolSlot struct {
	dc      int
	isMedia bool
	isTest  bool
}

type poolEntry struct {
	ws        *wsConn
	createdAt time.Time
}

const (
	wsPoolMaxAge        = 105 * time.Second // telegram drops idle WS at ~120s, CF at ~100s
	wsPoolCheckInterval = 15 * time.Second
)

type WsPool struct {
	queues    sync.Map // poolSlot -> chan *poolEntry
	refilling sync.Map // poolSlot -> *atomic.Int32
	ctx       context.Context
	cancel    context.CancelFunc
	size      atomic.Int32
	hits      atomic.Int64
	misses    atomic.Int64
}

var (
	globalWsPool     *WsPool
	globalWsPoolOnce sync.Once
)

func initGlobalWsPool(ctx context.Context) {
	globalWsPoolOnce.Do(func() {
		sz := readPoolSize()
		globalWsPool = newWsPool(ctx, sz)
		globalWsPool.StartRotation()
	})
}

func newWsPool(parentCtx context.Context, size int) *WsPool {
	ctx, cancel := context.WithCancel(parentCtx)
	p := &WsPool{
		ctx:    ctx,
		cancel: cancel,
	}
	p.size.Store(int32(size))
	return p
}

func (p *WsPool) getQueue(slot poolSlot) (chan *poolEntry, *atomic.Int32) {
	qVal, _ := p.queues.LoadOrStore(slot, make(chan *poolEntry, 8))
	rfVal, _ := p.refilling.LoadOrStore(slot, &atomic.Int32{})
	return qVal.(chan *poolEntry), rfVal.(*atomic.Int32)
}

func isPoolConnAlive(c net.Conn) bool {
	if c == nil {
		return false
	}
	_ = c.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	var one [1]byte
	n, err := c.Read(one[:])
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true // timeout means socket is still open and waiting for data
		}
		return false // EOF, reset, or broken pipe
	}
	// If we read unexpected data before MTProto handshake, socket is out of sync
	return n == 0
}

func (p *WsPool) Get(dc int, isMedia bool, isTest bool) *wsConn {
	if p == nil || p.size.Load() <= 0 {
		return nil
	}
	slot := poolSlot{dc: dc, isMedia: isMedia, isTest: isTest}
	q, _ := p.getQueue(slot)
	now := time.Now()

	for {
		select {
		case entry := <-q:
			if entry == nil || entry.ws == nil {
				continue
			}
			if now.Sub(entry.createdAt) > wsPoolMaxAge {
				_ = entry.ws.Close()
				continue
			}
			if !isPoolConnAlive(entry.ws.conn) {
				_ = entry.ws.Close()
				continue
			}
			p.hits.Add(1)
			go p.Refill(dc, isMedia, isTest)
			return entry.ws
		default:
			p.misses.Add(1)
			return nil
		}
	}
}

func (p *WsPool) Refill(dc int, isMedia bool, isTest bool) {
	if p == nil {
		return
	}
	sz := int(p.size.Load())
	if sz <= 0 {
		return
	}
	slot := poolSlot{dc: dc, isMedia: isMedia, isTest: isTest}
	q, rf := p.getQueue(slot)
	if !rf.CompareAndSwap(0, 1) {
		return // another refiller is already running for this slot
	}

	go func() {
		defer rf.Store(0)
		needed := sz - len(q)
		if needed <= 0 {
			return
		}

		for i := 0; i < needed; i++ {
			select {
			case <-p.ctx.Done():
				return
			default:
			}

			dialCtx, dialCancel := context.WithTimeout(p.ctx, 8*time.Second)
			ws, err := dialTelegramWS(dialCtx, dc, isMedia, isTest)
			dialCancel()

			if err == nil && ws != nil {
				entry := &poolEntry{ws: ws, createdAt: time.Now()}
				select {
				case q <- entry:
				case <-p.ctx.Done():
					_ = ws.Close()
					return
				default:
					_ = ws.Close()
				}
			}
		}
	}()
}

func (p *WsPool) Warmup(activeDCs []int) {
	if p == nil || p.size.Load() <= 0 {
		return
	}
	for _, dc := range activeDCs {
		if dc >= 1 && dc <= 5 {
			go p.Refill(dc, false, false)
			go p.Refill(dc, true, false)
		}
	}
}

func (p *WsPool) StartRotation() {
	go func() {
		ticker := time.NewTicker(wsPoolCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
				p.rotate()
			}
		}
	}()
}

func (p *WsPool) rotate() {
	if p.size.Load() <= 0 {
		return
	}
	now := time.Now()

	p.queues.Range(func(key, value any) bool {
		slot := key.(poolSlot)
		q := value.(chan *poolEntry)

		var retained []*poolEntry
		for {
			select {
			case entry := <-q:
				if entry == nil || entry.ws == nil {
					continue
				}
				// Discard if older than wsPoolMaxAge
				if now.Sub(entry.createdAt) > wsPoolMaxAge {
					_ = entry.ws.Close()
					continue
				}
				// Keep-alive ping frame (Opcode 9)
				if err := entry.ws.writeFrame(9, nil); err != nil {
					_ = entry.ws.Close()
					continue
				}
				retained = append(retained, entry)
			default:
				goto Drained
			}
		}

	Drained:
		for _, entry := range retained {
			select {
			case q <- entry:
			default:
				_ = entry.ws.Close()
			}
		}

		sz := int(p.size.Load())
		if len(q) < sz {
			go p.Refill(slot.dc, slot.isMedia, slot.isTest)
		}
		return true
	})
}

func (p *WsPool) IdleCount() int {
	if p == nil {
		return 0
	}
	total := 0
	p.queues.Range(func(_, value any) bool {
		q := value.(chan *poolEntry)
		total += len(q)
		return true
	})
	return total
}

func (p *WsPool) Stats() (hits, misses int64, idle int) {
	if p == nil {
		return 0, 0, 0
	}
	return p.hits.Load(), p.misses.Load(), p.IdleCount()
}

func (p *WsPool) Close() {
	if p == nil {
		return
	}
	p.cancel()
	p.queues.Range(func(_, value any) bool {
		q := value.(chan *poolEntry)
		for {
			select {
			case entry := <-q:
				if entry != nil && entry.ws != nil {
					_ = entry.ws.Close()
				}
			default:
				return true
			}
		}
	})
}

func readPoolSize() int {
	b, err := os.ReadFile(path("pool_size"))
	if err != nil {
		return 2 // default 2 pre-warmed connections per DC
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v < 0 {
		return 2
	}
	if v > 4 {
		return 4 // limit max 4 to protect mobile RAM and radio
	}
	return v
}

func writePoolSize(sz int) error {
	if sz < 0 {
		sz = 0
	}
	if sz > 4 {
		sz = 4
	}
	ensureDir()
	if globalWsPool != nil {
		globalWsPool.size.Store(int32(sz))
	}
	return os.WriteFile(path("pool_size"), []byte(strconv.Itoa(sz)), 0600)
}
