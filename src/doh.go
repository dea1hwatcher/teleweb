package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"` // 1 for A, 28 for AAAA
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

type dohCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}

var (
	dohCache      sync.Map // string -> dohCacheEntry
	dohHTTPClient *http.Client
	dohClientOnce sync.Once
)

var (
	dohEndpointsMu sync.RWMutex
	dohEndpoints   = []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
		"https://dns.adguard-dns.com/dns-query",
	}
)

func getDoHEndpoints() []string {
	dohEndpointsMu.RLock()
	defer dohEndpointsMu.RUnlock()
	out := make([]string, len(dohEndpoints))
	copy(out, dohEndpoints)
	return out
}

func setDoHEndpoints(eps []string) {
	dohEndpointsMu.Lock()
	defer dohEndpointsMu.Unlock()
	dohEndpoints = make([]string, len(eps))
	copy(dohEndpoints, eps)
}

// dohBootstrapIPs maps DoH hostnames to their canonical Anycast IPs so the DoH
// transport can bootstrap even when the ISP's local DNS is poisoned, broken,
// or completely blocks foreign DNS domain resolution.
var dohBootstrapIPs = map[string][]string{
	"cloudflare-dns.com":  {"1.1.1.1", "1.0.0.1"},
	"dns.google":          {"8.8.8.8", "8.8.4.4"},
	"dns.quad9.net":       {"9.9.9.9", "149.112.112.112"},
	"dns.adguard-dns.com": {"94.140.14.14", "94.140.15.15"},
}

func getDoHClient() *http.Client {
	dohClientOnce.Do(func() {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if conn, used, err := dialViaOutboundProxy(ctx, network, addr, 3*time.Second); used {
					return conn, err
				}
				d := net.Dialer{Resolver: systemDNSResolver(), Timeout: 3 * time.Second}
				conn, err := d.DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				// System DNS failed to resolve or dial the endpoint: fallback to hardcoded bootstrap IPs.
				host, port, splitErr := net.SplitHostPort(addr)
				if splitErr == nil {
					if bootstrapIPs, ok := dohBootstrapIPs[host]; ok {
						for _, ip := range bootstrapIPs {
							if bConn, bErr := d.DialContext(ctx, network, net.JoinHostPort(ip, port)); bErr == nil {
								return bConn, nil
							}
						}
					}
				}
				return nil, err
			},
			TLSClientConfig: &tls.Config{
				RootCAs:          getSystemRootCAs(),
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
				// Certificate verification stays ON: DoH exists precisely to
				// defeat spoofing, and these endpoints involve no SNI games.
			},
			ForceAttemptHTTP2: true,
			DisableKeepAlives: false,
			MaxIdleConns:      16,
			IdleConnTimeout:   90 * time.Second,
		}
		dohHTTPClient = &http.Client{
			Transport: tr,
			Timeout:   2 * time.Second,
		}
	})
	return dohHTTPClient
}

func readDoHEnabled() bool         { return readFlag("doh_enabled", true) }
func writeDoHEnabled(v bool) error { return writeFlag("doh_enabled", v) }

func storeDoHCache(host string, entry dohCacheEntry) {
	dohCache.Store(host, entry)
	var count int
	now := time.Now()
	dohCache.Range(func(key, val any) bool {
		count++
		if e, ok := val.(dohCacheEntry); ok && now.After(e.expires) {
			dohCache.Delete(key)
			count--
		} else if count > 256 {
			dohCache.Delete(key)
			count--
		}
		return true
	})
}

var (
	dohOutageUntil atomic.Int64
	dohLastProbe   atomic.Int64
)

const (
	dohOutageCooldownDuration = 30 * time.Second
	dohOutageProbeInterval    = 5 * time.Second
)

var errDoHOutageCooldown = errors.New("DoH is cooling down after total outage")

func isDoHInCooldown() bool {
	now := time.Now().UnixNano()
	until := dohOutageUntil.Load()
	if now >= until {
		return false
	}
	// Allow a single background probe every 5 seconds to test recovery
	last := dohLastProbe.Load()
	if now-last >= int64(dohOutageProbeInterval) {
		if dohLastProbe.CompareAndSwap(last, now) {
			return false // probe allowed
		}
	}
	return true
}

func markDoHOutage() {
	now := time.Now().UnixNano()
	dohOutageUntil.Store(now + int64(dohOutageCooldownDuration))
	dohLastProbe.Store(now)
}

func markDoHSuccess() {
	dohOutageUntil.Store(0)
}

func resetDoHOutage() {
	dohOutageUntil.Store(0)
	dohLastProbe.Store(0)
}

func resolveDoHRace(ctx context.Context, host string) ([]netip.Addr, error) {
	if !readDoHEnabled() {
		return nil, errors.New("DoH is disabled")
	}

	if isDoHInCooldown() {
		return nil, errDoHOutageCooldown
	}

	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return nil, errors.New("empty host")
	}

	// 1. Check in-memory DoH cache
	if val, ok := dohCache.Load(host); ok {
		entry := val.(dohCacheEntry)
		if time.Now().Before(entry.expires) && len(entry.ips) > 0 {
			return append([]netip.Addr(nil), entry.ips...), nil
		}
		dohCache.Delete(host)
	}

	// 2. Parallel race across endpoints
	client := getDoHClient()
	type raceResult struct {
		ips []netip.Addr
		ttl int
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	endpoints := getDoHEndpoints()
	results := make(chan raceResult, len(endpoints))
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		endpoint := ep
		wg.Add(1)
		go func() {
			defer wg.Done()

			reqURL := fmt.Sprintf("%s?name=%s&type=A", endpoint, url.QueryEscape(host))
			req, err := http.NewRequestWithContext(raceCtx, http.MethodGet, reqURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/dns-json")
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			if err != nil {
				return
			}

			var dResp dohResponse
			if err := json.Unmarshal(body, &dResp); err != nil || dResp.Status != 0 {
				return
			}

			var ips []netip.Addr
			minTTL := 300
			for _, ans := range dResp.Answer {
				if ans.Type == 1 { // A record
					if addr, err := netip.ParseAddr(strings.TrimSpace(ans.Data)); err == nil && addr.Is4() {
						ips = append(ips, addr)
						if ans.TTL > 0 && ans.TTL < minTTL {
							minTTL = ans.TTL
						}
					}
				}
			}

			if len(ips) > 0 {
				select {
				case results <- raceResult{ips: ips, ttl: minTTL}:
				default:
				}
			}
		}()
	}

	// Wait in background and close channel when all done
	go func() {
		wg.Wait()
		close(results)
	}()

	select {
	case res, ok := <-results:
		if ok && len(res.ips) > 0 {
			markDoHSuccess()
			ttlSec := res.ttl
			if ttlSec < 60 {
				ttlSec = 60
			}
			if ttlSec > 600 {
				ttlSec = 600
			}
			storeDoHCache(host, dohCacheEntry{
				ips:     res.ips,
				expires: time.Now().Add(time.Duration(ttlSec) * time.Second),
			})
			return res.ips, nil
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	markDoHOutage()
	return nil, fmt.Errorf("all DoH endpoints failed for %s", host)
}
