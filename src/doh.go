package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
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

var dohEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://dns.quad9.net/dns-query",
	"https://dns.adguard-dns.com/dns-query",
}

func getDoHClient() *http.Client {
	dohClientOnce.Do(func() {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: getSystemRootCAs(),
				// Certificate verification stays ON: DoH exists precisely to
				// defeat spoofing, and these endpoints involve no SNI games.
			},
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

func readDoHEnabled() bool {
	b, err := os.ReadFile(path("doh_enabled"))
	if err != nil {
		return true // enabled by default for protection against DNS spoofing
	}
	return strings.TrimSpace(string(b)) != "0"
}

func writeDoHEnabled(v bool) error {
	ensureDir()
	val := "1"
	if !v {
		val = "0"
	}
	return os.WriteFile(path("doh_enabled"), []byte(val), 0600)
}

func storeDoHCache(host string, entry dohCacheEntry) {
	var count int
	dohCache.Range(func(key, val any) bool {
		count++
		if e, ok := val.(dohCacheEntry); ok && time.Now().After(e.expires) {
			dohCache.Delete(key)
		}
		return true
	})
	if count > 256 {
		dohCache.Range(func(key, _ any) bool {
			dohCache.Delete(key)
			count--
			return count > 128
		})
	}
	dohCache.Store(host, entry)
}

func resolveDoHRace(ctx context.Context, host string) ([]netip.Addr, error) {
	if !readDoHEnabled() {
		return nil, errors.New("DoH is disabled")
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

	results := make(chan raceResult, len(dohEndpoints))
	var wg sync.WaitGroup

	for _, ep := range dohEndpoints {
		endpoint := ep
		wg.Add(1)
		go func() {
			defer wg.Done()

			reqURL := fmt.Sprintf("%s?name=%s&type=A", endpoint, url.QueryEscape(host))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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

	return nil, fmt.Errorf("all DoH endpoints failed for %s", host)
}
