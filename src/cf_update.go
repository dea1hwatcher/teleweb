package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	dynamicCFMu      sync.RWMutex
	dynamicCFDomains []string
)

const (
	primaryCFDomainsURL  = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"
	fallbackCFDomainsURL = "https://raw.githubusercontent.com/spatiumstas/tg-ws-proxy-go/main-go/.github/cfproxy-domains.txt"
)

// decodeCFProxyDomain applies the Caesar-cipher de-obfuscation used by tg-ws-proxy:
// the base letters before .com are shifted backwards by the length of the base,
// and the .com TLD is converted to .co.uk.
func decodeCFProxyDomain(raw string) string {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
	if !strings.HasSuffix(s, ".com") {
		return s
	}

	base := strings.TrimSuffix(s, ".com")
	letters := 0
	for _, ch := range base {
		if ch >= 'a' && ch <= 'z' {
			letters++
		}
	}

	decoded := make([]byte, 0, len(base)+len(".co.uk"))
	for i := 0; i < len(base); i++ {
		ch := base[i]
		if ch >= 'a' && ch <= 'z' {
			shift := int(ch-'a') - letters
			shift = ((shift % 26) + 26) % 26
			decoded = append(decoded, byte('a'+shift))
			continue
		}
		decoded = append(decoded, ch)
	}
	return string(decoded) + ".co.uk"
}

func loadRemoteCFDomainsCache() {
	b, err := os.ReadFile(path("cf-domains.remote"))
	if err != nil {
		return
	}
	var domains []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		d := strings.ToLower(strings.TrimSpace(line))
		if d == "" || strings.HasPrefix(d, "#") || !domainPattern.MatchString(d) || seen[d] {
			continue
		}
		seen[d] = true
		domains = append(domains, d)
	}
	if len(domains) >= 3 {
		dynamicCFMu.Lock()
		dynamicCFDomains = domains
		dynamicCFMu.Unlock()
		logf("cf-domains: загружен сохранённый пул из cf-domains.remote (%d доменов)", len(domains))
	}
}

func saveRemoteCFDomainsCache(domains []string) {
	if len(domains) < 3 {
		return
	}
	ensureDir()
	content := strings.Join(domains, "\n") + "\n"
	tmp := path("cf-domains.remote.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, path("cf-domains.remote")); err != nil {
		_ = os.Remove(tmp)
	}
}

func fetchCFDomainsFromURL(ctx context.Context, client *http.Client, targetURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TG-Open/2.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := decodeCFProxyDomain(line)
		if domain == "" || !domainPattern.MatchString(domain) || domain == "web.telegram.org" || strings.HasSuffix(domain, ".web.telegram.org") || seen[domain] {
			continue
		}
		seen[domain] = true
		out = append(out, domain)
	}
	if len(out) < 3 {
		return nil, fmt.Errorf("получено слишком мало валидных доменов (%d)", len(out))
	}
	return out, nil
}

func refreshCFDomains(ctx context.Context) error {
	client := &http.Client{Timeout: 12 * time.Second}
	domains, err := fetchCFDomainsFromURL(ctx, client, primaryCFDomainsURL)
	if err != nil {
		domains, err = fetchCFDomainsFromURL(ctx, client, fallbackCFDomainsURL)
	}
	if err != nil {
		return err
	}

	dynamicCFMu.Lock()
	dynamicCFDomains = domains
	dynamicCFMu.Unlock()
	saveRemoteCFDomainsCache(domains)
	logf("cf-domains: успешно обновлён пул Cloudflare-доменов из сети (%d доменов)", len(domains))
	return nil
}

func startCFDomainsUpdater(ctx context.Context) {
	loadRemoteCFDomainsCache()

	go func() {
		// Initial fetch shortly after boot, once network is likely up.
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
			if err := refreshCFDomains(ctx); err != nil {
				logf("cf-domains: первичное обновление не удалось: %v; используется локальный/встроенный список", err)
			}
		}

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := refreshCFDomains(ctx); err != nil {
					logf("cf-domains: плановое обновление не удалось: %v", err)
				}
			}
		}
	}()
}

func getDynamicCFDomains() []string {
	dynamicCFMu.RLock()
	defer dynamicCFMu.RUnlock()
	if len(dynamicCFDomains) == 0 {
		return nil
	}
	return append([]string(nil), dynamicCFDomains...)
}
