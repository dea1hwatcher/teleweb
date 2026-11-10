package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// shouldBypassOutboundProxy evaluates destination address against loopback
// and standard NO_PROXY comma-separated patterns (IP, CIDR, suffix, wildcard).
func shouldBypassOutboundProxy(target string, noProxy string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if noProxy == "" {
		return false
	}
	for _, rawRule := range strings.Split(noProxy, ",") {
		rule := strings.TrimSpace(strings.ToLower(rawRule))
		if rule == "" {
			continue
		}
		if rule == "*" {
			return true
		}
		// CIDR match (e.g. 192.168.0.0/16 or 10.0.0.0/8)
		if _, ipNet, err := net.ParseCIDR(rule); err == nil {
			if ip := net.ParseIP(host); ip != nil && ipNet.Contains(ip) {
				return true
			}
			continue
		}
		// Exact IP or host match
		if rule == host {
			return true
		}
		// Domain suffix match (*.example.com or .example.com or example.com)
		suffix := rule
		if strings.HasPrefix(suffix, "*.") {
			suffix = suffix[1:]
		} else if !strings.HasPrefix(suffix, ".") {
			suffix = "." + suffix
		}
		if strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	return false
}

// readOutboundProxyConfig reads configured outbound proxy from path("outbound_proxy")
// or falls back to standard ALL_PROXY, HTTPS_PROXY, HTTP_PROXY environment variables.
func readOutboundProxyConfig() (proxyURL string, noProxy string) {
	if b, err := os.ReadFile(path("outbound_proxy")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) > 0 {
			u := strings.TrimSpace(lines[0])
			if u == "direct" || u == "none" || u == "off" || u == "" {
				return "", ""
			}
			np := ""
			if len(lines) > 1 {
				np = strings.TrimSpace(lines[1])
			} else {
				np = os.Getenv("NO_PROXY")
				if np == "" {
					np = os.Getenv("no_proxy")
				}
			}
			return u, np
		}
	}

	for _, envKey := range []string{"ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
			if v == "direct" || v == "none" || v == "off" {
				return "", ""
			}
			np := os.Getenv("NO_PROXY")
			if np == "" {
				np = os.Getenv("no_proxy")
			}
			return v, np
		}
	}
	return "", ""
}

type bufConn struct {
	net.Conn
	r io.Reader
}

func (b *bufConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// dialHTTPConnect establishes a TCP tunnel through an upstream HTTP proxy via HTTP CONNECT.
func dialHTTPConnect(ctx context.Context, proxyAddr, targetAddr, user, pass string, forward net.Dialer) (net.Conn, error) {
	conn, err := forward.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("http proxy dial failed: %w", err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if user != "" || pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "User-Agent: TeleWEB/2.1\r\n\r\n"

	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy write failed: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy response failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy rejected CONNECT: status %d %s", resp.StatusCode, resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufConn{Conn: conn, r: io.MultiReader(br, conn)}, nil
	}
	return conn, nil
}

// dialViaOutboundProxy checks whether an outbound proxy is configured and applicable,
// returning (conn, used, err). If used is false, the caller should perform standard direct dial.
func dialViaOutboundProxy(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, bool, error) {
	proxyRaw, noProxy := readOutboundProxyConfig()
	if proxyRaw == "" || shouldBypassOutboundProxy(addr, noProxy) {
		return nil, false, nil
	}

	u, err := url.Parse(proxyRaw)
	if err != nil {
		return nil, true, fmt.Errorf("invalid outbound proxy URL %q: %w", proxyRaw, err)
	}

	forwardDialer := net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return setDialSockOpts(c)
		},
	}

	proxyHostPort := u.Host
	if !strings.Contains(proxyHostPort, ":") {
		if strings.EqualFold(u.Scheme, "http") {
			proxyHostPort += ":8080"
		} else {
			proxyHostPort += ":1080"
		}
	}

	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if user != "" || pass != "" {
			auth = &proxy.Auth{User: user, Password: pass}
		}
		s5Dialer, err := proxy.SOCKS5("tcp", proxyHostPort, auth, &forwardDialer)
		if err != nil {
			return nil, true, fmt.Errorf("socks5 proxy init failed: %w", err)
		}
		if ctxDialer, ok := s5Dialer.(proxy.ContextDialer); ok {
			conn, err := ctxDialer.DialContext(ctx, network, addr)
			return conn, true, err
		}
		// Fallback for non-context dialer
		type dialResult struct {
			c   net.Conn
			err error
		}
		ch := make(chan dialResult, 1)
		go func() {
			c, e := s5Dialer.Dial(network, addr)
			ch <- dialResult{c: c, err: e}
		}()
		select {
		case <-ctx.Done():
			return nil, true, ctx.Err()
		case res := <-ch:
			return res.c, true, res.err
		}

	case "http":
		conn, err := dialHTTPConnect(ctx, proxyHostPort, addr, user, pass, forwardDialer)
		return conn, true, err

	default:
		return nil, true, fmt.Errorf("unsupported outbound proxy scheme: %q", u.Scheme)
	}
}
