package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIRequestAllowed(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		origin   string
		secFetch string
		want     bool
	}{
		{"loopback", "127.0.0.1:17842", "", "", true},
		{"localhost", "localhost:17842", "", "", true},
		{"ipv6 loopback", "[::1]:17842", "", "", true},
		{"rebound host", "attacker.example:17842", "", "", false},
		{"cross origin", "127.0.0.1:17842", "https://attacker.example", "", false},
		{"same origin", "127.0.0.1:17842", "http://127.0.0.1:17842", "", true},
		{"localhost origin", "localhost:17842", "http://localhost:17842", "", true},
		{"cross-site fetch", "127.0.0.1:17842", "", "cross-site", false},
		{"same-origin fetch", "127.0.0.1:17842", "", "same-origin", true},
		{"address bar", "127.0.0.1:17842", "", "none", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/api", nil)
		req.Host = tc.host
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.secFetch != "" {
			req.Header.Set("Sec-Fetch-Site", tc.secFetch)
		}
		if got := apiRequestAllowed(req); got != tc.want {
			t.Errorf("%s: apiRequestAllowed=%t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestWebUIHandlerRejectsCrossSite(t *testing.T) {
	handler := newWebUIHandler(http.NotFoundHandler())

	post := func(host, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/api", strings.NewReader("eyJjbWQiOiJzdGF0dXMifQ=="))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post("127.0.0.1:17842", "https://attacker.example"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: code=%d, want 403", rec.Code)
	}
	if rec := post("attacker.example:17842", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("rebound host: code=%d, want 403", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17842/api", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api: code=%d, want 405", rec.Code)
	}
}
