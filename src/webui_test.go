package main

import (
	"encoding/base64"
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

func TestAPIPayloadFormats(t *testing.T) {
	if got, err := apiPayload([]byte(` {"cmd":"status"} `)); err != nil || string(got) != `{"cmd":"status"}` {
		t.Fatalf("raw JSON: got %q, err %v", got, err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"cmd":"status"}`))
	if got, err := apiPayload([]byte(b64)); err != nil || string(got) != `{"cmd":"status"}` {
		t.Fatalf("base64 payload: got %q, err %v", got, err)
	}
	if _, err := apiPayload(nil); err == nil {
		t.Fatal("empty payload must be rejected")
	}
	if _, err := apiPayload([]byte("not-base64!!")); err == nil {
		t.Fatal("garbage payload must be rejected")
	}
}

func TestWebUIHandlerRejectsAndServes(t *testing.T) {
	oldDir := baseDir
	baseDir = t.TempDir()
	t.Cleanup(func() { baseDir = oldDir })
	handler := newWebUIHandler(http.NotFoundHandler())

	post := func(host, origin, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/api", strings.NewReader(body))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// The bundled WebUI forwards the CLI bridge payload as base64.
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"cmd":"status"}`))
	if rec := post("127.0.0.1:17842", "", b64); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("base64 status: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := post("127.0.0.1:17842", "", `{"cmd":"status"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("raw JSON status: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// Cross-site pages and DNS-rebinding hosts must not reach the API.
	if rec := post("127.0.0.1:17842", "https://attacker.example", b64); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: code=%d, want 403", rec.Code)
	}
	if rec := post("attacker.example:17842", "", b64); rec.Code != http.StatusForbidden {
		t.Fatalf("rebound host: code=%d, want 403", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:17842/api", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api: code=%d, want 405", rec.Code)
	}
}
