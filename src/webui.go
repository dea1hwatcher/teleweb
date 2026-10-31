package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// cmdWebUI serves the bundled WebUI over loopback and bridges its API calls to
// the tgws binary, replacing the KernelSU ksu.exec transport on desktop.
func cmdWebUI(addr string) {
	if addr == "" {
		addr = "127.0.0.1:17842"
	}
	root := findWebroot()
	var static http.Handler
	source := root
	if root != "" {
		static = http.FileServer(http.Dir(root))
	} else if fsys := embeddedWebrootFS(); fsys != nil {
		static = http.FileServer(http.FS(fsys))
		source = "embedded"
	} else {
		fmt.Fprintln(os.Stderr, "webui: webroot/index.html not found and nothing embedded (set TELEWEB_WEBROOT)")
		os.Exit(1)
	}
	logf("WebUI listening on http://%s (root: %s)", addr, source)
	fmt.Printf("TeleWEB WebUI: http://%s\n", addr)
	srv := &http.Server{Addr: addr, Handler: newWebUIHandler(static), ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newWebUIHandler(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !apiRequestAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload := strings.TrimSpace(string(body))
		if payload == "" {
			http.Error(w, "empty payload", http.StatusBadRequest)
			return
		}
		self, err := os.Executable()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The WebUI forwards the CLI bridge payload (base64 JSON) unchanged;
		// `tgws api` decodes it.
		out, err := exec.Command(self, "api", payload).Output()
		w.Header().Set("Content-Type", "application/json")
		if err != nil && len(out) == 0 {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
			return
		}
		_, _ = w.Write(out)
	})
	mux.Handle("/", static)
	return mux
}

// apiRequestAllowed rejects cross-site and DNS-rebinding calls to the API.
// Browsers mark cross-origin requests with Origin / Sec-Fetch-Site, so a page
// on another site cannot toggle the transport; the Host allowlist defeats DNS
// rebinding, where the attacker's domain resolves to loopback but the request
// still carries the attacker's host name.
func apiRequestAllowed(r *http.Request) bool {
	if !loopbackName(r.Host) {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !loopbackName(u.Host) {
			return false
		}
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return false
}

func loopbackName(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func findWebroot() string {
	candidates := []string{os.Getenv("TELEWEB_WEBROOT")}
	if mod := os.Getenv("TELEWEB_MOD"); mod != "" {
		candidates = append(candidates, filepath.Join(mod, "webroot"))
	}
	if self, err := os.Executable(); err == nil {
		dir := filepath.Dir(self)
		candidates = append(candidates,
			filepath.Join(dir, "webroot"),
			filepath.Join(dir, "..", "share", "teleweb", "webroot"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "webroot"))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(filepath.Join(c, "index.html")); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}
