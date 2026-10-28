package main

import (
	"fmt"
	"io"
	"net/http"
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
	if root == "" {
		fmt.Fprintln(os.Stderr, "webui: webroot/index.html not found (set TELEWEB_WEBROOT)")
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
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
		out, err := exec.Command(self, "api", payload).Output()
		w.Header().Set("Content-Type", "application/json")
		if err != nil && len(out) == 0 {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())))
			return
		}
		_, _ = w.Write(out)
	})
	mux.Handle("/", http.FileServer(http.Dir(root)))
	logf("WebUI listening on http://%s (root: %s)", addr, root)
	fmt.Printf("TeleWEB WebUI: http://%s\n", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
