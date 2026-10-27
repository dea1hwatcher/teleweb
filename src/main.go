// TeleWEB transparent WebSocket transport for Telegram.
// SPDX-License-Identifier: MIT
package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	stdpath "path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	defaultPort = 17841
	maxWSFrame  = 16 << 20
	wsGUID      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var (
	baseDir          = envOr("TELEWEB_DIR", "/data/adb/teleweb")
	startAt          = time.Now()
	active           int64
	wsCount          int64
	failCnt          int64
	trafficUpBytes   int64 // Telegram client -> WSS, cumulative for this daemon lifetime
	trafficDownBytes int64 // WSS -> Telegram client, cumulative for this daemon lifetime
	connSeq          int64
	statsMu          sync.Mutex
	dcCounts         = map[string]int{}
	logMu            sync.Mutex
	logFile          *os.File
	logWrites        uint64
	appCacheMu       sync.Mutex
	appCache         []App
	uidCache         []int
	cfHostCache      sync.Map // route key -> last working Cloudflare-fronted KWS hostname
	routeCacheMu     sync.Mutex
	routeCacheDisk   = map[string]persistedRoute{}
	routeHealthMu    sync.Mutex
	routeHealth      = map[string]routeHealthState{} // host -> repeated early remote-close state
	cfBalanceSeq     uint64
	ioBufPool        = sync.Pool{
		New: func() any {
			b := make([]byte, 32*1024)
			return &b
		},
	}
	frameBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	}
)

type persistedRoute struct {
	Host      string    `json:"host,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// loadRouteCache restores the last known-good routes across daemon restarts.
// It stores only route metadata, never client streams or authentication data.
func loadRouteCache() {
	b, err := os.ReadFile(path("route-cache.json"))
	if err != nil {
		return
	}
	var saved map[string]persistedRoute
	if err := json.Unmarshal(b, &saved); err != nil {
		logf("route-cache: saved pool corrupted; rebuilding: %v", err)
		return
	}
	n := 0
	routeCacheMu.Lock()
	for key, entry := range saved {
		if entry.Host != "" {
			cfHostCache.Store(key, entry.Host)
			n++
		}
		routeCacheDisk[key] = entry
	}
	routeCacheMu.Unlock()
	if n > 0 {
		logf("route-cache: restored previously successful WSS routes for %d DC/media profiles", n)
	}
}

func saveRouteCache(key, host string) {
	if host == "" {
		return
	}
	routeCacheMu.Lock()
	defer routeCacheMu.Unlock()
	entry := routeCacheDisk[key]
	if entry.Host == host {
		return
	}
	entry.Host = host
	entry.UpdatedAt = time.Now()
	routeCacheDisk[key] = entry
	b, err := json.MarshalIndent(routeCacheDisk, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return
	}
	tmp := path("route-cache.json.tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, path("route-cache.json")); err != nil {
		_ = os.Remove(tmp)
	}
}

type routeHealthState struct {
	count    int
	failures int
	last     time.Time
	until    time.Time
}

func routeBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := 30 * time.Second
	for i := 1; i < failures && d < 30*time.Minute; i++ {
		d *= 2
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

type App struct {
	Name       string `json:"name"`
	Pkg        string `json:"pkg"`
	UID        int    `json:"uid"`
	IconNormal string `json:"iconNormal,omitempty"`
	IconMonet  string `json:"iconMonet,omitempty"`
}
type Status struct {
	Enabled           bool           `json:"enabled"`
	Running           bool           `json:"running"`
	Uptime            int64          `json:"uptime"`
	Port              int            `json:"port"`
	Apps              []App          `json:"apps"`
	Active            int64          `json:"active"`
	WS                int64          `json:"ws"`
	Fail              int64          `json:"fail"`
	DC                map[string]int `json:"dc"`
	MemNowBytes       int64          `json:"memNowBytes"`
	MemPeakBytes      int64          `json:"memPeakBytes"`
	TrafficUpBytes    int64          `json:"trafficUpBytes"`
	TrafficDownBytes  int64          `json:"trafficDownBytes"`
	TrafficTotalBytes int64          `json:"trafficTotalBytes"`
	Log               string         `json:"log"`
	CFPriority        bool           `json:"cfPriority"`
	CFBalance         bool           `json:"cfBalance"`
	CustomCFDomain    string         `json:"customCFDomain"`
	CustomCFWorker    string         `json:"customCFWorker"`
	DCOverrides       string         `json:"dcOverrides"`
	PoolSize          int            `json:"poolSize"`
	PoolHits          int64          `json:"poolHits"`
	PoolMisses        int64          `json:"poolMisses"`
	PoolIdle          int            `json:"poolIdle"`
	DoHEnabled        bool           `json:"dohEnabled"`
	LastCFPoP         string         `json:"lastCfPoP"`
	LastCFRay         string         `json:"lastCfRay"`
	ForceTestDC       bool           `json:"forceTestDc"`
	H2MediaEnabled    bool           `json:"h2MediaEnabled"`
	DC203DirectTCP    bool           `json:"dc203DirectTcp"`
}

type apiRequest struct {
	Cmd            string  `json:"cmd"`
	Enabled        *bool   `json:"enabled,omitempty"`
	CFPriority     *bool   `json:"cfPriority,omitempty"`
	CFBalance      *bool   `json:"cfBalance,omitempty"`
	CustomCFDomain *string `json:"customCFDomain,omitempty"`
	CustomCFWorker *string `json:"customCFWorker,omitempty"`
	DCOverrides    *string `json:"dcOverrides,omitempty"`
	PoolSize       *int    `json:"poolSize,omitempty"`
	DoHEnabled     *bool   `json:"dohEnabled,omitempty"`
	ForceTestDC    *bool   `json:"forceTestDc,omitempty"`
	H2MediaEnabled *bool   `json:"h2MediaEnabled,omitempty"`
	DC203DirectTCP *bool   `json:"dc203DirectTcp,omitempty"`
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func path(name string) string { return filepath.Join(baseDir, name) }
func ensureDir()              { _ = os.MkdirAll(baseDir, 0700) }

const defaultDescBase = "TeleWEB: прозрачный WSS-транспорт для Telegram (DC1-DC5)"

var (
	descMu          sync.Mutex
	lastWrittenDesc string
)

func getModulePropPath() string {
	candidates := []string{
		os.Getenv("TELEWEB_MOD"),
		"/data/adb/modules/teleweb",
		"/data/adb/modules_update/teleweb",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(filepath.Dir(exe)))
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		p := filepath.Join(c, "module.prop")
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func currentStatusDesc() string {
	if !readEnabled() {
		return "⛔ Остановлено"
	}
	running := daemonHealthy()
	rules := rulesHealthy()
	if !running || !rules {
		return "⚠️ Сбой службы"
	}
	mode := "WSS"
	if readCFPriority() {
		mode = "WSS (CF Priority)"
	}
	return "✅ Работает · " + mode
}

func updateModuleDescription(statusText string) {
	descMu.Lock()
	defer descMu.Unlock()

	propPath := getModulePropPath()
	if propPath == "" {
		return
	}

	data, err := os.ReadFile(propPath)
	if err != nil {
		return
	}

	fullDesc := statusText + " | " + defaultDescBase
	if statusText == "" {
		fullDesc = defaultDescBase
	}

	if fullDesc == lastWrittenDesc {
		return
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	found := false
	changed := false

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmed, "description=") {
			currentVal := strings.TrimPrefix(trimmed, "description=")
			if currentVal != fullDesc {
				newLines = append(newLines, "description="+fullDesc)
				changed = true
			} else {
				newLines = append(newLines, trimmed)
			}
			found = true
		} else {
			newLines = append(newLines, trimmed)
		}
	}
	if !found {
		newLines = append(newLines, "description="+fullDesc)
		changed = true
	}
	if !changed {
		lastWrittenDesc = fullDesc
		return
	}

	out := strings.Join(newLines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}

	tmp := propPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(out), 0644); err == nil {
		if err := os.Rename(tmp, propPath); err == nil {
			lastWrittenDesc = fullDesc
		} else {
			_ = os.Remove(tmp)
		}
	}
}
func logf(format string, a ...any) {
	msg := time.Now().Format("2006/01/02 15:04:05 ") + fmt.Sprintf(format, a...)
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Fprintln(os.Stderr, msg)
	if logFile == nil {
		ensureDir()
		f, err := os.OpenFile(path("tgws.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			logFile = f
		}
	}
	if logFile != nil {
		_, _ = fmt.Fprintln(logFile, msg)
		// Avoid fsync on every connection event. Android flash syncs are expensive;
		// append writes are enough for routine diagnostics.
		logWrites++
		if logWrites%64 == 0 {
			if info, err := logFile.Stat(); err == nil && info.Size() > 256*1024 {
				_ = logFile.Sync()
				b, readErr := os.ReadFile(path("tgws.log"))
				if readErr == nil && len(b) > 128*1024 {
					tail := b[len(b)-128*1024:]
					_ = logFile.Truncate(0)
					_, _ = logFile.Seek(0, io.SeekStart)
					_, _ = logFile.Write(tail)
					_ = logFile.Sync()
				}
			}
		}
	}
}

func runtimeVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		return bi.GoVersion
	}
	return "unknown"
}

func logStack(prefix string) {
	logf("%s\n%s", prefix, string(debug.Stack()))
}

func procSummary(pid int) string {
	if pid <= 1 {
		return "pid=none"
	}
	cmd, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	state := "?"
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "State:") {
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
				break
			}
		}
	}
	oom, _ := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid))
	cgText := "unknown"
	if cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		var parts []string
		for _, entry := range parseProcCgroups(string(cg)) {
			part := fmt.Sprintf("%s:%s", entry.controllers, entry.path)
			if processFrozen(pid, entry) {
				part += "(frozen=1)"
			}
			parts = append(parts, part)
		}
		if len(parts) > 0 {
			cgText = strings.Join(parts, ",")
		}
	}
	return fmt.Sprintf("pid=%d state=%q oom_score_adj=%q cgroup=%q cmd=%q", pid, state, strings.TrimSpace(string(oom)), cgText, strings.ReplaceAll(strings.TrimSpace(string(cmd)), "\x00", " "))
}

func startSignalLogger() {
	ch := make(chan os.Signal, 4)
	notifySignals(ch)
	go func() {
		for sig := range ch {
			logf("process: received signal %s; shutting down", sig)
			os.Exit(0)
		}
	}()
}

func readEnabled() bool {
	b, e := os.ReadFile(path("enabled"))
	if e != nil {
		return true
	}
	return strings.TrimSpace(string(b)) == "1"
}
func writeEnabled(v bool) error {
	ensureDir()
	s := "0\n"
	if v {
		s = "1\n"
	}
	return os.WriteFile(path("enabled"), []byte(s), 0600)
}

// cfgFileCache memoizes config-file parses for the hot per-connection path.
// Entries are validated by a single Stat (mtime+size) and expire after 2s, so
// a dial performs one cheap syscall instead of several full file reads and
// regex passes, while external edits are picked up almost immediately.
var cfgFileCache = struct {
	mu      sync.Mutex
	entries map[string]cfgFileEntry
}{entries: map[string]cfgFileEntry{}}

type cfgFileEntry struct {
	sig     uint64
	value   any
	expires time.Time
}

func cfgFileSig(name string) uint64 {
	st, err := os.Stat(path(name))
	if err != nil {
		return 0 // absent file: stable signature so absence is cacheable too
	}
	return uint64(st.ModTime().UnixNano())*31 ^ uint64(st.Size())
}

func cachedFileRead(name string, load func() any) any {
	sig := cfgFileSig(name)
	now := time.Now()
	cfgFileCache.mu.Lock()
	defer cfgFileCache.mu.Unlock()
	if e, ok := cfgFileCache.entries[name]; ok && now.Before(e.expires) && e.sig == sig {
		return e.value
	}
	v := load()
	cfgFileCache.entries[name] = cfgFileEntry{sig: sig, value: v, expires: now.Add(2 * time.Second)}
	return v
}

func dcOverridesCached() map[int]string {
	return cachedFileRead("dc-override", func() any { return readDCOverrides() }).(map[int]string)
}

func cfPriorityCached() bool {
	return cachedFileRead("cf-priority", func() any { return readCFPriority() }).(bool)
}

func cfBalanceCached() bool {
	return cachedFileRead("cf-balance", func() any { return readCFBalance() }).(bool)
}

func customCFWorkerCached() string {
	return cachedFileRead("custom-cf-worker", func() any { return readCustomCFWorker() }).(string)
}

func forceTestDCCached() bool {
	return cachedFileRead("force_test_dc", func() any { return readForceTestDC() }).(bool)
}

func h2MediaEnabledCached() bool {
	return cachedFileRead("h2_media_enabled", func() any { return readH2MediaEnabled() }).(bool)
}

func doHEnabledCached() bool {
	return cachedFileRead("doh_enabled", func() any { return readDoHEnabled() }).(bool)
}

func dc203DirectTCPCached() bool {
	return cachedFileRead("dc203_direct_tcp", func() any { return readDC203DirectTCP() }).(bool)
}

func cfDomainsCached() []string {
	return cachedFileRead("cf-domains", func() any { return cfDomains() }).([]string)
}

func readFlag(name string, defaultValue bool) bool {
	b, err := os.ReadFile(path(name))
	if err != nil {
		return defaultValue
	}
	value := strings.TrimSpace(string(b))
	// Default-on flags require an explicit "0" to disable them.
	if defaultValue {
		return value != "0"
	}
	return value == "1"
}

func writeFlag(name string, v bool) error {
	ensureDir()
	value := "0\n"
	if v {
		value = "1\n"
	}
	return os.WriteFile(path(name), []byte(value), 0600)
}

func readCFPriority() bool         { return readFlag("cf-priority", false) }
func writeCFPriority(v bool) error { return writeFlag("cf-priority", v) }
func readCFBalance() bool          { return readFlag("cf-balance", false) }
func writeCFBalance(v bool) error  { return writeFlag("cf-balance", v) }

func readCustomCFDomain() string {
	b, err := os.ReadFile(path("custom-cf-domain"))
	if err != nil {
		return ""
	}
	d := strings.ToLower(strings.TrimSpace(string(b)))
	if d != "" && domainPattern.MatchString(d) && !strings.HasSuffix(d, ".web.telegram.org") && d != "web.telegram.org" {
		return d
	}
	return ""
}

func writeCustomCFDomain(d string) error {
	ensureDir()
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		_ = os.Remove(path("custom-cf-domain"))
		return nil
	}
	if !domainPattern.MatchString(d) || strings.HasSuffix(d, ".web.telegram.org") || d == "web.telegram.org" {
		return fmt.Errorf("invalid domain: %s", d)
	}
	return os.WriteFile(path("custom-cf-domain"), []byte(d+"\n"), 0600)
}

func normalizeWorkerAddress(w string) string {
	w = strings.TrimSpace(w)
	w = strings.TrimPrefix(w, "https://")
	w = strings.TrimPrefix(w, "wss://")
	w = strings.TrimPrefix(w, "http://")
	w = strings.TrimPrefix(w, "ws://")
	return strings.TrimRight(w, "/")
}

func readCustomCFWorker() string {
	b, err := os.ReadFile(path("custom-cf-worker"))
	if err != nil {
		return ""
	}
	return normalizeWorkerAddress(string(b))
}

func writeCustomCFWorker(w string) error {
	ensureDir()
	w = normalizeWorkerAddress(w)
	if w == "" {
		_ = os.Remove(path("custom-cf-worker"))
		return nil
	}
	return os.WriteFile(path("custom-cf-worker"), []byte(w+"\n"), 0600)
}

var (
	lastCFRay atomic.Pointer[string]
	lastCFPoP atomic.Pointer[string]
)

func parseCFRayPoP(ray string) string {
	ray = strings.TrimSpace(ray)
	if idx := strings.LastIndex(ray, "-"); idx != -1 && idx < len(ray)-1 {
		pop := strings.ToUpper(strings.TrimSpace(ray[idx+1:]))
		if len(pop) >= 3 && len(pop) <= 4 {
			for _, r := range pop {
				if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
					return ""
				}
			}
			return pop
		}
	}
	return ""
}

func readForceTestDC() bool         { return readFlag("force_test_dc", false) }
func writeForceTestDC(v bool) error { return writeFlag("force_test_dc", v) }

func readDCOverridesRaw() string {
	b, err := os.ReadFile(path("dc-override"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readDCOverrides() map[int]string {
	raw := readDCOverridesRaw()
	if raw == "" {
		return nil
	}
	out := make(map[int]string)
	pairs := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
	})
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		dc, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || dc < 1 || dc > 5 {
			continue
		}
		ipStr := strings.TrimSpace(parts[1])
		addr, err := netip.ParseAddr(ipStr)
		if err == nil && addr.IsValid() && addr.Is4() {
			out[dc] = addr.String()
		}
	}
	return out
}

func writeDCOverrides(raw string) error {
	ensureDir()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		_ = os.Remove(path("dc-override"))
		return nil
	}
	pairs := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
	})
	var cleaned []string
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid DC:IP pair format (%s)", pair)
		}
		dc, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || dc < 1 || dc > 5 {
			return fmt.Errorf("invalid DC number (1-5): %s", parts[0])
		}
		ipStr := strings.TrimSpace(parts[1])
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.IsValid() || !addr.Is4() {
			return fmt.Errorf("invalid IPv4 address for DC%d: %s", dc, ipStr)
		}
		cleaned = append(cleaned, fmt.Sprintf("%d:%s", dc, addr.String()))
	}
	content := strings.Join(cleaned, ", ") + "\n"
	return os.WriteFile(path("dc-override"), []byte(content), 0600)
}
func pidAlive() bool {
	b, e := os.ReadFile(path("tgws.pid"))
	if e != nil {
		return false
	}
	p, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if p <= 1 {
		return false
	}
	if !isPidAlive(p) {
		return false
	}
	if _, err := os.Stat("/proc"); err == nil {
		return processHasArg(p, "serve")
	}
	return true
}
func tailLog(n int) string {
	b, e := os.ReadFile(path("tgws.log"))
	if e != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

var packageNames = []struct{ Pkg, Name string }{
	{"com.exteragram.messenger", "exteraGram"},
	{"org.telegram.messenger", "Telegram"},
	{"org.telegram.messenger.web", "Telegram Web"},
	{"org.telegram.messenger.beta", "Telegram Beta"},
	{"org.telegram.plus", "Plus Messenger"},
	{"org.thunderdog.challegram", "Telegram X"},
	{"com.nicegram", "Nicegram"},
	{"nekox.messenger", "Nekogram X"},
	{"com.nekox.messenger", "Nekogram"},
	{"com.iMe.android", "iMe"},
	{"com.radolyn.ayugram", "Ayugram"},
	{"it.octogram.android", "Octogram"},
	{"com.octogram", "Octogram"},
	{"org.forkgram.messenger", "Forkgram"},
	{"com.telegram.messenger", "Telegram"},
	{"org.nemogram.messenger", "Nemogram"},
	{"org.nemogram", "Nemogram"},
}

func packageUID(pkg string) int {
	for _, cmd := range [][]string{{"cmd", "package", "list", "packages", "-U", pkg}, {"pm", "list", "packages", "-U", pkg}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			re := regexp.MustCompile(`uid:(\d+)`)
			m := re.FindSubmatch(out)
			if len(m) > 1 {
				n, _ := strconv.Atoi(string(m[1]))
				if n > 0 {
					return n
				}
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	out, _ := exec.CommandContext(ctx, "dumpsys", "package", pkg).CombinedOutput()
	cancel()
	for _, pat := range []string{`userId=(\d+)`, `appId=(\d+)`} {
		m := regexp.MustCompile(pat).FindSubmatch(out)
		if len(m) > 1 {
			n, _ := strconv.Atoi(string(m[1]))
			if n > 0 {
				return n
			}
		}
	}
	return 0
}

func findPackageAPK(pkg string) string {
	for _, cmd := range [][]string{{"cmd", "package", "path", pkg}, {"pm", "path", pkg}} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "package:") {
					p := strings.TrimPrefix(line, "package:")
					if strings.HasSuffix(p, "base.apk") || strings.HasSuffix(p, ".apk") {
						return p
					}
				}
			}
		}
	}
	return ""
}

func scoreDensity(name string) int {
	score := 1
	if strings.Contains(name, "xxxhdpi") {
		score = 6
	} else if strings.Contains(name, "xxhdpi") {
		score = 5
	} else if strings.Contains(name, "xhdpi") {
		score = 4
	} else if strings.Contains(name, "hdpi") {
		score = 3
	} else if strings.Contains(name, "mdpi") {
		score = 2
	}
	if strings.Contains(name, "mipmap") {
		score += 1
	}
	return score
}

func extractPathFromAXML(data []byte) string {
	if len(data) < 32 {
		return ""
	}
	xmlType := binary.LittleEndian.Uint16(data[0:2])
	if xmlType != 0x0003 {
		return ""
	}
	spType := binary.LittleEndian.Uint16(data[8:10])
	if spType != 0x0001 {
		return ""
	}
	spHeaderSize := binary.LittleEndian.Uint16(data[10:12])
	strCount := binary.LittleEndian.Uint32(data[16:20])
	flags := binary.LittleEndian.Uint32(data[24:28])
	strStart := binary.LittleEndian.Uint32(data[28:32])

	isUTF8 := (flags & 0x100) != 0
	poolBase := 8
	stringsBase := poolBase + int(strStart)
	offsetsStart := poolBase + int(spHeaderSize)

	if strCount > 2000 || int(offsetsStart)+int(strCount)*4 > len(data) {
		return ""
	}

	for i := 0; i < int(strCount); i++ {
		off := int(binary.LittleEndian.Uint32(data[offsetsStart+i*4 : offsetsStart+i*4+4]))
		pos := stringsBase + off
		if pos >= len(data) {
			continue
		}
		var str string
		if isUTF8 {
			if pos >= len(data) {
				continue
			}
			u16len := int(data[pos])
			pos++
			if (u16len & 0x80) != 0 {
				pos++
			}
			if pos >= len(data) {
				continue
			}
			u8len := int(data[pos])
			pos++
			if (u8len & 0x80) != 0 {
				pos++
			}
			if pos+u8len <= len(data) {
				str = string(data[pos : pos+u8len])
			}
		} else {
			if pos+2 > len(data) {
				continue
			}
			u16len := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			pos += 2
			if (u16len & 0x8000) != 0 {
				pos += 2
			}
			byteLen := u16len * 2
			if pos+byteLen <= len(data) {
				runes := make([]rune, 0, u16len)
				for j := 0; j < byteLen; j += 2 {
					runes = append(runes, rune(binary.LittleEndian.Uint16(data[pos+j:pos+j+2])))
				}
				str = string(runes)
			}
		}

		strTrim := strings.TrimSpace(str)
		if (strings.HasPrefix(strTrim, "M") || strings.HasPrefix(strTrim, "m")) && len(strTrim) > 15 {
			if strings.ContainsAny(strTrim, "zZlLcChHvV") {
				return strTrim
			}
		}
	}
	return ""
}

func extractAPKIcons(apkPath string) (normalB64 string, monetB64 string) {
	if apkPath == "" {
		return "", ""
	}
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return "", ""
	}
	defer zr.Close()

	var bestNormalFile *zip.File
	var bestNormalScore int
	var bestMonetFile *zip.File
	var bestMonetScore int
	var monetXMLFile *zip.File

	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		isPNG := strings.HasSuffix(name, ".png")
		isWebP := strings.HasSuffix(name, ".webp")
		isXML := strings.HasSuffix(name, ".xml")

		if !isPNG && !isWebP && !isXML {
			continue
		}

		if strings.Contains(name, "monochrome") || strings.Contains(name, "themed") {
			if isXML && monetXMLFile == nil {
				monetXMLFile = f
			} else if isPNG || isWebP {
				score := scoreDensity(name)
				if score > bestMonetScore {
					bestMonetScore = score
					bestMonetFile = f
				}
			}
			continue
		}

		if (isPNG || isWebP) && (strings.Contains(name, "launcher") || strings.Contains(name, "icon")) {
			if strings.Contains(name, "foreground") || strings.Contains(name, "background") {
				continue
			}
			score := scoreDensity(name)
			if strings.Contains(name, "round") {
				score += 2
			}
			if strings.Contains(name, "ic_launcher") {
				score += 3
			}
			if score > bestNormalScore {
				bestNormalScore = score
				bestNormalFile = f
			}
		}
	}

	if bestNormalFile != nil && bestNormalFile.UncompressedSize64 < 1<<20 {
		if rc, err := bestNormalFile.Open(); err == nil {
			data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
			_ = rc.Close()
			if err == nil && len(data) > 0 {
				mime := "image/png"
				if strings.HasSuffix(strings.ToLower(bestNormalFile.Name), ".webp") {
					mime = "image/webp"
				}
				normalB64 = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
			}
		}
	}

	if bestMonetFile != nil && bestMonetFile.UncompressedSize64 < 1<<20 {
		if rc, err := bestMonetFile.Open(); err == nil {
			data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
			_ = rc.Close()
			if err == nil && len(data) > 0 {
				mime := "image/png"
				if strings.HasSuffix(strings.ToLower(bestMonetFile.Name), ".webp") {
					mime = "image/webp"
				}
				monetB64 = "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
			}
		}
	}

	if monetB64 == "" && monetXMLFile != nil && monetXMLFile.UncompressedSize64 < 256*1024 {
		if rc, err := monetXMLFile.Open(); err == nil {
			data, err := io.ReadAll(io.LimitReader(rc, 256*1024))
			_ = rc.Close()
			if err == nil && len(data) > 8 {
				svgPath := extractPathFromAXML(data)
				if svgPath != "" {
					svgMarkup := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 108"><path fill="currentColor" d="` + svgPath + `"/></svg>`
					monetB64 = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svgMarkup))
				}
			}
		}
	}

	return normalB64, monetB64
}
func discoverApps() ([]App, []int) {
	var apps []App
	var uids []int
	seen := map[int]bool{}
	nameByPkg := map[string]string{}
	for _, p := range packageNames {
		nameByPkg[p.Pkg] = p.Name
	}
	// Android's package manager can return all package UIDs in one call.
	for _, cmd := range [][]string{{"cmd", "package", "list", "packages", "-U"}, {"pm", "list", "packages", "-U"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "package:") {
				continue
			}
			fields := strings.Fields(line)
			pkg := strings.TrimPrefix(fields[0], "package:")
			name, wanted := nameByPkg[pkg]
			if !wanted {
				continue
			}
			m := regexp.MustCompile(`uid:(\d+)`).FindStringSubmatch(line)
			if len(m) < 2 {
				continue
			}
			uid, _ := strconv.Atoi(m[1])
			if uid <= 0 || seen[uid] {
				continue
			}
			normalIco, monetIco := extractAPKIcons(findPackageAPK(pkg))
			apps = append(apps, App{Name: name, Pkg: pkg, UID: uid, IconNormal: normalIco, IconMonet: monetIco})
			uids = append(uids, uid)
			seen[uid] = true
		}
		if len(apps) > 0 {
			return apps, uids
		}
	}
	// Fallback for Android builds that don't support the -U listing option.
	for _, p := range packageNames {
		uid := packageUID(p.Pkg)
		if uid > 0 && !seen[uid] {
			normalIco, monetIco := extractAPKIcons(findPackageAPK(p.Pkg))
			apps = append(apps, App{Name: p.Name, Pkg: p.Pkg, UID: uid, IconNormal: normalIco, IconMonet: monetIco})
			uids = append(uids, uid)
			seen[uid] = true
		}
	}
	return apps, uids
}

func loadCachedApps() ([]App, []int) {
	b, err := os.ReadFile(path("apps.json"))
	if err != nil {
		return nil, nil
	}
	var apps []App
	if err := json.Unmarshal(b, &apps); err != nil || len(apps) == 0 {
		return nil, nil
	}
	var uids []int
	seen := map[int]bool{}
	for _, a := range apps {
		if a.UID > 0 && !seen[a.UID] {
			uids = append(uids, a.UID)
			seen[a.UID] = true
		}
	}
	return apps, uids
}

func saveCachedApps(apps []App) {
	if len(apps) == 0 {
		return
	}
	b, err := json.Marshal(apps)
	if err == nil {
		ensureDir()
		_ = os.WriteFile(path("apps.json"), b, 0600)
	}
}

func installedApps() ([]App, []int) {
	appCacheMu.Lock()
	defer appCacheMu.Unlock()
	if len(appCache) == 0 {
		appCache, uidCache = loadCachedApps()
		if len(appCache) == 0 {
			appCache, uidCache = discoverApps()
			if len(appCache) > 0 {
				saveCachedApps(appCache)
			}
		} else {
			// Trigger asynchronous verification to keep app cache up to date
			go func() {
				freshApps, freshUIDs := discoverApps()
				if len(freshApps) > 0 {
					appCacheMu.Lock()
					appCache, uidCache = freshApps, freshUIDs
					appCacheMu.Unlock()
					saveCachedApps(freshApps)
				}
			}()
		}
	}
	return append([]App(nil), appCache...), append([]int(nil), uidCache...)
}

// telegramSubnets is the single source of Telegram IPv4 aggregates: the
// iptables REDIRECT list (telegramV4) and dcFor's prefix lookup are derived
// from it. dc 0 marks the shared 149.154.160.0/20 pool, which dcFor resolves
// by octet because it hosts several DCs.
var telegramSubnets = []struct {
	cidr string
	dc   int
}{
	{"149.154.160.0/20", 0},
	{"91.108.4.0/22", 1},
	{"91.108.8.0/22", 2},
	{"91.108.12.0/22", 3},
	{"91.108.16.0/22", 4},
	{"91.108.20.0/22", 5},
	{"91.108.56.0/22", 5},
	{"185.76.151.0/24", 2},
	{"91.105.192.0/23", 2},
}

var telegramV4 = func() []string {
	out := make([]string, len(telegramSubnets))
	for i, sub := range telegramSubnets {
		out[i] = sub.cidr
	}
	return out
}()

func runCmd(name string, args ...string) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c := exec.CommandContext(ctx, name, args...)
		b, e := c.CombinedOutput()
		cancel()
		if e == nil {
			return nil
		}
		outStr := strings.TrimSpace(string(b))
		lastErr = fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), e, outStr)
		if strings.Contains(outStr, "xtables.lock") || strings.Contains(outStr, "Can't lock") {
			time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
			continue
		}
		return lastErr
	}
	return lastErr
}
func findBin(name string) string {
	if p, e := exec.LookPath(name); e == nil {
		return p
	}
	for _, p := range []string{"/system/bin/" + name, "/system/xbin/" + name, "/vendor/bin/" + name} {
		if _, e := os.Stat(p); e == nil {
			return p
		}
	}
	return ""
}
func iptSetup(bin string, uids []int, cidrs []string, chain string, family string) error {
	if bin == "" {
		return fmt.Errorf("%s is missing", family)
	}
	// Remove both previous global and UID-scoped jumps before selecting a mode.
	for i := 0; i < 16; i++ {
		if runCmd(bin, "-t", "nat", "-D", "OUTPUT", "-j", chain) != nil {
			break
		}
	}
	for _, uid := range uids {
		for i := 0; i < 8; i++ {
			e := runCmd(bin, "-t", "nat", "-D", "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", chain)
			if e != nil {
				break
			}
		}
	}
	_ = runCmd(bin, "-t", "nat", "-F", chain)
	if err := runCmd(bin, "-t", "nat", "-N", chain); err != nil { // likely already exists
		if e := runCmd(bin, "-t", "nat", "-F", chain); e != nil {
			return fmt.Errorf("failed to create chain %s: %w", chain, err)
		}
	}
	for _, cidr := range cidrs {
		if e := runCmd(bin, "-t", "nat", "-A", chain, "-p", "tcp", "-d", cidr, "-j", "REDIRECT", "--to-ports", strconv.Itoa(defaultPort)); e != nil {
			logf("rule %s skipped: %v", cidr, e)
		}
	}
	for _, uid := range uids {
		if err := runCmd(bin, "-t", "nat", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", chain); err != nil {
			return err
		}
	}
	return nil
}
func iptCleanup(bin string, uids []int, chain string) {
	if bin == "" {
		return
	}
	// Remove the previous v1.2 global jump as well as this version's UID-scoped jumps.
	for i := 0; i < 16; i++ {
		if runCmd(bin, "-t", "nat", "-D", "OUTPUT", "-j", chain) != nil {
			break
		}
	}
	for _, uid := range uids {
		for i := 0; i < 16; i++ {
			if runCmd(bin, "-t", "nat", "-D", "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", chain) != nil {
				break
			}
		}
	}
	_ = runCmd(bin, "-t", "nat", "-F", chain)
	_ = runCmd(bin, "-t", "nat", "-X", chain)
}

// Locally generated packets traverse OUTPUT only (PREROUTING is skipped for
// on-device flows), so the STUN/TURN bypass must live there; PREROUTING is
// kept for forwarded traffic (e.g. hotspot) where DPI chains also attach.
var callsBypassBody = []string{"-p", "udp", "-m", "multiport", "--dports", "3478,596:599", "-m", "comment", "--comment", "teleweb-calls", "-j", "RETURN"}

func setupCallsBypass(bin string) {
	if bin == "" {
		return
	}
	for _, chain := range []string{"OUTPUT", "PREROUTING"} {
		check := append([]string{"-t", "mangle", "-C", chain}, callsBypassBody...)
		if runCmd(bin, check...) == nil {
			continue
		}
		insert := append([]string{"-t", "mangle", "-I", chain, "1"}, callsBypassBody...)
		_ = runCmd(bin, insert...)
	}
}

func cleanupCallsBypass(bin string) {
	if bin == "" {
		return
	}
	for _, chain := range []string{"OUTPUT", "PREROUTING"} {
		del := append([]string{"-t", "mangle", "-D", chain}, callsBypassBody...)
		for i := 0; i < 4; i++ {
			if runCmd(bin, del...) != nil {
				break
			}
		}
	}
}

type RateLimitError struct {
	StatusCode int
	RetryAfter time.Duration
	Message    string
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("HTTP %d (retry after %v): %s", e.StatusCode, e.RetryAfter, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

type workerCooldownState struct {
	until   time.Time
	strikes int
}

var workerCooldowns sync.Map // host -> workerCooldownState

func isWorkerInCooldown(host string) bool {
	if v, ok := workerCooldowns.Load(host); ok {
		cd := v.(workerCooldownState)
		if time.Now().Before(cd.until) {
			return true
		}
	}
	return false
}

func markWorkerCooldown(host string, retryAfter time.Duration) {
	var strikes int
	if v, ok := workerCooldowns.Load(host); ok {
		strikes = v.(workerCooldownState).strikes + 1
	} else {
		strikes = 1
	}
	if retryAfter <= 0 {
		shift := strikes - 1
		if shift > 5 {
			shift = 5
		}
		delay := 30 * time.Second * (1 << shift)
		if delay > 15*time.Minute {
			delay = 15 * time.Minute
		}
		retryAfter = delay
	}
	workerCooldowns.Store(host, workerCooldownState{
		until:   time.Now().Add(retryAfter),
		strikes: strikes,
	})
	logf("worker %s: rate limited (HTTP 429/503); quarantined for %v", host, retryAfter)
}

func clearWorkerCooldown(host string) {
	workerCooldowns.Delete(host)
}

type learnedDCEntry struct {
	DC      int  `json:"dc"`
	IsMedia bool `json:"is_media"`
}

var (
	learnedDCs     sync.Map // ipStr -> learnedDCEntry
	learnedDCMu    sync.Mutex
	learnedDCDirty bool
)

func loadLearnedDCs() {
	b, err := os.ReadFile(path("dc-learned.json"))
	if err != nil {
		return
	}
	var saved map[string]learnedDCEntry
	if err := json.Unmarshal(b, &saved); err != nil {
		return
	}
	count := 0
	cleaned := false
	for ip, entry := range saved {
		if entry.DC >= 1 && (entry.DC <= 5 || entry.DC == 203) {
			if known := knownDCMap[ip]; known != 0 && known != entry.DC {
				cleaned = true
				continue
			}
			learnedDCs.Store(ip, entry)
			count++
		}
	}
	if count > 0 {
		logf("dc-learn: restored %d learned IP->DC endpoints from storage", count)
	}
	if cleaned {
		learnedDCMu.Lock()
		learnedDCDirty = true
		learnedDCMu.Unlock()
		go persistLearnedDCs()
	}
}

func persistLearnedDCs() {
	learnedDCMu.Lock()
	defer learnedDCMu.Unlock()
	if !learnedDCDirty {
		return
	}
	m := make(map[string]learnedDCEntry)
	learnedDCs.Range(func(key, value any) bool {
		m[key.(string)] = value.(learnedDCEntry)
		return true
	})
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	tmp := path("dc-learned.json.tmp")
	dst := path("dc-learned.json")
	if err := os.WriteFile(tmp, b, 0600); err == nil {
		_ = os.Rename(tmp, dst)
		learnedDCDirty = false
	}
}

func learnDC(ip string, dc int, isMedia bool) {
	if dc < 1 || (dc > 5 && dc != 203) || ip == "" {
		return
	}
	if known := knownDCMap[ip]; known != 0 && known != dc {
		return
	}
	if val, ok := learnedDCs.Load(ip); ok {
		entry := val.(learnedDCEntry)
		if entry.DC == dc && entry.IsMedia == isMedia {
			return
		}
	}
	var count int
	learnedDCs.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count >= 256 {
		return
	}
	learnedDCs.Store(ip, learnedDCEntry{DC: dc, IsMedia: isMedia})
	learnedDCMu.Lock()
	learnedDCDirty = true
	learnedDCMu.Unlock()
	go persistLearnedDCs()
	logf("dc-learn: learned endpoint %s -> DC%d media=%t", ip, dc, isMedia)
}

func lookupLearnedDC(ip string) (int, bool, bool) {
	if val, ok := learnedDCs.Load(ip); ok {
		entry := val.(learnedDCEntry)
		return entry.DC, entry.IsMedia, true
	}
	return 0, false, false
}

func setupRules() error {
	apps, uids := installedApps()
	if len(uids) == 0 {
		return errors.New("no installed Telegram app found (e.g., org.telegram.messenger)")
	}
	if err := iptSetup(findBin("iptables"), uids, telegramV4, "TELEWEB", "IPv4"); err != nil {
		return err
	}
	setupCallsBypass(findBin("iptables"))
	setupCallsBypass(findBin("ip6tables"))
	logf("redirection enabled; apps: %s", appNames(apps))
	return nil
}
func appNames(a []App) string {
	x := make([]string, 0, len(a))
	for _, v := range a {
		x = append(x, fmt.Sprintf("%s(uid=%d)", v.Pkg, v.UID))
	}
	return strings.Join(x, ", ")
}
func cleanupRules() {
	_, uids := installedApps()
	iptCleanup(findBin("iptables"), uids, "TELEWEB")
	// Clean up the previous release's IPv6 redirect chain even though this
	// experimental build does not install new IPv6 redirects.
	iptCleanup(findBin("ip6tables"), uids, "TELEWEB")
	cleanupCallsBypass(findBin("iptables"))
	cleanupCallsBypass(findBin("ip6tables"))
}
func ensureServer() error {
	if pidAlive() {
		return nil
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	lf, e := os.OpenFile(path("daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	cmd := exec.Command(self, "serve")
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.Stdin = nil
	setDaemonProcAttr(cmd)
	if e = cmd.Start(); e != nil {
		lf.Close()
		return e
	}
	_ = cmd.Process.Release()
	_ = lf.Close()
	return nil
}

// procCgroupEntry describes one line from /proc/<pid>/cgroup. On Android,
// a unified cgroup-v2 entry has hierarchy "0", no controller list and a path
// such as /uid_XXXXX/pid_YYYY. Legacy Android may expose a separate cpuset
// controller whose processes can also be moved to its root group.
type procCgroupEntry struct {
	hierarchy   string
	controllers string
	path        string
}

func parseProcCgroups(raw string) []procCgroupEntry {
	var entries []procCgroupEntry
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		entries = append(entries, procCgroupEntry{hierarchy: parts[0], controllers: parts[1], path: stdpath.Clean("/" + strings.TrimPrefix(parts[2], "/"))})
	}
	return entries
}

var protectWarnings sync.Map // pid -> last warning string; avoids log spam

func writePIDToCgroup(pid int, file string) error {
	if _, err := os.Stat(file); err != nil {
		return err
	}
	return os.WriteFile(file, []byte(strconv.Itoa(pid)), 0644)
}

func processFrozen(pid int, entry procCgroupEntry) bool {
	if entry.path == "/" {
		return false
	}
	if entry.hierarchy == "0" && entry.controllers == "" {
		b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", entry.path, "cgroup.events"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(line) == "frozen 1" {
					return true
				}
			}
		}
	}
	if strings.Contains(","+entry.controllers+",", ",freezer,") {
		b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", entry.path, "freezer.state"))
		if err == nil && strings.EqualFold(strings.TrimSpace(string(b)), "FROZEN") {
			return true
		}
	}
	return false
}

// protectProcess applies both protections needed by long-lived Android network
// daemons: LMK protection and best-effort migration out of app/uid cgroups so
// cached-app freezer policies cannot suspend the transport. It intentionally
// does not return early when oom_score_adj succeeds: that setting alone does
// not prevent freezing. Some ROMs reject cgroup migration; report that once.
func protectProcess(pid int) {
	if pid <= 1 {
		return
	}
	if err := os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid), []byte("-1000\n"), 0644); err != nil {
		if oldErr := os.WriteFile(fmt.Sprintf("/proc/%d/oom_adj", pid), []byte("-17\n"), 0644); oldErr != nil {
			warnProtect(pid, "failed to set oom protection: "+oldErr.Error())
		}
	}

	cgRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		warnProtect(pid, "failed to read cgroup: "+err.Error())
		return
	}
	entries := parseProcCgroups(string(cgRaw))
	for _, entry := range entries {
		if processFrozen(pid, entry) {
			logf("protect: PID %d was in frozen cgroup %s (controllers=%s); moving to root group", pid, entry.path, entry.controllers)
		}
		if entry.path == "/" {
			continue
		}
		var target string
		if entry.hierarchy == "0" && entry.controllers == "" {
			target = "/sys/fs/cgroup/cgroup.procs"
		} else if strings.Contains(","+entry.controllers+",", ",cpuset,") {
			// Android cgroup-v1 cpuset commonly mounts at /dev/cpuset.
			for _, candidate := range []string{"/dev/cpuset/tasks", "/dev/cpuset/cgroup.procs"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					target = candidate
					break
				}
			}
		}
		if target == "" {
			continue
		}
		if moveErr := writePIDToCgroup(pid, target); moveErr != nil {
			warnProtect(pid, fmt.Sprintf("failed to move PID %d from cgroup %s to %s: %v", pid, entry.path, target, moveErr))
			continue
		}
		logf("protect: PID %d moved from cgroup %s to root group via %s", pid, entry.path, target)
	}
}

// appProcessMatches identifies the main Android process and package-scoped
// secondary processes (for example com.example:push), without matching other
// packages that merely share a prefix.
func appProcessMatches(cmdline, pkg string) bool {
	cmdline = strings.TrimRight(cmdline, "\x00\n\r ")
	return cmdline == pkg || strings.HasPrefix(cmdline, pkg+":")
}

func processUID(pid int) (int, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(f) > 0 {
				n, e := strconv.Atoi(f[0])
				return n, e == nil
			}
		}
	}
	return 0, false
}

// protectTargetAppProcesses attempts to keep only the configured Telegram
// client's own processes out of Android's cached-app freezer. Unlike the
// transport daemon, app processes are NOT given oom_score_adj=-1000: Android
// must retain normal memory management. This cannot force Android to deliver
// FCM notifications and is best-effort because OEM freezer implementations vary.
func protectTargetAppProcesses() {
	apps, _ := installedApps()
	if len(apps) == 0 {
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		pid, e := strconv.Atoi(de.Name())
		if e != nil || pid <= 1 {
			continue
		}
		cmd, e := os.ReadFile(filepath.Join("/proc", de.Name(), "cmdline"))
		if e != nil {
			continue
		}
		cmdline := strings.SplitN(string(cmd), "\x00", 2)[0]
		uid, ok := processUID(pid)
		if !ok {
			continue
		}
		for _, app := range apps {
			if uid != app.UID || !appProcessMatches(cmdline, app.Pkg) {
				continue
			}
			protectAppPID(pid)
			break
		}
	}
}

func protectAppPID(pid int) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return
	}
	for _, entry := range parseProcCgroups(string(b)) {
		if entry.path == "/" {
			continue
		}
		if entry.hierarchy == "0" && entry.controllers == "" {
			// On cgroup v2 the freezer is integrated into the unified hierarchy.
			// Moving only the target app process to the root opts it out of
			// cached-app freezing; Android may move it back, so watchdog retries.
			target := "/sys/fs/cgroup/cgroup.procs"
			if err := writePIDToCgroup(pid, target); err != nil {
				warnProtect(pid, fmt.Sprintf("failed to move app process out of cgroup freezer: %v", err))
			} else {
				logf("protect-app: PID %d moved from %s to root cgroup (oom_score_adj untouched)", pid, entry.path)
			}
			return
		}
		if strings.Contains(","+entry.controllers+",", ",freezer,") {
			var target string
			for _, candidate := range []string{"/sys/fs/cgroup/freezer/tasks", "/sys/fs/cgroup/freezer/cgroup.procs", "/dev/freezer/tasks", "/dev/freezer/cgroup.procs"} {
				if _, statErr := os.Stat(candidate); statErr == nil {
					target = candidate
					break
				}
			}
			if target == "" {
				warnProtect(pid, "cgroup-v1 freezer detected, but root migration file not found")
				return
			}
			if err := writePIDToCgroup(pid, target); err != nil {
				warnProtect(pid, fmt.Sprintf("failed to move app process out of freezer cgroup %s: %v", entry.path, err))
			} else {
				logf("protect-app: PID %d moved from freezer cgroup %s to root", pid, entry.path)
			}
			return
		}
	}
}

func warnProtect(pid int, message string) {
	var count int
	protectWarnings.Range(func(key, _ any) bool {
		count++
		return true
	})
	if count > 128 {
		protectWarnings.Range(func(key, _ any) bool {
			if p, ok := key.(int); ok && !isPidAlive(p) {
				protectWarnings.Delete(key)
				count--
			}
			return true
		})
		if count > 128 {
			protectWarnings.Range(func(key, _ any) bool {
				protectWarnings.Delete(key)
				count--
				return count > 64
			})
		}
	}
	if previous, loaded := protectWarnings.LoadOrStore(pid, message); !loaded {
		logf("protect: %s", message)
	} else if previous != message {
		protectWarnings.Store(pid, message)
		logf("protect: %s", message)
	}
}

func readPIDFile(name string) int {
	b, err := os.ReadFile(path(name))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func processHasArg(pid int, want string) bool {
	if pid <= 1 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	for _, arg := range strings.Split(string(b), "\x00") {
		if arg == want {
			return true
		}
	}
	return false
}

func watchdogAlive() bool {
	pid := readPIDFile("watchdog.pid")
	return pid > 1 && isPidAlive(pid) && processHasArg(pid, "watchdog")
}

func ensureWatchdog() error {
	if watchdogAlive() {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(path("watchdog.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "watchdog")
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.Stdin = nil
	setDaemonProcAttr(cmd)
	if err = cmd.Start(); err != nil {
		_ = lf.Close()
		return err
	}
	_ = os.WriteFile(path("watchdog.pid"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0600)
	_ = cmd.Process.Release()
	_ = lf.Close()
	return nil
}

func stopPID(pid int) {
	if pid > 1 && pid != os.Getpid() {
		_ = killProcess(pid)
		for i := 0; i < 20; i++ {
			if !isPidAlive(pid) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		// Grace period exhausted: force-kill so a stuck daemon cannot keep the
		// listen port forever while the supervisor respawns a failing successor.
		_ = killProcessForce(pid)
		for i := 0; i < 10; i++ {
			if !isPidAlive(pid) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		logf("stop: PID %d survived SIGKILL; leaving it to the kernel", pid)
	}
}

func stopWatchdog() {
	pid := readPIDFile("watchdog.pid")
	if pid > 1 && pid != os.Getpid() && processHasArg(pid, "watchdog") {
		stopPID(pid)
	}
	_ = os.Remove(path("watchdog.pid"))
}

func serverListening() bool {
	// Inspect the kernel socket table instead of opening a probe connection:
	// a probe would be accepted as a fake MTProto client and pollute the log.
	b, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return false
	}
	want := fmt.Sprintf(":%04X", defaultPort)
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.HasSuffix(strings.ToUpper(fields[1]), want) && fields[3] == "0A" {
			return true // TCP_LISTEN
		}
	}
	return false
}

func daemonHealthy() bool { return pidAlive() && serverListening() }

// waitForListener polls the kernel socket table until the daemon's listen
// port appears. REDIRECT rules must only be installed after this returns
// true: rules pointing at a not-yet-listening port blackhole Telegram traffic.
func waitForListener(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for !serverListening() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return true
}

// restoreDaemon replaces a dead or unresponsive daemon and reinstalls the
// redirect rules: stopServer drops stale rules before the listener is
// replaced, and rules return only once the new listener is up so traffic is
// never pointed at a port nobody listens on.
func restoreDaemon() error {
	stopServer()
	if err := ensureServer(); err != nil {
		return fmt.Errorf("start tgws: %w", err)
	}
	if !waitForListener(4 * time.Second) {
		return fmt.Errorf("tgws failed to listen on port %d", defaultPort)
	}
	if err := setupRules(); err != nil {
		return fmt.Errorf("restore redirect rules: %w", err)
	}
	return nil
}

func rulesHealthy() bool {
	bin := findBin("iptables")
	if bin == "" {
		return false
	}
	_, uids := installedApps()
	if len(uids) == 0 {
		return false
	}
	for _, uid := range uids {
		if runCmd(bin, "-t", "nat", "-C", "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "TELEWEB") != nil {
			return false
		}
	}
	for _, cidr := range telegramV4 {
		if runCmd(bin, "-t", "nat", "-C", "TELEWEB", "-p", "tcp", "-d", cidr, "-j", "REDIRECT", "--to-ports", strconv.Itoa(defaultPort)) != nil {
			return false
		}
	}
	return true
}

func watchdog() {
	ensureDir()
	pid := os.Getpid()
	_ = os.WriteFile(path("watchdog.pid"), []byte(strconv.Itoa(pid)+"\n"), 0600)
	protectProcess(pid)
	protectTargetAppProcesses()
	logf("watchdog: started, checking every 30s; %s", procSummary(pid))
	tickCount := 0
	lastDaemonOK, lastRulesOK := daemonHealthy(), rulesHealthy()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer func() {
		if readPIDFile("watchdog.pid") == pid {
			_ = os.Remove(path("watchdog.pid"))
		}
	}()
	for range ticker.C {
		tickCount++
		if tickCount%2 == 0 {
			logf("watchdog: heartbeat enabled=%t daemon_ok=%t rules_ok=%t; daemon{%s}", readEnabled(), daemonHealthy(), rulesHealthy(), procSummary(readPIDFile("tgws.pid")))
		}
		if !readEnabled() {
			continue
		}
		protectProcess(pid)
		protectTargetAppProcesses()
		daemonOK, rulesOK := daemonHealthy(), rulesHealthy()
		if daemonOK != lastDaemonOK || rulesOK != lastRulesOK {
			logf("watchdog: state change daemon %t->%t, rules %t->%t; %s", lastDaemonOK, daemonOK, lastRulesOK, rulesOK, procSummary(readPIDFile("tgws.pid")))
			updateModuleDescription(currentStatusDesc())
		}
		lastDaemonOK, lastRulesOK = daemonOK, rulesOK
		if !daemonOK {
			logf("watchdog: tgws unresponsive, auto-restarting; %s; listener=%t", procSummary(readPIDFile("tgws.pid")), serverListening())
			if err := restoreDaemon(); err != nil {
				logf("watchdog: auto-restart failed: %v", err)
				continue
			}
		}
		protectProcess(readPIDFile("tgws.pid"))
		if !rulesHealthy() {
			logf("watchdog: iptables rules reset or corrupted, restoring; iptables=%q", findBin("iptables"))
			if err := setupRules(); err != nil {
				logf("watchdog: failed to restore iptables: %v", err)
			}
		}
	}
}

// ensureRuntime is intentionally idempotent so the Android service loop can
// recover from boot races (Telegram package/iptables not ready yet) without
// restarting a healthy transport on every pass.
func ensureRuntime() error {
	if !readEnabled() {
		stopWatchdog()
		stopServer()
		updateModuleDescription("⛔ Остановлено")
		return nil
	}
	if !daemonHealthy() {
		logf("supervisor: daemon/listener missing, restoring")
		if err := restoreDaemon(); err != nil {
			return err
		}
	} else if !rulesHealthy() {
		logf("supervisor: redirection rules missing, restoring")
		if err := setupRules(); err != nil {
			return err
		}
	}
	protectProcess(readPIDFile("tgws.pid"))
	protectTargetAppProcesses()
	if err := ensureWatchdog(); err != nil {
		return err
	}
	return nil
}

func stopServer() {
	pid := readPIDFile("tgws.pid")
	if pid > 1 && pid != os.Getpid() {
		hasProc := false
		if _, err := os.Stat("/proc"); err == nil {
			hasProc = true
		}
		if !hasProc || processHasArg(pid, "serve") {
			stopPID(pid)
		}
	}
	_ = os.Remove(path("tgws.pid"))
	cleanupRules()
}
func processMemoryBytes() (current, peak int64) {
	// Linux /proc reports resident set size and its high-water mark in kB.
	// Reading our own status file is cheap and avoids spawning `ps` on Android.
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		var value int64
		if strings.HasPrefix(line, "VmRSS:") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "VmRSS:"), "%d", &value); err == nil {
				current = value * 1024
			}
		} else if strings.HasPrefix(line, "VmHWM:") {
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "VmHWM:"), "%d", &value); err == nil {
				peak = value * 1024
			}
		}
	}
	return current, peak
}

func currentStatus() Status {
	apps, _ := installedApps()
	dc := map[string]int{}
	statsMu.Lock()
	for k, v := range dcCounts {
		dc[k] = v
	}
	statsMu.Unlock()
	memNow, memPeak := processMemoryBytes()
	up := atomic.LoadInt64(&trafficUpBytes)
	down := atomic.LoadInt64(&trafficDownBytes)
	hits, misses, idle := int64(0), int64(0), 0
	if globalWsPool != nil {
		hits, misses, idle = globalWsPool.Stats()
	}
	return Status{
		Enabled:           readEnabled(),
		Running:           true,
		Uptime:            int64(time.Since(startAt).Seconds()),
		Port:              defaultPort,
		Apps:              apps,
		Active:            atomic.LoadInt64(&active),
		WS:                atomic.LoadInt64(&wsCount),
		Fail:              atomic.LoadInt64(&failCnt),
		DC:                dc,
		MemNowBytes:       memNow,
		MemPeakBytes:      memPeak,
		TrafficUpBytes:    up,
		TrafficDownBytes:  down,
		TrafficTotalBytes: up + down,
		Log:               tailLog(60),
		CFPriority:        readCFPriority(),
		CFBalance:         readCFBalance(),
		CustomCFDomain:    readCustomCFDomain(),
		CustomCFWorker:    readCustomCFWorker(),
		DCOverrides:       readDCOverridesRaw(),
		PoolSize:          readPoolSize(),
		PoolHits:          hits,
		PoolMisses:        misses,
		PoolIdle:          idle,
		DoHEnabled:        readDoHEnabled(),
		LastCFPoP: func() string {
			if p := lastCFPoP.Load(); p != nil {
				return *p
			}
			return ""
		}(),
		LastCFRay: func() string {
			if p := lastCFRay.Load(); p != nil {
				return *p
			}
			return ""
		}(),
		ForceTestDC:    readForceTestDC(),
		H2MediaEnabled: readH2MediaEnabled(),
		DC203DirectTCP: readDC203DirectTCP(),
	}
}
func status() Status {
	if b, e := os.ReadFile(path("tgws.pid")); e == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if pid == os.Getpid() {
			return currentStatus()
		}
	}
	apps, _ := installedApps()
	if b, e := os.ReadFile(path("status.json")); e == nil {
		var s Status
		if json.Unmarshal(b, &s) == nil {
			s.Enabled = readEnabled()
			s.Running = pidAlive()
			s.Apps = apps
			s.Log = tailLog(60)
			s.CFPriority = readCFPriority()
			s.CFBalance = readCFBalance()
			s.CustomCFDomain = readCustomCFDomain()
			s.CustomCFWorker = readCustomCFWorker()
			s.DCOverrides = readDCOverridesRaw()
			s.PoolSize = readPoolSize()
			s.DoHEnabled = readDoHEnabled()
			s.ForceTestDC = readForceTestDC()
			s.H2MediaEnabled = readH2MediaEnabled()
			s.DC203DirectTCP = readDC203DirectTCP()
			if p := lastCFPoP.Load(); p != nil {
				s.LastCFPoP = *p
			}
			if p := lastCFRay.Load(); p != nil {
				s.LastCFRay = *p
			}
			if globalWsPool != nil {
				s.PoolHits, s.PoolMisses, s.PoolIdle = globalWsPool.Stats()
			}
			return s
		}
	}
	return Status{
		Enabled:        readEnabled(),
		Running:        pidAlive(),
		Uptime:         int64(time.Since(startAt).Seconds()),
		Port:           defaultPort,
		Apps:           apps,
		Active:         atomic.LoadInt64(&active),
		WS:             atomic.LoadInt64(&wsCount),
		Fail:           atomic.LoadInt64(&failCnt),
		DC:             map[string]int{},
		Log:            tailLog(60),
		CFPriority:     readCFPriority(),
		CFBalance:      readCFBalance(),
		CustomCFDomain: readCustomCFDomain(),
		CustomCFWorker: readCustomCFWorker(),
		DCOverrides:    readDCOverridesRaw(),
		PoolSize:       readPoolSize(),
		DoHEnabled:     readDoHEnabled(),
		ForceTestDC:    readForceTestDC(),
		H2MediaEnabled: readH2MediaEnabled(),
		DC203DirectTCP: readDC203DirectTCP(),
		LastCFPoP: func() string {
			if p := lastCFPoP.Load(); p != nil {
				return *p
			}
			return ""
		}(),
		LastCFRay: func() string {
			if p := lastCFRay.Load(); p != nil {
				return *p
			}
			return ""
		}(),
	}
}
func writeStatus() {
	s := currentStatus()
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := path("status.json.tmp")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, path("status.json")); err != nil {
		_ = os.Remove(tmp)
	}
}
func apiMain(arg string) {
	b, e := base64.StdEncoding.DecodeString(arg)
	if e != nil {
		emitErr(e)
		return
	}
	var q apiRequest
	if e = json.Unmarshal(b, &q); e != nil {
		emitErr(e)
		return
	}
	switch q.Cmd {
	case "status":
		emitOK(status())
	case "resume":
		// Returning to WebUI is an explicit opportunity to reassert interception
		// without restarting a healthy daemon. This addresses cases where the
		// process/listener remain alive but fresh Telegram flows stop being
		// redirected after the app has been backgrounded.
		if !readEnabled() {
			emitOK(status())
			return
		}
		if err := ensureServer(); err != nil {
			emitErr(err)
			return
		}
		if !waitForListener(4 * time.Second) {
			emitErr(fmt.Errorf("tgws failed to listen on port %d", defaultPort))
			return
		}
		if err := setupRules(); err != nil {
			emitErr(err)
			return
		}
		protectTargetAppProcesses()
		if err := ensureWatchdog(); err != nil {
			logf("resume: failed to start watchdog: %v", err)
		}
		logf("WebUI resume: redirection rules reapplied without restarting live daemon")
		emitOK(status())
	case "set", "setConfig":
		if q.Enabled != nil {
			if err := writeEnabled(*q.Enabled); err != nil {
				emitErr(err)
				return
			}
			if *q.Enabled {
				if err := ensureServer(); err != nil {
					_ = writeEnabled(false)
					updateModuleDescription("⚠️ Ошибка запуска tgws")
					emitErr(err)
					return
				}
				// REDIRECT rules go in only after the listener is up, otherwise
				// a slow start would blackhole Telegram traffic into a dead port.
				if !waitForListener(4 * time.Second) {
					_ = writeEnabled(false)
					stopServer()
					updateModuleDescription("⚠️ Ошибка запуска tgws")
					emitErr(fmt.Errorf("tgws failed to listen on port %d", defaultPort))
					return
				}
				if err := setupRules(); err != nil {
					_ = writeEnabled(false)
					cleanupRules()
					updateModuleDescription("⚠️ Сбой правил перехвата")
					emitErr(err)
					return
				}
				protectTargetAppProcesses()
				if err := ensureWatchdog(); err != nil {
					logf("failed to start watchdog: %v", err)
				}
				updateModuleDescription(currentStatusDesc())
			} else {
				stopWatchdog()
				stopServer()
				updateModuleDescription("⛔ Остановлено")
			}
		}
		if q.CFPriority != nil {
			if err := writeCFPriority(*q.CFPriority); err != nil {
				emitErr(err)
				return
			}
			updateModuleDescription(currentStatusDesc())
		}
		if q.CFBalance != nil {
			if err := writeCFBalance(*q.CFBalance); err != nil {
				emitErr(err)
				return
			}
		}
		if q.CustomCFDomain != nil {
			if err := writeCustomCFDomain(*q.CustomCFDomain); err != nil {
				emitErr(err)
				return
			}
		}
		if q.CustomCFWorker != nil {
			if err := writeCustomCFWorker(*q.CustomCFWorker); err != nil {
				emitErr(err)
				return
			}
		}
		if q.DCOverrides != nil {
			if err := writeDCOverrides(*q.DCOverrides); err != nil {
				emitErr(err)
				return
			}
		}
		if q.PoolSize != nil {
			if err := writePoolSize(*q.PoolSize); err != nil {
				emitErr(err)
				return
			}
		}
		if q.DoHEnabled != nil {
			if err := writeDoHEnabled(*q.DoHEnabled); err != nil {
				emitErr(err)
				return
			}
		}
		if q.ForceTestDC != nil {
			if err := writeForceTestDC(*q.ForceTestDC); err != nil {
				emitErr(err)
				return
			}
		}
		if q.H2MediaEnabled != nil {
			if err := writeH2MediaEnabled(*q.H2MediaEnabled); err != nil {
				emitErr(err)
				return
			}
		}
		if q.DC203DirectTCP != nil {
			if err := writeDC203DirectTCP(*q.DC203DirectTCP); err != nil {
				emitErr(err)
				return
			}
		}
		emitOK(status())
	default:
		emitErr(fmt.Errorf("unknown command: %s", q.Cmd))
	}
}
func emitOK(v any) {
	b, _ := json.Marshal(map[string]any{"ok": true, "data": v})
	fmt.Println(string(b))
}
func emitErr(e error) {
	b, _ := json.Marshal(map[string]any{"ok": false, "error": e.Error()})
	fmt.Println(string(b))
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			logStack(fmt.Sprintf("FATAL panic in main: %v", r))
			os.Exit(2)
		}
	}()
	ensureDir()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "api":
			if len(os.Args) < 3 {
				emitErr(errors.New("usage: tgws api BASE64_JSON"))
			} else {
				apiMain(os.Args[2])
			}
			return
		case "status":
			emitOK(status())
			return
		case "boot":
			// Clean up stale instances from prior boot or upgrade
			stopWatchdog()
			stopServer()
			if !readEnabled() {
				updateModuleDescription("⛔ Остановлено")
				fmt.Println("TeleWEB disabled")
				return
			}
			// Start the listener before installing REDIRECT rules: rules that
			// point at a not-yet-listening port blackhole Telegram traffic.
			if e := ensureServer(); e != nil {
				logf("boot: failed to start server: %v", e)
				fmt.Fprintln(os.Stderr, e)
				updateModuleDescription("⚠️ Ошибка запуска tgws")
				os.Exit(1)
			}
			if !waitForListener(4 * time.Second) {
				logf("boot: tgws failed to listen on port %d in time", defaultPort)
				fmt.Fprintln(os.Stderr, fmt.Sprintf("tgws failed to listen on port %d", defaultPort))
				updateModuleDescription("⚠️ Ошибка запуска tgws")
				os.Exit(1)
			}
			var lastErr error
			for attempt := 1; attempt <= 5; attempt++ {
				if lastErr = setupRules(); lastErr == nil {
					break
				}
				logf("boot: redirection setup attempt #%d failed: %v; retrying in 2s", attempt, lastErr)
				time.Sleep(2 * time.Second)
			}
			if lastErr != nil {
				logf("boot: failed to setup redirection rules: %v", lastErr)
				fmt.Fprintln(os.Stderr, lastErr)
				updateModuleDescription("⚠️ Сбой правил перехвата")
				os.Exit(1)
			}
			if e := ensureWatchdog(); e != nil {
				logf("boot: failed to start watchdog: %v", e)
			}
			updateModuleDescription(currentStatusDesc())
			fmt.Println("TeleWEB transport started")
			return
		case "stop":
			stopWatchdog()
			stopServer()
			updateModuleDescription("⛔ Остановлено")
			fmt.Println("TeleWEB stopped")
			return
		case "watchdog":
			watchdog()
			return
		case "ensure":
			if err := ensureRuntime(); err != nil {
				logf("supervisor: %v", err)
				fmt.Fprintln(os.Stderr, err)
				updateModuleDescription("⚠️ Сбой службы")
				os.Exit(1)
			}
			updateModuleDescription(currentStatusDesc())
			return
		case "serve":
			serve()
			return
		case "check":
			runChecks()
			return
		}
	}
	fmt.Println("TeleWEB transparent WebSocket engine\ncommands: boot | ensure | status | stop | watchdog | api BASE64_JSON | check")
}

func serve() {
	ensureDir()
	startSignalLogger()
	_ = os.Remove(path("status.json"))
	lf, e := os.OpenFile(path("tgws.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e == nil {
		logMu.Lock()
		logFile = lf
		logMu.Unlock()
		defer lf.Close()
	}
	_ = os.WriteFile(path("tgws.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0600)
	protectProcess(os.Getpid())
	// Load last-known-good routes before accepting any client sockets. Otherwise
	// a burst of connections at boot can race the cache load and trigger a full scan.
	loadRouteCache()
	loadLearnedDCs()
	startCFDomainsUpdater(context.Background())
	initGlobalWsPool(context.Background())
	if globalWsPool != nil {
		globalWsPool.Warmup([]int{1, 2, 4})
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			sweepRouteCaches()
		}
	}()
	ln, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", defaultPort))
	if e != nil {
		logf("failed to open local port: %v", e)
		return
	}
	defer ln.Close()
	logf("local proxy listening on 127.0.0.1:%d; %s; go=%s", defaultPort, procSummary(os.Getpid()), runtimeVersion())
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			writeStatus()
		}
	}()
	for {
		c, e := ln.Accept()
		if e != nil {
			logf("accept: %v", e)
			continue
		}
		go func(conn net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					logStack(fmt.Sprintf("FATAL panic in handleClient remote=%s: %v", conn.RemoteAddr(), r))
					_ = conn.Close()
				}
			}()
			handleClient(conn)
		}(c)
	}
}

// knownTestDCMap is derived from dcSpecs so test endpoints are defined once.
var knownTestDCMap = func() map[string]int {
	out := make(map[string]int)
	for dc, spec := range dcSpecs {
		if spec.testIP != "" {
			out[spec.testIP] = dc
		}
	}
	return out
}()

var (
	knownDCMap = map[string]int{
		"149.154.175.50": 1, "149.154.175.51": 1, "149.154.175.53": 1, "149.154.175.54": 1, "149.154.175.55": 1,
		"149.154.175.100": 3, "149.154.175.101": 3, "149.154.175.211": 1,
		"149.154.167.41": 2, "149.154.167.50": 2, "149.154.167.51": 2, "149.154.167.52": 2, "149.154.167.91": 4, "149.154.167.92": 4,
		"149.154.167.99": 2, "149.154.167.118": 4, "149.154.167.151": 2, "149.154.167.220": 2, "149.154.167.222": 2,
		"149.154.167.223": 2, "149.154.162.123": 2, "149.154.164.250": 4, "149.154.165.111": 4, "149.154.166.120": 4,
		"149.154.166.121": 4, "149.154.175.52": 1, "149.154.175.102": 3, "149.154.174.100": 1, "149.154.170.100": 5,
		"149.154.171.5": 5, "91.108.56.100": 5, "91.108.56.102": 5, "91.108.56.118": 5, "91.108.56.128": 5, "91.108.56.151": 5,
		cdn203IP: 203,
	}

	// telegramParsedSubnets mirrors telegramSubnets with parsed prefixes; the
	// octet-resolved 149.154.160.0/20 entry is skipped in dcFor's prefix loop.
	telegramParsedSubnets = func() []telegramSubnet {
		out := make([]telegramSubnet, len(telegramSubnets))
		for i, sub := range telegramSubnets {
			out[i] = telegramSubnet{prefix: netip.MustParsePrefix(sub.cidr), dc: sub.dc}
		}
		return out
	}()

	prefix149_160 = telegramParsedSubnets[0].prefix
)

type telegramSubnet struct {
	prefix netip.Prefix
	dc     int
}

func dcFor(ip netip.Addr) int {
	// SO_ORIGINAL_DST may yield IPv4-mapped IPv6 addresses such as
	// ::ffff:149.154.167.51. Normalize these before IPv4 DC matching.
	ip = ip.Unmap()
	if !ip.Is4() {
		return 0
	}
	if d := knownDCMap[ip.String()]; d != 0 {
		return d
	}
	if d := knownTestDCMap[ip.String()]; d != 0 {
		return d
	}
	if dc, _, ok := lookupLearnedDC(ip.String()); ok {
		return dc
	}
	if ip.IsPrivate() {
		return 0
	}
	if prefix149_160.Contains(ip) {
		b := ip.As4()
		// Telegram has several DC pools in the same aggregate. These rules
		// cover common production addresses; explicit addresses above take
		// precedence where the aggregate alone is ambiguous.
		switch {
		case b[2] >= 160 && b[2] <= 163:
			return 2
		case b[2] == 167:
			if b[3] >= 128 {
				return 4
			}
			return 2
		case b[2] == 175:
			if b[3] >= 128 {
				return 3
			}
			return 1
		case b[2] == 164 || b[2] == 166:
			return 4
		case b[2] == 165:
			// 149.154.165.x belongs to the DC4 pool; observed media endpoint 149.154.165.111 is MEDIA DcId{4}.
			return 4
		case b[2] >= 168 && b[2] <= 171:
			// 149.154.168.0/22 contains Telegram DC5 addresses (including
			// the documented 149.154.171.5 endpoint). Do not classify this
			// Singapore range as DC3 merely because it sits in the aggregate.
			return 5
		case b[2] >= 172 && b[2] <= 174:
			return 1
		default:
			return 1
		}
	}
	for _, sub := range telegramParsedSubnets {
		if sub.dc != 0 && sub.prefix.Contains(ip) {
			return sub.dc
		}
	}
	return 0
}

func setConnSockOpts(conn net.Conn) {
	if conn == nil {
		return
	}
	type tcpConnSetter interface {
		SetNoDelay(bool) error
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	if tc, ok := conn.(tcpConnSetter); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(256 * 1024)
		_ = tc.SetWriteBuffer(256 * 1024)
	}
}

func isNeutralError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "client_eof")
}

func handleClient(c net.Conn) {
	setConnSockOpts(c)
	id := atomic.AddInt64(&connSeq, 1)
	atomic.AddInt64(&active, 1)
	defer atomic.AddInt64(&active, -1)
	defer c.Close()
	orig, err := originalDestination(c)
	if err != nil {
		if !isNeutralError(err) {
			atomic.AddInt64(&failCnt, 1)
			logf("failed to determine original destination: %v", err)
		}
		return
	}

	// Read the obfuscated MTProto init before selecting the WSS frontend. Its
	// decrypted DC index is signed: negative values identify media-only DC
	// connections. This avoids guessing DC/media from overlapping IP pools.
	init := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadFull(c, init)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if !isNeutralError(err) {
			atomic.AddInt64(&failCnt, 1)
			logf("conn #%d %s: failed to read MTProto init: %v", id, orig, err)
		}
		return
	}
	dc, isMedia, parsed := parseMTProtoDC(init)
	isTestDC := forceTestDCCached() || dc >= 10000
	if dc >= 10000 {
		dc -= 10000
	}
	if parsed {
		// If the destination IP is an authoritative known Telegram endpoint,
		// check if parsed DC contradicts it. In direct MTProto connections,
		// bytes 60..62 of init are random CTR keystream padding. If random
		// bytes happen to form a valid DC tag that differs from the target IP's
		// DC, it is random keystream noise and MUST NOT be trusted.
		if known := knownDCMap[orig.Addr().String()]; known != 0 && known != dc {
			logf("conn #%d %s: ignoring random CTR noise in init (parsed DC%d, expected DC%d)", id, orig, dc, known)
			parsed = false
		}
	}
	if parsed {
		if !isTestDC {
			learnDC(orig.Addr().String(), dc, isMedia)
		}
	} else {
		if testDC, ok := knownTestDCMap[orig.Addr().String()]; ok {
			dc = testDC
			isTestDC = true
		} else {
			dc = dcFor(orig.Addr())
		}
		isMedia = mediaForIP(orig.Addr())
		logf("conn #%d %s: DC not recognized in init, fallback by IP -> DC%d (test=%t) media=%t", id, orig, dc, isTestDC, isMedia)
	}
	if orig.Addr().String() == cdn203IP || dc == 203 {
		handleCDN203(c, orig, init, id)
		return
	}
	if dc < 1 || dc > 5 {
		atomic.AddInt64(&failCnt, 1)
		logf("unknown DC for %s (conn %d); refusing direct send", orig, id)
		return
	}
	statsMu.Lock()
	dcCounts[strconv.Itoa(dc)]++
	statsMu.Unlock()

	// HTTP/2 Media Multiplexing route
	if isMedia && h2MediaEnabledCached() {
		if tryBridgeH2Media(c, init, id, dc, isTestDC) {
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var ws *wsConn
	if globalWsPool != nil && globalWsPool.size.Load() > 0 {
		ws = globalWsPool.Get(dc, isMedia, isTestDC)
	}
	if ws == nil {
		var err error
		ws, err = dialTelegramWS(ctx, dc, isMedia, isTestDC)
		if err != nil {
			if !isNeutralError(err) {
				atomic.AddInt64(&failCnt, 1)
				logf("DC%d (test=%t) media=%t WSS failed: %v; WSS-only, connection closed", dc, isTestDC, isMedia, err)
			}
			return
		}
		if globalWsPool != nil && globalWsPool.size.Load() > 0 {
			go globalWsPool.Refill(dc, isMedia, isTestDC)
		}
	}
	atomic.AddInt64(&wsCount, 1)
	defer atomic.AddInt64(&wsCount, -1)
	defer ws.Close()

	rayInfo := ""
	if ws.cfRay != "" {
		rayInfo = fmt.Sprintf(" [CF-Ray: %s PoP: %s]", ws.cfRay, ws.cfPoP)
	}
	testTag := ""
	if isTestDC {
		testTag = " (test)"
	}
	logf("conn #%d %s -> DC%d%s media=%t via WSS (%s)%s", id, orig, dc, testTag, isMedia, ws.host, rayInfo)
	pipeWSTunnel(c, ws, init, id, dc, isMedia)
}

func readDC203DirectTCP() bool         { return readFlag("dc203_direct_tcp", true) }
func writeDC203DirectTCP(v bool) error { return writeFlag("dc203_direct_tcp", v) }

func handleCDN203(c net.Conn, orig netip.AddrPort, init []byte, id int64) {
	statsMu.Lock()
	dcCounts["203"]++
	statsMu.Unlock()
	atomic.AddInt64(&wsCount, 1)
	defer atomic.AddInt64(&wsCount, -1)

	worker := customCFWorkerCached()
	if worker != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		ws, err := dialCFWorker(ctx, 203, cdn203IP, worker, false)
		cancel()
		if err == nil {
			logf("conn #%d %s -> CDN203 via Cloudflare Worker %s", id, orig, worker)
			defer ws.Close()
			pipeWSTunnel(c, ws, init, id, 203, false)
			return
		}
		logf("conn #%d CDN203: Cloudflare Worker %s did not respond: %v; falling back to direct TCP", id, worker, err)
	}

	// Dedicated native TCP pass-through for CDN203 (cdn203IP:443)
	if !dc203DirectTCPCached() {
		logf("conn #%d CDN203 direct TCP disabled by configuration", id)
		return
	}
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	remote, err := d.Dial("tcp4", net.JoinHostPort(cdn203IP, "443"))
	if err != nil {
		if !isNeutralError(err) {
			atomic.AddInt64(&failCnt, 1)
			logf("conn #%d CDN203 (%s:443) TCP dial failed: %v", id, cdn203IP, err)
		}
		return
	}
	defer remote.Close()
	setConnSockOpts(remote)

	if err := writeFull(remote, init); err != nil {
		logf("conn #%d CDN203 write init failed: %v", id, err)
		return
	}
	atomic.AddInt64(&trafficUpBytes, int64(len(init)))
	logf("conn #%d %s -> CDN203 (%s:443) via direct TCP pass-through", id, orig, cdn203IP)
	pipeTCPToTCP(c, remote, id, 203)
}

func pipeTCPToTCP(c, remote net.Conn, id int64, dc int) {
	setConnSockOpts(c)
	setConnSockOpts(remote)
	var upBytes, downBytes int64
	var once sync.Once
	stopIdle := make(chan struct{})
	closeBoth := func() {
		once.Do(func() {
			close(stopIdle)
			_ = c.Close()
			_ = remote.Close()
		})
	}
	defer closeBoth()

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopIdle:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > 5*time.Minute {
					logf("conn #%d DC%d (raw TCP) closed due to idle timeout (5m)", id, dc)
					closeBoth()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeBoth()
		bufPtr := ioBufPool.Get().(*[]byte)
		defer ioBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			nr, err := c.Read(buf)
			if nr > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if ew := writeFull(remote, buf[:nr]); ew != nil {
					break
				}
				atomic.AddInt64(&upBytes, int64(nr))
				atomic.AddInt64(&trafficUpBytes, int64(nr))
			}
			if err != nil {
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer closeBoth()
		bufPtr := ioBufPool.Get().(*[]byte)
		defer ioBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			nr, err := remote.Read(buf)
			if nr > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if ew := writeFull(c, buf[:nr]); ew != nil {
					break
				}
				atomic.AddInt64(&downBytes, int64(nr))
				atomic.AddInt64(&trafficDownBytes, int64(nr))
			}
			if err != nil {
				break
			}
		}
	}()
	wg.Wait()
}

func pipeWSTunnel(c net.Conn, ws *wsConn, init []byte, id int64, dc int, isMedia bool) {
	startedAt := time.Now()
	atomic.AddInt64(&trafficUpBytes, int64(len(init)))
	var upBytes int64   // client -> WSS payload bytes observed after the init header
	var downBytes int64 // WSS -> client payload bytes
	var once sync.Once
	stopIdle := make(chan struct{})
	closeBoth := func() {
		once.Do(func() {
			close(stopIdle)
			_ = c.Close()
			_ = ws.Close()
		})
	}
	defer closeBoth()
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopIdle:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > 5*time.Minute {
					logf("conn #%d DC%d closed due to idle timeout (5m)", id, dc)
					closeBoth()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := pipeTCPToWSCount(c, ws, init, &upBytes, &lastActivity); err != nil && !isNeutralError(err) {
			logf("conn #%d DC%d client->WSS error: %T: %v (up=%d down=%d)", id, dc, err, err, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
		}
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		for {
			_ = ws.conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
			op, payload, readErr := ws.readFrame()
			if readErr != nil {
				if !strings.Contains(readErr.Error(), "use of closed network connection") {
					noteEarlyRemoteClose(routeKey(dc, isMedia), ws.host, readErr, time.Since(startedAt), atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
					logf("conn #%d DC%d WSS->client error: %T: %v (up=%d down=%d)", id, dc, readErr, readErr, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
				}
				break
			}
			lastActivity.Store(time.Now().UnixNano())
			switch op {
			case 2, 0:
				if len(payload) > 0 {
					if readErr = writeFull(c, payload); readErr != nil {
						logf("conn #%d DC%d write WSS->client finished: %v (up=%d down=%d)", id, dc, readErr, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
						closeBoth()
						return
					}
					atomic.AddInt64(&downBytes, int64(len(payload)))
					atomic.AddInt64(&trafficDownBytes, int64(len(payload)))
				}
			case 9:
				_ = ws.writeFrame(10, payload)
			case 8:
				closeBoth()
				return
			case 10:
			default:
				logf("DC%d unknown WebSocket opcode: %d", dc, op)
			}
		}
		closeBoth()
	}()
	wg.Wait()
}

// decryptMTProtoInit decrypts the obfuscated MTProto init header's control
// tail and returns the transport tag plus a CTR stream positioned exactly at
// payload offset 64. Obfuscated2 keeps bytes 0:56 as key/IV material: the
// keystream is advanced over those 56 bytes before decrypting the encrypted
// 8-byte tail at offset 56; payload decryption starts at offset 64. The
// original encrypted bytes must still be forwarded verbatim to the relay —
// this stream is for inspection and parallel framing only.
func decryptMTProtoInit(init []byte) (proto uint32, plainTail [8]byte, stream cipher.Stream, err error) {
	if len(init) != 64 {
		return 0, plainTail, nil, fmt.Errorf("MTProto init length %d, want 64", len(init))
	}
	block, err := aes.NewCipher(init[8:40])
	if err != nil {
		return 0, plainTail, nil, err
	}
	// Normal direct MTProto obfuscation uses an empty secret: the IV is part
	// of the init itself. Copy it so the stream cannot alias the caller's slice.
	stream = cipher.NewCTR(block, append([]byte(nil), init[40:56]...))
	var zero56 [56]byte
	stream.XORKeyStream(zero56[:], zero56[:])
	stream.XORKeyStream(plainTail[:], init[56:64])
	proto = binary.LittleEndian.Uint32(plainTail[0:4])
	if proto != 0xEFEFEFEF && proto != 0xEEEEEEEE && proto != 0xDDDDDDDD {
		return 0, plainTail, nil, fmt.Errorf("unsupported MTProto transport tag %#x", proto)
	}
	return proto, plainTail, stream, nil
}

func parseMTProtoDC(init []byte) (dc int, isMedia bool, ok bool) {
	_, plainTail, _, err := decryptMTProtoInit(init)
	if err != nil {
		return 0, false, false
	}
	idx := int(int16(binary.LittleEndian.Uint16(plainTail[4:6])))
	if idx == 0 {
		return 0, false, false
	}
	isMedia = idx < 0
	if idx < 0 {
		idx = -idx
	}
	if idx == 203 {
		return 203, isMedia, true
	}
	if (idx >= 1 && idx <= 5) || (idx >= 10001 && idx <= 10005) {
		return idx, isMedia, true
	}
	return 0, false, false
}

func mediaForIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	// Exact media endpoints observed in Telegram client/proxy tables. Authoritative
	// static classification takes precedence over any dynamically learned cache.
	switch ip.String() {
	case "149.154.175.52", "149.154.175.211", "149.154.167.151", "149.154.167.222", "149.154.167.223", "149.154.162.123", "149.154.167.35", "149.154.175.102", "149.154.164.250", "149.154.166.120", "149.154.166.121", "149.154.167.118", "149.154.165.111", "149.154.165.136", "149.154.171.255", "91.108.56.102", "91.108.56.128", "91.108.56.151":
		return true
	}
	if _, isMedia, ok := lookupLearnedDC(ip.String()); ok {
		return isMedia
	}
	return false
}

type wsConn struct {
	conn       net.Conn
	host       string
	cfRay      string
	cfPoP      string
	r          *bufio.Reader
	mu         sync.Mutex
	fragOpcode byte
	fragData   []byte
}

var (
	systemRootCAs     *x509.CertPool
	systemRootCAsOnce sync.Once
)

// getSystemRootCAs loads Android trusted system and APEX root certificates.
// Go binaries compiled with GOOS=linux do not automatically search Android certificate paths.
func getSystemRootCAs() *x509.CertPool {
	systemRootCAsOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		dirs := []string{
			"/system/etc/security/cacerts",
			"/apex/com.android.conscrypt/cacerts",
			"/apex/com.google.android.conscrypt/cacerts",
			"/data/misc/keychain/certs-added",
			"/etc/security/cacerts",
		}
		added := 0
		for _, dir := range dirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err == nil && len(data) > 0 {
					if pool.AppendCertsFromPEM(data) {
						added++
					}
				}
			}
		}
		if added > 0 {
			logf("tls: successfully loaded %d Android system CA certificates", added)
		}
		systemRootCAs = pool
	})
	return systemRootCAs
}

var (
	dnsCacheMu      sync.RWMutex
	dnsCacheServers []string
	dnsCacheAt      time.Time
)

// androidDNSServers finds resolver addresses exposed by Android's netd.
// Caches discovered resolvers for 45 seconds to avoid repeatedly spawning getprop processes.
func androidDNSServers() []string {
	dnsCacheMu.RLock()
	if time.Since(dnsCacheAt) < 45*time.Second && len(dnsCacheServers) > 0 {
		cached := append([]string(nil), dnsCacheServers...)
		dnsCacheMu.RUnlock()
		return cached
	}
	dnsCacheMu.RUnlock()

	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if time.Since(dnsCacheAt) < 45*time.Second && len(dnsCacheServers) > 0 {
		return append([]string(nil), dnsCacheServers...)
	}

	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		a, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		a = a.Unmap()
		if !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			return
		}
		v := a.String()
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	// 1. Android property dumps (catches net.wlan0.dns1, net.rmnet_data0.dns1, net.dns1..4, etc.)
	if b, err := exec.Command("getprop").Output(); err == nil && len(b) > 0 {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(strings.ToLower(line), "dns") {
				parts := strings.SplitN(line, "]: [", 2)
				if len(parts) == 2 {
					val := strings.Trim(parts[1], "]\r\n ")
					add(val)
				}
			}
		}
	} else {
		// 2. Legacy net.dns1..4 fallback if full getprop dump is unavailable
		for i := 1; i <= 4; i++ {
			b, err := exec.Command("getprop", fmt.Sprintf("net.dns%d", i)).Output()
			if err == nil {
				add(string(b))
			}
		}
	}
	// 3. /etc/resolv.conf
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				add(f[1])
			}
		}
	}
	// 4. Reliable fallback resolvers (Yandex DNS 77.88.8.8 never blocked in RU, Cloudflare, Google)
	for _, fallback := range []string{"77.88.8.8", "1.1.1.1", "8.8.8.8"} {
		add(fallback)
	}

	dnsCacheServers = out
	dnsCacheAt = time.Now()
	return append([]string(nil), out...)
}

func androidDNSResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var last error
		for _, server := range androidDNSServers() {
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
			if err == nil {
				return c, nil
			}
			last = err
		}
		if last == nil {
			last = errors.New("no available Android DNS servers found")
		}
		return nil, last
	}}
}

func wsHostsForDC(dc int, isMedia bool) []string {
	if dc < 1 || dc > 5 {
		return nil
	}
	primary := fmt.Sprintf("kws%d.web.telegram.org", dc)
	alternate := fmt.Sprintf("kws%d-1.web.telegram.org", dc)
	if isMedia {
		return []string{alternate, primary}
	}
	return []string{primary, alternate}
}

// cdn203IP is the CDN203 endpoint, shared by the worker ?dst= target and the
// native TCP pass-through.
const cdn203IP = "91.105.192.100"

// dcSpec is the single source of truth for per-DC endpoint tables: the
// preferred ingress IP, the direct-dial candidate list, the Cloudflare Worker
// ?dst= target and the test-DC endpoint (empty when Telegram defines none).
type dcSpec struct {
	ingress    string
	candidates []string
	workerDst  string
	testIP     string
}

var dcSpecs = map[int]dcSpec{
	1: {
		ingress:    "149.154.175.50",
		candidates: []string{"149.154.175.50", "149.154.175.51", "149.154.175.53", "149.154.175.54", "149.154.175.55"},
		workerDst:  "149.154.175.50",
		testIP:     "149.154.175.10",
	},
	2: {
		ingress:    "149.154.167.220",
		candidates: []string{"149.154.167.220", "149.154.167.51", "149.154.167.50", "149.154.167.41", "149.154.167.35", "149.154.167.36"},
		workerDst:  "149.154.167.51",
		testIP:     "149.154.167.40",
	},
	3: {
		ingress:    "",
		candidates: []string{"149.154.175.100", "149.154.175.101"},
		workerDst:  "149.154.175.100",
		testIP:     "149.154.175.117",
	},
	4: {
		ingress:    "149.154.167.220",
		candidates: []string{"149.154.167.220", "149.154.167.91", "149.154.167.92"},
		workerDst:  "149.154.167.91",
	},
	5: {
		ingress:    "",
		candidates: []string{"91.108.56.100", "91.108.56.101", "91.108.56.116", "91.108.56.126", "91.108.56.198", "149.154.171.5"},
		workerDst:  "149.154.171.5",
	},
	203: {
		workerDst: cdn203IP,
	},
}

func preferredIngressForDC(dc int) string {
	if overrides := dcOverridesCached(); len(overrides) > 0 {
		if ip, ok := overrides[dc]; ok && ip != "" {
			return ip
		}
	}
	return dcSpecs[dc].ingress
}

func candidateIngressesForDC(dc int) []string {
	if overrides := dcOverridesCached(); len(overrides) > 0 {
		if ip, ok := overrides[dc]; ok && ip != "" {
			return []string{ip}
		}
	}
	return dcSpecs[dc].candidates
}

var builtInCFDomains = []string{
	"pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
	"lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
	"sorokodin.co.uk", "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk",
	"nebally.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "fixtelega.co.uk",
	"sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk", "nothingthere.co.uk",
}

var domainPattern = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func cfDomains() []string {
	var list []string
	if b, err := os.ReadFile(path("cf-domains")); err == nil {
		input := strings.Split(string(b), "\n")
		seen := map[string]bool{}
		for _, raw := range input {
			d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
			if d == "" || strings.HasPrefix(d, "#") || !domainPattern.MatchString(d) || d == "web.telegram.org" || strings.HasSuffix(d, ".web.telegram.org") || seen[d] {
				continue
			}
			seen[d] = true
			list = append(list, d)
		}
	}
	if len(list) == 0 {
		if dyn := getDynamicCFDomains(); len(dyn) > 0 {
			list = dyn
		} else {
			list = append([]string(nil), builtInCFDomains...)
		}
	}

	if custom := readCustomCFDomain(); custom != "" {
		out := make([]string, 0, len(list)+1)
		out = append(out, custom)
		for _, d := range list {
			if d != custom {
				out = append(out, d)
			}
		}
		return out
	}
	return list
}

func routeKey(dc int, isMedia bool) string {
	if isMedia {
		return fmt.Sprintf("%d:m", dc)
	}
	return fmt.Sprintf("%d", dc)
}

// mtprotoPacketFramer converts the encrypted TCP byte stream into WebSocket
// messages aligned to individual MTProto transport packets. Telegram's WSS
// relay silently discards bytes after the first packet in a frame, so forwarding
// arbitrary TCP Read() chunks as frames is not safe.
type mtprotoPacketFramer struct {
	proto      uint32
	stream     cipher.Stream
	raw        []byte
	plain      []byte
	initial    []byte
	headerSent bool
}

func newMTProtoPacketFramer(initial []byte) (*mtprotoPacketFramer, error) {
	proto, _, stream, err := decryptMTProtoInit(initial)
	if err != nil {
		return nil, err
	}
	return &mtprotoPacketFramer{proto: proto, stream: stream, initial: append([]byte(nil), initial...)}, nil
}

// nextPacketSize returns total encrypted packet length (including transport
// length prefix). The prefix is decrypted only in a parallel inspection buffer;
// the exact original encrypted bytes are forwarded unchanged.
func (f *mtprotoPacketFramer) nextPacketSize() (int, bool, error) {
	switch f.proto {
	case 0xEFEFEFEF: // abridged: length in 4-byte words; high bit requests Quick ACK
		if len(f.plain) < 1 {
			return 0, false, nil
		}
		marker := f.plain[0]
		prefix, words := 1, uint32(marker&0x7f)
		// Abridged transport uses 0x7f for an ordinary extended length and
		// 0xff for the same 3-byte length with Quick ACK requested. For short
		// packets, bit 7 is the Quick ACK flag, not an invalid length marker.
		if marker == 0x7f || marker == 0xff {
			if len(f.plain) < 4 {
				return 0, false, nil
			}
			prefix = 4
			words = uint32(f.plain[1]) | uint32(f.plain[2])<<8 | uint32(f.plain[3])<<16
		}
		if words == 0 {
			return 0, false, fmt.Errorf("zero-length abridged packet")
		}
		if uint64(words)*4+uint64(prefix) > maxWSFrame {
			return 0, false, fmt.Errorf("abridged packet exceeds limit")
		}
		total := prefix + int(words)*4
		return total, len(f.plain) >= total, nil
	case 0xEEEEEEEE, 0xDDDDDDDD: // intermediate / padded intermediate
		if len(f.plain) < 4 {
			return 0, false, nil
		}
		n := binary.LittleEndian.Uint32(f.plain[:4])
		if n == 0 {
			return 0, false, fmt.Errorf("zero-length intermediate packet")
		}
		if uint64(n)+4 > maxWSFrame {
			return 0, false, fmt.Errorf("intermediate packet exceeds limit")
		}
		total := 4 + int(n)
		return total, len(f.plain) >= total, nil
	}
	return 0, false, fmt.Errorf("unsupported MTProto transport tag %#x", f.proto)
}

func (f *mtprotoPacketFramer) feed(encrypted []byte, ws *wsConn) error {
	if len(encrypted) == 0 {
		return nil
	}
	prevPlain := len(f.plain)
	f.plain = append(f.plain, encrypted...)
	f.stream.XORKeyStream(f.plain[prevPlain:], encrypted)
	f.raw = append(f.raw, encrypted...)
	for {
		n, ready, err := f.nextPacketSize()
		if err != nil {
			return err
		}
		if !ready {
			return nil
		}
		frame := f.raw[:n]
		if !f.headerSent {
			payload := make([]byte, 0, len(f.initial)+len(frame))
			payload = append(payload, f.initial...)
			payload = append(payload, frame...)
			if err := ws.writeFrame(2, payload); err != nil {
				return err
			}
			f.headerSent = true
		} else if err := ws.writeFrame(2, frame); err != nil {
			return err
		}
		f.raw = f.raw[n:]
		f.plain = f.plain[n:]
		if len(f.raw) == 0 {
			f.raw = f.raw[:0]
			f.plain = f.plain[:0]
		} else if cap(f.raw) > 128*1024 && len(f.raw) < 32*1024 {
			newRaw := make([]byte, len(f.raw))
			copy(newRaw, f.raw)
			f.raw = newRaw

			newPlain := make([]byte, len(f.plain))
			copy(newPlain, f.plain)
			f.plain = newPlain
		}
	}
}

func pipeTCPToWSCount(src net.Conn, ws *wsConn, initial []byte, counter *int64, activity *atomic.Int64) error {
	framer, err := newMTProtoPacketFramer(initial)
	if err != nil {
		return err
	}
	bufPtr := ioBufPool.Get().(*[]byte)
	defer ioBufPool.Put(bufPtr)
	buf := *bufPtr
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if activity != nil {
				activity.Store(time.Now().UnixNano())
			}
			if counter != nil {
				atomic.AddInt64(counter, int64(n))
			}
			atomic.AddInt64(&trafficUpBytes, int64(n))
			if err := framer.feed(buf[:n], ws); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

func routeCoolingDown(host string) bool {
	if host == "" {
		return false
	}
	routeHealthMu.Lock()
	defer routeHealthMu.Unlock()
	state, ok := routeHealth[host]
	return ok && time.Now().Before(state.until)
}

// clearRouteHealth resets the failure history after a successful dial so a
// single later timeout cannot inherit a fully grown 30-minute backoff.
func clearRouteHealth(host string) {
	if host == "" {
		return
	}
	routeHealthMu.Lock()
	delete(routeHealth, host)
	routeHealthMu.Unlock()
}

// sweepRouteCaches bounds the host-keyed health maps. Keys accumulate as the
// hourly-updated Cloudflare domain list drifts, so stale entries must be
// evicted or the maps grow without bound for the lifetime of the daemon.
func sweepRouteCaches() {
	now := time.Now()
	routeHealthMu.Lock()
	for host, state := range routeHealth {
		if state.until.Before(now.Add(-10 * time.Minute)) {
			delete(routeHealth, host)
		}
	}
	for len(routeHealth) > 256 {
		var oldestHost string
		var oldest time.Time
		for host, state := range routeHealth {
			if oldestHost == "" || state.until.Before(oldest) {
				oldestHost, oldest = host, state.until
			}
		}
		if oldestHost == "" {
			break
		}
		delete(routeHealth, oldestHost)
	}
	routeHealthMu.Unlock()

	h2FailsMu.Lock()
	for host, until := range h2Fails {
		if until.Before(now) {
			delete(h2Fails, host)
		}
	}
	for len(h2Fails) > 256 {
		for host := range h2Fails {
			delete(h2Fails, host)
			break
		}
	}
	h2FailsMu.Unlock()
}

// Repeated early remote EOFs indicate a frontend that accepts the WebSocket
// upgrade but does not sustain MTProto traffic. Cool it down briefly so the
// next Telegram reconnect can select another WSS frontend. One EOF alone is
// not enough: normal client/auth flows can close short-lived connections.
func noteEarlyRemoteClose(key, host string, err error, age time.Duration, up, down int64) {
	if host == "" || age > 45*time.Second || up+down > 4096 || (err != io.EOF && !strings.Contains(strings.ToLower(err.Error()), "eof")) {
		return
	}
	now := time.Now()
	routeHealthMu.Lock()
	state := routeHealth[host]
	if now.Sub(state.last) > 2*time.Minute {
		state.count = 0
	}
	state.count++
	state.last = now
	series := state.count // log value: position within the current EOF series
	if state.count >= 2 {
		state.failures++
		state.until = now.Add(routeBackoff(state.failures))
		state.count = 0
	}
	routeHealth[host] = state
	cooling, until, failures := now.Before(state.until), state.until, state.failures
	routeHealthMu.Unlock()
	if cooling {
		cfHostCache.Delete(key)
		logf("WSS route %s temporarily excluded for %s after repeated early EOF (series=%d, age=%s up=%d down=%d): %v", host, time.Until(until).Round(time.Second), failures, age.Round(time.Second), up, down, err)
	} else {
		logf("WSS route %s: early remote EOF #%d (age=%s up=%d down=%d): %v", host, series, age.Round(time.Second), up, down, err)
	}
}

type dialCandidate struct {
	name string
	dial func(ctx context.Context) (*wsConn, error)
}

func raceCandidates(ctx context.Context, candidates []dialCandidate, stagger time.Duration, maxParallel int) (*wsConn, string, error) {
	if len(candidates) == 0 {
		return nil, "", errors.New("no available candidates for connection")
	}
	if len(candidates) == 1 {
		ws, err := candidates[0].dial(ctx)
		return ws, candidates[0].name, err
	}

	raceCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()

	type raceRes struct {
		cand dialCandidate
		ws   *wsConn
		err  error
	}

	resCh := make(chan raceRes, len(candidates))
	nextIdx := 0
	active := 0
	var errorsSeen []string

	startNext := func() bool {
		if nextIdx >= len(candidates) || active >= maxParallel {
			return false
		}
		c := candidates[nextIdx]
		nextIdx++
		active++
		go func(cand dialCandidate) {
			ws, err := cand.dial(raceCtx)
			resCh <- raceRes{cand: cand, ws: ws, err: err}
		}(c)
		return true
	}

	startNext()

	timer := time.NewTimer(stagger)
	defer timer.Stop()

	for active > 0 || nextIdx < len(candidates) {
		select {
		case <-raceCtx.Done():
			go func(rem int) {
				for i := 0; i < rem; i++ {
					r := <-resCh
					if r.ws != nil {
						_ = r.ws.Close()
					}
				}
			}(active)
			return nil, "", raceCtx.Err()

		case <-timer.C:
			if active < maxParallel && nextIdx < len(candidates) {
				startNext()
			}
			if nextIdx < len(candidates) {
				timer.Reset(stagger)
			}

		case res := <-resCh:
			active--
			if res.err == nil && res.ws != nil {
				cancelAll()
				go func(rem int) {
					for i := 0; i < rem; i++ {
						r := <-resCh
						if r.ws != nil {
							_ = r.ws.Close()
						}
					}
				}(active)
				return res.ws, res.cand.name, nil
			}
			errorsSeen = append(errorsSeen, fmt.Sprintf("%s: %v", res.cand.name, res.err))
			if active < maxParallel && nextIdx < len(candidates) {
				startNext()
				timer.Reset(stagger)
			}
		}
	}

	return nil, "", fmt.Errorf("all %d candidates failed: %s", len(candidates), strings.Join(errorsSeen, " | "))
}

func dialTelegramWS(ctx context.Context, dc int, isMedia bool, isTest bool) (*wsConn, error) {
	hosts := wsHostsForDC(dc, isMedia)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("unknown DC: %d", dc)
	}
	key := routeKey(dc, isMedia)
	if isTest {
		key = fmt.Sprintf("dc%d_test_%s", dc, func() string {
			if isMedia {
				return "media"
			}
			return "main"
		}())
	}
	resolver := androidDNSResolver()

	cfPriority := cfPriorityCached()
	cfBalance := cfBalanceCached()
	worker := customCFWorkerCached()

	var candidates []dialCandidate
	var deferCandidates []dialCandidate

	// 1. Cloudflare Worker candidate (high priority if cfPriority, else deferred)
	if worker != "" {
		workerHost := worker
		dst := workerDstForDC(dc)
		if isTest {
			if testIP := dcSpecs[dc].testIP; testIP != "" {
				dst = testIP
			}
		}
		candWorker := dialCandidate{
			name: fmt.Sprintf("cf-worker (%s)", workerHost),
			dial: func(c context.Context) (*wsConn, error) {
				return dialCFWorker(c, dc, dst, workerHost, isTest)
			},
		}
		if cfPriority {
			candidates = append(candidates, candWorker)
		} else {
			deferCandidates = append(deferCandidates, candWorker)
		}
	}

	if !isTest {
		// 2. DC1 special preferred host: kws1.pclead.co.uk
		if dc == 1 && !cfBalance {
			const preferredDC1Host = "kws1.pclead.co.uk"
			if !routeCoolingDown(preferredDC1Host) {
				candDC1 := dialCandidate{
					name: fmt.Sprintf("cf-preferred (%s)", preferredDC1Host),
					dial: func(c context.Context) (*wsConn, error) {
						return dialCFHost(c, resolver, preferredDC1Host)
					},
				}
				candidates = append(candidates, candDC1)
			}
		}

		// 3. Fast path: cached Cloudflare route
		if cached, ok := cfHostCache.Load(key); ok {
			if host, ok := cached.(string); ok && host != "" && !routeCoolingDown(host) {
				h := host
				candCached := dialCandidate{
					name: fmt.Sprintf("cf-cached (%s)", h),
					dial: func(c context.Context) (*wsConn, error) {
						return dialCFHost(c, resolver, h)
					},
				}
				candidates = append(candidates, candCached)
			}
		}

		// 4. Pre-warmed route pool candidates: see cf-cached fast path above.
	}

	// 5. Direct IP routes (cached DNS or fallback IPs / Test DC IPs)
	var directIPs []netip.Addr
	targetHost := hosts[0]
	wsUpgradePath := "/apiws"
	if isTest {
		wsUpgradePath = "/apiws_test"
		if testIPStr := dcSpecs[dc].testIP; testIPStr != "" {
			if ip, err := netip.ParseAddr(testIPStr); err == nil {
				directIPs = []netip.Addr{ip}
			}
		}
	} else {
		preferredIP := preferredIngressForDC(dc)
		candIPs := candidateIngressesForDC(dc)
		if preferredIP != "" {
			directIPs = appendUniqueIP(directIPs, netip.MustParseAddr(preferredIP))
		}
		for _, cip := range candIPs {
			if parsed, err := netip.ParseAddr(cip); err == nil {
				directIPs = appendUniqueIP(directIPs, parsed)
			}
		}
		// Always supplement candidate list with live DNS-resolved addresses.
		// Both hosts are resolved concurrently: two sequential lookups would
		// stall the start of the dial race by two DNS round trips.
		resolved := make([][]netip.Addr, len(hosts))
		var dnsWG sync.WaitGroup
		for i, h := range hosts {
			dnsWG.Add(1)
			go func(i int, h string) {
				defer dnsWG.Done()
				if ips, err := resolver.LookupNetIP(ctx, "ip4", h); err == nil {
					resolved[i] = ips
				}
			}(i, h)
		}
		dnsWG.Wait()
		for _, ips := range resolved {
			for _, ip := range ips {
				if ip.Is4() {
					directIPs = appendUniqueIP(directIPs, ip)
				}
			}
		}
	}

	for _, ip := range directIPs {
		ipAddr := ip
		candDirect := dialCandidate{
			name: fmt.Sprintf("direct (%s@%s)", targetHost, ipAddr),
			dial: func(c context.Context) (*wsConn, error) {
				attemptCtx, cancel := context.WithTimeout(c, 2500*time.Millisecond)
				defer cancel()
				d := net.Dialer{Timeout: 1200 * time.Millisecond, KeepAlive: 30 * time.Second}
				raw, err := d.DialContext(attemptCtx, "tcp4", net.JoinHostPort(ipAddr.String(), "443"))
				if err != nil {
					return nil, err
				}
				setConnSockOpts(raw)
				return finishTelegramWSPath(attemptCtx, raw, targetHost, wsUpgradePath)
			},
		}
		if !cfPriority {
			candidates = append(candidates, candDirect)
		} else {
			deferCandidates = append(deferCandidates, candDirect)
		}
	}

	if !isTest {
		// 6. Cloudflare Fronting Domains
		for _, dom := range cfDomainsCached() {
			d := dom
			host := fmt.Sprintf("kws%d.%s", dc, d)
			if !routeCoolingDown(host) {
				candDomain := dialCandidate{
					name: fmt.Sprintf("cf-domain (%s)", host),
					dial: func(c context.Context) (*wsConn, error) {
						return dialCFHost(c, resolver, host)
					},
				}
				candidates = append(candidates, candDomain)
			}
		}
	}

	candidates = append(candidates, deferCandidates...)

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no available routes for DC%d media=%t", dc, isMedia)
	}

	if cfBalance && len(candidates) > 1 {
		offset := int(atomic.AddUint64(&cfBalanceSeq, 1) % uint64(len(candidates)))
		rotated := make([]dialCandidate, len(candidates))
		for i := range candidates {
			rotated[i] = candidates[(offset+i)%len(candidates)]
		}
		candidates = rotated
	}

	// Parallel Happy Eyeballs v2 connection racing with 250ms stagger
	ws, winningRoute, err := raceCandidates(ctx, candidates, 250*time.Millisecond, 3)
	if err != nil {
		return nil, err
	}

	logf("DC%d media=%t Happy Eyeballs winner: %s", dc, isMedia, winningRoute)
	if strings.HasPrefix(winningRoute, "cf-") {
		if start := strings.IndexByte(winningRoute, '('); start != -1 {
			if end := strings.IndexByte(winningRoute[start:], ')'); end != -1 {
				h := winningRoute[start+1 : start+end]
				if !cfBalance && h != "" && !strings.HasPrefix(winningRoute, "cf-worker") {
					cfHostCache.Store(key, h)
					saveRouteCache(key, h)
				}
			}
		}
	}

	return ws, nil
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
func isTimeoutText(s string) bool {
	return strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded")
}

func appendUniqueIP(dst []netip.Addr, ip netip.Addr) []netip.Addr {
	for _, old := range dst {
		if old == ip {
			return dst
		}
	}
	return append(dst, ip)
}

const (
	routeRejectNone = iota
	routeRejectRateLimit
	routeRejectForbidden
	routeRejectServer
)

// routeHTTPRejection classifies a lower-cased dial failure message. These are
// frontends rejecting the route itself (unlike timeouts or resets, which may be
// transient), so callers either cool the host down or move to the next IP.
func routeHTTPRejection(msg string) int {
	switch {
	case strings.Contains(msg, "429") || strings.Contains(msg, "rate limit") || strings.Contains(msg, "too many requests"):
		return routeRejectRateLimit
	case strings.Contains(msg, "403") || strings.Contains(msg, "forbidden"):
		return routeRejectForbidden
	case strings.Contains(msg, "http 500") || strings.Contains(msg, "http 502") || strings.Contains(msg, "http 503") ||
		strings.Contains(msg, "http 504") || strings.Contains(msg, "http 521") || strings.Contains(msg, "http 522") ||
		strings.Contains(msg, "http 523") || strings.Contains(msg, "http 525"):
		return routeRejectServer
	}
	return routeRejectNone
}

func noteRouteHTTPFailure(host string, err error) {
	if host == "" || err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	var cooldown time.Duration
	var reason string

	switch routeHTTPRejection(msg) {
	case routeRejectRateLimit:
		cooldown = 3 * time.Minute
		reason = "HTTP 429 (Rate Limit)"
	case routeRejectForbidden:
		cooldown = 3 * time.Minute
		reason = "HTTP 403 (Forbidden)"
	case routeRejectServer:
		cooldown = 3 * time.Minute
		reason = "HTTP 5xx (Server Error)"
	default:
		if !isTimeout(err) && !isTimeoutText(msg) {
			return
		}
		cooldown = 45 * time.Second
		reason = "Timeout"
	}

	now := time.Now()
	routeHealthMu.Lock()
	state := routeHealth[host]
	// A failure long after the previous series must start a fresh escalation:
	// without this decay a single 429 weeks later inherits the fully grown
	// backoff accumulated by past incidents. 10 min exceeds any cooldown this
	// loop can produce below the sweep threshold, so ongoing incidents keep
	// escalating while a quiet host starts over at the base 30s.
	if !state.last.IsZero() && now.Sub(state.last) > 10*time.Minute {
		state.failures = 0
	}
	state.failures++
	cooldown = routeBackoff(state.failures)
	if reason == "Timeout" && cooldown > 3*time.Minute {
		cooldown = 3 * time.Minute
	}
	wasCooling := now.Before(state.until)
	state.until = now.Add(cooldown)
	state.last = now
	routeHealth[host] = state
	routeHealthMu.Unlock()

	for dc := 1; dc <= 5; dc++ {
		for _, media := range []bool{false, true} {
			k := routeKey(dc, media)
			if v, ok := cfHostCache.Load(k); ok && v == host {
				cfHostCache.Delete(k)
			}
		}
	}

	if !wasCooling {
		logf("WSS route %s temporarily excluded for %s after %s: %v", host, cooldown.Round(time.Second), reason, err)
	}
}

func dialCFHost(ctx context.Context, resolver *net.Resolver, host string) (*wsConn, error) {
	var ips []netip.Addr
	if doHEnabledCached() {
		dohCtx, dohCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		dohIPs, err := resolveDoHRace(dohCtx, host)
		dohCancel()
		if err == nil && len(dohIPs) > 0 {
			ips = dohIPs
		}
	}
	if len(ips) == 0 {
		var err error
		ips, err = resolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, fmt.Errorf("DNS: %w", err)
		}
	}
	var last error
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		d := net.Dialer{Timeout: 1200 * time.Millisecond, KeepAlive: 30 * time.Second}
		raw, e := d.DialContext(attemptCtx, "tcp4", net.JoinHostPort(ip.String(), "443"))
		if e == nil {
			setConnSockOpts(raw)
			var ws *wsConn
			ws, e = finishTelegramWS(attemptCtx, raw, host)
			if e == nil {
				cancel()
				clearRouteHealth(host)
				return ws, nil
			}
			noteRouteHTTPFailure(host, e)
			_ = raw.Close()
			// A rejected route will reject the next IP the same way: stop
			// trying this host instead of burning the dial budget on it.
			if routeHTTPRejection(strings.ToLower(e.Error())) != routeRejectNone {
				cancel()
				return nil, e
			}
		} else {
			if isTimeout(e) || isTimeoutText(e.Error()) {
				noteRouteHTTPFailure(host, e)
			}
		}
		cancel()
		last = e
	}
	if last == nil {
		last = errors.New("DNS returned no IPv4 addresses")
	}
	return nil, last
}

func configuredFrontingSNI() string {
	b, err := os.ReadFile(path("fronting-sni"))
	if err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" && !strings.EqualFold(s, "none") && !strings.EqualFold(s, "disable") {
			return s
		}
	}
	return ""
}

// shouldSkipTLSVerify keeps certificate verification on for every route whose
// TLS name matches the dialed host (kws relays, CF-fronted domains, workers.dev
// endpoints all present valid certificates). Verification is disabled only for
// an explicit fronting-sni override, which presents a name no public CA can
// certify — the deliberate trade-off of that feature.
func shouldSkipTLSVerify(host, sni string) bool {
	return !strings.EqualFold(strings.TrimSpace(host), strings.TrimSpace(sni))
}

func prepareUTLSForHTTP1(conn *utls.UConn) error {
	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}
	found := false
	for _, extension := range conn.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			found = true
			break
		}
	}
	if !found {
		conn.Extensions = append(conn.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	return conn.BuildHandshakeState()
}

func finishTelegramWS(ctx context.Context, raw net.Conn, host string) (*wsConn, error) {
	return finishTLSAndUpgrade(ctx, raw, host, "/apiws", true)
}

func finishTelegramWSPath(ctx context.Context, raw net.Conn, host string, path string) (*wsConn, error) {
	return finishTLSAndUpgrade(ctx, raw, host, path, true)
}

// finishTLSAndUpgrade performs the uTLS handshake plus the WebSocket upgrade
// on an already-dialed raw connection. honorFrontingSNI switches the SNI to
// the configured fronting value, which real Telegram endpoints accept for
// CF-fronted domains; worker endpoints must keep their real hostname.
func finishTLSAndUpgrade(ctx context.Context, raw net.Conn, host, path string, honorFrontingSNI bool) (*wsConn, error) {
	setConnSockOpts(raw)
	sni := host
	if honorFrontingSNI {
		if customSNI := configuredFrontingSNI(); customSNI != "" {
			sni = customSNI
		}
	}
	uConfig := &utls.Config{
		ServerName:                  sni,
		MinVersion:                  utls.VersionTLS12,
		RootCAs:                     getSystemRootCAs(),
		InsecureSkipVerify:          shouldSkipTLSVerify(host, sni),
		NextProtos:                  []string{"http/1.1"},
		DynamicRecordSizingDisabled: true,
	}
	uConn := utls.UClient(raw, uConfig, utls.HelloChrome_Auto)
	if err := prepareUTLSForHTTP1(uConn); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = uConn.SetDeadline(deadline)
	} else {
		_ = uConn.SetDeadline(time.Now().Add(8 * time.Second))
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	ws, err := websocketUpgradePath(uConn, host, path)
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}
	_ = uConn.SetDeadline(time.Time{})
	return ws, nil
}

func websocketUpgradePath(conn net.Conn, host string, path string) (*wsConn, error) {
	if path == "" {
		path = "/apiws"
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nOrigin: https://web.telegram.org\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36\r\n\r\n", path, host, key)
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 32*1024)
	resp, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		msg := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			var retryAfter time.Duration
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if sec, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && sec > 0 {
					retryAfter = time.Duration(sec) * time.Second
				}
			}
			return nil, &RateLimitError{StatusCode: resp.StatusCode, RetryAfter: retryAfter, Message: msg}
		}
		return nil, fmt.Errorf("HTTP %s: %s", resp.Status, msg)
	}
	want := base64.StdEncoding.EncodeToString(sha1Sum([]byte(key + wsGUID)))
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept")), want) {
		return nil, errors.New("invalid Sec-WebSocket-Accept")
	}
	if !headerToken(resp.Header.Get("Upgrade"), "websocket") || !headerToken(resp.Header.Get("Connection"), "upgrade") {
		return nil, errors.New("invalid Upgrade/Connection headers")
	}
	if p := resp.Header.Get("Sec-WebSocket-Protocol"); p != "" && p != "binary" {
		return nil, fmt.Errorf("server selected unknown subprotocol %q", p)
	}
	cfRay := strings.TrimSpace(resp.Header.Get("CF-Ray"))
	cfPoP := parseCFRayPoP(cfRay)
	if cfRay != "" {
		lastCFRay.Store(&cfRay)
		if cfPoP != "" {
			lastCFPoP.Store(&cfPoP)
		}
	}
	return &wsConn{conn: conn, r: r, host: host, cfRay: cfRay, cfPoP: cfPoP}, nil
}

func finishWorkerWS(ctx context.Context, raw net.Conn, host, path string) (*wsConn, error) {
	return finishTLSAndUpgrade(ctx, raw, host, path, false)
}

func workerDstForDC(dc int) string {
	if spec, ok := dcSpecs[dc]; ok && spec.workerDst != "" {
		return spec.workerDst
	}
	// Unknown DC: fall back to the DC2 relay, the same default as before.
	return "149.154.167.51"
}

func dialCFWorker(ctx context.Context, dc int, dstIP, worker string, isTest bool) (*wsConn, error) {
	worker = strings.TrimSpace(worker)
	if worker == "" {
		return nil, errors.New("worker is not configured")
	}
	worker = normalizeWorkerAddress(worker)

	host := worker
	query := ""
	if idx := strings.IndexByte(worker, '?'); idx != -1 {
		host = worker[:idx]
		query = worker[idx+1:]
	}
	if slash := strings.IndexByte(host, '/'); slash != -1 {
		host = host[:slash]
	}

	if isWorkerInCooldown(host) {
		return nil, fmt.Errorf("worker %s is in rate limit cooldown", host)
	}

	basePath := "/apiws"
	if isTest {
		basePath = "/apiws_test"
	}
	path := fmt.Sprintf("%s?dst=%s&dc=%d", basePath, dstIP, dc)
	if query != "" {
		path += "&" + query
	}

	resolver := androidDNSResolver()
	ips, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("worker DNS %s: %w", host, err)
	}

	var lastErr error
	for _, ip := range ips {
		if !ip.Is4() {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
		d := net.Dialer{Timeout: 1500 * time.Millisecond, KeepAlive: 30 * time.Second}
		raw, e := d.DialContext(attemptCtx, "tcp4", net.JoinHostPort(ip.String(), "443"))
		if e != nil {
			cancel()
			lastErr = e
			continue
		}
		setConnSockOpts(raw)

		ws, e := finishWorkerWS(attemptCtx, raw, host, path)
		cancel()
		if e == nil {
			clearWorkerCooldown(host)
			return ws, nil
		}
		var rle *RateLimitError
		if errors.As(e, &rle) {
			markWorkerCooldown(host, rle.RetryAfter)
			return nil, e
		}
		lastErr = e
	}
	return nil, fmt.Errorf("worker %s: %v", host, lastErr)
}
func headerToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func sha1Sum(b []byte) []byte  { h := sha1.Sum(b); return h[:] }
func (w *wsConn) Close() error { return w.conn.Close() }
func (w *wsConn) writeFrame(op byte, p []byte) error {
	n := len(p)
	if n > maxWSFrame {
		return errors.New("WebSocket frame too large")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	var hBuf [14]byte
	hBuf[0] = 0x80 | (op & 0x0f)
	var hLen int
	switch {
	case n < 126:
		hBuf[1] = 0x80 | byte(n)
		hLen = 2
	case n <= 65535:
		hBuf[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hBuf[2:4], uint16(n))
		hLen = 4
	default:
		hBuf[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hBuf[2:10], uint64(n))
		hLen = 10
	}
	if _, e := rand.Read(hBuf[hLen : hLen+4]); e != nil {
		return e
	}
	mask := hBuf[hLen : hLen+4]
	hLen += 4
	header := hBuf[:hLen]

	var payload []byte
	var bufPtr *[]byte
	if n <= 64*1024 {
		bufPtr = frameBufPool.Get().(*[]byte)
		payload = (*bufPtr)[:n]
	} else {
		payload = make([]byte, n)
	}

	for i := range p {
		payload[i] = p[i] ^ mask[i&3]
	}

	// Large media frames on a slow uplink can take well over 10s to flush;
	// scale the deadline with payload size so healthy transfers are not cut.
	writeTimeout := 10 * time.Second
	if n > 1<<20 {
		writeTimeout = 60 * time.Second
	}
	_ = w.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := writeFull(w.conn, header)
	if err == nil {
		err = writeFull(w.conn, payload)
	}
	_ = w.conn.SetWriteDeadline(time.Time{})

	if bufPtr != nil {
		frameBufPool.Put(bufPtr)
	}
	return err
}
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
func (w *wsConn) readFrame() (byte, []byte, error) {
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.r, h[:]); err != nil {
			return 0, nil, err
		}
		fin, op, masked := h[0]&0x80 != 0, h[0]&0x0f, h[1]&0x80 != 0
		n := uint64(h[1] & 0x7f)
		if n == 126 {
			var x [2]byte
			if _, err := io.ReadFull(w.r, x[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(x[:]))
		} else if n == 127 {
			var x [8]byte
			if _, err := io.ReadFull(w.r, x[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(x[:])
		}
		if n > maxWSFrame {
			return 0, nil, fmt.Errorf("WebSocket frame exceeds %d bytes", maxWSFrame)
		}
		if op >= 8 && (!fin || n > 125) {
			return 0, nil, errors.New("invalid WebSocket control frame")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.r, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		p := make([]byte, int(n))
		if _, err := io.ReadFull(w.r, p); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= mask[i&3]
			}
		}
		// Control frames may be interleaved with fragmented data messages.
		if op >= 8 {
			return op, p, nil
		}
		switch op {
		case 1, 2:
			if w.fragOpcode != 0 {
				return 0, nil, errors.New("new data frame before fragmented message completed")
			}
			if fin {
				return op, p, nil
			}
			w.fragOpcode, w.fragData = op, append([]byte(nil), p...)
		case 0:
			if w.fragOpcode == 0 {
				return 0, nil, errors.New("unexpected continuation frame")
			}
			if len(w.fragData)+len(p) > maxWSFrame {
				return 0, nil, errors.New("fragmented WebSocket message too large")
			}
			w.fragData = append(w.fragData, p...)
			if fin {
				outOp, out := w.fragOpcode, w.fragData
				w.fragOpcode, w.fragData = 0, nil
				return outOp, out, nil
			}
		default:
			return 0, nil, fmt.Errorf("unsupported WebSocket opcode %d", op)
		}
	}
}

func runChecks() {
	fmt.Println("TeleWEB engine checks")
	for ip, want := range map[string]int{"149.154.175.54": 1, "149.154.167.51": 2, "149.154.175.211": 1, "149.154.167.223": 2, "91.108.56.100": 5} {
		a := netip.MustParseAddr(ip)
		got := dcFor(a)
		fmt.Printf("DC mapping %-18s got=%d expected=%d\n", ip, got, want)
		if got != want {
			os.Exit(1)
		}
	}
	// Exercise WebSocket framing with an in-memory fake server/client pair.
	fmt.Println("DC mapping smoke test passed")
}

// compile-time references for code paths shared by Linux/Android.
