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
	"math"
	"net"
	"net/http"
	_ "net/http/pprof" // gated behind TELEWEB_PPROF, loopback only
	"net/netip"
	"os"
	"os/exec"
	stdpath "path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
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
	baseDir          = envOr("TELEWEB_DIR", defaultBaseDir())
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
	lastLogRaw       string
	repeatLogCount   int
	lastRepeatLog    time.Time
	// logSuppressed counts the lines the dedupe folded into a summary, so a
	// storm that looks quiet in the log is still visible in the status.
	logSuppressed      atomic.Uint64
	appCacheMu         sync.Mutex
	appCache           []App
	uidCache           []int
	cfHostCache        sync.Map // route key -> last working Cloudflare-fronted KWS hostname
	routeCacheMu       sync.Mutex
	routeCacheDisk     = map[string]persistedRoute{}
	routeHealthMu      sync.Mutex
	routeHealth        = map[string]routeHealthState{} // host -> repeated early remote-close state
	cfBalanceSeq       uint64
	cfFrontSeq         uint64
	dcDomainAffinityMu sync.RWMutex
	dcDomainAffinity   = map[int]string{} // dc -> preferred working front domain
	ioBufPool          = sync.Pool{
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

// routeCacheTTL bounds how long a last-known-good route keeps the fast path.
// Once it expires the next dial re-evaluates every route instead of fronting
// the same frontend forever; a winning dial re-stamps the entry. Six hours
// mirrors the measured route decision used by the sibling TG Open build.
const routeCacheTTL = 6 * time.Hour

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
		// Keep the in-memory freshness stamp current without rewriting the
		// file on every dial; the persisted timestamp only matters across
		// daemon restarts.
		entry.UpdatedAt = time.Now()
		routeCacheDisk[key] = entry
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

// routeCacheFresh reports whether key's last-known-good route is recent enough
// to keep front-loading. A stale entry is skipped once so the full race
// re-evaluates the route instead of pinning an old frontend forever.
func routeCacheFresh(key, host string) bool {
	routeCacheMu.Lock()
	entry := routeCacheDisk[key]
	routeCacheMu.Unlock()
	return entry.Host == host && time.Since(entry.UpdatedAt) < routeCacheTTL
}

type routeHealthState struct {
	count    int
	failures int
	last     time.Time
	until    time.Time
	// busyAt is the last time the 5xx busy notice was logged for this host. It
	// only throttles logging; it never feeds the escalation counters.
	busyAt time.Time
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
	GCNum             uint32         `json:"gcNum"`
	GCCPUPercent      float64        `json:"gcCpuPercent"`
	GCPauseAvgMs      float64        `json:"gcPauseAvgMs"`
	HeapLiveBytes     int64          `json:"heapLiveBytes"`
	Log               string         `json:"log"`
	LogSuppressed     uint64         `json:"logSuppressed"`
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
	Redirector        bool           `json:"redirector"`
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

const defaultDescBase = "Прозрачный WSS-транспорт для Telegram (DC1-DC5)"

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
		return "status: disabled ❌"
	}
	running := daemonHealthy()
	rules := rulesHealthy()
	if !running || !rules {
		return "status: failed ⚠️"
	}
	mode := "WSS"
	if readCFPriority() {
		mode = "WSS (CF Priority)"
	}
	return "status: active ✅ | " + mode + " · DC1-DC5"
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

	fullDesc := statusText
	if fullDesc == "" {
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
func flushRepeatLocked(now time.Time) {
	if repeatLogCount > 0 {
		repeatMsg := now.Format("2006/01/02 15:04:05 ") + fmt.Sprintf("[last message repeated %d times]", repeatLogCount)
		fmt.Fprintln(os.Stderr, repeatMsg)
		if logFile != nil {
			_, _ = fmt.Fprintln(logFile, repeatMsg)
			logWrites++
		}
		repeatLogCount = 0
		lastRepeatLog = now
	}
}

func flushLogDedupe() {
	logMu.Lock()
	defer logMu.Unlock()
	flushRepeatLocked(time.Now())
	lastLogRaw = ""
	logSuppressed.Store(0)
}

func logf(format string, a ...any) {
	raw := fmt.Sprintf(format, a...)
	now := time.Now()

	logMu.Lock()
	defer logMu.Unlock()

	if raw == lastLogRaw {
		repeatLogCount++
		logSuppressed.Add(1)
		// Flush summary periodically during extended duplicate storms
		if now.Sub(lastRepeatLog) >= 5*time.Second || repeatLogCount >= 50 {
			flushRepeatLocked(now)
		}
		return
	}

	flushRepeatLocked(now)
	lastLogRaw = raw
	lastRepeatLog = now

	msg := now.Format("2006/01/02 15:04:05 ") + raw
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

var (
	shutdownMu    sync.Mutex
	shutdownHooks []func()
)

func registerShutdownHook(fn func()) {
	shutdownMu.Lock()
	defer shutdownMu.Unlock()
	shutdownHooks = append(shutdownHooks, fn)
}

func runShutdownHooks() {
	shutdownMu.Lock()
	hooks := append(([]func())(nil), shutdownHooks...)
	shutdownHooks = nil
	shutdownMu.Unlock()
	for _, h := range hooks {
		func() {
			defer func() { _ = recover() }()
			h()
		}()
	}
}

func startSignalLogger() {
	ch := make(chan os.Signal, 4)
	notifySignals(ch)
	go func() {
		for sig := range ch {
			logf("process: received signal %s; shutting down gracefully", sig)
			runShutdownHooks()
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
	// Same file format as the readFlag/writeFlag pair; readEnabled keeps its
	// own default-true rule for a missing file, unlike readFlag.
	return writeFlag("enabled", v)
}

// cfgFileCache memoizes config-file parses for the hot per-connection path.
// Entries are validated by a single Stat (mtime+size) signature, so a dial
// performs one cheap syscall instead of several full file reads and regex
// passes, while external edits are picked up on the next call. The signature is
// the whole invalidation mechanism: there is no time limit, which holds while
// the filesystem reports nanosecond mtime (ext4, f2fs and NTFS all do) and a
// rewrite of a flag file changes its size or timestamp.
var cfgFileCache = struct {
	mu      sync.Mutex
	entries map[string]cfgFileEntry
}{entries: map[string]cfgFileEntry{}}

type cfgFileEntry struct {
	sig   uint64
	value any
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
	cfgFileCache.mu.Lock()
	defer cfgFileCache.mu.Unlock()
	if e, ok := cfgFileCache.entries[name]; ok && e.sig == sig {
		return e.value
	}
	v := load()
	cfgFileCache.entries[name] = cfgFileEntry{sig: sig, value: v}
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
	f, err := os.Open(path("tgws.log"))
	if err != nil {
		return ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return ""
	}

	const maxTailBytes = 32 * 1024
	offset := int64(0)
	readLen := fi.Size()
	if readLen > maxTailBytes {
		offset = readLen - maxTailBytes
		readLen = maxTailBytes
	}
	buf := make([]byte, readLen)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return ""
	}

	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

var packageNames = []struct{ Pkg, Name string }{
	{"com.exteragram.messenger", "exteraGram"},
	{"org.telegram.messenger", "Telegram"},
	{"org.telegram.messenger.beta", "Telegram Beta"},
	{"org.telegram.plus", "Plus Messenger"},
	{"org.telegram.plus.beta", "Plus Messenger Beta"},
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
	{"org.swiftgram.messenger", "Swiftgram"},
	{"org.telegram.messenger.cherry", "Cherrygram"},
	{"com.cherrygram.messenger", "Cherrygram"},
	{"org.telegram.messenger.mdgram", "MDGram"},
	{"com.turrit.chat", "Turrit"},
	{"org.telegram.bgram", "BGram"},
	{"ir.ilmili.telegraph", "Telegraph"},
	{"org.catogram.messenger", "Catogram"},
}

var curatedClientNames = func() map[string]string {
	m := make(map[string]string, len(packageNames))
	for _, p := range packageNames {
		m[p.Pkg] = p.Name
	}
	return m
}()

// telegramClientName decides whether a package belongs in the detected
// clients list. A curated name always qualifies; anything else has to prove
// itself with Telegram's native libraries inside its APK.
//
// The old substring keyword guess over package names is gone: "gram", "tele",
// "ime", "plus" and "tg" matched Instagram, the telecom and telephony
// services, the realme/OnePlus system packages and a large part of any
// Android install, and every match became a UI entry, a freezer target and an
// apps.json record with two base64 icons.
func telegramClientName(pkg, apkPath string) (string, bool) {
	if name, ok := curatedClientNames[pkg]; ok {
		return name, true
	}
	if isTelegramAPK(apkPath) {
		return humanizePackageName(pkg), true
	}
	return "", false
}

func humanizePackageName(pkg string) string {
	for _, p := range packageNames {
		if p.Pkg == pkg {
			return p.Name
		}
	}
	parts := strings.Split(pkg, ".")
	last := parts[len(parts)-1]
	if (last == "messenger" || last == "android" || last == "chat" || last == "app" || last == "client") && len(parts) > 1 {
		last = parts[len(parts)-2]
	}
	if len(last) > 0 {
		return strings.ToUpper(last[:1]) + last[1:]
	}
	return pkg
}

func isTelegramAPK(apkPath string) bool {
	if apkPath == "" {
		return false
	}
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return false
	}
	defer zr.Close()

	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		if strings.Contains(name, "libtmessages") ||
			strings.Contains(name, "libtgnet") ||
			strings.Contains(name, "libtdjson") ||
			strings.Contains(name, "libtdjni") ||
			strings.Contains(name, "libtelegram") {
			return true
		}
	}
	return false
}

func parseProcNetTCPIP(hexAddr string) (netip.Addr, uint16, bool) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 || len(parts[1]) != 4 {
		return netip.Addr{}, 0, false
	}
	portNum, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	// /proc/net/tcp stores IPv4 as little-endian 32-bit uint (8 hex digits)
	if len(parts[0]) == 8 {
		ipNum, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		b0 := byte(ipNum & 0xff)
		b1 := byte((ipNum >> 8) & 0xff)
		b2 := byte((ipNum >> 16) & 0xff)
		b3 := byte((ipNum >> 24) & 0xff)
		addr := netip.AddrFrom4([4]byte{b0, b1, b2, b3})
		return addr, uint16(portNum), true
	}
	// /proc/net/tcp6 stores IPv6 as four 32-bit little-endian words (32 hex digits)
	if len(parts[0]) == 32 {
		var b [16]byte
		for i := 0; i < 4; i++ {
			wordHex := parts[0][i*8 : (i+1)*8]
			w, err := strconv.ParseUint(wordHex, 16, 32)
			if err != nil {
				return netip.Addr{}, 0, false
			}
			b[i*4] = byte(w & 0xff)
			b[i*4+1] = byte((w >> 8) & 0xff)
			b[i*4+2] = byte((w >> 16) & 0xff)
			b[i*4+3] = byte((w >> 24) & 0xff)
		}
		addr := netip.AddrFrom16(b).Unmap()
		return addr, uint16(portNum), true
	}
	return netip.Addr{}, 0, false
}

func parseProcNetTCPContent(content string) []int {
	seen := map[int]bool{}
	var uids []int
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		st := fields[3]
		// 01 = ESTABLISHED, 02 = SYN_SENT, 03 = SYN_RECV
		if st != "01" && st != "02" && st != "03" {
			continue
		}
		addr, _, ok := parseProcNetTCPIP(fields[2])
		if !ok || !isTelegramAggregate(addr) {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err == nil && uid > 0 && !seen[uid] {
			seen[uid] = true
			uids = append(uids, uid)
		}
	}
	return uids
}

func scanActiveTelegramSockets() []int {
	if !isAndroidRuntime() && runtime.GOOS != "linux" {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	for _, procPath := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(procPath)
		if err != nil {
			continue
		}
		for _, uid := range parseProcNetTCPContent(string(data)) {
			if !seen[uid] {
				seen[uid] = true
				out = append(out, uid)
			}
		}
	}
	return out
}

func resolveUIDToPackage(uid int) string {
	// 1. Try reading /data/system/packages.list on rooted Android
	if b, err := os.ReadFile("/data/system/packages.list"); err == nil {
		target := strconv.Itoa(uid)
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == target {
				return fields[0]
			}
		}
	}
	// 2. Try inspecting running processes in /proc
	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, de := range entries {
			if !de.IsDir() {
				continue
			}
			pid, e := strconv.Atoi(de.Name())
			if e != nil || pid <= 1 {
				continue
			}
			puid, ok := processUID(pid)
			if ok && puid == uid {
				if cmd, err := os.ReadFile(filepath.Join("/proc", de.Name(), "cmdline")); err == nil {
					cmdline := strings.SplitN(string(cmd), "\x00", 2)[0]
					cmdline = strings.TrimSpace(cmdline)
					if cmdline != "" && !strings.HasPrefix(cmdline, "/") {
						pkg := strings.Split(cmdline, ":")[0]
						return pkg
					}
				}
			}
		}
	}
	// 3. Fallback to pm / cmd
	for _, cmd := range [][]string{{"cmd", "package", "list", "packages", "-U"}, {"pm", "list", "packages", "-U"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			if pkg := packageFromPMListing(string(out), uid); pkg != "" {
				return pkg
			}
		}
	}
	return ""
}

// packageFromPMListing returns the package that owns uid in
// `pm list packages -U` output. The uid is compared as a whole field: looking
// for it as a substring made "uid:10234" match the line of uid:102345 and
// report another app's package name as the detected client.
func packageFromPMListing(out string, uid int) string {
	target := "uid:" + strconv.Itoa(uid)
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields[1:] {
			if field == target {
				return strings.TrimPrefix(fields[0], "package:")
			}
		}
	}
	return ""
}

// rejectedLiveUIDs remembers UIDs that a live-traffic probe showed not to be
// Telegram clients, so the watchdog's 30 second tick does not resolve and
// open the same APK over and over.
var rejectedLiveUIDs = map[int]bool{}

func discoverActiveTelegramClients() {
	activeUIDs := scanActiveTelegramSockets()
	if len(activeUIDs) == 0 {
		return
	}
	appCacheMu.Lock()
	defer appCacheMu.Unlock()

	known := map[int]bool{}
	for _, u := range uidCache {
		known[u] = true
	}

	dirty := false
	for _, uid := range activeUIDs {
		if known[uid] || rejectedLiveUIDs[uid] {
			continue
		}
		pkg := resolveUIDToPackage(uid)
		if pkg == "" {
			rejectedLiveUIDs[uid] = true
			continue
		}
		apkPath := findPackageAPK(pkg)
		name, wanted := telegramClientName(pkg, apkPath)
		if !wanted {
			// Something else in this UID's traffic reached a Telegram address
			// — a browser on t.me, a mail checker. Not a client, and inventing
			// "unknown.telegram.uidN" for it only grew apps.json and the
			// base64 icons carried in every status write.
			rejectedLiveUIDs[uid] = true
			continue
		}
		normalIco, monetIco := extractAPKIcons(apkPath)
		appCache = append(appCache, App{Name: name, Pkg: pkg, UID: uid, IconNormal: normalIco, IconMonet: monetIco})
		uidCache = append(uidCache, uid)
		known[uid] = true
		dirty = true
		logf("detected Telegram client by live traffic: %s (uid=%d)", pkg, uid)
	}
	if dirty {
		saveCachedApps(appCache)
	}
}

// pmUIDRe parses the uid field of `pm list packages -U` output.
var (
	pmUIDRe         = regexp.MustCompile(`uid:(\d+)`)
	dumpsysUserIdRe = regexp.MustCompile(`userId=(\d+)`)
	dumpsysAppIdRe  = regexp.MustCompile(`appId=(\d+)`)
)

func packageUID(pkg string) int {
	for _, cmd := range [][]string{{"cmd", "package", "list", "packages", "-U", pkg}, {"pm", "list", "packages", "-U", pkg}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			m := pmUIDRe.FindSubmatch(out)
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
	for _, re := range []*regexp.Regexp{dumpsysUserIdRe, dumpsysAppIdRe} {
		m := re.FindSubmatch(out)
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

// pmPackage is one entry of a package manager listing.
type pmPackage struct {
	pkg     string
	uid     int
	apkPath string
}

// parsePMPackagesListing reads both shapes of `pm list packages`:
//
//	package:com.example.fork uid:10234
//	/data/app/~~abcd==/com.example.fork-EF12==/base.apk=com.example.fork uid:10234
//
// The -f form carries the APK path, which is what the scan needs to prove a
// package is a Telegram client. Installed paths contain '=' themselves, so
// the package name starts after the last one.
func parsePMPackagesListing(out string) []pmPackage {
	var res []pmPackage
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		var rest, apkPath string
		if strings.HasPrefix(line, "package:") {
			rest = strings.TrimPrefix(line, "package:")
		} else {
			sep := strings.LastIndex(line, "=")
			if sep < 0 {
				continue
			}
			apkPath = line[:sep]
			rest = line[sep+1:]
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		uid := 0
		for _, field := range fields[1:] {
			if m := pmUIDRe.FindStringSubmatch(field); len(m) == 2 {
				uid, _ = strconv.Atoi(m[1])
			}
		}
		if uid <= 0 {
			continue
		}
		res = append(res, pmPackage{pkg: fields[0], uid: uid, apkPath: apkPath})
	}
	return res
}

func discoverApps() ([]App, []int) {
	var apps []App
	var uids []int
	seen := map[int]bool{}
	// A single listing per form. With -f the APK path comes out of the listing
	// itself, so the scan stopped shelling out to `pm path` once for every
	// installed package - several hundred subprocesses on a phone.
	for _, cmd := range [][]string{
		{"cmd", "package", "list", "packages", "-f", "-U"},
		{"pm", "list", "packages", "-f", "-U"},
		{"cmd", "package", "list", "packages", "-U"},
		{"pm", "list", "packages", "-U"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err != nil {
			continue
		}
		for _, entry := range parsePMPackagesListing(string(out)) {
			if seen[entry.uid] {
				continue
			}
			apkPath := entry.apkPath
			if apkPath == "" {
				// This pm build or listing form carried no paths: resolve the
				// path per package instead.
				apkPath = findPackageAPK(entry.pkg)
			}
			name, wanted := telegramClientName(entry.pkg, apkPath)
			if !wanted {
				continue
			}
			normalIco, monetIco := extractAPKIcons(apkPath)
			apps = append(apps, App{Name: name, Pkg: entry.pkg, UID: entry.uid, IconNormal: normalIco, IconMonet: monetIco})
			uids = append(uids, entry.uid)
			seen[entry.uid] = true
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
	kept := apps[:0]
	for _, a := range apps {
		// Older builds invented a package name whenever a live-traffic UID
		// could not be resolved. Those are not clients.
		if strings.HasPrefix(a.Pkg, "unknown.telegram.uid") {
			continue
		}
		kept = append(kept, a)
		if a.UID > 0 && !seen[a.UID] {
			uids = append(uids, a.UID)
			seen[a.UID] = true
		}
	}
	return kept, uids
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

// discoverMu serializes full package scans: a cold-start scan takes seconds
// (hundreds of pm/cmd subprocesses and APK opens), and it must never run
// under appCacheMu — watchdog and writeStatus would otherwise block on every
// 5s tick while the scan holds the lock.
var discoverMu sync.Mutex

func installedApps() ([]App, []int) {
	// Fast path: serve a copy of the warm cache without scanning.
	appCacheMu.Lock()
	if len(appCache) > 0 {
		apps, uids := append([]App(nil), appCache...), append([]int(nil), uidCache...)
		appCacheMu.Unlock()
		return apps, uids
	}
	appCacheMu.Unlock()

	discoverMu.Lock()
	defer discoverMu.Unlock()

	// Another caller may have completed the scan while we waited for it.
	appCacheMu.Lock()
	if len(appCache) > 0 {
		apps, uids := append([]App(nil), appCache...), append([]int(nil), uidCache...)
		appCacheMu.Unlock()
		return apps, uids
	}
	appCacheMu.Unlock()

	apps, uids := loadCachedApps()
	if len(apps) == 0 {
		apps, uids = discoverApps()
		if len(apps) > 0 {
			saveCachedApps(apps)
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

	appCacheMu.Lock()
	appCache, uidCache = apps, uids
	appCacheMu.Unlock()

	return append([]App(nil), apps...), append([]int(nil), uids...)
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

// telegramV6 lists the broad IPv6 aggregates handed to ip6tables. It is the
// single source for telegramV6Prefixes (the SOCKS/transparency checks); the
// finer telegramV6Subnets table refines some of these aggregates into per-DC
// /48-/64 mappings for dcFor and is deliberately kept separate.
var telegramV6 = []string{
	"2001:b28::/32",
	"2001:67c:4e8::/48",
	"2a0a:f280::/32",
	"2001:b88::/32", // legacy compatibility alias
}

var telegramV6Prefixes = func() []netip.Prefix {
	out := make([]netip.Prefix, len(telegramV6))
	for i, c := range telegramV6 {
		out[i] = netip.MustParsePrefix(c)
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

// deleteChainJumps removes the jumps an earlier run installed on OUTPUT: the
// global one, the root-excluding one and the per-UID ones. Each loop repeats
// until iptables reports nothing left to delete, which clears rules from every
// version this project has shipped before a new mode is installed.
func deleteChainJumps(bin string, uids []int, chain string) {
	for i := 0; i < 16; i++ {
		if runCmd(bin, "-t", "nat", "-D", "OUTPUT", "-j", chain) != nil {
			break
		}
	}
	for i := 0; i < 16; i++ {
		if runCmd(bin, "-t", "nat", "-D", "OUTPUT", "-m", "owner", "!", "--uid-owner", "0", "-j", chain) != nil {
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
}

func iptSetup(bin string, uids []int, cidrs []string, chain string, family string) error {
	if bin == "" {
		return fmt.Errorf("%s is missing", family)
	}
	// Remove both previous global, root-excluding and UID-scoped jumps before
	// selecting a mode.
	deleteChainJumps(bin, uids, chain)
	_ = runCmd(bin, "-t", "nat", "-F", chain)
	if err := runCmd(bin, "-t", "nat", "-N", chain); err != nil { // likely already exists
		if e := runCmd(bin, "-t", "nat", "-F", chain); e != nil {
			return fmt.Errorf("failed to create chain %s: %w", chain, err)
		}
	}
	// 1. Root exclusion inside chain: the daemon's own WSS and direct dials to Telegram
	// must never be looped back into its listener.
	_ = runCmd(bin, "-t", "nat", "-A", chain, "-m", "owner", "--uid-owner", "0", "-j", "RETURN")

	// 2. Telegram destination redirects
	for _, cidr := range cidrs {
		if e := runCmd(bin, "-t", "nat", "-A", chain, "-p", "tcp", "-d", cidr, "-j", "REDIRECT", "--to-ports", strconv.Itoa(defaultPort)); e != nil {
			logf("rule %s skipped: %v", cidr, e)
		}
	}
	// 3. Universal non-root redirection: every local TCP flow to a Telegram DC
	// aggregate is redirected. This ensures 100% compatibility with all Telegram
	// clients, mods, and clones regardless of package name.
	if err := runCmd(bin, "-t", "nat", "-I", "OUTPUT", "1", "-m", "owner", "!", "--uid-owner", "0", "-j", chain); err == nil {
		return nil
	}
	return runCmd(bin, "-t", "nat", "-I", "OUTPUT", "1", "-j", chain)
}
func iptCleanup(bin string, uids []int, chain string) {
	if bin == "" {
		return
	}
	// Remove the previous v1.2 global jump as well as this version's UID-scoped
	// and desktop (root-excluding) jumps.
	deleteChainJumps(bin, uids, chain)
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

var workerCooldowns sync.Map // host or host:dcN -> workerCooldownState

func workerCooldownKey(host string, dc int) string {
	if dc <= 0 {
		return host
	}
	return fmt.Sprintf("%s:dc%d", host, dc)
}

func isWorkerInCooldown(host string, optDC ...int) bool {
	dc := 0
	if len(optDC) > 0 {
		dc = optDC[0]
	}
	now := time.Now()
	if dc > 0 {
		k := workerCooldownKey(host, dc)
		if v, ok := workerCooldowns.Load(k); ok {
			cd := v.(workerCooldownState)
			if now.Before(cd.until) {
				return true
			}
			workerCooldowns.Delete(k)
		}
	}
	if v, ok := workerCooldowns.Load(host); ok {
		cd := v.(workerCooldownState)
		if now.Before(cd.until) {
			return true
		}
		workerCooldowns.Delete(host)
	}
	return false
}

func markWorkerCooldownDC(host string, dc int, retryAfter time.Duration) {
	key := host
	if dc > 0 {
		key = workerCooldownKey(host, dc)
	}
	var strikes int
	if v, ok := workerCooldowns.Load(key); ok {
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
	} else if retryAfter > 15*time.Minute {
		retryAfter = 15 * time.Minute
	}
	workerCooldowns.Store(key, workerCooldownState{
		until:   time.Now().Add(retryAfter),
		strikes: strikes,
	})
	if dc > 0 {
		logf("worker %s (DC%d): rate limited (HTTP 429/503); quarantined for %v", host, dc, retryAfter)
	} else {
		logf("worker %s: rate limited (HTTP 429/503); quarantined for %v", host, retryAfter)
	}
}

func clearWorkerCooldown(host string, optDC ...int) {
	dc := 0
	if len(optDC) > 0 {
		dc = optDC[0]
	}
	if dc > 0 {
		workerCooldowns.Delete(workerCooldownKey(host, dc))
	}
	workerCooldowns.Delete(host)
}

type learnedDCEntry struct {
	DC        int   `json:"dc"`
	IsMedia   bool  `json:"is_media"`
	UpdatedAt int64 `json:"updated_at,omitempty"`
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
	now := time.Now().Unix()
	for ip, entry := range saved {
		if entry.DC >= 1 && (entry.DC <= 5 || entry.DC == 203) {
			// Re-validate on load: a dc-learned.json written by a build
			// without the learnDC aggregate guard may hold non-Telegram
			// addresses, and the file itself has no entry cap.
			if addr, err := netip.ParseAddr(ip); err != nil || !isTelegramAggregate(addr) {
				cleaned = true
				continue
			}
			if dcInitContradictsKnownIP(ip, entry.DC) {
				cleaned = true
				continue
			}
			if entry.UpdatedAt == 0 {
				entry.UpdatedAt = now
			}
			learnedDCs.Store(ip, entry)
			count++
		}
	}
	// learnDC caps its writes at learnedDCCap; a hand-edited or legacy file
	// must not exceed that on load. Keep the freshest entries.
	if count > learnedDCCap {
		type ipEntry struct {
			ip    string
			entry learnedDCEntry
		}
		all := make([]ipEntry, 0, count)
		learnedDCs.Range(func(key, value any) bool {
			all = append(all, ipEntry{key.(string), value.(learnedDCEntry)})
			return true
		})
		sort.Slice(all, func(i, j int) bool { return all[i].entry.UpdatedAt > all[j].entry.UpdatedAt })
		for _, e := range all[learnedDCCap:] {
			learnedDCs.Delete(e.ip)
			cleaned = true
		}
		count = learnedDCCap
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
		if err := os.Rename(tmp, dst); err != nil {
			// A failed rename (AV lock, ENOSPC) must not silently drop the
			// learned map: the dirty flag stays set, so the next learnDC
			// retries the persist, and the orphaned tmp file is removed.
			logf("dc-learn: persist failed: %v", err)
			_ = os.Remove(tmp)
			return
		}
		learnedDCDirty = false
	}
}

// learnedDCCap bounds the learned IP->DC map (see learnDC); when it overflows,
// the oldest entries are evicted down to learnedDCLive.
const (
	learnedDCCap  = 256
	learnedDCLive = 192
)

func learnDC(ip string, dc int, isMedia bool) {
	if dc < 1 || (dc > 5 && dc != 203) || ip == "" {
		return
	}
	// Only genuine Telegram endpoints may enter the learned map: IPs parsed
	// out of forged inits would silently occupy the 256-entry cap and evict
	// real media endpoints once it fills up.
	if addr, err := netip.ParseAddr(ip); err != nil || !isTelegramAggregate(addr) {
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
	type dcItem struct {
		key       string
		updatedAt int64
	}
	var count int
	var items []dcItem
	learnedDCs.Range(func(k, v any) bool {
		count++
		if e, ok := v.(learnedDCEntry); ok {
			items = append(items, dcItem{key: k.(string), updatedAt: e.UpdatedAt})
		}
		return true
	})
	if count >= learnedDCCap {
		sort.Slice(items, func(i, j int) bool {
			return items[i].updatedAt < items[j].updatedAt
		})
		toDelete := count - learnedDCLive
		if toDelete > len(items) {
			toDelete = len(items)
		}
		for i := 0; i < toDelete; i++ {
			learnedDCs.Delete(items[i].key)
		}
	}
	learnedDCs.Store(ip, learnedDCEntry{DC: dc, IsMedia: isMedia, UpdatedAt: time.Now().Unix()})
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
	if redirectorSupported() {
		return ensureRedirector()
	}
	if runtime.GOOS == "windows" {
		if err := redirectorUnsupportedReason(); err != nil {
			return err
		}
	}
	apps, uids := installedApps()
	if err := iptSetup(findBin("iptables"), uids, telegramV4, "TELEWEB", "IPv4"); err != nil {
		return err
	}
	if ip6tables := findBin("ip6tables"); ip6tables != "" {
		if err := iptSetup(ip6tables, uids, telegramV6, "TELEWEB", "IPv6"); err != nil {
			// Not fatal: some kernels ship without usable ip6tables; IPv6
			// Telegram traffic (2001:b28::/32, 2a0a:f280::/32) then bypasses the WSS
			// transport undiagnosed. rulesHealthy deliberately ignores the
			// IPv6 family so the watchdog does not flap on such devices,
			// so surface the failure here and flag it for the rate-limited
			// retry instead of leaving it broken for the daemon's lifetime.
			ip6RulesFailed.Store(true)
			logf("redirect: IPv6 rules failed: %v — Telegram IPv6 will bypass WSS until a retry succeeds", err)
		}
	}
	setupCallsBypass(findBin("iptables"))
	setupCallsBypass(findBin("ip6tables"))
	if len(apps) > 0 {
		logf("redirection enabled; apps: %s (+ universal package-agnostic scope)", appNames(apps))
	} else {
		logf("redirection enabled; package-agnostic universal scope=all local TCP to Telegram DC ranges")
	}
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
	if redirectorSupported() {
		return
	}
	_, uids := installedApps()
	iptCleanup(findBin("iptables"), uids, "TELEWEB")
	// Remove the previous release's IPv6 chain as well: setupRules installs
	// TELEWEB into ip6tables whenever ip6tables exists, so cleanup must not
	// leave a stale chain behind.
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
	if !isAndroidRuntime() {
		// Desktop systemd/service managers already handle restarts and OOM
		// policy; Android cgroup/oom plumbing would only add log noise.
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

// protectTargetAppProcesses attempts to keep Telegram client processes
// out of Android's cached-app freezer, regardless of package name.
func protectTargetAppProcesses() {
	if !isAndroidRuntime() {
		return
	}
	apps, uids := installedApps()
	if len(apps) == 0 && len(uids) == 0 {
		return
	}
	uidSet := map[int]bool{}
	for _, u := range uids {
		uidSet[u] = true
	}
	for _, a := range apps {
		if a.UID > 0 {
			uidSet[a.UID] = true
		}
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
		uid, ok := processUID(pid)
		if !ok || !uidSet[uid] {
			continue
		}
		protectAppPID(pid)
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
		// Platforms without procfs (Windows): fall back to a liveness check so
		// watchdogAlive/stopWatchdog keep working with just the PID file.
		return isPidAlive(pid)
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

func daemonHealthy() bool {
	if !pidAlive() {
		return false
	}
	if b, e := os.ReadFile(path("tgws.pid")); e == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid == os.Getpid() {
			return true
		}
	}
	// If the daemon wrote a fresh status snapshot within the last 5s, it is
	// actively executing its loop; avoid an unnecessary TCP probe.
	if st, err := os.Stat(path("status.json")); err == nil && time.Since(st.ModTime()) < 5*time.Second {
		return true
	}
	return serverListening()
}

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
	if redirectorSupported() {
		return redirectorHealthy()
	}
	bin := findBin("iptables")
	if bin == "" {
		return false
	}
	for _, cidr := range telegramV4 {
		if runCmd(bin, "-t", "nat", "-C", "TELEWEB", "-p", "tcp", "-d", cidr, "-j", "REDIRECT", "--to-ports", strconv.Itoa(defaultPort)) != nil {
			return false
		}
	}
	// Universal jump check (with root exclusion or global jump)
	if runCmd(bin, "-t", "nat", "-C", "OUTPUT", "-m", "owner", "!", "--uid-owner", "0", "-j", "TELEWEB") == nil ||
		runCmd(bin, "-t", "nat", "-C", "OUTPUT", "-j", "TELEWEB") == nil {
		return true
	}
	// UID-scoped fallback check
	_, uids := installedApps()
	if len(uids) > 0 {
		for _, uid := range uids {
			if runCmd(bin, "-t", "nat", "-C", "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "TELEWEB") != nil {
				return false
			}
		}
		return true
	}
	return false
}

// ip6RulesFailed remembers that the ip6tables setup failed at least once, so
// the watchdog can retry it: a boot-time xtables.lock contention or a
// not-yet-ready netd used to leave Telegram IPv6 bypassing the WSS transport
// for the daemon's entire lifetime.
var (
	ip6RulesFailed atomic.Bool
	ip6LastRetry   atomic.Int64
)

const ip6RetryInterval = 5 * time.Minute

// retryFailedIPv6Rules re-attempts the ip6tables setup after a failure. It is
// rate-limited so a device without a usable ip6tables does not spawn extra
// subprocesses on every watchdog tick; the flag stays set until a retry
// succeeds.
func retryFailedIPv6Rules() {
	if !ip6RulesFailed.Load() {
		return
	}
	now := time.Now().Unix()
	if last := ip6LastRetry.Load(); last != 0 && now-last < int64(ip6RetryInterval/time.Second) {
		return
	}
	ip6LastRetry.Store(now)
	bin := findBin("ip6tables")
	if bin == "" {
		// Device has no ip6tables at all: stay quiet, the flag simply
		// remains set and nothing is retried.
		return
	}
	_, uids := installedApps()
	if err := iptSetup(bin, uids, telegramV6, "TELEWEB", "IPv6"); err != nil {
		logf("redirect: IPv6 rules retry failed: %v", err)
		return
	}
	setupCallsBypass(bin)
	ip6RulesFailed.Store(false)
	logf("redirect: IPv6 rules restored on retry; Telegram IPv6 is back on the WSS transport")
}

func watchdog() {
	ensureDir()
	pid := os.Getpid()
	_ = os.WriteFile(path("watchdog.pid"), []byte(strconv.Itoa(pid)+"\n"), 0600)
	protectProcess(pid)
	discoverActiveTelegramClients()
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
		if tickCount%20 == 0 {
			logf("watchdog: heartbeat enabled=%t daemon_ok=%t rules_ok=%t; daemon{%s}", readEnabled(), daemonHealthy(), rulesHealthy(), procSummary(readPIDFile("tgws.pid")))
		}
		if !readEnabled() {
			continue
		}
		protectProcess(pid)
		discoverActiveTelegramClients()
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
		retryFailedIPv6Rules()
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
		updateModuleDescription("status: disabled ❌")
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
	if redirectorSupported() {
		stopRedirector()
	}
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

// fillGCStats overlays this process's GC telemetry on the snapshot. During the
// on-device CPU incident these numbers separate a GC death spiral (gcNum
// climbing fast, gcCpuPercent far above the runtime's 25% pacing target,
// heapLiveBytes pinned near the limit) from a dial storm, where the counters
// barely move while ws and fail race.
//
// runtime/metrics rather than runtime.ReadMemStats: the latter stops the world
// to take its sample, which is exactly the cost being measured here, and its
// pause bookkeeping reads back as zero on newer toolchains.
func fillGCStats(s *Status) {
	samples := []metrics.Sample{
		{Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/gc/heap/live:bytes"},
		{Name: "/gc/pauses:seconds"},
	}
	metrics.Read(samples)
	var gcCPU, totalCPU float64
	for _, sample := range samples {
		switch sample.Name {
		case "/gc/cycles/total:gc-cycles":
			s.GCNum = uint32(sample.Value.Uint64())
		case "/gc/heap/live:bytes":
			s.HeapLiveBytes = int64(sample.Value.Uint64())
		case "/cpu/classes/gc/total:cpu-seconds":
			gcCPU = sample.Value.Float64()
		case "/cpu/classes/total:cpu-seconds":
			totalCPU = sample.Value.Float64()
		case "/gc/pauses:seconds":
			// Pauses arrive bucketed, so the mean is an estimate rounded up to
			// each bucket's upper edge. The overflow bucket is ignored: a pause
			// longer than the largest measurable one is a different problem.
			h := sample.Value.Float64Histogram()
			var count uint64
			var weighted float64
			for i, c := range h.Counts {
				if c == 0 || i+1 >= len(h.Buckets) {
					continue
				}
				edge := h.Buckets[i+1]
				if math.IsInf(edge, 1) {
					continue
				}
				count += c
				weighted += float64(c) * edge
			}
			if count > 0 {
				s.GCPauseAvgMs = weighted / float64(count) * float64(time.Second/time.Millisecond)
			}
		}
	}
	if totalCPU > 0 {
		s.GCCPUPercent = gcCPU / totalCPU * 100
	}
}

// buildStatus assembles the invariant part of every status snapshot: flags
// read from the config files, the app list, the log tail and this process's
// Cloudflare telemetry. Callers overlay the live metrics on top — from
// process globals inside the daemon, or from the persisted status.json when
// a CLI process reports on a running daemon. A new status field is added
// here exactly once.
func buildStatus(apps []App) Status {
	s := Status{
		Enabled:        readEnabled(),
		Port:           defaultPort,
		Apps:           apps,
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
		Redirector:     localRedirectorHealthy(),
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
	if globalWsPool != nil {
		s.PoolHits, s.PoolMisses, s.PoolIdle = globalWsPool.Stats()
	}
	return s
}

// liveMetrics overlays this process's live counters on an already assembled
// snapshot. Every path that reports on a running daemon goes through here, so a
// new counter is added once instead of in each caller.
func liveMetrics(s *Status) {
	statsMu.Lock()
	dc := make(map[string]int, len(dcCounts))
	for k, v := range dcCounts {
		dc[k] = v
	}
	statsMu.Unlock()
	memNow, memPeak := processMemoryBytes()
	up := atomic.LoadInt64(&trafficUpBytes)
	down := atomic.LoadInt64(&trafficDownBytes)
	s.Running = true
	s.Uptime = int64(time.Since(startAt).Seconds())
	s.Active = atomic.LoadInt64(&active)
	s.WS = atomic.LoadInt64(&wsCount)
	s.Fail = atomic.LoadInt64(&failCnt)
	s.LogSuppressed = logSuppressed.Load()
	s.DC = dc
	s.MemNowBytes = memNow
	s.MemPeakBytes = memPeak
	s.TrafficUpBytes = up
	s.TrafficDownBytes = down
	s.TrafficTotalBytes = up + down
	fillGCStats(s)
}

// statusMetrics is the snapshot that gets persisted: the config flags and the
// live counters, without the app list and the log tail, which status() rebuilds
// from apps.json and the log file for the API answer.
func statusMetrics() Status {
	s := buildStatus(nil)
	// The persisted snapshot is rewritten every five seconds and its log tail
	// is never read back: status() rebuilds it from the log file for the API
	// answer. buildStatus fills Log for that answer, so drop it here.
	s.Log = ""
	liveMetrics(&s)
	return s
}

func currentStatus() Status {
	apps, _ := installedApps()
	s := buildStatus(apps)
	liveMetrics(&s)
	return s
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
		var file Status
		if json.Unmarshal(b, &file) == nil {
			s := buildStatus(apps)
			s.Running = pidAlive()
			// Live metrics come from the daemon's persisted snapshot: this
			// process may be a CLI invocation whose own counters are empty.
			s.Uptime = file.Uptime
			s.Active = file.Active
			s.WS = file.WS
			s.Fail = file.Fail
			s.DC = file.DC
			s.MemNowBytes = file.MemNowBytes
			s.MemPeakBytes = file.MemPeakBytes
			s.TrafficUpBytes = file.TrafficUpBytes
			s.TrafficDownBytes = file.TrafficDownBytes
			s.TrafficTotalBytes = file.TrafficTotalBytes
			s.GCNum = file.GCNum
			s.GCCPUPercent = file.GCCPUPercent
			s.GCPauseAvgMs = file.GCPauseAvgMs
			s.HeapLiveBytes = file.HeapLiveBytes
			if globalWsPool == nil {
				s.PoolHits, s.PoolMisses, s.PoolIdle = file.PoolHits, file.PoolMisses, file.PoolIdle
			}
			// The redirector state belongs to the daemon, not this process.
			s.Redirector = file.Redirector
			// Telemetry captured by this process (if any) is fresher than
			// the file; otherwise fall back to the persisted values.
			if s.LastCFPoP == "" {
				s.LastCFPoP = file.LastCFPoP
			}
			if s.LastCFRay == "" {
				s.LastCFRay = file.LastCFRay
			}
			return s
		}
	}
	s := buildStatus(apps)
	s.Running = pidAlive()
	s.Uptime = int64(time.Since(startAt).Seconds())
	s.Active = atomic.LoadInt64(&active)
	s.WS = atomic.LoadInt64(&wsCount)
	s.Fail = atomic.LoadInt64(&failCnt)
	s.DC = map[string]int{}
	return s
}
func writeStatus() {
	s := statusMetrics()
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
func executeAPICommand(q apiRequest) (any, error) {
	switch q.Cmd {
	case "status":
		return status(), nil
	case "resume":
		if !readEnabled() {
			return status(), nil
		}
		if err := ensureServer(); err != nil {
			return nil, err
		}
		if !waitForListener(4 * time.Second) {
			return nil, fmt.Errorf("tgws failed to listen on port %d", defaultPort)
		}
		if err := setupRules(); err != nil {
			return nil, err
		}
		protectTargetAppProcesses()
		if err := ensureWatchdog(); err != nil {
			logf("resume: failed to start watchdog: %v", err)
		}
		logf("WebUI resume: redirection rules reapplied without restarting live daemon")
		return status(), nil
	case "set", "setConfig":
		if q.Enabled != nil {
			if err := writeEnabled(*q.Enabled); err != nil {
				return nil, err
			}
			if *q.Enabled {
				if err := ensureServer(); err != nil {
					_ = writeEnabled(false)
					updateModuleDescription("status: failed ⚠️")
					return nil, err
				}
				// REDIRECT rules go in only after the listener is up, otherwise
				// a slow start would blackhole Telegram traffic into a dead port.
				if !waitForListener(4 * time.Second) {
					_ = writeEnabled(false)
					stopServer()
					updateModuleDescription("status: failed ⚠️")
					return nil, fmt.Errorf("tgws failed to listen on port %d", defaultPort)
				}
				if err := setupRules(); err != nil {
					_ = writeEnabled(false)
					cleanupRules()
					updateModuleDescription("status: failed ⚠️")
					return nil, err
				}
				protectTargetAppProcesses()
				if err := ensureWatchdog(); err != nil {
					logf("failed to start watchdog: %v", err)
				}
				updateModuleDescription(currentStatusDesc())
			} else {
				stopWatchdog()
				stopServer()
				updateModuleDescription("status: disabled ❌")
			}
		}
		if q.CFPriority != nil {
			if err := writeCFPriority(*q.CFPriority); err != nil {
				return nil, err
			}
			updateModuleDescription(currentStatusDesc())
		}
		if q.CFBalance != nil {
			if err := writeCFBalance(*q.CFBalance); err != nil {
				return nil, err
			}
		}
		if q.CustomCFDomain != nil {
			if err := writeCustomCFDomain(*q.CustomCFDomain); err != nil {
				return nil, err
			}
		}
		if q.CustomCFWorker != nil {
			if err := writeCustomCFWorker(*q.CustomCFWorker); err != nil {
				return nil, err
			}
		}
		if q.DCOverrides != nil {
			if err := writeDCOverrides(*q.DCOverrides); err != nil {
				return nil, err
			}
		}
		if q.PoolSize != nil {
			if err := writePoolSize(*q.PoolSize); err != nil {
				return nil, err
			}
		}
		if q.DoHEnabled != nil {
			if err := writeDoHEnabled(*q.DoHEnabled); err != nil {
				return nil, err
			}
		}
		if q.ForceTestDC != nil {
			if err := writeForceTestDC(*q.ForceTestDC); err != nil {
				return nil, err
			}
		}
		if q.H2MediaEnabled != nil {
			if err := writeH2MediaEnabled(*q.H2MediaEnabled); err != nil {
				return nil, err
			}
		}
		if q.DC203DirectTCP != nil {
			if err := writeDC203DirectTCP(*q.DC203DirectTCP); err != nil {
				return nil, err
			}
		}
		return status(), nil
	case "clearlogs":
		flushLogDedupe()
		for _, name := range []string{"tgws.log", "daemon.log", "supervisor.log", "watchdog.log"} {
			_ = os.Truncate(path(name), 0)
		}
		return map[string]any{"cleared": true}, nil
	default:
		return nil, fmt.Errorf("unknown command: %s", q.Cmd)
	}
}

func executeAPIPayload(arg string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		b = []byte(arg)
	}
	var q apiRequest
	if err := json.Unmarshal(b, &q); err != nil {
		return json.Marshal(map[string]any{"ok": false, "error": err.Error()})
	}
	res, err := executeAPICommand(q)
	if err != nil {
		return json.Marshal(map[string]any{"ok": false, "error": err.Error()})
	}
	return json.Marshal(map[string]any{"ok": true, "data": res})
}

func apiMain(arg string) {
	out, err := executeAPIPayload(arg)
	if err != nil {
		emitErr(err)
		return
	}
	fmt.Println(string(out))
}
func emitOK(v any) {
	b, _ := json.Marshal(map[string]any{"ok": true, "data": v})
	fmt.Println(string(b))
}
func emitErr(e error) {
	b, _ := json.Marshal(map[string]any{"ok": false, "error": e.Error()})
	fmt.Println(string(b))
}

// loopbackPprofAddr validates the TELEWEB_PPROF value and returns the address
// to bind, or "" when profiling stays off. A pprof endpoint hands out heap
// dumps and CPU profiles, so it is refused anywhere but on loopback.
func loopbackPprofAddr(raw string) string {
	if raw == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || port == "" {
		return ""
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ""
	}
	return net.JoinHostPort(ip.String(), port)
}

// maybeStartPprof serves net/http/pprof on TELEWEB_PPROF, e.g.
// TELEWEB_PPROF=127.0.0.1:6060. Off unless the variable is set; used to tell a
// GC spiral from a dial storm on the device without rebuilding.
func maybeStartPprof() {
	addr := loopbackPprofAddr(os.Getenv("TELEWEB_PPROF"))
	if addr == "" {
		if raw := os.Getenv("TELEWEB_PPROF"); raw != "" {
			logf("pprof: TELEWEB_PPROF=%q ignored: profiling only binds a loopback address", raw)
		}
		return
	}
	go func() {
		logf("pprof: listening on %s", addr)
		// Explicit timeouts: a stalled loopback client must not hold a
		// handler goroutine forever.
		srv := &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("pprof: server exited: %v", err)
		}
	}()
}

func initMemoryTuning() {
	// No forced GOMEMLIMIT: clamping the heap at 48 MB drove the GC into a
	// death spiral whenever media buffers or the socket pool pushed the live
	// heap past the limit (observed as ~220% user CPU on-device). An explicit
	// GOMEMLIMIT environment variable is still honoured by the runtime itself.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			logStack(fmt.Sprintf("FATAL panic in main: %v", r))
			os.Exit(2)
		}
	}()
	startConsole()
	initMemoryTuning()
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
				updateModuleDescription("status: disabled ❌")
				fmt.Println("TeleWEB disabled")
				return
			}
			// Start the listener before installing REDIRECT rules: rules that
			// point at a not-yet-listening port blackhole Telegram traffic.
			if e := ensureServer(); e != nil {
				logf("boot: failed to start server: %v", e)
				fmt.Fprintln(os.Stderr, e)
				updateModuleDescription("status: failed ⚠️")
				os.Exit(1)
			}
			if !waitForListener(4 * time.Second) {
				logf("boot: tgws failed to listen on port %d in time", defaultPort)
				fmt.Fprintln(os.Stderr, fmt.Sprintf("tgws failed to listen on port %d", defaultPort))
				updateModuleDescription("status: failed ⚠️")
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
				updateModuleDescription("status: failed ⚠️")
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
			updateModuleDescription("status: disabled ❌")
			fmt.Println("TeleWEB stopped")
			return
		case "watchdog":
			watchdog()
			return
		case "ensure":
			if err := ensureRuntime(); err != nil {
				logf("supervisor: %v", err)
				fmt.Fprintln(os.Stderr, err)
				updateModuleDescription("status: failed ⚠️")
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
		case "run":
			cmdRun()
			return
		case "socks":
			addr := ""
			if len(os.Args) > 2 {
				addr = os.Args[2]
			}
			cmdSocks(addr)
			return
		case "webui":
			addr := ""
			if len(os.Args) > 2 {
				addr = os.Args[2]
			}
			cmdWebUI(addr)
			return
		case "gui":
			addr := ""
			if len(os.Args) > 2 {
				addr = os.Args[2]
			}
			cmdGui(addr)
			return
		case "svc-install":
			if err := svcInstall(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "svc-uninstall":
			if err := svcUninstall(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "svc-run":
			if err := svcRun(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	if !isAndroidRuntime() {
		// Desktop double-click: launch the WebUI instead of printing usage.
		cmdGui("")
		return
	}
	fmt.Println("TeleWEB transparent WebSocket engine\ncommands: boot | ensure | status | stop | watchdog | run | socks [addr] | webui [addr] | gui [addr] | api BASE64_JSON | check | svc-install | svc-uninstall | svc-run")
}

func serve() {
	ensureDir()
	startSignalLogger()
	registerShutdownHook(func() {
		if redirectorSupported() {
			stopRedirector()
		}
		cleanupRules()
		_ = os.Remove(path("tgws.pid"))
	})
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
	maybeStartPprof()
	// Load last-known-good routes before accepting any client sockets. Otherwise
	// a burst of connections at boot can race the cache load and trigger a full scan.
	loadRouteCache()
	loadLearnedDCs()
	// Both background workers get a cancellable context so a graceful stop
	// can reach them; the pool additionally gets drained, otherwise up to
	// poolSize pre-warmed sockets and the rotation goroutine survive until
	// process death.
	workerCtx, workerStop := context.WithCancel(context.Background())
	startCFDomainsUpdater(workerCtx)
	initGlobalWsPool(workerCtx)
	if globalWsPool != nil {
		globalWsPool.Warmup([]int{1, 2, 4})
	}
	registerShutdownHook(func() {
		if globalWsPool != nil {
			globalWsPool.drainAll()
		}
		workerStop()
	})
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
	registerShutdownHook(func() { _ = ln.Close() })

	if ln6, e6 := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", defaultPort)); e6 == nil {
		defer ln6.Close()
		registerShutdownHook(func() { _ = ln6.Close() })
		go func() {
			for {
				c, err := ln6.Accept()
				if err != nil {
					if pause := acceptPause(err); pause < 0 {
						return
					} else if pause > 0 {
						time.Sleep(pause)
					}
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
		}()
		logf("local proxy listening on [::1]:%d; IPv6 ready", defaultPort)
	}
	go selfDialJanitor()
	if redirectorSupported() {
		if err := startRedirector(); err != nil {
			logf("redirector: failed to start: %v", err)
		} else {
			defer stopRedirector()
		}
	}
	logf("local proxy listening on 127.0.0.1:%d; %s; go=%s", defaultPort, procSummary(os.Getpid()), runtimeVersion())
	writeStatus()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			writeStatus()
		}
	}()
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			// When there are no active flows, return unused heap pages to OS.
			// This prevents RSS from lingering at peak watermarks on legacy Android kernels.
			if atomic.LoadInt64(&active) == 0 {
				debug.FreeOSMemory()
			}
		}
	}()
	for {
		c, e := ln.Accept()
		if e != nil {
			// EMFILE/ENFILE return immediately and would spin the CPU at
			// 100%; pause briefly instead. A closed listener stops the loop.
			if pause := acceptPause(e); pause < 0 {
				return
			} else if pause > 0 {
				logf("accept: %v; retrying in %s", e, pause)
				time.Sleep(pause)
			}
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

	// sharedIngressIPs are endpoints that appear in more than one DC's
	// candidate list. 149.154.174.100 is listed for both DC1 and DC3, so for
	// them the destination IP says nothing authoritative about the DC and the
	// tag parsed from the init header must win (a DC3 session to that ingress
	// used to be re-labelled DC1 and rejected by the far side).
	sharedIngressIPs = func() map[string]bool {
		count := map[string]int{}
		for _, spec := range dcSpecs {
			for _, ip := range spec.candidates {
				count[ip]++
			}
		}
		shared := make(map[string]bool)
		for ip, n := range count {
			if n > 1 {
				shared[ip] = true
			}
		}
		return shared
	}()

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

	telegramV6Subnets = []telegramSubnet{
		{prefix: netip.MustParsePrefix("2001:b28:f23d:f001::/64"), dc: 1},
		{prefix: netip.MustParsePrefix("2001:67c:4e8:f002::/64"), dc: 2},
		{prefix: netip.MustParsePrefix("2001:b28:f23d:f003::/64"), dc: 3},
		{prefix: netip.MustParsePrefix("2001:67c:4e8:f004::/64"), dc: 4},
		{prefix: netip.MustParsePrefix("2001:b28:f23f:f005::/64"), dc: 5},
		{prefix: netip.MustParsePrefix("2001:b28:f23d::/48"), dc: 1},
		{prefix: netip.MustParsePrefix("2001:b28:f23f::/48"), dc: 5},
		{prefix: netip.MustParsePrefix("2001:b28:f23c::/48"), dc: 1},
		{prefix: netip.MustParsePrefix("2001:67c:4e8::/48"), dc: 2},
		{prefix: netip.MustParsePrefix("2001:b28::/32"), dc: 2},
		{prefix: netip.MustParsePrefix("2a0a:f280::/32"), dc: 2},
		// Legacy compatibility aliases for tests
		{prefix: netip.MustParsePrefix("2001:b88:0::/48"), dc: 1},
		{prefix: netip.MustParsePrefix("2001:b88:2::/48"), dc: 3},
		{prefix: netip.MustParsePrefix("2001:b88:3::/48"), dc: 5},
		{prefix: netip.MustParsePrefix("2001:b88::/32"), dc: 2},
	}
)

type telegramSubnet struct {
	prefix netip.Prefix
	dc     int
}

// dcInitContradictsKnownIP reports whether a DC tag parsed from the MTProto
// init has to be discarded as random CTR keystream noise. Only an
// unambiguous single-DC endpoint may override the tag; for a shared ingress
// the tag is the only real signal.
func dcInitContradictsKnownIP(ip string, dc int) bool {
	if sharedIngressIPs[ip] {
		return false
	}
	known := knownDCMap[ip]
	return known != 0 && known != dc
}

func dcFor(ip netip.Addr) int {
	// SO_ORIGINAL_DST may yield IPv4-mapped IPv6 addresses such as
	// ::ffff:149.154.167.51. Normalize these before IPv4 DC matching.
	ip = ip.Unmap()
	if !ip.Is4() {
		if dc, _, ok := lookupLearnedDC(ip.String()); ok {
			return dc
		}
		for _, sub := range telegramV6Subnets {
			if sub.dc != 0 && sub.prefix.Contains(ip) {
				return sub.dc
			}
		}
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

var errNoOriginalDst = errors.New("no intercepted flow mapping for this socket")

func isNeutralError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, errNoOriginalDst) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "context canceled")
}

func handleClient(c net.Conn) {
	setConnSockOpts(c)
	orig, err := originalDestination(c)
	if err != nil {
		if !isNeutralError(err) {
			atomic.AddInt64(&failCnt, 1)
			logf("failed to determine original destination: %v", err)
		}
		_ = c.Close()
		return
	}
	serveConn(c, orig)
}

// serveConn runs the MTProto-over-WSS pipeline for an established client
// socket with a known original destination (transparent redirect or SOCKS5).
// acceptPause decides how an accept loop reacts to Accept() returning an
// error. A closed listener (-1) means the loop must stop; a transient failure
// such as EMFILE/ENFILE returns immediately and would otherwise busy-spin the
// CPU, so the loop pauses briefly before retrying; anything else retries at
// once (0).
func acceptPause(err error) time.Duration {
	if err == nil {
		return 0
	}
	if errors.Is(err, net.ErrClosed) {
		return -1
	}
	return 50 * time.Millisecond
}

func serveConn(c net.Conn, orig netip.AddrPort) {
	id := atomic.AddInt64(&connSeq, 1)
	atomic.AddInt64(&active, 1)
	defer atomic.AddInt64(&active, -1)
	defer c.Close()
	setConnSockOpts(c)

	// Read the obfuscated MTProto init before selecting the WSS frontend. Its
	// decrypted DC index is signed: negative values identify media-only DC
	// connections. This avoids guessing DC/media from overlapping IP pools.
	init := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadFull(c, init)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if !isNeutralError(err) {
			atomic.AddInt64(&failCnt, 1)
			logf("conn #%d %s: failed to read MTProto init: %v", id, orig, err)
		}
		return
	}
	dc, isMedia, parsed := parseMTProtoDC(init)
	// testDCRouting scopes the WebUI force_test_dc toggle to DCs that actually
	// define a test endpoint (DC1-DC3). DC4/DC5 have none: marking them "test"
	// removed every Cloudflare front and left zero routes (28.10 incident).
	isTestDC := testDCRouting(dc, forceTestDCCached(), dc >= 10000)
	if dc >= 10000 {
		dc -= 10000
	}
	if parsed {
		// If the destination IP is an authoritative known Telegram endpoint,
		// check if parsed DC contradicts it. In direct MTProto connections,
		// bytes 60..62 of init are random CTR keystream padding. If random
		// bytes happen to form a valid DC tag that differs from the target IP's
		// DC, it is random keystream noise and MUST NOT be trusted.
		if dcInitContradictsKnownIP(orig.Addr().String(), dc) {
			logf("conn #%d %s: ignoring random CTR noise in init (parsed DC%d, known DC%d)", id, orig, dc, knownDCMap[orig.Addr().String()])
			parsed = false
		}
	}
	if parsed {
		if !isTestDC {
			learnDC(orig.Addr().String(), dc, isMedia)
		}
	} else {
		if isCDN203IP(orig.Addr()) {
			// Unknown/unparseable transport to a CDN203 address: pass it
			// through verbatim instead of guessing a DC from the IP (the
			// 91.105.192.0/23 aggregate maps to DC2 in dcFor, which would
			// feed non-MTProto garbage into the WSS path).
			handleCDN203(c, orig, init, id)
			return
		}
		if testDC, ok := knownTestDCMap[orig.Addr().String()]; ok {
			dc = testDC
			isTestDC = true
		} else {
			dc = dcFor(orig.Addr())
		}
		isMedia = mediaForIP(orig.Addr())
		logf("conn #%d %s: DC not recognized in init, fallback by IP -> DC%d (test=%t) media=%t", id, orig, dc, isTestDC, isMedia)
	}
	if cdn203Dispatch(orig, dc) {
		handleCDN203(c, orig, init, id)
		return
	}
	if dc == 203 {
		// DC203 in the init marks a CDN203 media session. A DC203 tag aimed
		// at a destination outside the CDN203 aggregate means the client
		// forged the tag to obtain a raw TCP tunnel to an arbitrary host.
		atomic.AddInt64(&failCnt, 1)
		logf("conn #%d %s: refusing forged CDN203 for non-Telegram dst", id, orig)
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

// cdn203Prefix is the CDN203 aggregate from telegramSubnets (91.105.192.0/23).
var cdn203Prefix = netip.MustParsePrefix("91.105.192.0/23")

func isCDN203IP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Is4() && (cdn203Prefix.Contains(ip) || ip.String() == cdn203IP)
}

// cdn203Dispatch reports whether a connection must take the CDN203 path: the
// client dialed the dedicated CDN203 endpoint, or sent a DC203 init tag while
// aiming at an address inside the CDN203 aggregate. A DC203 tag combined with
// a destination outside the aggregate is a forgery (open-proxy attempt) and
// must be refused by the caller.
func cdn203Dispatch(orig netip.AddrPort, dc int) bool {
	if orig.Addr().String() == cdn203IP {
		return true
	}
	return dc == 203 && isCDN203IP(orig.Addr())
}

// failCache is a negative cache of destinations whose direct dial recently
// failed. When an endpoint is known-unreachable (an ISP blocking the CDN
// range, or DPI filtering direct Telegram IPs), client connections are failed
// fast instead of piling up dozens of parallel dial timeouts from churning
// clients. cdn203Fails and directDialFails previously carried two verbatim
// copies of this machinery; they are instances of the same thing.
type failCache struct {
	mu      sync.Mutex
	m       map[string]time.Time
	backoff time.Duration
}

func newFailCache(backoff time.Duration) *failCache {
	return &failCache{m: map[string]time.Time{}, backoff: backoff}
}

func (fc *failCache) blockedRecently(key string) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	t, ok := fc.m[key]
	return ok && time.Now().Before(t)
}

func (fc *failCache) markFail(key string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.m[key] = time.Now().Add(fc.backoff)
	capFailMapLocked(fc.m)
}

func (fc *failCache) markReachable(key string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	delete(fc.m, key)
}

// size reports the current entry count (diagnostics and tests).
func (fc *failCache) size() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.m)
}

// clear drops every entry (tests).
func (fc *failCache) clear() {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for k := range fc.m {
		delete(fc.m, k)
	}
}

// expireOlderThan drops entries whose negative-cache window has passed; the
// hourly sweep uses it so stale keys do not linger until overwritten.
func (fc *failCache) expireOlderThan(now time.Time) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for key, until := range fc.m {
		if until.Before(now) {
			delete(fc.m, key)
		}
	}
}

// cdn203Fails covers CDN endpoints whose direct dial recently failed.
var (
	cdn203Fails      = newFailCache(30 * time.Second)
	cdn203FailLogAt  time.Time
	cdn203FailLogged int
)

func cdn203BlockedRecently(dst string) bool { return cdn203Fails.blockedRecently(dst) }

func cdn203MarkFail(dst string) {
	cdn203Fails.markFail(dst)
	now := time.Now()
	if now.Sub(cdn203FailLogAt) >= 10*time.Second {
		until := time.Now().Add(cdn203Fails.backoff)
		logf("CDN203 %s unreachable on the direct path (%d failed dials in 10s); failing client connections fast for %s", dst, cdn203FailLogged+1, until.Format("15:04:05"))
		cdn203FailLogAt = now
		cdn203FailLogged = 0
		return
	}
	cdn203FailLogged++
}

func cdn203MarkReachable(dst string) { cdn203Fails.markReachable(dst) }

// directDialFails covers direct Telegram IP endpoints whose dial recently failed.
var directDialFails = newFailCache(60 * time.Second)

func directDialBlockedRecently(ipStr string) bool { return directDialFails.blockedRecently(ipStr) }

func directDialMarkFail(ipStr string) { directDialFails.markFail(ipStr) }

func directDialMarkReachable(ipStr string) { directDialFails.markReachable(ipStr) }

func handleCDN203(c net.Conn, orig netip.AddrPort, init []byte, id int64) {
	statsMu.Lock()
	dcCounts["203"]++
	statsMu.Unlock()

	worker := customCFWorkerCached()
	if worker != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		ws, err := dialCFWorker(ctx, 203, cdn203IP, worker, false)
		cancel()
		if err == nil {
			atomic.AddInt64(&wsCount, 1)
			defer atomic.AddInt64(&wsCount, -1)
			logf("conn #%d %s -> CDN203 via Cloudflare Worker %s", id, orig, worker)
			defer ws.Close()
			pipeWSTunnel(c, ws, init, id, 203, false)
			return
		}
		logf("conn #%d CDN203: Cloudflare Worker %s did not respond: %v; falling back to direct TCP", id, worker, err)
	}

	// Dedicated native TCP pass-through to the client's original CDN
	// destination (IP and port as dialed by the client — CDN203 serves both
	// :443 and :80).
	if !dc203DirectTCPCached() {
		logf("conn #%d CDN203 direct TCP disabled by configuration", id)
		return
	}
	if !isCDN203IP(orig.Addr()) {
		// Defense in depth: a forged DC203 tag must never turn this function
		// into a raw TCP tunnel to an arbitrary destination.
		logf("conn #%d %s: refusing forged CDN203 for non-Telegram dst", id, orig)
		return
	}
	dst := net.JoinHostPort(orig.Addr().String(), strconv.Itoa(int(orig.Port())))
	if cdn203BlockedRecently(dst) {
		return
	}
	remote, err := trackedDial(context.Background(), "tcp4", dst, 5*time.Second)
	if err != nil {
		if !isNeutralError(err) {
			atomic.AddInt64(&failCnt, 1)
			cdn203MarkFail(dst)
		}
		return
	}
	cdn203MarkReachable(dst)
	defer remote.Close()
	setConnSockOpts(remote)

	if err := writeFull(remote, init); err != nil {
		logf("conn #%d CDN203 write init failed: %v", id, err)
		return
	}
	atomic.AddInt64(&trafficUpBytes, int64(len(init)))
	logf("conn #%d %s -> CDN203 (%s) via direct TCP pass-through", id, orig, dst)
	pipeTCPToTCP(c, remote, id, 203)
}

// startIdleWatchdog closes the connection through onIdle once no bytes have
// moved for the 5-minute idle limit, and stops as soon as the relay tears the
// connection down for any other reason (stopIdle is closed by closeBoth).
// Shared by pipeTCPToTCP and pipeWSTunnel, which previously carried two
// verbatim copies of this goroutine.
func startIdleWatchdog(stopIdle <-chan struct{}, lastActivity *atomic.Int64, onIdle func()) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopIdle:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, lastActivity.Load())) > 5*time.Minute {
				onIdle()
				return
			}
		}
	}
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
	go startIdleWatchdog(stopIdle, &lastActivity, func() {
		logf("conn #%d DC%d (raw TCP) closed due to idle timeout (5m)", id, dc)
		closeBoth()
	})

	// halfClose marks one direction finished. For a TCP peer that means
	// shutting down our write side, so the other direction can drain: a client
	// that half-closes after its request still gets the final reply instead of
	// an abrupt close. Peers without half-close support fall back to a full
	// close, and so does a hard error -- those kill the session either way.
	halfClose := func(dst net.Conn) {
		if tc, ok := dst.(*net.TCPConn); ok && tc.CloseWrite() == nil {
			return
		}
		closeBoth()
	}
	directionDone := func(err error, dst net.Conn) {
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			closeBoth()
			return
		}
		halfClose(dst)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bufPtr := ioBufPool.Get().(*[]byte)
		defer ioBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			nr, err := c.Read(buf)
			if nr > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if ew := writeFull(remote, buf[:nr]); ew != nil {
					closeBoth()
					return
				}
				atomic.AddInt64(&upBytes, int64(nr))
				atomic.AddInt64(&trafficUpBytes, int64(nr))
			}
			if err != nil {
				directionDone(err, remote)
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		bufPtr := ioBufPool.Get().(*[]byte)
		defer ioBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			nr, err := remote.Read(buf)
			if nr > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if ew := writeFull(c, buf[:nr]); ew != nil {
					closeBoth()
					return
				}
				atomic.AddInt64(&downBytes, int64(nr))
				atomic.AddInt64(&trafficDownBytes, int64(nr))
			}
			if err != nil {
				directionDone(err, c)
				return
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
	// A WebSocket has no half-close: once one side is done the session ends,
	// so this relay keeps the plain closeBoth semantics.
	go startIdleWatchdog(stopIdle, &lastActivity, func() {
		logf("conn #%d DC%d closed due to idle timeout (5m)", id, dc)
		closeBoth()
	})

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
			case 2:
				if len(payload) > 0 {
					_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
					if readErr = writeFull(c, payload); readErr != nil {
						logf("conn #%d DC%d write WSS->client finished: %v (up=%d down=%d)", id, dc, readErr, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
						closeBoth()
						return
					}
					_ = c.SetWriteDeadline(time.Time{})
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
	// Bootstrap list of media endpoints observed in Telegram client/proxy
	// tables: lookupLearnedDC below is empty until the first learned session,
	// so this list cannot be dropped. Authoritative static classification
	// takes precedence over the learned cache; do NOT extend it by hand when
	// an endpoint can be learned instead.
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

	// Discovery runs without holding dnsCacheMu: it spawns several getprop
	// subprocesses and reads /etc/resolv.conf, and holding the write lock here
	// stalled every systemDNSResolver lookup for seconds. A rare duplicate
	// discovery is harmless — both runs produce the same resolver list.
	out := discoverAndroidDNSServers()

	dnsCacheMu.Lock()
	dnsCacheServers = out
	dnsCacheAt = time.Now()
	dnsCacheMu.Unlock()
	return append([]string(nil), out...)
}

// discoverAndroidDNSServers probes Android's netd resolvers and the local
// resolv.conf, falling back to well-known public resolvers.
func discoverAndroidDNSServers() []string {
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
	return out
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

func systemDNSResolver() *net.Resolver {
	if isAndroidRuntime() {
		return androidDNSResolver()
	}
	return net.DefaultResolver
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
		candidates: []string{"149.154.175.50", "149.154.175.51", "149.154.175.53", "149.154.175.54", "149.154.175.55", "149.154.174.100"},
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
		candidates: []string{"149.154.175.100", "149.154.175.101", "149.154.174.100"},
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
		candidates: []string{"91.108.56.100", "91.108.56.101", "91.108.56.116", "91.108.56.126", "91.108.56.198", "149.154.171.5", "149.154.170.100"},
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

// shrinkBuffers releases oversized framer buffers once the residual data is
// small, so one large media packet does not pin megabytes for the lifetime of
// the connection.
func (f *mtprotoPacketFramer) shrinkBuffers() {
	if len(f.raw) == 0 {
		if cap(f.raw) > 128*1024 {
			f.raw = nil
			f.plain = nil
		} else {
			f.raw = f.raw[:0]
			f.plain = f.plain[:0]
		}
	} else if cap(f.raw) > 128*1024 && len(f.raw) < 32*1024 {
		newRaw := make([]byte, len(f.raw))
		copy(newRaw, f.raw)
		f.raw = newRaw

		newPlain := make([]byte, len(f.plain))
		copy(newPlain, f.plain)
		f.plain = newPlain
	}
}

// popPackets drains every complete packet currently buffered and advances the
// framer past them. It returns, per packet, both the original encrypted frame
// (with the transport length prefix, forwarded verbatim by the WSS relay) and
// the decrypted packet (same prefix, POSTed by the H2 bridge). Consumers that
// only feed the decrypted side -- the H2 bridge -- leave raw empty and get nil
// frames. This is the single framing loop shared by both transports, which
// previously carried two divergent copies.
func (f *mtprotoPacketFramer) popPackets() (frames, packets [][]byte, err error) {
	for {
		n, ready, err := f.nextPacketSize()
		if err != nil {
			return frames, packets, err
		}
		if !ready {
			return frames, packets, nil
		}
		if len(f.raw) >= n {
			frames = append(frames, f.raw[:n])
		} else {
			frames = append(frames, nil)
		}
		packets = append(packets, f.plain[:n])
		f.raw = f.raw[min(n, len(f.raw)):]
		f.plain = f.plain[n:]
		f.shrinkBuffers()
	}
}

func (f *mtprotoPacketFramer) feed(encrypted []byte, ws *wsConn) error {
	if len(encrypted) == 0 {
		return nil
	}
	prevPlain := len(f.plain)
	f.plain = append(f.plain, encrypted...)
	f.stream.XORKeyStream(f.plain[prevPlain:], encrypted)
	f.raw = append(f.raw, encrypted...)
	frames, _, err := f.popPackets()
	if err != nil {
		return err
	}
	for _, frame := range frames {
		if !f.headerSent {
			payload := make([]byte, 0, len(f.initial)+len(frame))
			payload = append(payload, f.initial...)
			payload = append(payload, frame...)
			if err := ws.writeFrame(2, payload); err != nil {
				return err
			}
			f.headerSent = true
			f.initial = nil
		} else if err := ws.writeFrame(2, frame); err != nil {
			return err
		}
	}
	return nil
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

// backgroundDialCtxKey marks dials that are not driven by a client connection
// (currently WsPool refills). Their failures say nothing about what a client
// would experience, and letting them write to the shared route-health table let
// the background refill loop quarantine every front on its own.
type backgroundDialCtxKey struct{}

func withBackgroundDial(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundDialCtxKey{}, true)
}

func isBackgroundDial(ctx context.Context) bool {
	v, _ := ctx.Value(backgroundDialCtxKey{}).(bool)
	return v
}

const (
	// serverBusyRetry is how long a front is parked after answering 5xx. The
	// public fronting fleet shares one upstream worker: when it is overloaded
	// every domain answers 503 at once, and the very same host serves the next
	// request fine. The 2026-10-28 log shows exactly that on
	// kws2.pyatdesyatodin.co.uk: 503 -> success -> 503 within three seconds.
	// A per-host 30s..30min quarantine therefore said nothing about the host,
	// but it did remove every cf candidate and left direct-only dials, which
	// are blocked on censored networks.
	serverBusyRetry = 1500 * time.Millisecond
	// frontTimeoutPark is how long a front is parked after a dial/read timeout.
	// Every front is an anycast Cloudflare edge IP, and the ISP drops those in
	// waves: in the 11:58 log forty different hosts timed out within eight
	// seconds while neighbouring IPs kept answering. That is a shared outage,
	// not a per-host verdict, so the park stays short and never escalates --
	// with the old 30s..2m cooldown a single wave parked the whole pool and the
	// module fell back to direct-only dials for minutes.
	frontTimeoutPark = 5 * time.Second
	// serverBusyLogInterval throttles the park notice: with short parks an
	// unthrottled line would fire for every host every other second.
	serverBusyLogInterval = 30 * time.Second
	// frontRetryWaitLimit bounds the pause when every front for a DC is parked.
	// It must be at least frontTimeoutPark: with a 2s ceiling a 5s timeout park
	// produced wait > cap, the pause was skipped entirely, and the candidate
	// list collapsed to direct-only dials, which are blocked on censored
	// networks. frontCandidatesForRace additionally keeps one dialable front
	// for the case where even this ceiling does not free the pool.
	frontRetryWaitLimit = frontTimeoutPark
	// frontDialReserve keeps this much of the caller's dial budget for the
	// actual dial after a parked-front pause.
	frontDialReserve = 2 * time.Second
	// routeHealthCap bounds every host-keyed health/negative-cache map, on the
	// write path (capRouteHealthLocked / capFailMapLocked) as well as in the
	// hourly sweep.
	routeHealthCap = 256
	// maxFrontsPerRace caps how many fronts a single dial attempt races. Every
	// front costs up to ~2s (DoH + DNS + dial), so an uncapped pool of twenty
	// could not finish inside the client's 12s budget: attempts ended in
	// "context deadline exceeded" instead of a verdict. A rotating slice keeps
	// each attempt bounded while successive attempts still cover the pool.
	maxFrontsPerRace = 6
)

// parkFront records a short retry window for a front without touching the
// escalation counters. Those counters belong to failures that really are
// host-specific (429/403), and a park must never shorten a longer cooldown
// already recorded for the host.
func parkFront(host string, park time.Duration, reason string, err error) {
	now := time.Now()
	routeHealthMu.Lock()
	state := routeHealth[host]
	if until := now.Add(park); until.After(state.until) {
		state.until = until
	}
	logNow := state.busyAt.IsZero() || now.Sub(state.busyAt) >= serverBusyLogInterval
	if logNow {
		state.busyAt = now
	}
	routeHealth[host] = state
	capRouteHealthLocked()
	routeHealthMu.Unlock()
	if logNow {
		logf("WSS route %s parked for %s (%s): %v", host, park, reason, err)
	}
}

// noteServerBusy handles a 5xx from the shared upstream behind every front.
func noteServerBusy(host string, err error) {
	parkFront(host, serverBusyRetry, "shared front busy", err)
}

// noteFrontUnreachable handles a dial or read timeout towards a front.
func noteFrontUnreachable(host string, err error) {
	parkFront(host, frontTimeoutPark, "front unreachable", err)
}

// shouldPenalizeRoute reports whether a dial failure may be written to the
// shared route-health table. It must not be when the failure is our own
// bookkeeping: a race that ran out of budget or was cancelled by a winning
// sibling says nothing about the route, and the pool dials speculatively.
func shouldPenalizeRoute(ctx context.Context) bool {
	return ctx.Err() == nil && !isBackgroundDial(ctx)
}

// nearestRetryFor reports the shortest remaining park time across hosts. It
// returns false as soon as one host is usable, because then the caller has a
// real candidate and must not wait at all.
func nearestRetryFor(hosts []string) (time.Duration, bool) {
	if len(hosts) == 0 {
		return 0, false
	}
	now := time.Now()
	routeHealthMu.Lock()
	defer routeHealthMu.Unlock()
	nearest := time.Duration(0)
	for _, host := range hosts {
		state, ok := routeHealth[host]
		if !ok || !now.Before(state.until) {
			return 0, false
		}
		if wait := state.until.Sub(now); nearest == 0 || wait < nearest {
			nearest = wait
		}
	}
	return nearest, nearest > 0
}

// frontsForDC expands the Cloudflare domain pool into the per-DC front hosts.
func frontsForDC(dc int) []string {
	domains := cfDomainsCached()
	hosts := make([]string, 0, len(domains))
	for _, d := range domains {
		hosts = append(hosts, frontHost(dc, d))
	}
	return hosts
}

func getDCDomainAffinity(dc int) string {
	dcDomainAffinityMu.RLock()
	defer dcDomainAffinityMu.RUnlock()
	return dcDomainAffinity[dc]
}

func setDCDomainAffinity(dc int, domain string) {
	if dc <= 0 || domain == "" {
		return
	}
	dcDomainAffinityMu.Lock()
	defer dcDomainAffinityMu.Unlock()
	dcDomainAffinity[dc] = domain
}

// clampFrontRetryWait bounds a parked-front pause by both the retry ceiling and
// the caller's remaining dial budget, always leaving room for the actual dial.
func clampFrontRetryWait(ctx context.Context, wait time.Duration) time.Duration {
	if wait > frontRetryWaitLimit {
		wait = frontRetryWaitLimit
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline) - frontDialReserve; remaining < wait {
			wait = remaining
		}
	}
	if wait < 0 {
		return 0
	}
	return wait
}

// frontCandidatesForRace returns up to max usable fronts for the DC, starting
// at a rotating offset so successive attempts still cover the whole pool while
// each individual attempt stays inside the client's dial budget.
func frontCandidatesForRace(dc int, domains []string, start, max int) []string {
	if len(domains) == 0 || max <= 0 {
		return nil
	}
	if start < 0 {
		start = 0
	}
	hosts := make([]string, 0, max)
	seen := map[string]bool{}

	// If a preferred affinity domain exists for this DC and is healthy, try it first
	if pref := getDCDomainAffinity(dc); pref != "" {
		host := frontHost(dc, pref)
		if !routeCoolingDown(host) {
			hosts = append(hosts, host)
			seen[pref] = true
		}
	}

	for i := 0; i < len(domains) && len(hosts) < max; i++ {
		domain := domains[(start+i)%len(domains)]
		if seen[domain] {
			continue
		}
		host := frontHost(dc, domain)
		if routeCoolingDown(host) {
			continue
		}
		seen[domain] = true
		hosts = append(hosts, host)
	}

	// When every front is parked (an ISP drop wave or a shared 429 answers for
	// the whole pool at once), still return one candidate. Falling through to
	// direct-only dials, which are blocked on censored networks, is strictly
	// worse than one attempt against a front whose park may have just expired.
	if len(hosts) == 0 {
		hosts = append(hosts, frontHost(dc, domains[start%len(domains)]))
	}
	return hosts
}

// frontHost is the single source of the Cloudflare front naming scheme, shared
// by candidate building and by the parked-front check.
func frontHost(dc int, domain string) string {
	return fmt.Sprintf("kws%d.%s", dc, domain)
}

// allFrontsParked reports whether every Cloudflare front for this DC is inside
// a retry window and, if so, how long until the first one frees up.
func allFrontsParked(dc int, isMedia bool) (time.Duration, bool) {
	if host, ok := cfHostCache.Load(routeKey(dc, isMedia)); ok {
		if h, ok := host.(string); ok && h != "" && !routeCoolingDown(h) {
			return 0, false
		}
	}
	return nearestRetryFor(frontsForDC(dc))
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
	capRouteHealthLocked()
	routeHealthMu.Unlock()

	h2FailsMu.Lock()
	for host, until := range h2Fails {
		if until.Before(now) {
			delete(h2Fails, host)
		}
	}
	capFailMapLocked(h2Fails)
	h2FailsMu.Unlock()

	h2SuccessMu.Lock()
	for host, until := range h2Success {
		if until.Before(now) {
			delete(h2Success, host)
		}
	}
	h2SuccessMu.Unlock()

	directDialFails.expireOlderThan(now)
	cdn203Fails.expireOlderThan(now)

	workerCooldowns.Range(func(key, val any) bool {
		if cd, ok := val.(workerCooldownState); ok {
			if now.After(cd.until) {
				workerCooldowns.Delete(key)
			}
		}
		return true
	})
}

// capRouteHealthLocked trims routeHealth to routeHealthCap, keeping the hosts
// with the longest remaining park. Callers must hold routeHealthMu. The hourly
// sweep is the primary bound; this keeps the map honest between sweeps, when a
// burst of unique hosts -- a user-edited custom worker domain among them --
// would otherwise grow it without limit until the next sweep.
func capRouteHealthLocked() {
	for len(routeHealth) > routeHealthCap {
		var oldestHost string
		var oldest time.Time
		for host, state := range routeHealth {
			if oldestHost == "" || state.until.Before(oldest) {
				oldestHost, oldest = host, state.until
			}
		}
		if oldestHost == "" {
			return
		}
		delete(routeHealth, oldestHost)
	}
}

// capFailMapLocked trims a time-keyed negative cache to routeHealthCap the
// same way; callers must hold the map's own mutex.
func capFailMapLocked(m map[string]time.Time) {
	for len(m) > routeHealthCap {
		for k := range m {
			delete(m, k)
			break
		}
	}
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
	capRouteHealthLocked()
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

// testDCRouting reports whether a connection should be routed through the
// test-DC endpoints. force_test_dc is a global WebUI toggle, but Telegram
// defines test endpoints only for DC1-DC3: applying the toggle to DC4/DC5
// (or to an unparsed/203 tag) removed every Cloudflare candidate and left zero
// routes. An explicit test tag from the init header (dc >= 10000) is honoured
// only when the target DC actually has an endpoint, for the same reason.
func testDCRouting(dc int, forceTest, explicitTest bool) bool {
	if !forceTest && !explicitTest {
		return false
	}
	return dcSpecs[dc].testIP != ""
}

func dialTelegramWS(ctx context.Context, dc int, isMedia bool, isTest bool) (*wsConn, error) {
	hosts := wsHostsForDC(dc, isMedia)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("unknown DC: %d", dc)
	}
	// A DC without a test endpoint cannot be routed in test mode at all: the
	// test branch leaves the direct-IP list empty and skips every Cloudflare
	// candidate. DC4/DC5 define no testIP, so keep production routing for them
	// instead of a guaranteed-empty candidate list.
	if isTest && dcSpecs[dc].testIP == "" {
		isTest = false
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
	resolver := systemDNSResolver()

	cfPriority := cfPriorityCached()
	cfBalance := cfBalanceCached()
	worker := customCFWorkerCached()

	// When every Cloudflare front for this DC is parked, the candidate list
	// would collapse to direct-only dials, which are blocked on censored
	// networks, so the client gets an instant close. Wait for the nearest park
	// to expire (bounded by the caller's dial budget), and
	// frontCandidatesForRace additionally keeps one dialable front for the
	// case where the whole pool is parked for longer than the budget.
	if !isTest && worker == "" {
		if wait, parked := allFrontsParked(dc, isMedia); parked && wait > 0 {
			if pause := clampFrontRetryWait(ctx, wait); pause > 0 {
				select {
				case <-time.After(pause):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
	}

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

		// 3. Fast path: cached Cloudflare route, while its stamp is fresh.
		// A stale entry is skipped so this dial re-evaluates every route;
		// the race stores the winner again with a new stamp.
		if cached, ok := cfHostCache.Load(key); ok {
			if host, ok := cached.(string); ok && host != "" && !routeCoolingDown(host) {
				if routeCacheFresh(key, host) {
					h := host
					candCached := dialCandidate{
						name: fmt.Sprintf("cf-cached (%s)", h),
						dial: func(c context.Context) (*wsConn, error) {
							return dialCFHost(c, resolver, h)
						},
					}
					candidates = append(candidates, candCached)
				} else {
					logf("DC%d media=%t cached route %s is stale; re-evaluating all routes", dc, isMedia, host)
				}
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
		dnsCtx := ctx
		if len(directIPs) > 0 {
			var dnsCancel context.CancelFunc
			dnsCtx, dnsCancel = context.WithTimeout(ctx, 350*time.Millisecond)
			defer dnsCancel()
		}
		for i, h := range hosts {
			dnsWG.Add(1)
			go func(i int, h string) {
				defer dnsWG.Done()
				if ips, err := resolver.LookupNetIP(dnsCtx, "ip4", h); err == nil {
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
		ipStr := ipAddr.String()
		if directDialBlockedRecently(ipStr) {
			continue
		}
		candDirect := dialCandidate{
			name: fmt.Sprintf("direct (%s@%s)", targetHost, ipAddr),
			dial: func(c context.Context) (*wsConn, error) {
				attemptCtx, cancel := context.WithTimeout(c, 2500*time.Millisecond)
				defer cancel()
				raw, err := trackedDial(attemptCtx, "tcp4", net.JoinHostPort(ipStr, "443"), 1200*time.Millisecond)
				if err != nil {
					directDialMarkFail(ipStr)
					return nil, err
				}
				directDialMarkReachable(ipStr)
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
		// 6. Cloudflare Fronting Domains, capped and rotating (see
		// maxFrontsPerRace): an uncapped list cannot be raced within the
		// client's dial budget, and every attempt would end in a ctx expiry
		// instead of a verdict.
		domains := cfDomainsCached()
		if len(domains) > 0 {
			start := int(atomic.AddUint64(&cfFrontSeq, 1) % uint64(len(domains)))
			for _, host := range frontCandidatesForRace(dc, domains, start, maxFrontsPerRace) {
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

	if cfBalance && len(candidates) > 1 {
		offset := int(atomic.AddUint64(&cfBalanceSeq, 1) % uint64(len(candidates)))
		rotated := make([]dialCandidate, len(candidates))
		for i := range candidates {
			rotated[i] = candidates[(offset+i)%len(candidates)]
		}
		candidates = rotated
	}

	candidates = append(candidates, deferCandidates...)

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no available routes for DC%d media=%t", dc, isMedia)
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
					parts := strings.SplitN(h, ".", 2)
					if len(parts) == 2 && parts[1] != "" {
						setDCDomainAffinity(dc, parts[1])
					}
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
	case routeRejectServer:
		// 5xx comes from the shared upstream behind every front, not from the
		// host itself: park it briefly and never escalate (see noteServerBusy).
		noteServerBusy(host, err)
		return
	case routeRejectRateLimit:
		reason = "HTTP 429 (Rate Limit)"
	case routeRejectForbidden:
		reason = "HTTP 403 (Forbidden)"
	default:
		if !isTimeout(err) && !isTimeoutText(msg) {
			return
		}
		// Every front is an anycast Cloudflare edge IP and the ISP drops those
		// in waves, so a timeout is a shared-outage signal as well: park
		// briefly, never escalate (see frontTimeoutPark).
		noteFrontUnreachable(host, err)
		return
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
	var rle *RateLimitError
	if errors.As(err, &rle) && rle.RetryAfter > 0 {
		if rle.RetryAfter > cooldown {
			cooldown = rle.RetryAfter
		}
	}
	if cooldown > 5*time.Minute {
		cooldown = 5 * time.Minute
	}
	wasCooling := now.Before(state.until)
	state.until = now.Add(cooldown)
	state.last = now
	routeHealth[host] = state
	capRouteHealthLocked()
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

const maxConcurrentCFDials = 4

var cfDialSem = make(chan struct{}, maxConcurrentCFDials)

func acquireCFDialSlot(ctx context.Context) (func(), error) {
	select {
	case cfDialSem <- struct{}{}:
		return func() { <-cfDialSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func dialCFHost(ctx context.Context, resolver *net.Resolver, host string) (*wsConn, error) {
	release, err := acquireCFDialSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

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
	for i, ip := range ips {
		if !ip.Is4() {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
		raw, e := trackedDial(attemptCtx, "tcp4", net.JoinHostPort(ip.String(), "443"), 1200*time.Millisecond)
		if e == nil {
			setConnSockOpts(raw)
			var ws *wsConn
			helloID := utls.HelloChrome_Auto
			if i%2 == 1 || readFlag("utls_firefox", false) {
				helloID = utls.HelloFirefox_Auto
			}
			ws, e = finishTelegramWS(attemptCtx, raw, host, helloID)
			if e == nil {
				cancel()
				clearRouteHealth(host)
				return ws, nil
			}
			if shouldPenalizeRoute(ctx) {
				noteRouteHTTPFailure(host, e)
			}
			_ = raw.Close()
			// A rejected route will reject the next IP the same way: stop
			// trying this host instead of burning the dial budget on it.
			if routeHTTPRejection(strings.ToLower(e.Error())) != routeRejectNone {
				cancel()
				return nil, e
			}
		} else {
			if (isTimeout(e) || isTimeoutText(e.Error())) && shouldPenalizeRoute(ctx) {
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

// tlsHandshakeForHost returns the SNI to send on the wire and whether
// certificate verification has to be skipped for this dial.
//
// The fronting-SNI override belongs to Cloudflare-fronted routes only: it is
// what lets the daemon talk to a front while disguising the SNI. Direct dials
// to Telegram endpoints and worker sessions have no use for it — and applying
// it there silently disabled certificate verification for a connection that
// needs no disguise at all.
func tlsHandshakeForHost(host string, honorFrontingSNI bool) (sni string, skipVerify bool) {
	sni = host
	if honorFrontingSNI {
		if custom := configuredFrontingSNI(); custom != "" {
			sni = custom
		}
	}
	return sni, shouldSkipTLSVerify(host, sni)
}

// verifyFrontingPeerChain is attached when a fronting-SNI override forces
// InsecureSkipVerify. The presented name deliberately differs from the dialed
// host, so uTLS's own hostname check cannot succeed — but the certificate must
// still chain to a system-trusted CA. Without this callback any self-signed
// certificate from an on-path device would terminate the WSS session.
func verifyFrontingPeerChain(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("TLS: peer sent no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("TLS: malformed peer certificate: %w", err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         getSystemRootCAs(),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("TLS: peer certificate is not anchored in the system trust store: %w", err)
	}
	return nil
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
		}
		if sc, ok := extension.(*utls.SupportedCurvesExtension); ok {
			var filtered []utls.CurveID
			for _, c := range sc.Curves {
				// Strip Post-Quantum groups (e.g. X25519Kyber768Draft00, X25519MLKEM768) that trigger TSPU blocks
				if c == utls.X25519 || c == utls.CurveP256 || c == utls.CurveP384 || c == utls.CurveP521 {
					filtered = append(filtered, c)
				}
			}
			if len(filtered) > 0 {
				sc.Curves = filtered
			}
		}
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			var filtered []utls.KeyShare
			for _, k := range ks.KeyShares {
				if k.Group == utls.X25519 || k.Group == utls.CurveP256 {
					filtered = append(filtered, k)
				}
			}
			if len(filtered) > 0 {
				ks.KeyShares = filtered
			}
		}
	}
	if !found {
		conn.Extensions = append(conn.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	return conn.BuildHandshakeState()
}

func finishTelegramWS(ctx context.Context, raw net.Conn, host string, helloIDs ...utls.ClientHelloID) (*wsConn, error) {
	return finishTLSAndUpgrade(ctx, raw, host, "/apiws", true, helloIDs...)
}

// finishTelegramWSPath performs the TLS handshake plus WebSocket upgrade for a
// direct dial to a Telegram endpoint by IP. Fronting-SNI overrides belong to
// Cloudflare-fronted hosts only: applying one here would silently disable
// certificate verification for a session that needs no disguise.
func finishTelegramWSPath(ctx context.Context, raw net.Conn, host string, path string, helloIDs ...utls.ClientHelloID) (*wsConn, error) {
	return finishTLSAndUpgrade(ctx, raw, host, path, false, helloIDs...)
}

// finishTLSAndUpgrade performs the uTLS handshake plus the WebSocket upgrade
// on an already-dialed raw connection. honorFrontingSNI switches the SNI to
// the configured fronting value, which real Telegram endpoints accept for
// CF-fronted domains; direct and worker endpoints must keep their real
// hostname (and their certificate verification).
func finishTLSAndUpgrade(ctx context.Context, raw net.Conn, host, path string, honorFrontingSNI bool, helloIDs ...utls.ClientHelloID) (*wsConn, error) {
	setConnSockOpts(raw)
	sni, skipVerify := tlsHandshakeForHost(host, honorFrontingSNI)
	uConfig := &utls.Config{
		ServerName:                  sni,
		MinVersion:                  utls.VersionTLS12,
		RootCAs:                     getSystemRootCAs(),
		InsecureSkipVerify:          skipVerify,
		NextProtos:                  []string{"http/1.1"},
		DynamicRecordSizingDisabled: true,
		CurvePreferences:            []utls.CurveID{utls.X25519, utls.CurveP256},
	}
	if skipVerify {
		// The SNI override presents a name that does not match the dialed
		// host, so uTLS's own hostname check is relaxed here -- but the peer
		// certificate is still held to the system trust store.
		uConfig.VerifyPeerCertificate = verifyFrontingPeerChain
	}
	helloID := utls.HelloChrome_Auto
	if len(helloIDs) > 0 {
		helloID = helloIDs[0]
	} else if readFlag("utls_firefox", false) {
		helloID = utls.HelloFirefox_Auto
	}
	uConn := utls.UClient(raw, uConfig, helloID)
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

func finishWorkerWS(ctx context.Context, raw net.Conn, host, path string, helloIDs ...utls.ClientHelloID) (*wsConn, error) {
	return finishTLSAndUpgrade(ctx, raw, host, path, false, helloIDs...)
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
	customPath := ""
	if slash := strings.IndexByte(host, '/'); slash != -1 {
		customPath = host[slash:]
		host = host[:slash]
	}

	if isWorkerInCooldown(host, dc) {
		return nil, fmt.Errorf("worker %s (DC%d) is in rate limit cooldown", host, dc)
	}

	// Worker handshakes go to the same Cloudflare edge as the fronts, so they
	// share cfDialSem: without this, a custom worker plus four fronts plus a
	// warm H2 pool could open far more concurrent Cloudflare handshakes than
	// the 429 budget the cap was introduced to protect.
	release, err := acquireCFDialSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	basePath := "/apiws"
	if isTest {
		basePath = "/apiws_test"
	}
	if customPath != "" {
		basePath = customPath
	}
	path := fmt.Sprintf("%s?dst=%s&dc=%d", basePath, dstIP, dc)
	if query != "" {
		path += "&" + query
	}

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
		resolver := systemDNSResolver()
		var err error
		ips, err = resolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, fmt.Errorf("worker DNS %s: %w", host, err)
		}
	}

	var lastErr error
	for i, ip := range ips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !ip.Is4() {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 3000*time.Millisecond)
		raw, e := trackedDial(attemptCtx, "tcp4", net.JoinHostPort(ip.String(), "443"), 1500*time.Millisecond)
		if e != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = e
			continue
		}
		setConnSockOpts(raw)

		helloID := utls.HelloChrome_Auto
		if i%2 == 1 || readFlag("utls_firefox", false) {
			helloID = utls.HelloFirefox_Auto
		}
		ws, e := finishWorkerWS(attemptCtx, raw, host, path, helloID)
		cancel()
		if e == nil {
			clearWorkerCooldown(host, dc)
			return ws, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var rle *RateLimitError
		if errors.As(e, &rle) {
			if shouldPenalizeRoute(ctx) {
				markWorkerCooldownDC(host, dc, rle.RetryAfter)
			}
			return nil, e
		}
		lastErr = e
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
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
	fmt.Println("DC mapping smoke test passed")
}
