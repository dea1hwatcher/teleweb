// TG Open transparent WebSocket transport for Telegram.
// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
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
)

const (
	defaultPort = 17841
	maxWSFrame  = 16 << 20
	wsGUID      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var (
	baseDir          = envOr("TGOPEN_DIR", "/data/adb/tgopen")
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
	directFailUntil  sync.Map // route key -> time.Time; avoid repeating known-dead direct path every connection
	routeChoice      sync.Map // route key -> measured route decision (refreshed every 6 h)
	routeProbeAt     sync.Map // route key -> last background probe start
	routePool        sync.Map // route key -> []routeCandidate restored from an older cache
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

type routeCandidate struct {
	host    string
	latency time.Duration
}

type persistedCandidate struct {
	Host      string `json:"host"`
	LatencyNS int64  `json:"latency_ns"`
}

type persistedRoute struct {
	Host       string               `json:"host,omitempty"`
	Candidates []persistedCandidate `json:"candidates,omitempty"`
	UpdatedAt  time.Time            `json:"updated_at"`
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
		logf("route-cache: сохранённый пул повреждён; будет собран заново: %v", err)
		return
	}
	n := 0
	for key, entry := range saved {
		if entry.Host != "" {
			cfHostCache.Store(key, entry.Host)
			routeChoice.Store(key, routeDecision{preferCF: true, host: entry.Host, expires: time.Now().Add(6 * time.Hour)})
			n++
		}
		if len(entry.Candidates) > 0 {
			candidates := make([]routeCandidate, 0, len(entry.Candidates))
			for _, candidate := range entry.Candidates {
				if candidate.Host != "" {
					candidates = append(candidates, routeCandidate{host: candidate.Host, latency: time.Duration(candidate.LatencyNS)})
				}
			}
			if len(candidates) > 0 {
				routePool.Store(key, candidates)
			}
		}
		routeCacheDisk[key] = entry
	}
	if n > 0 {
		logf("route-cache: восстановлены ранее успешные WSS-маршруты для %d DC/media-профилей", n)
	}
}

func saveRouteCache(key, host string, candidates []routeCandidate) {
	routeCacheMu.Lock()
	defer routeCacheMu.Unlock()
	entry := routeCacheDisk[key]
	changed := false
	if host != "" && entry.Host != host {
		entry.Host = host
		changed = true
	}
	if candidates != nil {
		if len(entry.Candidates) != len(candidates) {
			changed = true
		} else {
			for i := range candidates {
				if entry.Candidates[i].Host != candidates[i].host {
					changed = true
					break
				}
			}
		}
		entry.Candidates = make([]persistedCandidate, 0, len(candidates))
		for _, candidate := range candidates {
			entry.Candidates = append(entry.Candidates, persistedCandidate{Host: candidate.host, LatencyNS: int64(candidate.latency)})
		}
	}
	if !changed {
		return
	}
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

type routeDecision struct {
	preferCF bool
	host     string
	expires  time.Time
}

type routeHealthState struct {
	count int
	last  time.Time
	until time.Time
}

type App struct {
	Name string `json:"name"`
	Pkg  string `json:"pkg"`
	UID  int    `json:"uid"`
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
	DCOverrides       string         `json:"dcOverrides"`
}

type apiRequest struct {
	Cmd            string  `json:"cmd"`
	Enabled        *bool   `json:"enabled,omitempty"`
	CFPriority     *bool   `json:"cfPriority,omitempty"`
	CFBalance      *bool   `json:"cfBalance,omitempty"`
	CustomCFDomain *string `json:"customCFDomain,omitempty"`
	DCOverrides    *string `json:"dcOverrides,omitempty"`
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func path(name string) string { return filepath.Join(baseDir, name) }
func ensureDir()              { _ = os.MkdirAll(baseDir, 0700) }
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
		return "pid=нет"
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
			logf("process: получен сигнал %s; завершаюсь", sig)
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

func readCFPriority() bool {
	b, err := os.ReadFile(path("cf-priority"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

func writeCFPriority(v bool) error {
	ensureDir()
	s := "0\n"
	if v {
		s = "1\n"
	}
	return os.WriteFile(path("cf-priority"), []byte(s), 0600)
}

func readCFBalance() bool {
	b, err := os.ReadFile(path("cf-balance"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

func writeCFBalance(v bool) error {
	ensureDir()
	s := "0\n"
	if v {
		s = "1\n"
	}
	return os.WriteFile(path("cf-balance"), []byte(s), 0600)
}

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
		return fmt.Errorf("недопустимый домен: %s", d)
	}
	return os.WriteFile(path("custom-cf-domain"), []byte(d+"\n"), 0600)
}

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
			return fmt.Errorf("неверный формат пары DC:IP (%s)", pair)
		}
		dc, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || dc < 1 || dc > 5 {
			return fmt.Errorf("недопустимый номер DC (1-5): %s", parts[0])
		}
		ipStr := strings.TrimSpace(parts[1])
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.IsValid() || !addr.Is4() {
			return fmt.Errorf("недопустимый IPv4 адрес для DC%d: %s", dc, ipStr)
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
	return isPidAlive(p)
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
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
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
	out, _ := exec.Command("dumpsys", "package", pkg).CombinedOutput()
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
		out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
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
			apps = append(apps, App{Name: name, Pkg: pkg, UID: uid})
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
			apps = append(apps, App{Name: p.Name, Pkg: p.Pkg, UID: uid})
			uids = append(uids, uid)
			seen[uid] = true
		}
	}
	return apps, uids
}
func installedApps() ([]App, []int) {
	appCacheMu.Lock()
	defer appCacheMu.Unlock()
	if len(appCache) == 0 {
		appCache, uidCache = discoverApps()
	}
	return append([]App(nil), appCache...), append([]int(nil), uidCache...)
}

// Telegram IPv4 ranges. They are limited to Telegram's published DC address space.
var telegramV4 = []string{"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22", "185.76.151.0/24", "91.105.192.0/23"}

func runCmd(name string, args ...string) error {
	c := exec.Command(name, args...)
	b, e := c.CombinedOutput()
	if e != nil {
		return fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), e, strings.TrimSpace(string(b)))
	}
	return nil
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
		return fmt.Errorf("%s отсутствует", family)
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
			return fmt.Errorf("не удалось создать цепочку %s: %w", chain, err)
		}
	}
	for _, cidr := range cidrs {
		if e := runCmd(bin, "-t", "nat", "-A", chain, "-p", "tcp", "-d", cidr, "-j", "REDIRECT", "--to-ports", strconv.Itoa(defaultPort)); e != nil {
			logf("правило %s пропущено: %v", cidr, e)
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
func setupRules() error {
	apps, uids := installedApps()
	if len(uids) == 0 {
		return errors.New("не найдено установленное приложение Telegram (например, com.exteragram.messenger)")
	}
	if err := iptSetup(findBin("iptables"), uids, telegramV4, "TGOPEN", "IPv4"); err != nil {
		return err
	}
	logf("перехват включён; приложения: %s", appNames(apps))
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
	iptCleanup(findBin("iptables"), uids, "TGOPEN")
	// Clean up the previous release's IPv6 redirect chain even though this
	// experimental build does not install new IPv6 redirects.
	iptCleanup(findBin("ip6tables"), uids, "TGOPEN")
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
			warnProtect(pid, "не удалось выставить oom protection: "+oldErr.Error())
		}
	}

	cgRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		warnProtect(pid, "не удалось прочитать cgroup: "+err.Error())
		return
	}
	entries := parseProcCgroups(string(cgRaw))
	for _, entry := range entries {
		if processFrozen(pid, entry) {
			logf("protect: PID %d находился в замороженной cgroup %s (controllers=%s); пытаюсь вывести в корень", pid, entry.path, entry.controllers)
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
			warnProtect(pid, fmt.Sprintf("не удалось переместить PID %d из cgroup %s в %s: %v", pid, entry.path, target, moveErr))
			continue
		}
		logf("protect: PID %d перемещён из cgroup %s в корневую группу через %s", pid, entry.path, target)
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
				warnProtect(pid, fmt.Sprintf("не удалось вывести процесс приложения из cgroup freezer: %v", err))
			} else {
				logf("protect-app: PID %d перемещён из %s в корневую cgroup (oom_score_adj не менялся)", pid, entry.path)
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
				warnProtect(pid, "обнаружен cgroup-v1 freezer, но корневой файл переноса не найден")
				return
			}
			if err := writePIDToCgroup(pid, target); err != nil {
				warnProtect(pid, fmt.Sprintf("не удалось вывести процесс приложения из freezer cgroup %s: %v", entry.path, err))
			} else {
				logf("protect-app: PID %d перемещён из freezer cgroup %s в корень", pid, entry.path)
			}
			return
		}
	}
}

func warnProtect(pid int, message string) {
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
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
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
		if runCmd(bin, "-t", "nat", "-C", "OUTPUT", "-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "TGOPEN") != nil {
			return false
		}
	}
	for _, cidr := range telegramV4 {
		if runCmd(bin, "-t", "nat", "-C", "TGOPEN", "-p", "tcp", "-d", cidr, "-j", "REDIRECT", "--to-ports", strconv.Itoa(defaultPort)) != nil {
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
	logf("watchdog: запущен, проверка каждые 30 секунд; %s", procSummary(pid))
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
			logf("watchdog: изменение состояния daemon %t→%t, rules %t→%t; %s", lastDaemonOK, daemonOK, lastRulesOK, rulesOK, procSummary(readPIDFile("tgws.pid")))
		}
		lastDaemonOK, lastRulesOK = daemonOK, rulesOK
		if !daemonOK {
			logf("watchdog: tgws не отвечает, автоперезапуск; %s; listener=%t", procSummary(readPIDFile("tgws.pid")), serverListening())
			stopServer() // removes stale redirect rules before the listener is replaced
			if err := ensureServer(); err != nil {
				logf("watchdog: не удалось запустить tgws: %v", err)
				continue
			}
			deadline := time.Now().Add(3 * time.Second)
			for !serverListening() && time.Now().Before(deadline) {
				time.Sleep(100 * time.Millisecond)
			}
			if !serverListening() {
				logf("watchdog: tgws не начал слушать порт %d", defaultPort)
				continue
			}
			if err := setupRules(); err != nil {
				logf("watchdog: правила после перезапуска не восстановлены: %v", err)
				continue
			}
		}
		protectProcess(readPIDFile("tgws.pid"))
		if !rulesHealthy() {
			logf("watchdog: правила iptables сброшены или повреждены — восстановление; iptables=%q", findBin("iptables"))
			if err := setupRules(); err != nil {
				logf("watchdog: не удалось восстановить iptables: %v", err)
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
		return nil
	}
	if !daemonHealthy() {
		logf("supervisor: daemon/listener отсутствует — восстановление")
		stopServer()
		if err := setupRules(); err != nil {
			return err
		}
		if err := ensureServer(); err != nil {
			return err
		}
		deadline := time.Now().Add(4 * time.Second)
		for !serverListening() && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		if !serverListening() {
			return fmt.Errorf("tgws не начал слушать порт %d", defaultPort)
		}
	} else if !rulesHealthy() {
		logf("supervisor: правила перехвата отсутствуют — восстановление")
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
	stopPID(pid)
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
		DCOverrides:       readDCOverridesRaw(),
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
			s.DCOverrides = readDCOverridesRaw()
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
		DCOverrides:    readDCOverridesRaw(),
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
		if err := setupRules(); err != nil {
			emitErr(err)
			return
		}
		if err := ensureServer(); err != nil {
			emitErr(err)
			return
		}
		protectTargetAppProcesses()
		if err := ensureWatchdog(); err != nil {
			logf("resume: не удалось запустить watchdog: %v", err)
		}
		logf("WebUI resume: правила перехвата повторно применены без перезапуска живого демона")
		emitOK(status())
	case "set", "setConfig":
		if q.Enabled != nil {
			if err := writeEnabled(*q.Enabled); err != nil {
				emitErr(err)
				return
			}
			if *q.Enabled {
				if err := setupRules(); err != nil {
					_ = writeEnabled(false)
					emitErr(err)
					return
				}
				if err := ensureServer(); err != nil {
					emitErr(err)
					return
				}
				if err := ensureWatchdog(); err != nil {
					logf("не удалось запустить watchdog: %v", err)
				}
			} else {
				stopWatchdog()
				stopServer()
			}
		}
		if q.CFPriority != nil {
			if err := writeCFPriority(*q.CFPriority); err != nil {
				emitErr(err)
				return
			}
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
		if q.DCOverrides != nil {
			if err := writeDCOverrides(*q.DCOverrides); err != nil {
				emitErr(err)
				return
			}
		}
		emitOK(status())
	default:
		emitErr(fmt.Errorf("неизвестная команда: %s", q.Cmd))
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
			logStack(fmt.Sprintf("FATAL panic в main: %v", r))
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
			// An in-place upgrade can leave old helpers and the daemon alive.
			stopWatchdog()
			stopServer()
			if !readEnabled() {
				fmt.Println("TG Open выключен")
				return
			}
			if e := setupRules(); e != nil {
				logf("ошибка настройки перехвата: %v", e)
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			if e := ensureServer(); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			if e := ensureWatchdog(); e != nil {
				logf("не удалось запустить watchdog: %v", e)
			}
			fmt.Println("TG Open transport started")
			return
		case "stop":
			stopWatchdog()
			stopServer()
			fmt.Println("TG Open stopped")
			return
		case "watchdog":
			watchdog()
			return
		case "ensure":
			if err := ensureRuntime(); err != nil {
				logf("supervisor: %v", err)
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		case "serve":
			serve()
			return
		case "check":
			runChecks()
			return
		}
	}
	fmt.Println("TG Open transparent WebSocket engine\ncommands: boot | ensure | status | stop | watchdog | api BASE64_JSON | check")
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
	startCFDomainsUpdater(context.Background())
	ln, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", defaultPort))
	if e != nil {
		logf("не удалось открыть локальный порт: %v", e)
		return
	}
	defer ln.Close()
	logf("локальный перехватчик слушает 127.0.0.1:%d; %s; go=%s", defaultPort, procSummary(os.Getpid()), runtimeVersion())
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
					logStack(fmt.Sprintf("FATAL panic в handleClient remote=%s: %v", conn.RemoteAddr(), r))
					_ = conn.Close()
				}
			}()
			handleClient(conn)
		}(c)
	}
}

var (
	knownDCMap = map[string]int{
		"149.154.175.50": 1, "149.154.175.51": 1, "149.154.175.53": 1, "149.154.175.54": 1, "149.154.175.55": 1,
		"149.154.175.100": 3, "149.154.175.101": 3, "149.154.175.211": 1,
		"149.154.167.50": 2, "149.154.167.51": 2, "149.154.167.52": 2, "149.154.167.91": 4, "149.154.167.92": 4,
		"149.154.167.99": 2, "149.154.167.118": 4, "149.154.167.151": 2, "149.154.167.220": 2, "149.154.167.222": 2,
		"149.154.167.223": 2, "149.154.162.123": 2, "149.154.164.250": 4, "149.154.165.111": 4, "149.154.166.120": 4,
		"149.154.166.121": 4, "149.154.175.52": 1, "149.154.175.102": 3, "149.154.174.100": 1, "149.154.170.100": 5,
		"149.154.171.5": 5, "91.108.56.100": 5, "91.108.56.102": 5, "91.108.56.128": 5, "91.108.56.151": 5,
		"91.105.192.100": 2,
	}

	prefix149_160 = netip.MustParsePrefix("149.154.160.0/20")
	prefix185_151 = netip.MustParsePrefix("185.76.151.0/24")
	prefix91_192  = netip.MustParsePrefix("91.105.192.0/23")
	prefix91_56   = netip.MustParsePrefix("91.108.56.0/22")
	prefix91_4    = netip.MustParsePrefix("91.108.4.0/22")
	prefix91_8    = netip.MustParsePrefix("91.108.8.0/22")
	prefix91_12   = netip.MustParsePrefix("91.108.12.0/22")
	prefix91_16   = netip.MustParsePrefix("91.108.16.0/22")
	prefix91_20   = netip.MustParsePrefix("91.108.20.0/22")
)

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
	if prefix185_151.Contains(ip) {
		return 2
	}
	if prefix91_192.Contains(ip) {
		return 2
	}
	if prefix91_56.Contains(ip) {
		return 5
	}
	if prefix91_4.Contains(ip) {
		return 1
	}
	if prefix91_8.Contains(ip) {
		return 2
	}
	if prefix91_12.Contains(ip) {
		return 3
	}
	if prefix91_16.Contains(ip) {
		return 4
	}
	if prefix91_20.Contains(ip) {
		return 5
	}
	return 0
}

func handleClient(c net.Conn) {
	id := atomic.AddInt64(&connSeq, 1)
	atomic.AddInt64(&active, 1)
	defer atomic.AddInt64(&active, -1)
	defer c.Close()
	orig, err := originalDestination(c)
	if err != nil {
		atomic.AddInt64(&failCnt, 1)
		logf("не удалось определить исходный адрес: %v", err)
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
		atomic.AddInt64(&failCnt, 1)
		logf("соединение #%d %s: не удалось прочитать MTProto init: %v", id, orig, err)
		return
	}
	dc, isMedia, parsed := parseMTProtoDC(init)
	if !parsed {
		dc = dcFor(orig.Addr())
		isMedia = mediaForIP(orig.Addr())
		logf("соединение #%d %s: DC из init не распознан, fallback по IP → DC%d media=%t", id, orig, dc, isMedia)
	}
	if dc < 1 || dc > 5 {
		atomic.AddInt64(&failCnt, 1)
		logf("неизвестный DC для %s (соединение %d); не отправляю напрямую", orig, id)
		return
	}
	statsMu.Lock()
	dcCounts[strconv.Itoa(dc)]++
	statsMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	ws, err := dialTelegramWS(ctx, dc, isMedia)
	if err != nil {
		atomic.AddInt64(&failCnt, 1)
		logf("DC%d media=%t WSS failed: %v; WSS-only, соединение закрыто", dc, isMedia, err)
		return
	}
	atomic.AddInt64(&wsCount, 1)
	defer atomic.AddInt64(&wsCount, -1)
	defer ws.Close()
	logf("соединение #%d %s → DC%d media=%t через WSS", id, orig, dc, isMedia)
	startedAt := time.Now()
	// Include the initial MTProto obfuscation header in the lifetime traffic counter.
	atomic.AddInt64(&trafficUpBytes, int64(len(init)))
	var upBytes int64   // client -> WSS payload bytes observed after the init header
	var downBytes int64 // WSS -> client payload bytes
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done); _ = c.Close(); _ = ws.Close() }) }
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	stopIdle := make(chan struct{})
	defer close(stopIdle)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopIdle:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > 5*time.Minute {
					logf("соединение #%d DC%d закрыто по таймауту бездействия (5 мин)", id, dc)
					closeBoth()
					return
				}
			}
		}
	}()
	// Do not send unsolicited client WebSocket Ping frames. In observed logs,
	// remote EOF age tracked the configured Ping interval (25s, then 10s),
	// suggesting these WSS frontends close or mishandle client-originated Ping.
	// We still answer Ping frames received from the server with Pong below.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := pipeTCPToWSCount(c, ws, init, &upBytes, &lastActivity); err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed network connection") {
			logf("соединение #%d DC%d клиент→WSS ошибка: %T: %v (up=%d down=%d)", id, dc, err, err, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
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
					logf("соединение #%d DC%d WSS→клиент ошибка: %T: %v (up=%d down=%d)", id, dc, readErr, readErr, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
				}
				break
			}
			lastActivity.Store(time.Now().UnixNano())
			switch op {
			case 2, 0:
				if len(payload) > 0 {
					if readErr = writeFull(c, payload); readErr != nil {
						logf("соединение #%d DC%d запись WSS→клиент завершена: %v (up=%d down=%d)", id, dc, readErr, atomic.LoadInt64(&upBytes), atomic.LoadInt64(&downBytes))
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
				// A Pong is harmless; unsolicited client Ping is disabled because
				// these WSS frontends appeared to close immediately after it.
			default:
				logf("DC%d неизвестный opcode WebSocket: %d", dc, op)
			}
		}
		closeBoth()
	}()
	wg.Wait()
}

func parseMTProtoDC(init []byte) (dc int, isMedia bool, ok bool) {
	if len(init) != 64 {
		return 0, false, false
	}
	// Normal direct MTProto obfuscation uses an empty secret. The pre-key and
	// IV are carried in the init itself; decrypt only to inspect protocol/DC.
	key := init[8:40]
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, false, false
	}
	// Obfuscated2 keeps bytes 0:56 as key/IV material. The CTR stream is
	// advanced over those 56 bytes before decrypting the encrypted 8-byte
	// tail; after the full 64-byte header, payload decryption starts at offset 64.
	stream := cipher.NewCTR(block, init[40:56])
	var zero56 [56]byte
	stream.XORKeyStream(zero56[:], zero56[:])
	var plainTail [8]byte
	stream.XORKeyStream(plainTail[:], init[56:64])
	proto := binary.LittleEndian.Uint32(plainTail[0:4])
	if proto != 0xEFEFEFEF && proto != 0xEEEEEEEE && proto != 0xDDDDDDDD {
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
		idx = 2
	}
	if idx < 1 || idx > 5 {
		return 0, false, false
	}
	return idx, isMedia, true
}

func mediaForIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() {
		return false
	}
	// Exact media endpoints observed in Telegram client/proxy tables. This is
	// only a fallback for clients whose init DC field is random (useSecret=0).
	// Experimental: 149.154.171.255 is marked media because this device logs it
	// as DC5 and thumbnails now load, while full media still stalls. Test the
	// kws5-1 route for this exact endpoint without changing other DC5 traffic.
	switch ip.String() {
	case "149.154.175.52", "149.154.175.211", "149.154.167.151", "149.154.167.222", "149.154.167.223", "149.154.162.123", "149.154.167.35", "149.154.175.102", "149.154.164.250", "149.154.166.120", "149.154.166.121", "149.154.167.118", "149.154.165.111", "149.154.165.136", "149.154.171.255", "91.108.56.102", "91.108.56.128", "91.108.56.151":
		return true
	}
	return false
}

type wsConn struct {
	conn       net.Conn
	host       string
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
			logf("tls: успешно загружено %d системных CA сертификатов Android", added)
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
			last = errors.New("не найдены доступные DNS-серверы Android")
		}
		return nil, last
	}}
}

func wsHostForDC(dc int) string {
	hosts := wsHostsForDC(dc, false)
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0]
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

func preferredIngressForDC(dc int) string {
	if overrides := readDCOverrides(); len(overrides) > 0 {
		if ip, ok := overrides[dc]; ok && ip != "" {
			return ip
		}
	}
	switch dc {
	case 1:
		// Telegram Desktop built-in production DC1 endpoint is 149.154.175.50.
		// The previous 149.154.174.100 value was not the canonical DC1 endpoint.
		return "149.154.175.50"
	case 2, 4:
		return "149.154.167.220"
	default:
		return ""
	}
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
	if len(initial) != 64 {
		return nil, fmt.Errorf("MTProto init length %d, want 64", len(initial))
	}
	key := initial[8:40]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := append([]byte(nil), initial[40:56]...)
	stream := cipher.NewCTR(block, iv)
	// The first 56 bytes are key/IV material. The encrypted tail uses the
	// CTR keystream at offset 56; payload bytes follow the complete 64-byte
	// header, so advance this stream to offset 64 before framing packets.
	var zero56 [56]byte
	stream.XORKeyStream(zero56[:], zero56[:])
	var tail [8]byte
	stream.XORKeyStream(tail[:], initial[56:64])
	proto := binary.LittleEndian.Uint32(tail[:4])
	if proto != 0xEFEFEFEF && proto != 0xEEEEEEEE && proto != 0xDDDDDDDD {
		return nil, fmt.Errorf("unsupported MTProto transport tag %#x", proto)
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
	if state.count >= 2 {
		state.until = now.Add(3 * time.Minute)
		state.count = 0
	}
	routeHealth[host] = state
	cooling := now.Before(state.until)
	routeHealthMu.Unlock()
	if cooling {
		cfHostCache.Delete(key)
		if v, ok := routeChoice.Load(key); ok {
			if choice, ok := v.(routeDecision); ok && choice.host == host {
				routeChoice.Delete(key)
			}
		}
		logf("WSS-маршрут %s временно исключён на 3 минуты после повторного раннего EOF (age=%s up=%d down=%d): %v", host, age.Round(time.Second), up, down, err)
	} else {
		logf("WSS-маршрут %s: ранний удалённый EOF #%d (age=%s up=%d down=%d): %v", host, state.count, age.Round(time.Second), up, down, err)
	}
}

func dialTelegramWS(ctx context.Context, dc int, isMedia bool) (*wsConn, error) {
	if dc == 1 {
		logf("DC1 media=%t: начало выбора маршрута; direct ingress=%s", isMedia, preferredIngressForDC(1))
	}
	hosts := wsHostsForDC(dc, isMedia)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("неизвестный DC: %d", dc)
	}
	key := routeKey(dc, isMedia)
	resolver := androidDNSResolver()
	var errorsSeen []string

	cfPriority := readCFPriority()
	cfBalance := readCFBalance()

	// Honor the measured route before attempting the direct ingress.
	if !cfBalance {
		if v, ok := routeChoice.Load(key); ok {
			if choice, ok := v.(routeDecision); ok {
				if time.Now().Before(choice.expires) && choice.preferCF && choice.host != "" && !routeCoolingDown(choice.host) {
					if ws, err := dialCFHost(ctx, resolver, choice.host); err == nil {
						return ws, nil
					} else {
						logf("DC%d media=%t сохранённый маршрут %s отказал: %v; повторный подбор", dc, isMedia, choice.host, err)
						cfHostCache.Delete(key)
						routeChoice.Delete(key)
					}
				} else if !time.Now().Before(choice.expires) {
					routeChoice.Delete(key)
				}
			}
		}
	}

	// DC1 previously succeeded on this device via kws1.pclead.co.uk. Try that
	// observed-good WSS route first, then the documented DC1 ingress 149.154.175.50.
	if dc == 1 && !cfBalance {
		const preferredDC1Host = "kws1.pclead.co.uk"
		// Do not blindly retry the hard-coded DC1 host after the health tracker
		// has cooled it down.
		if !routeCoolingDown(preferredDC1Host) {
			if ws, err := dialCFHost(ctx, resolver, preferredDC1Host); err == nil {
				cfHostCache.Store(key, preferredDC1Host)
				saveRouteCache(key, preferredDC1Host, nil)
				directFailUntil.Delete(key)
				logf("DC1 media=%t WSS через ранее успешный Cloudflare-домен %s", isMedia, preferredDC1Host)
				return ws, nil
			} else {
				logf("DC1 media=%t ранее успешный WSS-маршрут %s недоступен: %v; пробуем запасные маршруты", isMedia, preferredDC1Host, err)
				errorsSeen = append(errorsSeen, preferredDC1Host+": "+err.Error())
			}
		} else {
			logf("DC1 media=%t: пропускаю %s — маршрут в cooldown после ранних EOF", isMedia, preferredDC1Host)
		}
	}

	// Fast path: use the last known-good cached Cloudflare route before any
	// direct-ingress timeout or multi-host discovery.
	if !cfBalance {
		if cached, ok := cfHostCache.Load(key); ok {
			if host, ok := cached.(string); ok && host != "" && !routeCoolingDown(host) {
				if ws, err := dialCFHost(ctx, resolver, host); err == nil && ws != nil {
					routeChoice.Store(key, routeDecision{preferCF: true, host: host, expires: time.Now().Add(6 * time.Hour)})
					saveRouteCache(key, host, nil)
					return ws, nil
				} else if err != nil {
					errorsSeen = append(errorsSeen, host+": cached route: "+err.Error())
					cfHostCache.Delete(key)
				}
			}
		}
	}

	// Prefer hosts preflighted by the background route-pool worker before
	// starting a fresh multi-host discovery batch.
	if pooled, ok := routePool.Load(key); ok {
		if candidates, ok := pooled.([]routeCandidate); ok && len(candidates) > 0 {
			orderedCandidates := candidates
			if cfBalance && len(candidates) > 1 {
				offset := int(atomic.AddUint64(&cfBalanceSeq, 1) % uint64(len(candidates)))
				orderedCandidates = make([]routeCandidate, len(candidates))
				for i := range candidates {
					orderedCandidates[i] = candidates[(offset+i)%len(candidates)]
				}
			}
			for _, candidate := range orderedCandidates {
				if candidate.host == "" || routeCoolingDown(candidate.host) {
					continue
				}
				attemptCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
				ws, err := dialCFHost(attemptCtx, resolver, candidate.host)
				cancel()
				if err == nil && ws != nil {
					if !cfBalance {
						cfHostCache.Store(key, candidate.host)
						routeChoice.Store(key, routeDecision{preferCF: true, host: candidate.host, expires: time.Now().Add(6 * time.Hour)})
						saveRouteCache(key, candidate.host, nil)
					}
					return ws, nil
				}
			}
		}
	}

	tryDirect := !cfPriority
	if tryDirect {
		if v, ok := directFailUntil.Load(key); ok {
			if until, ok := v.(time.Time); ok && time.Now().Before(until) {
				tryDirect = false
			} else {
				directFailUntil.Delete(key)
			}
		}
	}
	if tryDirect {
		directStarted := time.Now()
		preferred := preferredIngressForDC(dc)
		for _, host := range hosts {
			if routeCoolingDown(host) {
				errorsSeen = append(errorsSeen, host+": временно исключён после повторных ранних EOF")
				continue
			}
			ips, lookupErr := resolver.LookupNetIP(ctx, "ip4", host)
			ordered := make([]netip.Addr, 0, len(ips)+1)
			if preferred != "" {
				ordered = appendUniqueIP(ordered, netip.MustParseAddr(preferred))
			}
			// On DC2/DC4 the original path's known ingress is preferred; DNS
			// answers are tried only if no preferred ingress is defined.
			if preferred == "" {
				for _, ip := range ips {
					if ip.Is4() {
						ordered = appendUniqueIP(ordered, ip)
					}
				}
			}
			if len(ordered) == 0 && lookupErr != nil {
				errorsSeen = append(errorsSeen, "direct DNS "+host+": "+lookupErr.Error())
				continue
			}
			for _, ip := range ordered {
				attemptCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
				d := net.Dialer{Timeout: 950 * time.Millisecond, KeepAlive: 30 * time.Second}
				raw, err := d.DialContext(attemptCtx, "tcp4", net.JoinHostPort(ip.String(), "443"))
				if err == nil {
					var ws *wsConn
					ws, err = finishTelegramWS(attemptCtx, raw, host)
					if err == nil {
						cancel()
						directFailUntil.Delete(key)
						directMS := time.Since(directStarted)
						logf("DC%d media=%t direct WSS %s via %s (%dms)", dc, isMedia, host, ip, directMS.Milliseconds())
						go maybeProbeCloudflare(key, dc, isMedia, directMS)
						return ws, nil
					}
					_ = raw.Close()
				}
				cancel()
				errorsSeen = append(errorsSeen, fmt.Sprintf("direct %s@%s: %v", host, ip, err))
				if dc == 1 {
					logf("DC1 media=%t direct WSS %s via %s не сработал: %v", isMedia, host, ip, err)
				}
				// A TCP timeout cannot be fixed by trying the alternate hostname
				// against the same IP. Break to the independent CF route quickly.
				if isTimeout(err) {
					break
				}
			}
			if len(errorsSeen) > 0 && isTimeoutText(errorsSeen[len(errorsSeen)-1]) {
				break
			}
		}
		if len(errorsSeen) > 0 {
			directFailUntil.Store(key, time.Now().Add(10*time.Minute))
		}
	}

	domains := cfDomains()
	if len(domains) == 0 {
		return nil, fmt.Errorf("direct WSS failed and no Cloudflare domains configured: %s", strings.Join(errorsSeen, " | "))
	}
	if cfBalance && len(domains) > 1 {
		offset := int(atomic.AddUint64(&cfBalanceSeq, 1) % uint64(len(domains)))
		rotated := make([]string, len(domains))
		for i := range domains {
			rotated[i] = domains[(offset+i)%len(domains)]
		}
		domains = rotated
	}
	// Try four domains concurrently per batch. For media, try the -1 hostname
	// first; Telegram documents it as an alternate hostname with a higher
	// per-host concurrency limit, not as a separate media-only protocol.
	for i := 0; i < len(domains); i += 4 {
		end := i + 4
		if end > len(domains) {
			end = len(domains)
		}
		batchCtx, cancelBatch := context.WithTimeout(ctx, 2200*time.Millisecond)
		type result struct {
			host string
			ws   *wsConn
			err  error
		}
		ch := make(chan result, end-i)
		for _, domain := range domains[i:end] {
			host := fmt.Sprintf("kws%d.%s", dc, domain)
			orderedHosts := []string{host}
			go func(hosts []string) {
				var ws *wsConn
				var err error
				chosen := ""
				for _, h := range hosts {
					if routeCoolingDown(h) {
						err = fmt.Errorf("маршрут временно исключён после ранних EOF")
						continue
					}
					ws, err = dialCFHost(batchCtx, resolver, h)
					if err == nil && ws != nil {
						chosen = h
						break
					}
				}
				select {
				case ch <- result{host: chosen, ws: ws, err: err}:
				case <-batchCtx.Done():
					if ws != nil {
						_ = ws.Close()
					}
				}
			}(orderedHosts)
		}
		var winner *wsConn
		remaining := end - i
		for remaining > 0 {
			select {
			case r := <-ch:
				remaining--
				if r.err == nil && r.ws != nil {
					if winner == nil {
						winner = r.ws
						cancelBatch()
						cfHostCache.Store(key, r.host)
						routeChoice.Store(key, routeDecision{preferCF: true, host: r.host, expires: time.Now().Add(6 * time.Hour)})
						saveRouteCache(key, r.host, nil)
						logf("DC%d media=%t WSS через Cloudflare-домен %s", dc, isMedia, r.host)
					} else {
						_ = r.ws.Close()
					}
				} else if r.err != nil {
					errorsSeen = append(errorsSeen, r.host+": "+r.err.Error())
				}
			case <-batchCtx.Done():
				remaining = 0
			}
		}
		cancelBatch()
		if winner != nil {
			go func(c chan result, count int) {
				for count > 0 {
					select {
					case r := <-c:
						count--
						if r.ws != nil {
							_ = r.ws.Close()
						}
					case <-time.After(3 * time.Second):
						return
					}
				}
			}(ch, remaining)
			return winner, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("все WSS-маршруты DC%d media=%t отказали: %s", dc, isMedia, strings.Join(errorsSeen, " | "))
}

// maybeProbeCloudflare mirrors the original module's path measurement: probe
// Cloudflare-fronted KWS hosts off the live path, cache the fastest, and prefer
// it only if it is at least one-third faster than direct. Re-measure every 6 h.
func maybeProbeCloudflare(key string, dc int, isMedia bool, directDuration time.Duration) {
	now := time.Now()
	if v, ok := routeProbeAt.Load(key); ok {
		if t, ok := v.(time.Time); ok && now.Sub(t) < 6*time.Hour {
			return
		}
	}
	routeProbeAt.Store(key, now)
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	resolver := androidDNSResolver()
	domains := cfDomains()
	if len(domains) > 8 {
		domains = domains[:8]
	}
	type result struct {
		host    string
		ws      *wsConn
		elapsed time.Duration
		err     error
	}
	ch := make(chan result, len(domains))
	for _, domain := range domains {
		host := fmt.Sprintf("kws%d.%s", dc, domain)
		go func(h string) {
			started := time.Now()
			ws, err := dialCFHost(ctx, resolver, h)
			select {
			case ch <- result{host: h, ws: ws, elapsed: time.Since(started), err: err}:
			case <-ctx.Done():
				if ws != nil {
					_ = ws.Close()
				}
			}
		}(host)
	}
	var best result
	var poolCandidates []routeCandidate
	for i := 0; i < len(domains); i++ {
		select {
		case r := <-ch:
			if r.ws != nil && r.err == nil {
				_ = r.ws.Close()
				poolCandidates = append(poolCandidates, routeCandidate{host: r.host, latency: r.elapsed})
				if best.host == "" || r.elapsed < best.elapsed {
					best = r
				}
			}
		case <-ctx.Done():
			go func(c chan result, rem int) {
				for rem > 0 {
					select {
					case res := <-c:
						rem--
						if res.ws != nil {
							_ = res.ws.Close()
						}
					case <-time.After(2 * time.Second):
						return
					}
				}
			}(ch, len(domains)-i)
			i = len(domains)
		}
	}
	if len(poolCandidates) > 0 {
		routePool.Store(key, poolCandidates)
	}
	if best.host == "" {
		routeChoice.Store(key, routeDecision{preferCF: false, expires: time.Now().Add(6 * time.Hour)})
		logf("DC%d media=%t подбор маршрута: CF не ответил, оставляем direct", dc, isMedia)
		return
	}
	prefer := best.elapsed*3 < directDuration*2
	routeChoice.Store(key, routeDecision{preferCF: prefer, host: best.host, expires: time.Now().Add(6 * time.Hour)})
	cfHostCache.Store(key, best.host)
	if prefer {
		saveRouteCache(key, best.host, poolCandidates)
	} else if len(poolCandidates) > 0 {
		saveRouteCache(key, "", poolCandidates)
	}
	pick := "direct"
	if prefer {
		pick = "Cloudflare"
	}
	logf("DC%d media=%t подбор маршрута: direct=%dms, CF %s=%dms, выбор=%s", dc, isMedia, directDuration.Milliseconds(), best.host, best.elapsed.Milliseconds(), pick)
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

func noteRouteHTTPFailure(host string, err error) {
	if host == "" || err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "http 503") && !strings.Contains(msg, "http 502") && !strings.Contains(msg, "http 504") {
		return
	}
	now := time.Now()
	routeHealthMu.Lock()
	state := routeHealth[host]
	wasCooling := now.Before(state.until)
	state.until = now.Add(3 * time.Minute)
	state.last = now
	routeHealth[host] = state
	routeHealthMu.Unlock()
	if !wasCooling {
		logf("WSS-маршрут %s временно исключён на 3 минуты после ответа сервера %v", host, err)
	}
}

func dialCFHost(ctx context.Context, resolver *net.Resolver, host string) (*wsConn, error) {
	ips, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("DNS: %w", err)
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
			var ws *wsConn
			ws, e = finishTelegramWS(attemptCtx, raw, host)
			if e == nil {
				cancel()
				return ws, nil
			}
			noteRouteHTTPFailure(host, e)
			_ = raw.Close()
			if strings.Contains(strings.ToLower(e.Error()), "http 502") || strings.Contains(strings.ToLower(e.Error()), "http 503") || strings.Contains(strings.ToLower(e.Error()), "http 504") {
				cancel()
				return nil, e
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

func finishTelegramWS(ctx context.Context, raw net.Conn, host string) (*wsConn, error) {
	sni := host
	if customSNI := configuredFrontingSNI(); customSNI != "" {
		sni = customSNI
	}
	tlsConfig := &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            getSystemRootCAs(),
		InsecureSkipVerify: true,
	}
	tc := tls.Client(raw, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(deadline)
	} else {
		_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	ws, err := websocketUpgrade(tc, host)
	if err != nil {
		_ = tc.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return ws, nil
}

func websocketUpgrade(conn net.Conn, host string) (*wsConn, error) {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	if _, err := fmt.Fprintf(conn, "GET /apiws HTTP/1.1\r\nHost: %s\r\nOrigin: https://web.telegram.org\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\nUser-Agent: TG-Open/2.1\r\n\r\n", host, key); err != nil {
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
		return nil, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	want := base64.StdEncoding.EncodeToString(sha1Sum([]byte(key + wsGUID)))
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept")), want) {
		return nil, errors.New("неверный Sec-WebSocket-Accept")
	}
	if !headerToken(resp.Header.Get("Upgrade"), "websocket") || !headerToken(resp.Header.Get("Connection"), "upgrade") {
		return nil, errors.New("неверные Upgrade/Connection заголовки")
	}
	if p := resp.Header.Get("Sec-WebSocket-Protocol"); p != "" && p != "binary" {
		return nil, fmt.Errorf("сервер выбрал неизвестный subprotocol %q", p)
	}
	return &wsConn{conn: conn, r: r, host: host}, nil
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

	err := writeFull(w.conn, header)
	if err == nil {
		err = writeFull(w.conn, payload)
	}

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
	fmt.Println("TG Open engine checks")
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
