# AGENTS.md

Instructions, operational invariants, and engineering standards for AI agents and human contributors working with this repository.

Project: **TeleWEB** — High-performance transparent Go daemon that encapsulates Telegram (MTProto) traffic into WebSocket (WSS) sessions routed through Cloudflare edge CDN anycast IPs and custom Cloudflare Workers. The codebase powers five synchronized branches targeting Android root environments (KernelSU Next, KernelSU, APatch, SukiSU, Magisk) and desktop operating systems (Windows and Linux).

Authoritative reference documents:
- Architectural history and system status: [MEMORY.md](MEMORY.md)
- Release execution runbook: [docs/RELEASING.md](docs/RELEASING.md)

---

## 1. Branch Topography & Git Lifecycle (CRITICAL)

The repository relies on a multi-branch architecture where platform-specific trees intentionally differ. **Branches must NEVER be merged directly into one another** (with the sole exception of merging `dev` into `master`). Instead, individual logical changes must be developed on `dev`, committed, and then selectively cherry-picked (`git cherry-pick -x <commit>`) across platform branches.

### Branch Matrix

| Branch | Primary Role | Contents & Constraints |
| :--- | :--- | :--- |
| `dev` | **Primary development branch**. All new features, refactoring, and bug fixes start here. | Full cross-platform tree (contains all core, Android, Windows, and Linux files). Version metadata remains frozen. |
| `android` | Android root module (Magisk / KernelSU / APatch). **Authorizes and initiates GitHub releases.** | Stripped of Windows desktop files (`redirect_windows.go`, `win32_gui_windows.go`, `embed_assets_windows_*.go`, `gui_native.go`). Owns live `module.prop` and `update.json`. |
| `win` | Windows desktop standalone package. | Windows desktop layer without Android module scripts and without Linux redirector files. |
| `linux` | Linux desktop standalone package. | Linux desktop layer without Windows driver/GUI layer. |
| `master` | Public release showcase branch for in-app updaters. | Mirror of `dev` plus merge commits and current `update.json` / `changelog.md`. |

### Mandatory Branch Rules

1. **Always verify the active branch before making edits**:
   ```sh
   git branch --show-current
   ```
   Making edits on the wrong branch causes history divergences and cherry-pick collisions.
2. **Standard Promotion Order**:
   `dev` (author & test) $\rightarrow$ commit $\rightarrow$ `git cherry-pick -x` to `android` $\rightarrow$ `git cherry-pick -x` to `win` $\rightarrow$ `git cherry-pick -x` to `linux` $\rightarrow$ merge `dev` into `master`.
3. **Handling "DU" (Deleted by Us) Cherry-Pick Conflicts**:
   Platform branches (`android`, `linux`) do not contain the Windows driver/GUI subsystem. When a commit touches both core files and Windows-only files, cherry-picking onto `android` or `linux` will flag Windows files as `DU`.
   - Resolve by un-staging: `git rm --cached <path>`
   - **Crucial**: Delete the untracked file from the working directory. In git, running `git rm --cached` on a file that does not exist in `HEAD` leaves it as an untracked file.
4. **Frozen Metadata on `dev`**:
   `module.prop` and `update.json` on `dev` remain pinned to historical versions. Version bumps are strictly executed on `android` during releases.

---

## 2. Compilation, Verification & Quality Gates

All Go source code resides under `src/`. Before creating any commit, run the mandatory verification battery:

```sh
cd src
gofmt -l .                 # Must return empty (zero unformatted files)
go vet ./...               # Must exit with code 0 (zero warnings)
go test -count=1 ./...     # Must run without cache to validate state resets
go test -race -count=1 ./... # Must pass with zero data races
```

### Full 8-Target Cross-Compilation Matrix

Continuous Integration builds and verifies all supported operating systems and architectures. Validate builds locally before pushing:

```sh
# Cross-compilation loop
for spec in "windows amd64" "windows 386" "windows arm64" \
            "linux amd64" "linux arm64" "linux arm" "android arm64"; do
  set -- $spec
  GOOS=$1 GOARCH=$2 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /dev/null . || echo "FAIL $1/$2"
done

# Native Windows GUI build
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags nativegui -trimpath -ldflags "-s -w" -o /dev/null .
```

### The Platform Branch Validation Trap

When checking out `android` or `linux` on a Windows development machine, the default host environment (`GOOS=windows`) will fail to build because those branches do not contain the Windows redirector layer (`redirect_windows.go`, `win32_gui_windows.go`), yielding errors like `undefined: redirectorSupported`, `undefined: ensureRedirector`.

**This is expected branch divergence, not a code defect.**

Validate platform branches using the exact environment used by CI:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /dev/null .
```

### Local Multi-Platform Release Assembly

To assemble all 14 release artifacts locally without waiting for CI, execute:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_all.ps1
```

This compiles all targets, stages them into `dist/`, packages the Android multi-arch ZIP, and verifies asset count and integrity.

---

## 3. Code Style & Formatting Conventions

- **Line Endings (Strict LF)**: All files must have UNIX line endings (`\n`, LF). Git enforces `eol=lf` via `.gitattributes`. Windows tools that write CRLF must be normalized. Verify before committing:
  ```sh
  # In PowerShell:
  powershell -Command "(Get-Content -Raw <file>) -match '\r'" # Must return False
  ```
- **Commit Messages**: Conventional commits format with a **single-line subject** (e.g. `fix(core): ...`, `feat(webui): ...`, `chore(release): ...`). Signed-off commits are mandatory: `git commit -s`.
- **Language Policy**:
  - Documentation, git commit messages, architecture records, and code comments are written in Russian or English according to active repository context; `AGENTS.md` is strictly maintained in **English**.
  - All programming identifiers, variables, functions, and API endpoints are strictly in English.
- **Regression Tests**: Every bug fix must include a deterministic unit or integration test in `src/main_test.go` verifying the fixed condition.

---

## 4. Testing & State Isolation Invariants

The entire application engine lives in `package main`. Consequently, global runtime state is shared across tests running in the same binary.

### Global State Leak Prevention

Tests that mutate or inspect global routing, balancer, or cooldown state (`routeHealth`, `dcDomainAffinity`, `cfDomains`, `learnedDCs`, `workerCooldowns`, `domainLastPoP`, `globalMediaCircuitBreaker`) **MUST isolate state**:
1. Save existing state under lock.
2. Initialize clean state (or clear the map).
3. Use `defer` to restore the original state upon test conclusion.

```go
// Canonical isolation pattern
dcDomainAffinityMu.Lock()
oldAffinity := dcDomainAffinity[2]
delete(dcDomainAffinity, 2)
dcDomainAffinityMu.Unlock()
defer func() {
    dcDomainAffinityMu.Lock()
    dcDomainAffinity[2] = oldAffinity
    dcDomainAffinityMu.Unlock()
}()
```

### Deterministic Timeout Synchronization

Never use `time.Sleep` to wait for a context timeout in unit tests. On Windows hosts with 15.6 ms timer resolution, arbitrary sleeps produce flaky test failures under CPU load. Always synchronize directly with the context channel:

```go
expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
defer cancel()
<-expired.Done() // Guaranteed deterministic expiration
```

---

## 5. Hard System & Security Invariants (Violation = Production Regression)

The following invariants prevent critical outages, memory death spirals, and security vulnerabilities:

1. **Zero Forced `GOMEMLIMIT` in Launch Scripts**:
   Launch scripts (`service.sh`, `action.sh`, `post-fs-data.sh`) must **NEVER export `GOMEMLIMIT`**. The Go runtime honors this environment variable even if internal Go code clears it. In releases v0.1.7–v0.1.9, an active `export GOMEMLIMIT=48MiB` caused memory allocation thrashing and a 220% CPU GC death spiral. The only allowed memory tuning knob is `GOGC`. CI gate:
   ```sh
   git grep -nE '^[[:space:]]*export[[:space:]]+GOMEMLIMIT' -- '*.sh' # Must exit code 1 (no matches)
   ```
2. **Strict TLS & SNI Validation**:
   `InsecureSkipVerify` is strictly prohibited except for Cloudflare fronting domains with an explicit `fronting-sni`. In those cases, `verifyFrontingPeerChain` is mandatory to validate the leaf against the system root CA store. Direct dials and Cloudflare Workers must always enforce full TLS certificate verification.
3. **Non-Zero Front Candidate Guarantee**:
   The front balancer `frontCandidatesForRace` must never return an empty candidate slice. Parking or cooldown logic must always leave at least one front available; otherwise, resolution collapses to direct Telegram IPs, which are blocked under censorship.
4. **`force_test_dc` Scope Restriction**:
   The `force_test_dc` option applies exclusively to DC1, DC2, and DC3 (which possess designated `testIP` endpoints). Applying it to DC4 or DC5 results in zero resolvable routes.
5. **Strict CDN203 Allowlist**:
   `handleCDN203` must never act as an open proxy or tunnel arbitrary destination IPs. The `isCDN203IP` verification check is mandatory before dispatching a WSS tunnel.
6. **Zero Silent IPv6 Packet Loss**:
   If an intercepted IPv6 packet cannot be mapped or tunneled, it must be explicitly dropped (`v6Drop`) or rejected (`TCP RST`), never forwarded directly to the cleartext WAN where it would leak unencrypted metadata.
7. **Fast Non-MTProto Ingress Rejection**:
   Transparent ingress intercepts (`serveConn`) must validate MTProto Obfuscated2 transport headers via `decryptMTProtoInit`. Non-Telegram traffic (e.g. Google connectivity probes to `194.221.250.50`, raw TLS ClientHello, HTTP requests) must be rejected immediately without dialing WSS tunnels.
8. **Cloudflare Error Code Preservation**:
   `cleanHTTPErrorBody` must preserve specific Cloudflare error codes (`Error 1015`, `Error 1027`, `Error 1101`) even when HTML `<title>` tags are present. `routeHTTPRejection` must classify codes 1015 and 1027 as `routeRejectRateLimit` to trigger exponential backoff rather than short forbidden cooldowns.
9. **Russian Cloudflare PoP Avoidance**:
   `isRussianPoP` identifies and avoids Cloudflare edge nodes located in Russia (`DME`, `LED`, `KJA`, `SVX`, `OVB`, `SVO`, `ROV`, `KZN`) to bypass domestic TSPU/DPI throttling and destination-based MTProto filtering.
10. **Zero-Allocation Hot Relays**:
    WebSocket frame masking must use 64-bit SIMD-friendly vector operations (`binary.NativeEndian.Uint64`). Buffer recycling must return raw pointers (`*[]byte`) to `sync.Pool` to prevent slice header heap allocations.

---

## 6. Repository File Layout & Responsibilities

| Path / File | Subsystem & Architecture Responsibilities |
| :--- | :--- |
| `src/main.go` | Core daemon: packet redirection, MTProto obfuscation, DC dispatcher, WSS relay, route balancer, iptables management, watchdog, stealth engine, HTTP REST API. |
| `src/cf_h2.go` | Cloudflare HTTP/2 media stream bridge (POST multiplexing for heavy media downloads). |
| `src/ws_pool.go` | Pre-warmed WebSocket connection pool and keep-alive health manager. |
| `src/doh.go` | Resilient DNS-over-HTTPS client with multi-provider fallback and fast-fail backoff. |
| `src/cf_update.go` | Dynamic Cloudflare edge IP/domain list updater with outbound proxy support. |
| `src/redirect_windows.go` | Windows transparent redirection engine using WinDivert (IPv4/IPv6 NAT table). |
| `src/gui_native.go` | Native Windows GUI layer (`-tags nativegui`): tray icon, notifications, status window. |
| `src/win32_gui_windows.go` | Win32 API window bindings, DPI-aware message pump, and single-instance mutex. |
| `src/webui.go` | Embedded HTTP server serving WebUI assets and handling JSON API calls. |
| `webroot/index.html` | Single-file responsive WebUI (Vanilla JS/CSS, tab navigation, diagnostics, stealth sheet). |
| `worker/cloudflare-worker.js` | Custom Cloudflare Worker script with strict destination DC allowlist. |
| `lib.sh` | Core Android shell library: iptables/nftables setup, UID resolution, stealth detection. |
| `service.sh`, `action.sh` | Android daemon startup, supervision, and quick-action menu scripts. |
| `build_all.ps1` | Unified local build orchestrator for all 14 multi-platform release assets. |
| `package_zip.py` | Android multi-arch Magisk/KernelSU ZIP packaging script. |
| `docs/` | In-depth operational documentation, troubleshooting runbooks, and incident post-mortems. |

---

## 7. Release Execution Runbook

Releases are published as a unified multi-platform GitHub Release containing **14 assets** assembled across branches. Full runbook is in [docs/RELEASING.md](docs/RELEASING.md).

### Pre-Release Checklist

1. **Verify branch parity**:
   ```sh
   git diff android dev -- src/main.go src/ws_pool.go src/cf_h2.go src/webui.go
   ```
   Output must be completely empty.
2. **Update metadata on `android`**:
   - `module.prop`: Set `version=vX.Y.Z`, increment `versionCode`.
   - `update.json`: Update `version`, `versionCode`, and `zipUrl`.
   - `changelog.md`: Prepend `### Изменения в vX.Y.Z:` section.
3. **Synchronize changelog**: Add identical `### Изменения в vX.Y.Z:` section to `changelog.md` on `win`, `linux`, `dev`, and `master`. Update `update.json` on `master`.
4. **Enforce `GOMEMLIMIT` gate**:
   ```sh
   git grep -nE '^[[:space:]]*export[[:space:]]+GOMEMLIMIT' -- '*.sh' # Must exit code 1
   ```

### Publishing Steps

```bash
git checkout android
git add module.prop update.json changelog.md
git commit -s -m "chore: release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z"

# Push using Git Credential Manager to prevent terminal hang
GCM_INTERACTIVE=never GIT_TERMINAL_PROMPT=0 git -c credential.helper=manager push origin android
GCM_INTERACTIVE=never GIT_TERMINAL_PROMPT=0 git -c credential.helper=manager push origin vX.Y.Z
GCM_INTERACTIVE=never GIT_TERMINAL_PROMPT=0 git -c credential.helper=manager push origin win linux master dev
```

### Release Verification

The GitHub Actions `release.yml` workflow automatically builds all platforms, checks for exactly **14 assets**, publishes the release, and updates `master`. Verify after run completion:
- **14 Assets Present**:
  - `teleweb-vX.Y.Z-multiarch.zip` (Android Magisk/KernelSU/APatch module).
  - 9 Windows desktop assets: `tgws-windows-{amd64,386,arm64}.exe` and `.zip` / `.tar.gz`.
  - 4 Linux desktop assets: `teleweb-linux-{amd64,arm64}.zip` and `.tar.gz`.
- `update.json` on `master` returns HTTP 200 on its `zipUrl`.

---

## 8. Tracked Upstream Repositories

| Remote Name | Upstream Repository | Purpose |
| :--- | :--- | :--- |
| `origin` | `dea1hwatcher/teleweb` | Canonical TeleWEB repository. |
| `upstream_flowseal` | `Flowseal/tg-ws-proxy` | Upstream Go implementation; reference for CF Worker protocols and routing. |
| `upstream_spatiumstas`| `spatiumstas/tg-ws-proxy-go` | High-performance Go proxy reference; DoH concurrency and early-boot retries. |
| `upstream_valnesfjord`| `valnesfjord/tg-ws-proxy-rs` | Rust reference; connection pooling and memory safety patterns. |
| `upstream_mirrly` | `joycecurcirt539-dot/Mirrly-TG-Proxy` | Rust engine reference; scope-isolated rate limiting and PoP filtering. |
| `upstream_regstar` | `Regstar2/tg-ws-proxy-android` | **Completely separate legacy codebase** with v1.11.x tags. Do NOT cherry-pick from it or confuse its tags with TeleWEB releases. |
