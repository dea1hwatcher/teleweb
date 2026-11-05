# TeleWEB Project Memory

---

## Project Overview
TeleWEB is a cross‑platform networking utility written in Go that provides transparent proxying, DNS‑over‑HTTPS (DoH) support, IPv6 handling, and optional integration with WinDivert for Windows traffic redirection. It targets Windows, Linux, macOS, and Android, delivering a unified CLI and native GUI for end‑users.

---

## Architecture Overview

| Directory / Module | Purpose |
|--------------------|---------|
| `src/` | Core Go source code – networking stack, redirector, DoH resolver, configuration handling, and platform‑specific wrappers. |
| `drivers/` | Platform‑specific drivers (e.g., WinDivert for Windows traffic capture). |
| `desktop/` | Native GUI implementation for Windows (uses Go bindings to native UI). |
| `webroot/` | Embedded web UI assets served by the built‑in HTTP server. |
| `build/` | Build scripts for all targets (PowerShell, Python, Docker). |
| `pkg/` | Reusable Go packages (e.g., `cf_h2`, `ipv6`, `metrics`). |
| `test/` | Unit and integration test suites.

### Key Components
- **Redirector** – Handles packet capture and redirection using WinDivert (Windows) or raw sockets (Linux/macOS). 
- **DoH Resolver** – Performs DNS‑over‑HTTPS queries with fallback to Anycast bootstrap IPs for resilience. 
- **IPv6 Parser** – Extends parsing of `/proc/net/tcp6` and Windows socket tables to support IPv6 flows. 
- **GUI Wrapper** – Exposes `apiDispatch` to the native desktop UI, allowing user‑initiated commands. 
- **Graceful Shutdown** – Hook system that registers shutdown callbacks to cleanly stop listeners and free resources.

---

## Release History
| Version | Date | Major Highlights |
|---------|------|------------------|
| v0.1.5 | 2024‑11‑02 | Initial multi‑arch support, basic proxying. |
| v0.1.6 | 2025‑02‑15 | Added DoH support, IPv4/IPv6 dual‑stack listener. |
| v0.1.7 | 2025‑09‑10 | Windows GUI improvements, first Android package. |
| **v0.1.8** | **2026‑11‑04** | **This release** – see "Recent Fixes (v0.1.8)" below. |

---

## Recent Fixes (v0.1.8)
- **WinDivert mask correction** – Fixed `prefixLast` bit‑shift error causing over‑capture; added unit test to guard against future regressions. 
- **Graceful shutdown hooks** – Implemented `registerShutdownHook` / `runShutdownHooks` to ensure listeners and driver resources are released on exit. 
- **IPv6 parsing extension** – Added support for the 32‑hex format in `/proc/net/tcp6` and Windows socket tables; normalised address handling across platforms. 
- **DoH bootstrap resilience** – Switched to Anycast bootstrap IPs; improved fallback logic when primary resolver is unreachable. 
- **API dispatch export** – Restored exported `apiDispatch` variable for native GUI integration; added thin wrapper in `src/main.go`. 
- **Cross‑platform build validation** – Ran full build matrix (Windows amd64/386/arm64, Linux amd64/arm64, Android multi‑arch) and verified artifact sizes. 
- **Test suite pass** – `go test -count=1 ./...` succeeded on all platforms; added missing platform‑specific tests for Windows redirector. 
- **Documentation sync** – Updated `changelog.md`, `module.prop`, and `update.json` to reflect new features and bug fixes.

---

## Universal Rules Applied
- **Autonomous Engineering Notes** – All major architectural changes logged in `Notes/NOTES_CHANGELOG.md`. 
- **Deep Code Inspection & Audit** – Hot‑path audit performed on redirector and DoH resolver to eliminate hidden allocations. 
- **Evidence‑First** – Every fix was verified by running the full test suite and building all target binaries. 
- **Root‑Cause First** – Bugs were diagnosed by examining actual code paths (e.g., mask bug traced to incorrect shift operation). 
- **Project Safety & Backup** – All changes committed with signed‑off commits; binary artifacts excluded via `.gitignore`.

---

## Testing & Verification
- **Unit Tests** – `go test ./...` passed on Windows, Linux, macOS. Added new tests for WinDivert mask handling. 
- **Integration Builds** – Executed PowerShell script `build_desktop.ps1` for Windows packages and Python script `package_zip.py` for Android. 
- **CI Checks** – GitHub Actions `release` workflow ran successfully after adding `memory.md`. 
- **Manual Smoke Test** – Ran the CLI on a Windows VM; verified traffic redirection and DoH resolution work as expected.

---

## Open Issues / Future Work
- **Windows NAT stability** – Monitor for edge‑case packet loss under high throughput; consider adding packet‑loss metrics. 
- **IPv6 subnet range expansion** – Add support for /96 and /64 IPv6 subnets in the redirector rule engine. 
- **DoH performance metrics** – Instrument latency counters and expose via `/metrics` endpoint. 
- **GUI polish** – Refine native UI layout for high‑DPI displays; add dark‑mode toggle. 
- **Android UI** – Implement compose‑based settings screen for user‑friendly configuration.

---

*This memory document is generated autonomously following the project’s engineering protocols and is intended to serve as a single source of truth for future maintainers.*
