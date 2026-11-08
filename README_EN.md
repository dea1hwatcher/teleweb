# TeleWEB

**English** | [Русский](README.md)

<img align='right' src='icon.png' width='220px' alt="TeleWEB Icon">

Full-featured transparent WSS-based Telegram censorship circumvention solution for Android, Windows, and Linux.

[![KernelSU](https://img.shields.io/badge/KernelSU-Supported-brightgreen.svg)](https://github.com/tiann/KernelSU)
[![Magisk](https://img.shields.io/badge/Magisk-Supported-blue.svg)](https://github.com/topjohnwu/Magisk)
[![APatch](https://img.shields.io/badge/APatch-Supported-orange.svg)](https://github.com/bmax121/APatch)
[![Release](https://img.shields.io/github/v/release/dea1hwatcher/teleweb?label=Release)](https://github.com/dea1hwatcher/teleweb/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

TeleWEB transparently intercepts and routes Telegram data center traffic (DC1–DC5) natively at the kernel level (`iptables/ip6tables nat REDIRECT` on Linux/Android and `WinDivert` on Windows) into encrypted WebSocket sessions (WSS) over Cloudflare. Unlike conventional VPN clients (V2Ray, Clash, ByeDPI, etc.), this solution **does not create a virtual network interface (tun)**, requires zero proxy configuration inside Telegram apps, consumes negligible battery, and preserves full network connection speeds.

## Features

* **Native Kernel Interception without VPN (`iptables REDIRECT` / `WinDivert`)**: Redirects Telegram traffic directly to local daemon port `17841`. No virtual TUN interfaces (`tun0`), ensuring 100% compatibility with any external VPN applications.
* **Full Dual-Stack (IPv4 & IPv6) Support**: Seamless transparent proxying for both address families (IPv4 via `iptables`, IPv6 via `ip6tables` on Android/Linux, and parallel dual-stack WinDivert filters on Windows).
* **Wi-Fi Hotspot & USB Tethering Interception**: Forwarded traffic from connected devices is redirected through the `PREROUTING` chain, complete with automatic BPF offload detachment (`schedcls_tether_*`) on Android 13–15.
* **Pre-warmed Connection Pool (WsPool)**: Background maintenance of pre-warmed WSS sessions (1 to 4 sockets per DC) with periodic liveness probes. Delivers instant response (0 ms latency) when opening chats, channels, or downloading media immediately after device wake-up.
* **Happy Eyeballs v2 Connection Racing**: Concurrently races all available routes (Direct KWS, Cloudflare Domain Fronting, Custom Worker) with a 250 ms staggered start, instantly selecting the lowest-latency handshake and cancelling losing attempts.
* **Russian Cloudflare Edge Avoidance**: Tracks Cloudflare PoP codes (`DME`, `LED`, `KJA`, `SVX`, `OVB`) in `CF-Ray` headers, prioritizing European and international edges to circumvent localized edge censorship.
* **Multi-DoH Racing**: Parallel DNS-over-HTTPS resolution via Google, Cloudflare, Quad9, and AdGuard DoH with an in-memory LRU cache (up to 256 entries) to defeat ISP DNS poisoning and censorship.
* **HTTP/2 Media Multiplexing**: Concurrent downloads of large media files through multiplexed HTTP/2 streams without head-of-line blocking on the primary message channel.
* **VoIP Call Protection**: Automatically bypasses STUN/TURN UDP packets (ports 3478, 596:599) to prevent audio/video latency spikes or call drops.
* **Universal Telegram Client Detection**: Automatically detects official Telegram, Telegram X, Nekogram, Forkgram, Cherrygram, Ayugram, MDGram, Swiftgram, Turbotel, and third-party builds by package signatures and native libraries.
* **Cgroup Unfreezer & Anti-Freeze Watchdog**: Protects daemon from OOM killer (`oom_score_adj = -1000`) and pulls background Telegram client processes from `cgroup freezer` to guarantee push notifications during deep sleep (Doze mode).
* **Material Design 3 Expressive WebUI**: Dynamic Monet palette engine, light/dark/AMOLED modes, live metrics, routing profiles, cellular IP renewal (`net-renew`), and log management.
* **CLI Control**: Global `tgws` command-line utility (`tgws status`, `tgws boot`, `tgws stop`, `tgws ensure`, `tgws check`) for management via root shell or Termux.

## Requirements

1. Root manager: **KernelSU**, **APatch**, or **Magisk** (v20.4+).
2. Processor architecture: **ARM64** (`arm64-v8a`), **ARM** (`armeabi-v7a`), **x86**, **x86_64**.
3. System version: **Android 8.0 — 16+**.

## Supported WebUI Managers

- [KsuWebUI](https://github.com/5ec1cff/KsuWebUIStandalone)
- [WebUI-X](https://github.com/MMRLApp/WebUI-X-Portable)
- [MMRL](https://github.com/MMRLApp/MMRL)

## Windows and Linux Desktop Ports

Desktop versions provide transparent redirection via WinDivert (Windows) and iptables (Linux), driverless SOCKS5 mode, Windows Service / systemd units, and a native Windows 11 Fluent Design GUI. For details and caveats, see [`docs/DESKTOP.md`](docs/DESKTOP.md). Desktop packages are built with `build_desktop.ps1`.

## Installation

1. Download the latest `teleweb-v...-multiarch.zip` package from the [Releases](https://github.com/dea1hwatcher/teleweb/releases/latest) section.
2. Flash the module via your root manager (Magisk, KernelSU, APatch, or MMRL).
3. Reboot your device.
4. The service starts automatically at boot, detects installed Telegram clients, and installs redirection rules.

## Configuration & Working Files

The module stores its persistent settings and runtime state in `/data/adb/teleweb/`:

| File / Setting | Purpose |
| :--- | :--- |
| `cf-domains` | Custom list of Cloudflare domains for Domain Fronting |
| `custom-cf-domain` | Preferred Cloudflare domain override |
| `custom-cf-worker` | Custom Cloudflare Worker gateway address |
| `pool_size` | Pre-warmed WSS connection pool size (`0` = disabled, `1`–`4` active sockets) |
| `dc203_direct_tcp` | CDN203 media transport mode (`1` = direct TCP pass-through, `0` = WSS) |
| `doh_enabled` | Enable Multi-DoH resolver (`1` = enabled, `0` = system DNS) |
| `h2_media_enabled` | HTTP/2 media multiplexing acceleration (`1` = enabled, `0` = disabled) |
| `dc-override` | Manual IP overrides for Telegram data centers |
| `route-cache.json` | Persistent cache of validated, fast WSS routes |
| `status.json` | Atomic service state snapshot and performance metrics |
| `tgws.log` | Primary network event, route decision, and error log |
| `supervisor.log` | Service startup and background supervisor log |

## Command-Line Interface (CLI)

The module provides a global CLI accessible via `/system/bin/tgws` (or `/data/adb/modules/teleweb/bin/tgws`):

```bash
# Check service status, active Telegram clients, and live metrics
su -c tgws status

# Start service (iptables rules + daemon + watchdog)
su -c tgws boot

# Stop service and flush redirection rules cleanly
su -c tgws stop

# Healthcheck and auto-recovery (supervisor)
su -c tgws ensure

# Verify MTProto parsers and internal routing invariants
su -c tgws check
```

## Custom Cloudflare Worker Gateway

For maximum routing stability and resilient circumvention, deploy your own worker gateway on Cloudflare Workers:

1. Open Cloudflare Dashboard ➔ **Workers & Pages** ➔ **Create Worker**.
2. Paste the code from [`worker/cloudflare-worker.js`](worker/cloudflare-worker.js).
3. Click **Deploy**.
4. Copy the assigned domain (e.g., `my-tg-gateway.user.workers.dev`).
5. Open TeleWEB WebUI ➔ **Routing** tab, enter your worker address in **Custom Cloudflare Worker**, and save changes.

> **Recommended: Protect your worker with a token.** Without a token, your worker acts as an open relay. Add the `TELEWEB_TOKEN` environment variable in your worker settings, and append the token in WebUI: `my-tg-gateway.user.workers.dev?token=YOUR_SECRET`. TeleWEB automatically forwards it with upgrade requests.
>
> Full guide with verification, contract details, limits, and troubleshooting: [`docs/WORKER_SETUP.md`](docs/WORKER_SETUP.md).

## Building from Source

Building requires **Go 1.24+** and **Python 3**. Multi-architecture compilation (`ARM64`, `ARM`, `x86`, `x86_64`) and zip packaging are automated:

```powershell
# Build binaries for all architectures and pack the multi-arch zip module:
python .\package_zip.py

# Or via PowerShell script:
powershell -ExecutionPolicy Bypass -File .\build_all.ps1

# Optional flags for package_zip.py:
#   --skip-build   - skip Go compilation and repack zip only
#   --build-only   - compile binaries only without creating zip
```

## Credits & Acknowledgements

* [amurcanov/tg-ws-proxy-android](https://github.com/amurcanov/tg-ws-proxy-android) — for the transparent WSS module concept on Android.
* [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) — for MTProto protocol research and Cloudflare infrastructure insights.
* [nfqws2-android](https://github.com/Dea1hwa1cher/nfqws2-android) — for MD3e WebUI design patterns.
* Developers of [KernelSU](https://github.com/tiann/kernelSU), [Magisk](https://github.com/topjohnwu/magisk), and [APatch](https://github.com/bmax121/APatch).
