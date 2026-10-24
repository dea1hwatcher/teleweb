# TeleWEB v2.1.48 — Multi-Arch (ARM64, ARM, x86, x86_64) & Performance Release

## Что нового в v2.1.48

- **Мультиархитектурная поддержка**:
  - `ARM64` (`arm64-v8a`, `aarch64`)
  - `ARM` (`armeabi-v7a`, `armv7l`)
  - `x86` (`i686`, 32-bit x86 c корректной эмуляцией `SYS_SOCKETCALL` для `SO_ORIGINAL_DST`)
  - `x86_64` (`amd64`)
  - Скрипт установки `customize.sh` автоматически определяет ABI целевого устройства через менеджер рута (Magisk/KernelSU/APatch) и системные свойства `ro.product.cpu.abi` / `uname -m`, копирует подходящий бинарник и удаляет лишние архитектуры для экономии места на `/data`.
- **Zero-Allocation I/O буферизация**:
  - Использование `sync.Pool` (`ioBufPool`, `frameBufPool`) для исключения постоянных аллокаций памяти и сброса давления на GC при высокоскоростной передаче трафика.
- **Динамическое автообновление доменов Cloudflare**:
  - Фоновое периодическое обновление резервных Cloudflare WSS-доменов с расшифровкой полезной нагрузки.
- **Поддержка Cloudflare Domain Fronting**:
  - Возможность задания кастомного SNI через параметр `fronting_sni` в конфигурации.
- **Нормализация DC 203**:
  - Поддержка тестового DC 203 с автоматической нормализацией маршрутизации на инфраструктуру DC 2.
- **5-минутный Active Idle Watchdog**:
  - Автоматическое превентивное закрытие зависших односторонне разорванных туннелей без активности.
- **Исправление подсетей Telegram**:
  - Исправлены маски и диапазоны для `149.154.160.0/22`, `185.76.151.0/24` и `91.105.192.0/23`.
- **Атомарная запись `status.json`**:
  - Исключены гонки чтения WebUI за счёт записи во временный файл с последующим атомарным переименованием.

---

# TeleWEB v2.1.44 — DC1 route cooldown fix

## DC2 minute pulse and adaptive DC learning (v2.1.47)

- A short WSS upgrade probe is attempted for DC2 at startup and every 60 seconds while the daemon process is scheduled.
- The daemon also tracks which DCs are actually used by intercepted app connections. If another DC is the most frequently observed, it probes that DC too once per minute. DC2 remains the baseline probe.
- A successful probe closes immediately and refreshes the cached route choice; it does not keep an empty socket open. This can warm up DNS/TCP/TLS/WebSocket routing and make a later connection faster.
- Important limitation: a WSS upgrade probe is **not** an authenticated MTProto session and cannot itself request or guarantee push notifications. It tests reachability of the WSS ingress only. Android Doze may also delay the minute ticker.
- Logs use the `dc-pulse:` prefix and report DC, route host, probe duration, and success/failure.

## Что изменено для теста фоновой устойчивости

- Исправлена ошибка выбора маршрута DC1: ранее `kws1.pclead.co.uk` пробовался безусловно до проверки кеша и пула, даже если health tracker уже пометил его как плохой. Теперь домен пропускается на время cooldown, а соединение сразу пробует альтернативные маршруты. Это должно убрать повторные задержки подключения на 2–3 секунды при каждом открытии, если причина — ранний EOF этого домена.
- Плохой WSS-маршрут временно исключается после **двух** ранних удалённых EOF с малым объёмом данных вместо пяти. Один EOF по-прежнему не приводит к блокировке маршрута. Cooldown — 3 минуты.
- Не добавлял WebSocket Ping: в предыдущих логах он сам коррелировал с ранним EOF и мог ухудшать соединение. TCP keepalive остаётся включённым.
- Это проверка выбора/восстановления маршрута, а не гарантия push-уведомлений: прокси не может поддерживать сокет Telegram, если сам клиент его закрыл или Android остановил процесс.

Проверено: `go test ./...`, `go test -race ./...`, `go vet ./...`, Android ARM64 cross-build и целостность ZIP. На физическом телефоне не проверено.

---

# TeleWEB v2.1.34 — Abridged Quick ACK framing fix


## v2.1.34 — исправление обрыва при отправке сообщений

- Исправлен разбор abridged MTProto: байты `0x80–0xFE` кодируют короткую длину пакета с установленным флагом Quick ACK, а не ошибочный маркер.
- Добавлена обработка `0xFF` как расширенной длины с Quick ACK; `0x7F` остаётся обычной расширенной длиной.
- Добавлены unit-тесты для коротких и расширенных пакетов с Quick ACK. Это адресует сценарий, когда исходящий пакет закрывал туннель с ошибкой `invalid abridged length marker`.
- Проверки автоматические; на физическом устройстве эта версия пока не проверена.

## Сборка поверх v2.1.30: восстановление без открытия WebUI

- `service.sh` теперь остаётся активным и каждые 30 секунд вызывает идемпотентную команду `ensure`. Она восстанавливает daemon, watchdog и правила перехвата, если запуск при загрузке опередил готовность Package Manager/iptables или один из процессов завершился.
- Проверка не перезапускает здоровый daemon и не требует открывать WebUI. Если обход выключен в настройках модуля, supervisor не включает его сам.
- Ошибки раннего запуска пишутся в `/data/adb/teleweb/supervisor.log`; повторная попытка происходит через 30 секунд.


- Сохранена логика транспорта v2.1.26; новые изменения предназначены для сбора причин сбоя, а не для смены WSS-маршрутов.
- Watchdog пишет heartbeat примерно раз в минуту: состояние процесса, порт 17841, состояние правил, число активных соединений и параметры процесса из `/proc`. При изменении состояния записывает отдельное событие.
- Демон пишет в журнал полученные SIGTERM/SIGINT/SIGHUP, включая завершение по сигналу. Добавлены stack trace при panic в основном процессе и обработчиках соединений.
- Сообщения `use of closed network connection`, возникающие после закрытия второй стороны соединения, теперь отмечаются как локальное закрытие, чтобы не маскировать реальные сетевые ошибки.
- Кнопка действия модуля показывает увеличенный объём журналов и пытается извлечь из `logcat` признаки LMK/OOM. Доступность kernel-логов зависит от прошивки и прав.

**После воспроизведения сбоя:** открой действие (Action) модуля и пришли весь вывод, особенно блоки Watchdog, WebSocket и Kernel/Android kill hints. Не очищай журналы и не переоткрывай WebUI до снятия логов, если это возможно. Автоматические host-тесты прошли, но физический телефон не проверен.

---

# TeleWEB v2.1.14 — DC4 media IP mapping fix

TeleWEB перехватывает TCP-соединения поддерживаемых клиентов Telegram и прозрачно переносит поток через WebSocket. В Telegram не нужно включать прокси. Сборка предназначена для Magisk / KernelSU / APatch на Android ARM64.

## Исправление маршрута медиа DC4 (v2.1.14)

- По журналу пользователя адрес `149.154.165.136` ошибочно классифицировался как `DC2 media=false`.
- Исправлено: адресный блок `149.154.165.x` классифицируется как DC4, а наблюдавшийся media-IP `149.154.165.136` отмечается как media, чтобы выбирать `kws4-1` в приоритете. Это основано на опубликованных логах TDLib, где `149.154.165.111` фигурирует как `MEDIA DcId{4}`; на устройстве ещё требуется проверить.
- Не менялась логика MTProto packet framing и WSS-only.

## Исправление v2.1.2 после ошибки v2.1.1

- Исправлена причина `unsupported MTProto transport tag`: AES-256 ключ obfuscated2 берётся непосредственно из `init[8:40]`, без ошибочного SHA-256-хеширования.
- При разборе заголовка первые 56 байт считаются материалом ключа/IV и не расшифровываются; AES-CTR-поток продвигается на 56 байт, после чего расшифровываются только байты `init[56:64]`.
- Перед расшифровкой транспортных пакетов CTR-поток корректно продвигается на все 64 байта заголовка.
- Добавлены/обновлены тестовые фикстуры под реальную схему obfuscated2. Проверены unit-тесты, race detector, `go vet`, Android ARM64-сборка и целостность ZIP. На физическом устройстве пока не проверено.

## Что изменено относительно v2.1.0

- Исправлена критическая ошибка WSS-фрейминга: исходящий TCP-поток больше не отправляется произвольными чанками `Read()` как WebSocket-кадры. Модуль расшифровывает копию obfuscated2-потока только для определения границ MTProto-пакетов и отправляет каждый пакет отдельным бинарным кадром. Первый кадр содержит все 64 байта obfuscated2-заголовка вместе с первым полным пакетом. Сами исходные зашифрованные байты не меняются.
- Сохранены Cloudflare-маршруты и WSS-only.

## Что изменено относительно v2.0.9

- Сохранён прямой WSS-маршрут `kwsN.web.telegram.org/apiws` и приоритет известного входа `149.154.167.220` для DC2/DC4.
- Первые 64 байта MTProto obfuscation init читаются до выбора маршрута и расшифровываются только для извлечения signed DC ID и media-флага. Это исправляет прежнюю ошибочную классификацию части media IP как DC2/DC4 по одному лишь диапазону адресов.
- После отказа прямого пути используется резервный WSS через Cloudflare-проксируемые домены (`kwsN.<domain>`). Это нужно для сетей, где IP Telegram для DC1/DC3/DC5 недоступны напрямую.
- Неудачный прямой маршрут уходит в 60-секундный cooldown, чтобы каждое новое соединение не зависало на одном и том же недоступном IP.
- Первые 64 байта MTProto obfuscation init буферизуются для извлечения DC ID и media-флага; исходный буфер затем отправляется без изменения. WebSocket-сообщения рассматриваются как один непрерывный поток байтов, как требует транспорт Telegram.
- WSS-only сохранён: **сырого TCP-fallback нет**. Если все WSS-маршруты недоступны, перехваченное соединение закрывается.
- В лог добавляется выбранный прямой или Cloudflare-маршрут.

## Маршрутизация

1. Для DC2/DC4 сначала проверяется известный прямой вход `149.154.167.220:443`, сохраняя правильный TLS SNI/HTTP Host (`kws2` или `kws4`).
2. Для всех DC пробуется обычный KWS-вход, если он не находится в cooldown.
3. Если прямой WSS не работает, проверяются Cloudflare-домены партиями по четыре, чтобы не тратить полный тайм-аут на каждый домен по очереди.
4. Успешный Cloudflare-host кешируется отдельно для каждого DC.

Cloudflare-путь использует TLS к домену Cloudflare и WSS `/apiws`; Cloudflare затем проксирует соединение к Telegram. MTProto остаётся обфусцированным/зашифрованным до Telegram, но оператор домена/Cloudflare может видеть метаданные соединений (например, время, объём и целевой DC). Список встроенных доменов — сторонний, общественный и может устаревать.

## Список Cloudflare-доменов

По умолчанию используется встроенный список общественных доменов, опубликованный в техническом разборе от 10 октября 2026 года. Каждый домен проверяется реальным WSS-рукопожатием, а успешный hostname кешируется для пары DC/media. Список не обновляется автоматически и может устареть.

Чтобы заменить список или указать собственные домены, создай файл:

`/data/adb/teleweb/cf-domains`

Добавляй по одному домену на строку. Строки `#` считаются комментариями. Если файл существует, он **заменяет** встроенный список; не добавляй схему `https://`, поддомены `kwsN` или путь. Пример:

```text
# one domain per line
my-cloudflare-domain.example
another-domain.example
```

Предпочтительнее собственный домен, настроенный на Cloudflare с проксированием DNS-записей `kws1`–`kws5` и режимом SSL/TLS **Flexible**. Если используешь общественные домены, имей в виду, что они управляются третьими лицами и могут перестать работать.

## Диагностика и откат

- Лог: `/data/adb/teleweb/tgws.log`
- Статус/последние строки: кнопка действия модуля.
- Для отката отключи/удали v2.1.0 и верни исходный архив. Не держи одновременно два модуля, устанавливающих перехват Telegram.

## Проверки сборки

Пройдены `go test -race ./...`, `go vet ./...`, кросс-компиляция Android ARM64 и проверка целостности ZIP. **На реальном телефоне эта сборка не тестировалась**, поэтому после установки нужно проверить загрузку изображений и стабильность соединения.

Исходник: `src/main.go`; тесты: `src/main_test.go`. Go engine — MIT.


## v2.1.28 changes

- Restores the original v1.0.0 adaptive route-selection policy in the transparent WSS engine: probe Cloudflare-fronted KWS endpoints after a successful direct connection, cache the fastest route, prefer Cloudflare only when it is at least one-third faster, and re-measure after six hours.
- If direct WSS fails, the selected Cloudflare route is preferred for subsequent connections rather than repeatedly paying the direct timeout. The direct route is reconsidered after the cooldown/route measurement expires.
- Does not send unsolicited client-originated WebSocket Ping frames because observed remote EOF timing tracked the Ping interval. Server-originated Ping frames are still answered with Pong. TCP keepalive remains enabled and the stale-read timeout is 10 minutes.
- Does not replace the transparent Go engine with the original optional `tg-ws-proxy` manual Telegram proxy; the original route-selection policy is adapted to the existing WSS-only transparent path.


## v2.1.31 changes

- Adds an idempotent `ensure` command and a persistent Android service loop (30-second interval). It retries startup after package-manager/iptables boot races and recovers missing daemon/watchdog/rules without opening WebUI or restarting a healthy daemon.
- Logs supervisor recovery/errors to `/data/adb/teleweb/supervisor.log`.

## v2.1.30 changes

- Reverted Obfuscated2 CTR offsets to the previously used v2.1.23 behavior: decrypt the 8-byte encrypted tail at keystream offset 56 and continue payload at offset 64.
- Updated packet-framer and DC parser tests to generate valid headers with the same offsets.
- This directly targets the random `unsupported MTProto transport tag` failures observed in v2.1.29.

## v2.1.29 changes
- Fixed AES-CTR position for MTProto Obfuscated2: the first 56 header bytes are random and unencrypted; the encrypted 8-byte transport tag uses keystream offset 0, and subsequent payload bytes continue at offset 8.
- Corrected both DC/transport-tag detection and packet-framing stream state. The previous implementation incorrectly skipped 56/64 keystream bytes, causing valid client traffic to decrypt as invalid abridged markers such as `0xff`.
- Updated tests to generate valid Obfuscated2 headers and encrypted packet streams using the correct CTR offset.


## v2.1.32 changes

- Avoids forcing reconnects with client-originated WebSocket Ping; uses TCP keepalive plus a 10-minute stale-read timeout to recover genuinely idle/dead tunnels.
- Logs the selected WSS hostname, tunnel age, byte counters and the missing-Pong reason.
- Tracks repeated early remote EOFs per WSS hostname. After two low-volume early EOFs within two minutes, temporarily cools that hostname down for three minutes and clears matching route preferences so reconnects can try another frontend. A single EOF is not enough to penalize a route.
- Keeps the known working MTProto framing/DC mapping and watchdog logic unchanged.
- Automated tests include repeated-EOF route cooldown. Device-level validation is still required.


## v2.1.33 changes

- When the existing WebUI returns to the foreground, it invokes a new idempotent `resume` API command. The command re-applies the Telegram iptables redirect rules and ensures the daemon/watchdog exist, without toggling the module or restarting an already healthy daemon.
- This targets the reported symptom where switching away and back to the already-open WebUI coincides with traffic recovering, despite the daemon staying alive. The cause is not proven yet; device-level validation is required.


## v2.1.38 — background client process protection

The watchdog now periodically finds the installed Telegram client process(es) by exact package command line and UID, then best-effort moves those processes out of the Android cached-app freezer cgroup. Unlike the transport daemon, client app processes are not assigned `oom_score_adj=-1000`; Android retains normal memory-pressure handling. This is a root/OEM-dependent mitigation, not a guarantee of instant notifications: app-owned sockets still depend on the client staying connected, and FCM/system notification policy is outside TeleWEB. Moving an app process to the root cgroup may affect Android scheduling/accounting and can increase background battery use. Check `watchdog.log` for `protect-app:` and `protect:` warnings.


## v2.1.41 — persistent route cache and quiet cache hits

- Saves the last known-good WSS hostname and ranked preflight candidates to `/data/adb/teleweb/route-cache.json`, outside the module directory, so module/daemon restarts do not discard the route pool.
- Loads the cache **before opening the local listener**, so startup connection bursts can use the saved route immediately instead of racing a background scan.
- Starts background route refresh immediately after startup; refresh remains independent of Exteragram activity and repeats every 30 minutes. Failed refreshes do not erase the previously saved pool.
- Successful route choices update the persistent cache atomically. A saved route is still tested on use; if it fails, the engine can fall back to other candidates and refresh the cache.
- Suppresses repetitive “selected saved route” log entries on cache hits. Per-connection tunnel lifecycle logs remain available.
- This fixes route discovery/cache loss across daemon restarts; it does **not** keep authenticated Telegram MTProto sessions alive after Exteragram closes its own sockets, and it does not guarantee push delivery if Android/client push is stopped.
- Host-side Go tests and Android ARM64 cross-build checked; physical-device behavior remains unverified.

## v2.1.40 — background WSS route pool

- Removed the experimental all-UID/global redirect mode; interception is restricted to detected Telegram app UIDs again. On upgrade, stale global jumps are removed when rules are rebuilt.
- The daemon now checks a bounded set of WSS entry points in the background shortly after startup and every 30 minutes, caching reachable candidates ordered by handshake latency. When the direct route fails, it tries cached candidates before doing a new discovery batch.
- The pool caches route candidates, not reusable MTProto tunnels. Each app TCP connection still gets its own WSS tunnel; a transparent proxy cannot safely multiplex unrelated app streams over one WSS connection without implementing the Telegram protocol/session itself.
- Background probing does not guarantee push delivery if Android freezes the Telegram client or the client closes its own long-lived connection.


## v2.1.42 — background notification policy (best effort)

- On watchdog startup and every five minutes, asks Android to whitelist supported Telegram clients from Doze, allow `RUN_IN_BACKGROUND` and `RUN_ANY_IN_BACKGROUND`, and set the standby bucket to `active`. This targets ordinary background restrictions that can interrupt Exteragram's own notification connection.
- Keeps the existing target-process freezer protection; no app process is given `oom_score_adj=-1000`.
- Does not force-launch Exteragram and does not undo Android's explicit force-stop state. It cannot manufacture a Telegram session or guarantee notifications if the app has no live background connection and its push path is unavailable. Check `watchdog.log` for `background-policy:` outcomes.


## v2.1.43 — fast cached-route reconnect rollback

- Reverts the v2.1.42 Android Doze/AppOps/standby-bucket mutations after the user reported worse background connection behavior. Existing daemon and client cgroup freezer protections remain.
- Moves the last known-good cached Cloudflare WSS route and preflighted route pool ahead of direct-ingress attempts, so reconnects do not pay direct-path timeouts before using known working routes.
- Raises early-EOF cooldown threshold from two to five low-volume EOFs, preventing a burst of several sockets closing together from immediately invalidating the saved route. Five repeated early EOFs still trigger a temporary three-minute cooldown.
- Route cache persistence and background preflight remain enabled. This reduces route-selection latency but does not itself keep Exteragram's Telegram session alive when the app closes its sockets.
- Automated tests and Android ARM64 cross-build are required; physical-device verification remains outstanding.


## v2.1.46-lite-clean

- Removed the minute-by-minute DC2 WSS pulse probes; they only opened and closed dummy WebSocket upgrades and did not carry Telegram sessions or improve push delivery.
- Disabled automatic full route-pool scans. Existing persisted route cache/candidates remain usable; new routes are selected on actual client traffic.
- Reduced watchdog polling from 20 to 30 seconds, supervisor checks from 30 to 60 seconds, and status snapshots from 2 to 5 seconds.
- Removed per-log fsync and stopped rereading/trimming the entire log on every event.
- Normal local socket teardown is no longer logged as an error.
- A WSS frontend returning HTTP 502/503/504 is cooled down for three minutes to avoid immediately selecting it again.


### WebUI: память и трафик (v2.1.47)

WebUI показывает текущую резидентную память процесса (RSS), пиковую резидентную память с момента запуска процесса, а также суммарный, отправленный и полученный объём трафика Telegram, прошедшего через WSS. Значения оперативной памяти и трафика сбрасываются при перезапуске демона; это счётчики только текущего запуска, без записи истории на диск.
