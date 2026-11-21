# Код-ревью `dev` — 18.11.2026

База: `dev` `acd4d73b` (v0.2.3). Проверены `src/` (22 422 строки Go),
`worker/cloudflare-worker.js`, `webroot/index.html`, платформенные слои.
Метод: четыре независимых фокусных ревью (трафик/безопасность, утечки и
конкурентность, дубли и мёртвый код, платформы/WebUI) + ручная сверка каждой
находки по исходнику. Апстримы подтянуты; прямые фиксы оттуда непереносимы
(Python/Kotlin), но темы совпали (stale sockets, SNI vs Host, H2 media).

## Валидация

| Проверка | Результат |
| :--- | :--- |
| `gofmt -l src/` | чисто |
| `go vet ./...` | чисто |
| `go test -count=1 ./...` | ok 4.19 s |
| `go test -race -count=1 ./...` | **флейк**: 3/5 прогонов падают с `ThreadSanitizer failed to allocate 1843396608 bytes (error code 1455)` — это нехватка памяти в окружении, не data race ( GOPATH/TSan shadow memory). Причина находок ниже не в этом. |
| кросс-сборки windows amd64/386/arm64, linux amd64, darwin/amd64, `-tags nativegui` | OK |

## Сводка

| Severity | Кол-во | Что |
| :--- | :--- | :--- |
| P0 | 0 | — |
| P1 | 4 | allowlist-дыра в CDN203 по порту, неограниченный буфер H2-ответов, NAT по одному порту, `os.Exit` при elevate |
| P2 | 8 | detached ArrayBuffer в Worker, срыв stagger-гонки, logMu под fsync, IPv6-фрагменты, гонки в GUI, чужой системный прокси, рассинхрон API/CLI, startup-дубли |
| P3 | 6 | мёртвый `dcCounts`, неиспользуемый `pid`, дубли PoP-телеметрии, хардкод DC2, `isPidAlive` на Darwin, WebUI-poll в фоне |

---

## P1

### P1-1. CDN203: allowlist проверяет только IP, туннель идёт на произвольный порт

`src/main.go:5099-5105`, `:5132`, `:5194-5195`.

```go
if !isCDN203IP(orig.Addr()) { ... return }        // проверен только IP
dst := net.JoinHostPort(orig.Addr().String(), strconv.Itoa(int(orig.Port())))
...
remote, err := trackedDial(ctx, "tcp4", dst, 3*time.Second)
```

Правило iptables (`main.go:2481`) и Windows `v6InterceptTarget` (`redirect_windows.go:478`)
перехватывают Telegram-подсети **без `--dport`**. Клиент может открыть
`tcp://91.105.192.100:8080` (порт из `91.105.192.0/23`); первый кадр не MTProto →
`handleCDN203` → direct TCP на клиентский порт. Это нарушает инвариант №5
(`AGENTS.md`): allowlist остаётся allowlist'ом. Не P0 только потому, что IP
ограничен CDN-диапазоном.

**Фикс:** требовать `orig.Port() == 443` (или вообще не брать порт из `orig`, а
диалить `cdn203IP:443`); тест `TestCDN203RejectsNon443Port`.

### P1-2. H2 media bridge: `h2ReplySequencer.buffered` растёт без границ

`src/cf_h2.go:177-204`, `:390`, `:445`, `:547`.

`buffered[seq] = body` — нет ни лимита записей, ни лимита байт, ни таймаута
ожидания «дыры». `h2InFlight=16` ограничивает параллельные POST, но не число
выданных seq: пока seq=0 висит до 15 s, остальные ответы складываются в map.
Тело — до `maxWSFrame` (16 MiB). Десятки ответов по мегабайту → OOM на Android.
WSS-путь от этого защищён, H2 — нет.

**Фикс:** `bufferedBytes` + лимит (~32 записи / 4 MiB), при превышении —
`bridgeCancel()`; либо не выдавать следующий seq, пока предыдущий не сфазирован.

### P1-3. WinDivert: возвратный поток ищется по одному порту

`src/redirect_windows.go:459`, `:984`, `:1057`.

```go
e := natReturnEntry(m.dport)   // без проверки кортежа
```

Фильтр ловит любой loopback-пакет `127.0.0.1:17841 → 127.0.0.1:<nat_port>`.
Если расширен dynamic port range (частая «правка» при port exhaustion), порт
NAT-пула пересекается с эфемерными — чужое соединение переписывается на
`Telegram IP → client:port`, таймеры легитимного потока портятся.

**Фикс:** выделять NAT-порты вне dynamic range; в `retLoop`/`ret6Loop`
проверять полный кортеж, а не только `dport`.

### P1-4. `restartElevated()` выходит через `os.Exit`, минуя teardown

`src/win32_gui_windows.go:296-299`, вызов из `gui_native.go:348-352`.

```go
if r > 32 { os.Exit(0) }
```

Не выполняется `defer teardown()` (`gui_native.go:162`): не зовутся
`stopServer()`, `trayCleanup`, `stopRedirector()`. Дочерний `tgws serve`
остаётся не-elevated, WinDivert не поднимается —透明ный режим сломан до
полного рестарта; mutex и трей не снимаются.

**Фикс:** сначала `runShutdownHooks()`, потом `os.Exit(0)`.

---

## P2

### P2-1. Worker: бинарные кадры пишутся из detachment-views

`worker/cloudflare-worker.js:81`, `:108-124`.

`server.binaryType = "arraybuffer"`, `chunk = new Uint8Array(data)` — это
**view**, а не копия. Кадр кладётся в `pending`-цепочку и пишется после возврата
из `message`-handler; Worker runtime может отсоединить буфер → в TCP уходят
урезанные/пустые данные → CTR-десинхронизация и обрыв сессии. Blob-веть уже
копирует (`await data.arrayBuffer()`).

**Фикс:** копировать синхронно в хендлере: `new Uint8Array(data.slice(0))`
(для view — `new Uint8Array(data).slice()`).

### P2-2. `dialTelegramWS`: `timer.Reset` срывает stagger

`src/main.go:6828-6870`. Ветка `<-timer.C` стартует кандидата и делает
`Reset(stagger)`; ветка `<-resCh` при быстром отказе тоже зовёт `startNext()` +
`timer.Reset(stagger)`. Если кандидаты отказывают быстрее 250 мс (403/refused —
обычно 100–200 мс), таймер никогда не срабатывает: гонка вырождается в
последовательный перебор. При 10 кандидатах клиентский бюджет 12 s истекает
до рабочего маршрута в конце списка.

**Фикс:** не двигать таймер в `case res`; хранить `nextStartAt` и переставлять
таймер только на абсолютную точку.

### P2-3. `logMu` удерживается на fsync и ротации

`src/main.go:984-985`, `:1015-1029`. Каждая 64-я запись при логе >256 КБ делает
`Sync + ReadFile(128K) + Truncate + Write + Sync` под глобальным `logMu`.
На Android flash — десятки мс, блокируются все `logf`, включая hot path релеев.

**Фикс:** под локом только подготовка строки/счётчиков, ротация — отдельной
горутиной или отдельным `rotateMu`.

### P2-4. IPv6 Fragment: не проверяется fragment offset

`src/redirect_windows.go:566-571`.

```go
case 44: next = int(pkt[off]); off += 8
```

Для не-первого фрагмента `Next Header=6` тоже ведёт в `parseTCPv6`, который
читает `sport/dport/flags` из полезной нагрузки. PMTU-фрагментация к Telegram
IPv6 создаёт ложные NAT-записи с мусорными портами (съедают пул) и портит пакеты.

**Фикс:** проверять `binary.BigEndian.Uint16(pkt[off+2:off+4]) >> 3 != 0` → pass through.

### P2-5. Гонки в GUI: виджеты и `saveMsg` вне `st.mu`

`gui_native.go:282-284` (poll-горутина, под лок) против `:1227-1228`,
`:1284-1292` (UI-поток, без лока). `refresh()` каждые 1.5 s зовёт
`ed*.SetText`, пока рендер делает `Layout`/`.Text()` на тех же `widget.Editor`.
Аналогично `saveMsg`/`saveMsgTime`.

**Фикс:** не трогать виджеты из poll-горутины; хранить строки в `st`, применять
`SetText` в `FrameEvent`; читать `saveMsg` под локом.

### P2-6. Windows «Сброс сети» выключает чужой локальный прокси

`src/sys_windows.go:193-207`: `strings.Contains(proxyServer, "127.0.0.1")`
отключает `ProxyEnable` у Fiddler/другого VPN/dev-сервера.

**Фикс:** парсить порт и отключать только если он совпадает с нашим `defaultPort`.

### P2-7. `status()` (CLI) теряет часть полей — рассинхрон с API

`main.go:3785-3803` (`liveMetrics`) против `:3834-3860` (`status()`).
`LogSuppressed` копируется только в `liveMetrics`; `grep` — ровно 3 вхождения
(объявление, `liveMetrics`, тест). `tgws status` всегда показывает `0`, хотя
демон пишет ненулевое значение в `status.json`.

**Фикс:** один `overlayFrom(file Status)` для обеих ветвей + тест паритета полей.

### P2-8. Последовательность старта продублирована в 5 местах

`restoreDaemon()` `:3409`, `resume` `:3902`, `set` `:3923`, `boot` `:4217`,
`runDesktop()` `desktop.go:165`. Таймауты 4 s против 6 s, ретраи `setupRules`
только в `boot`, `protectTargetAppProcesses()` — не везде.

**Фикс:** один `startRuntime(timeout, withRetries)`; специфику оставить в вызовах.

---

## P3

1. **`main.go:63,118-122`** — мёртвый `dcCounts` (записей нет) и `statsMu`, его охраняющий. Удалить.
2. **`main.go:3077`** — `processFrozen(pid int, entry ...)`: `pid` не используется в теле; убрать параметр и править 2 вызова.
3. **CF-Ray/PoP телеметрия** — три копии (`cf_h2.go:231-238`, `main.go:7649-7656`, `main.go:7155-7158`) + ручной `SplitN`. Один `noteCFRay()`.
4. **DC2 хардкод** — `main.go:7674`, `:7845`, `:8079`: `149.154.167.51` вместо `dcSpecs[2].workerDst`.
5. **`sys_other.go:31-37`** — `isPidAlive` через `os.FindProcess` на Darwin всегда успешен; мёртвые PID считаются живыми.
6. **WebUI** (`webroot/index.html:4894`) — `setInterval(refresh, 3000)` не ставится на паузу в скрытой вкладке; лишний трафик/батарея на мобильных.

Дополнительно: `capFailMapLocked()` (`main.go:6737`) удаляет первый попавшийся
ключ, а не самый старый — при переполнении выбрасывает свежие записи.|(MEDIUM)

---

## Что проверено и **не** является дефектом

- Allowlist SOCKS5: входящего SOCKS-листенера нет; `outbound.go:187` — исходящий dialer.
- TLS: `finishTelegramWSPath` и `finishWorkerWS` вызывают `finishTLSAndUpgrade` с проверкой; `InsecureSkipVerify` только на CF-фронтах с `fronting-sni` + `verifyFrontingPeerChain`.
- `frontCandidatesForRace`: fallback гарантирует ≥1 фронт; 1015/1027_category корректно мапируются; RU PoP включает SVO/ROV/KZN.
- `decryptMTProtoInit`/`feed`/`popPackets`: CTR сдвигается ровно на 56+8, новые байты не перешифровываются; границы проверены.
- `stopRedirector()` не держит `redirectorMu` на `sc.exe`; `v6Drop` и fail-close на месте; CSRF/DNS-rebinding и XSS-экранирование в WebUI корректны.
- Утечек `net.Conn`/`Body`/тикеров на error-путях не найдено; `outbound.go` SOCKS fallback — латентный, но недостижимый код.

## Рекомендуемый порядок фиксов

1. **P1-1** (allowlist-дыра) и **P1-2** (OOM на Android) — перед следующим релизом.
2. **P1-3**, **P1-4** — Windows-ветка, нужны на реальном железе.
3. **P2-1** (Worker) и **P2-2** (stagger) — заметно влияют на стабильность сессий.
4. Остальное — плановой чисткой.

Отчёт подготовлен без правок исходников.


---

## Перепроверка 18.11.2026 (после публикации отчёта)

Повторная сверка по исходникам уточняет две находки:

1. **P2-5 (GUI) сужен.** `renderRoutingPage()` (`gui_native.go:1224-1230`)
   **уже** читает `saveMsg`/`saveMsgTime`/`busy` под `st.mu`. Ложное утверждение
   отчёта про `saveMsg` снимается. Реальная гонка остаётся только на виджетах
   `widget.Editor`: `guiPollLoop()` вызывает `SetText` раз в 1.5 с
   (`gui_native.go:282-284`), а UI-поток делает `material.Editor(...).Layout()`
   (`gui_native.go:1377-1381`) без блока — Gio-виджеты не потокобезопасны.
   Плюс `st.st` читается в poll-goroutine (`:247-253`) и в рендере (`:828`,
   `:1469`) без лока, хотя `refresh()` пишет её под локом (`:272`).
2. **P1-1 (CDN203) уточнён.** `orig` пришёл из `SO_ORIGINAL_DST`
   (`sys_linux.go:146`, `sys_windows.go:133` → `natLookup`), то есть из
   **исходного порта назначения**, который клиент действительно запросил.
   Значитitects сценарий «клиент диалит 91.105.192.100:8080» корректен, но
   на Android/Linux iptables-правило перехватывает только если пакет дошёл до
   демона; на Windows natGetOrCreate создаёт запись с `orig.Port()` из
   перехваченного SYN. Уязвимость сохраняется, но эксплуатируется только
   локально/в туннели через уже разрешённый CIDR.

Всё остальное (P1-2, P1-3, P1-4, P2-1…P2-4, P2-6…P2-8, P3) подтверждено
повторной сверкой. Race-флейк — `ThreadSanitizer failed to allocate`, не data race.
