# Полное код-ревью TeleWEB — 06.11.2026

**База:** ветка `dev`, HEAD `5c2c4e1` (`chore: drop the stray project overview from the repo root`), версия v0.1.9.
**Объём:** `src/` — 16 084 строк Go, 28 файлов, 206 функций в `main.go`; оболочные скрипты Android, `worker/cloudflare-worker.js`.
**Дополнительно проверено:** ветки `android`, `win`, `linux`, `master` и **опубликованный артефакт** релиза v0.1.9 (скачан и вскрыт).

Репо подтянут: `git fetch --all --prune --tags`. С 31.10 влито **59 коммитов** (v0.1.7 → v0.1.9): IPv6-туннелирование, WinDivert dual-stack, нативный GUI, H2 media bridge, dedupe логов, DC affinity, 429-backoff. Появился второй remote `upstream_regstar` (`Regstar2/tg-ws-proxy-android`) с тегами до `v1.11.7` — в ревью не входит, это отдельная кодовая база.

## Статическая база (всё зелёное)

| Проверка | Результат |
| :--- | :--- |
| `go version` | go1.27.3 windows/amd64 |
| `gofmt -l src/` | чисто |
| `go vet ./...` | чисто |
| `go build ./...` | OK |
| `go test -count=1 ./...` | `ok teleweb 10.1s` |
| `go test -race -count=1 ./...` | `ok teleweb 14.1s` (gcc найден) |
| кросс-сборки | windows/{amd64,386,arm64}, linux/{amd64,arm64,arm}, android/arm64 — **7/7 OK** |

То есть всё ниже — про корректность, а не про сборку. Компилятор, vet и race-детектор это не ловят.

---

## Сводка

| Приоритет | Кол-во | Суть |
| :--- | ---: | :--- |
| **P0** | 1 | В опубликованном v0.1.9 снова включён `GOMEMLIMIT=48MiB` → GC death spiral |
| **P1** | 5 | Отключение проверки TLS, обход WSS при парковке фронтов, blackhole `force_test_dc`, осиротевший демон при выходе из GUI, неоднозначный DC |
| **P2** | 14 | Утечки/конкурентность, обход IPv6, полузакрытие, fail-open WinDivert, неограниченные кэши |
| **P3** | 16 | Дубли и мёртвый код (7 из 18 пунктов прошлого плана не закрыты) |

**Важно про охват:** все находки в Go-ядре (`main.go`, `ws_pool.go`, `socks.go`, `cf_h2.go`, `redirect_windows.go`, `gui_native.go`) присутствуют **в каждой из пяти веток** — проверено по наличию маркеров `frontRetryWaitLimit`, `shouldSkipTLSVerify`, `knownDCMap`, `forceTestDCCached`, `dnsCacheMu.Lock`, `org.telegram.messenger.web`. Ветки черри-пикаются, поэтому фикс надо раскатывать пятью коммитами. `service.sh` с GOMEMLIMIT есть только в `android`.

---

# P0 — release blocker

## F1. `android:service.sh:63` отменяет фикс GOMEMLIMIT в опубликованном v0.1.9

```sh
# android/service.sh
63  export GOMEMLIMIT=48MiB
64  export GOGC=50
```

При этом и в `dev`, и в `android` Go-код **уже исправлен** (`src/main.go:3012`):

```go
func initMemoryTuning() {
    // No forced GOMEMLIMIT: clamping the heap at 48 MB drove the GC into a
    // death spiral whenever media buffers or the socket pool pushed the live
    // heap past the limit (observed as ~220% user CPU on-device).
    if os.Getenv("GOGC") == "" { debug.SetGCPercent(50) }
}
```

Комментарий прямо говорит, что лимит убран; но `GOMEMLIMIT` из окружения рантайм **уважает всегда**, поэтому строка в `service.sh` реактивирует ровно ту регрессию, которую коммит `190c4fc` / `690b9ec` устранял. На устройстве демону снова выставлен жёсткий потолок кучи 48 МБ → при медиа-чанках и прогретом пуле сокетов GC уходит в спираль (~220% CPU, Realme 9 Pro 5G).

**Подтверждено end-to-end:** скачан `teleweb-v0.1.9-multiarch.zip` из релиза `v0.1.9` (опубликован 2026-11-06T01:50:42Z, 14 ассетов), вскрыт — внутри `service.sh:63` с `export GOMEMLIMIT=48MiB`, `module.prop` = v0.1.9/109. То есть баг **в проде**, не только в ветке.

`docs/DIAGNOSTICS.md:27` даже предупреждает: «урезанный лимит спираль только усиливает» — а runbook `docs/RELEASING.md` про проверку `service.sh` не упоминает вообще.

**Что делать:** удалить строку 63 в `android` (оставить `GOGC=50`), добавить в runbook предрелизную проверку `git grep GOMEMLIMIT android -- '*.sh'` и перевыпустить v0.1.10. Это единственная находка, требующая немедленного hotfix.

---

# P1 — трафик и безопасность

## F2. `fronting-sni` отключает проверку сертификата на ВСЕХ маршрутах

`main.go:5267`:
```go
func shouldSkipTLSVerify(host, sni string) bool {
    return !strings.EqualFold(strings.TrimSpace(host), strings.TrimSpace(sni))
}
```
`main.go:5335` применяет это в `finishTLSAndUpgrade`. А `finishTelegramWS` (`5311`) и `finishTelegramWSPath` (`5315`) **обе** передают `honorFrontingSNI=true`. В том числе прямой диалайл по IP (`main.go:4985` внутри `candDirect`). Только `finishWorkerWS` (`5423`) передаёт `false`.

**Триггер:** пользователь создаёт файл `fronting-sni` (документированная функция обхода DPI). После этого `InsecureSkipVerify=true` для cf-фронтов **и для прямых IP-диалов**, хотя SNI-оверрайд нужен только фронтам. On-path DPI или отравленный DNS может terminates WSS с любым сертификатом, демон примет его и отправит весь обфусцированный поток → подмена/дроп/переупорядочивание WS-кадров, рассинхронизация релея, компрометация туннеля. Прямым диалам оверрайд вообще не нужен, но они теряют аутентификацию тоже.

**Фикс:** сузить skip-verify до кандидатов, реально использующих оверрайд; для direct и worker оставить проверку включённой. Лучше — пинить ожидаемый SPKI вместо полного отключения.

## F3. Ожидание «все фронты припаркованы» не покрывает собственные парковки

Константы `main.go:4441-4454`:
```go
serverBusyRetry     = 1500 * time.Millisecond
frontTimeoutPark    = 5 * time.Second
frontRetryWaitLimit = 2 * time.Second
```
Проверка `main.go:4843`: `if ... wait > 0 && wait <= frontRetryWaitLimit { подождать }`.

**Триггер:** волна таймаутов провайдера (в логе от 28.10 за 8 секунд легло 40 из 41 пары «домен × DC») паркует все фронты на 5 с; WAF 429 даёт `routeBackoff(1) = 30s` (`main.go:187`). `wait` = 5…30 с > 2 с → ожидание **пропускается** → `frontCandidatesForRace` отфильтровывает все фронты → список кандидатов = только direct IP, которые на цензурируемых сетях заблокированы → мгновенный обрыв на срок до 5 минут. Ровно тот сценарий, для которого в патче от 31.10 добавляли ожидание; константа осталась от эпохи, когда парковка была только 1.5 с.

**Фикс:** ждать до ближайшего освобождения в пределах оставшегося бюджета `ctx` (12 с), а не фиксированных 2 с; и никогда не парковать 100% фронтов от одного общего класса ошибок — оставлять ≥1 диалимый.

## F4. `force_test_dc` по-прежнему гарантированный blackhole (известно с 28.10, не исправлено)

`main.go:3472`: `isTestDC := forceTestDCCached() || dc >= 10000` — флаг применяется **ко всем DC**. В `dialTelegramWS`:
- `4919`: `isTest` → только `dcSpecs[dc].testIP`;
- `4995`: `if !isTest { cf-фронты }` — фронтовка выключена целиком;
- `dcSpecs[4]` и `dcSpecs[5]` (`main.go:4168-4175`) **не имеют `testIP`**;
- `4842`: ожидание парковки тоже `if !isTest`.

**Триггер:** `force_test_dc=1` без своего Worker → DC4/DC5 дают `len(candidates)==0` → `no available routes`, соединение рвётся сразу; DC1-3 идут только на тестовые IP без фронтовки. Это главная причина инцидента из первого разбора лога 28.10 — рекомендация «не отключать фронтовку при `force_test_dc` и не применять его к DC без `testIP`» в код так и не попала.

**Фикс:** применять флаг только когда у DC есть `testIP`; сохранять cf-фронты как fallback; не выключать ожидание парковки.

## F5. Выход из нативного GUI оставляет демон и WinDivert работать без UI

`gui_native.go:111` — `cmdGui()` вызывает `startSignalLogger()`, но **не регистрирует ни одного shutdown-хука**. `main.go:517-526`: сигнал → `runShutdownHooks()` (список пуст) → `os.Exit(0)`. При этом `stopServer()` вызывается только в колбэке трея «Quit» (`gui_native.go:131`), а все остальные выходы — `os.Exit` (`132`, `147`, `149`), что пропускает `defer cleanup()` (`:118`) и `defer trayCleanup()` (`:135`).

**Следствие:** Ctrl+C в консоли GUI → процесс GUI умирает, а дочерний `tgws serve` + WinDivert-перехват продолжают работать с уже удалённой иконкой трея (`Shell_NotifyIcon(NIM_DELETE)` в `win32_gui_windows.go:409` не выполняется → «призрачная» иконка). Пользователь теряет управление трафиком.

**Фикс:** зарегистрировать хуки (`trayCleanup`, `cleanup`, `stopServer`) в `cmdGui`; заменить `os.Exit` на канал выхода, чтобы `defer` отработали.

## F6. `149.154.174.100` числится и в DC1, и в DC3 → неверная маршрутизация

`main.go:3292` — `knownDCMap["149.154.174.100"] = 1`. При этом IP входит в `dcSpecs[1].candidates` (`4149`) **и** в `dcSpecs[3].candidates` (`4161`). Guard `main.go:3482` отбрасывает распарсенный DC, если он противоречит `knownDCMap`.

**Триггер:** клиент подключается к общему ingress `149.154.174.100:443` с корректным `dc=3` в init → `known=1 != 3` → `parsed=false` → `dcFor(orig)` вернёт 1 → туннель уйдёт на `kws1.*`. Auth-ключ DC3 на DC1 не примут → обрыв соединения/медиа.

**Фикс:** не считать общие ingress-адреса авторитетными; доверять тегу из init, используя IP только как тай-брейкер, либо убрать неоднозначные IP из `knownDCMap`.

---

# P2 — утечки, конкурентность, надёжность

| ID | Место | Дефект и сценарий |
| :--- | :--- | :--- |
| **F7** | `main.go:3189`, `ws_pool.go:51-67,190-204` | `initGlobalWsPool(context.Background())` — `p.cancel` в проде **никогда не вызывается** (только в тестах: `main_test.go:1857,2202`, `memory_leak_test.go:179`). `p.ctx.Done()` всегда nil → goroutine `StartRotation` и до `poolSize` прогретых FDs живут до смерти процесса. Shutdown-хук (`3166-3172`) не отменяет и не дренит. |
| **F8** | `main.go:517-526,3166-3210` | `os.Exit(0)` в обработчике сигнала пропускает **все** `defer` в `serve()`: `ln.Close()` (`3205`), `ln6.Close()` (`3208`), `lf.Close()` (`3179`), `defer stopRedirector()` (`3233`), три `ticker.Stop()`. `startCFDomainsUpdater`/`initGlobalWsPool`/hourly-sweep стартуют **до** `net.Listen` (`3186-3199`) и не имеют teardown на early-return `3203`. Хуки идемпотентны (`507`), но покрывают только redirector/rules/pid. |
| **F9** | `redirect_windows.go:687-706` | `redirectorMu.Lock()` удерживается через `tryUnloadWinDivertService()`: `mgr.Connect()`/`s.Control(Stop)` (`670-677`) или 3× `exec.CommandContext(ctx,"sc.exe","stop")` по 1 с (`680-684`). Конкурентный `startRedirector()` / `localRedirectorHealthy()` (watchdog, status) встаёт на секунды. Вызывается при каждом `stopServer()`, даже когда `activeRedirector == nil`. Вынести выгрузку сервиса из критической секции. |
| **F10** | `main.go:4033-4077` | `dnsCacheMu.Lock()` держится на время `exec.Command("getprop").Output()` + до 4 `getprop` + `os.ReadFile("/etc/resolv.conf")`. По истечении TTL 45 с первый caller блокирует все остальные `systemDNSResolver()` → периодический скачок задержки на Android под нагрузкой. Считать `out` вне лока, под локом — только swap. |
| **F11** | `main.go:3256-3261`, `socks.go:34-44` | Accept-циклы: `if err != nil { logf(...); continue }` без backoff. При EMFILE/ENFILE `Accept()` возвращает ошибку **немедленно и повторно** на живом listener → busy-spin и залив лога. Это опровергает «осознанно принятый» пункт `FIX_PLAN:268-269` («busy-loop возможен только при закрытом listener»). Добавить `errors.Is(err, net.ErrClosed) → return` + `time.Sleep(50ms)`. |
| **F12** | `main.go:2012-2020,2453-2465` | Ошибка `ip6tables` логируется **один раз** (`2019`), `rulesHealthy()` проверяет только `telegramV4` → watchdog не ретраит. Транзиентный `xtables.lock` на буте = весь IPv6-трафик Telegram (`2001:b28::/32`, `2a0a:f280::/32`) идёт **мимо WSS до конца жизни демона**. Пункт 2.1 прошлого плана выполнен по букве, но не по смыслу. Нужен отдельный IPv6-флаг состояния + ретрай на следующем тике. |
| **F13** | `main.go:3760-3805,3840-3852` | Оба релея вызывают `closeBoth()` при первом же `io.EOF` в любой стороне; `isNeutralError(io.EOF)` лишь подавляет лог, не закрытие. Half-close клиента → WSS закрывается мгновенно, финальный ответ не дописывается. Нужно `CloseWrite()` только получателю и дать обратной стороне дочитать до EOF (idle-watchdog как предохранитель). |
| **F14** | `redirect_windows.go:432-434,487-499,822-828` | `parseTCPv6` требует `pkt[6] == 6` — IPv6-пакеты с extension headers (Hop-by-Hop, Dest-Opts, Routing, Fragment) не разбираются → идут напрямую, минуя WSS. При исчерпании NAT-портов (`e == nil` из `natGetOrCreateV6`) пакет **реинжектится неизменённым** (`return false`) → fail-open, лог прямо говорит «escapes the tunnel». Парсить цепочку next-header; на исчерпании дропать, а не пропускать. |
| **F15** | `main.go:5171-5189` vs `5435`, `cf_h2.go:57-83` | `cfDialSem` (cap `maxConcurrentCFDials`) берётся только в `dialCFHost` (`5185`). `dialCFWorker` и H2-POST идут мимо → «глобальный» лимит рукопожатий не глобальный: worker + 4 фронта = 5, плюс H2-посты → тот самый 429-шторм, ради которого лимит вводили в v0.1.7, и он же питает F3. |
| **F16** | `main.go:1933-1936` | `_ = os.Rename(tmp, dst)` — ошибка проигнорирована, но `learnedDCDirty = false` выставляется **безусловно**. Провал rename (Windows AV/лок, ENOSPC) → карта выученных DC никогда не пересохранится + осиротевший `.tmp`. Тихая потеря данных. |
| **F17** | `main.go:1892-1904,1971-1982` | `loadLearnedDCs` не ограничивает число записей и **не** повторяет `isTelegramAggregate`-проверку (только сверку с `knownDCMap`, `1894`). Файл, отравленный билдом до фикса 1.2, загружается как доверенный; cap 256 живёт только на пути записи и только по порядку `UpdatedAt`, без expire по времени. |
| **F18** | `main.go:4616,4637,4659,4673`, `4478,4713,5154` | Жёсткие лимиты `routeHealth`/`h2Fails`/`directDialFails`/`cdn203Fails` = 256 enforced **только** в hourly `sweepRouteCaches()`. Пути записи не ограничены → между свипами карты не ограничены. Ключом может быть произвольный `custom-cf-worker`/`custom-cf-domain` из конфига (`594,679-687`), т.е. строка, заданная пользователем. |
| **F19** | `main.go:2996-3008` (`ListenAndServe` на `3005`) | `maybeStartPprof`: `go http.ListenAndServe(addr, nil)` без `ReadHeaderTimeout`/`Read/Write/IdleTimeout` — зависший loopback-клиент держит handler-goroutine бесконечно. Opt-in + loopback, поэтому низкий приоритет; в `webui.go:38` таймаут есть. |
| **F20** | `gui_native.go:1` | Build-tag `//go:build nativegui` **без `windows`**, тогда как `setupSystemTray`, `acquireSingleInstance`, `applyWindowsDarkTheme`, `restartElevated`, `updateSystemTray` определены только в `win32_gui_windows.go` с `//go:build windows && nativegui` (проверено: по одному определению, стабов нет). `GOOS=linux -tags nativegui` не слинкуется. Добавить `windows` в тег. |

---

# P3 — дублирующийся и мёртвый код

| ID | Место | Что |
| :--- | :--- | :--- |
| D1 | `main.go:3608-3665` | Два идентичных стека negative-cache: `cdn203BlockedRecently/MarkFail/MarkReachable` (30 s) и `directDialBlockedRecently/MarkFail/MarkReachable` (60 s). Одинаковые `map[string]time.Time` + mutex + `time.Now().Before` + `.Add(backoff)`; каждая константа используется ровно один раз. Вынести `failCache`. |
| D2 | `main.go:3726-3748` и `3810-3832` | `pipeTCPToTCP` и `pipeWSTunnel` дословно дублируют `sync.Once`+`closeBoth`+`stopIdle`, `lastActivity atomic.Int64`, 30-секундный тикер и 5-минутный idle-watchdog. `runIdleWatchdog` отсутствует → **пункт 3.4 плана не закрыт**. |
| D3 | `main.go:4317-4360` и `cf_h2.go:406-429` | `append` + `XORKeyStream` + `nextPacketSize` + shrink 128 KiB продублированы; комментарий `cf_h2.go:425` сам это признаёт («like `mtprotoPacketFramer.feed` does»). Расхождение: `feed` синхронно урезает `f.raw`, H2 — только `plain`. `popPackets` отсутствует → **пункт 3.5 не закрыт**. |
| D4 | `embed_assets_windows_{386,amd64,arm64}.go:17-19` | `subEmbedded` байт-в-байт повторён трижды; теги взаимоисключающие. Вынести в один `//go:build windows` файл. |
| D5 | `main.go:536-543` и `631-638` | `writeEnabled` — дословная копия `writeFlag` (отличается только имя файла). При этом `readEnabled` (`529`) расходится с `readFlag` правилом default (`== "1"` против `!= "0"`). Свести запись и задокументировать расхождение чтения. |
| D6 | `main.go:3605-3665` | Две пары констант backoff + дублирование логики (см. D1). |
| D7 | `gui_native.go:40,43` | `colSecondary`, `colOutline` — по 1 вхождению (объявление), ни одного использования. |
| D8 | `sys_windows.go:127,136`, `sys_other.go:64-78`, `sys_linux.go:177,192` | `serverListening`, `setReuseAddr`, `startConsole`, `isAndroidRuntime`, `killProcessForce` продублированы попарно/дословно между платформами. |
| D9 | `win32_gui_windows.go:58-61` | Осиротевший комментарий про `attachParentConsole` — дословная копия дока из `sys_windows.go:46-49`; функции в этом файле нет. |
| D10 | `redirect_windows.go:588-593` | Док `v6CoverageNotice` утверждает, что IPv6 «cannot be intercepted» и «leave unproxied», хотя теперь есть `buildOutboundFilterV6` (`432`), `processOut6` (`811`), `out6Loop` (`855`) и лог `658` «Telegram IPv6 -> [::1]». Функция вызывается только на путях отказа/выключения (`646,652,662`), поэтому текст контекстуально верен, но как общее утверждение — устарел. |
| D11 | `main.go:5708` | Последняя строка файла — осиротевший `// compile-time references for code paths shared by Linux/Android.` (**4.2 не закрыт**). |
| D12 | `main.go:840` | `{"org.telegram.messenger.web", "Telegram Web"}` — несуществующий пакет (**4.3 не закрыт**). |
| D13 | `main.go:2044-2045` | «does not install new IPv6 redirects», хотя `2013` ставит `ip6tables` через `iptSetup`, а cleanup дёргает `ip6tables` на `2046/2048` (**4.4 не закрыт**). |
| D14 | `worker/cloudflare-worker.js:59,131` | Двойной `upstream.closed.catch` (**4.5 не закрыт**). |
| D15 | `main.go:3942-3957` | `mediaForIP` — хардкод media-IP без обещанного комментария «bootstrap, не расширять руками» (**3.6 не закрыт**). |
| D16 | `main.go:1623` / `3309` | `telegramV6` (4 широких префикса) и `telegramV6Subnets` (DC-специфичные /64 и /48) частично перекрываются. Это **не** точный дубль — вторые являются уточнением первых для `dcFor`, поэтому приоритет ниже, чем в пункте 3.2; достаточно комментария о связи. |

---

# Статус плана от 03.11.2026

| Пункт | Статус | Доказательство |
| :--- | :--- | :--- |
| 1.1 forged CDN203 / open proxy | ✅ FIXED | `main.go:3695` guard `isCDN203IP`; `serveConn:3513-3520` отказ; `socks.go:127` требует `isTelegramEndpoint`/`V6`, спекулятивный port-allow убран |
| 1.2 `learnDC` guard | ✅ FIXED с пробелом | `main.go:1946` reject `!isTelegramAggregate`; но загрузка из файла не проверяется → F17 |
| 2.1 лог ошибки ip6tables | ✅ по букве / ❌ по трафику | лог `2019` есть; нет ретрая → F12 |
| 2.2 `appCacheMu` | ✅ FIXED | `installedApps:1548-1594` через `discoverMu`, скан вне `appCacheMu` |
| 2.3 семафор H2 POST | ✅ FIXED | `cf_h2.go:233-250,393` cap 16, acquire до `go func`, release через defer |
| 2.4 fail-fast потерянного POST | ✅ FIXED | `cf_h2.go:364-372`: первый `r.data == nil` → `bridgeCancel()` |
| 2.5 счёт download-байт | ✅ FIXED | `cf_h2.go:357` считает `len(encoded)` |
| 3.1 `buildStatus` | ✅ FIXED | `main.go:2666`, оверлеи `liveMetrics`/`statusMetrics` |
| 3.2 один источник IPv6 CIDR | ✅ FIXED | `main.go:1623` `telegramV6` → `telegramV6Prefixes` → `socks.go:191`; `telegramParsedSubnetsV6` удалён |
| 3.3 парсер tcp6 | ✅ FIXED | `main.go:955-971` 32-hex, цикл по `/proc/net/tcp` + `tcp6` (`1007`), тест `main_test.go:2884` |
| 3.4 `runIdleWatchdog` | ❌ OPEN | D2 / F13 |
| 3.5 `popPackets` | ❌ OPEN | D3 |
| 3.6 комментарий `mediaForIP` | ❌ OPEN | D15 |
| 4.1 `WsPool.Close` | ✅ FIXED | метода нет, `ws_pool.go` заканчивается `Stats` |
| 4.2 / 4.3 / 4.4 / 4.5 | ❌ OPEN | D11 / D12 / D13 / D14 |

**Итог:** 11 из 18 пунктов закрыты, 7 остаются (все косметические, кроме D2/D3).

**Два «осознанно принятых» допущения плана устарели:**
- «serve() accept-loop continue безопасен» (`FIX_PLAN:268-269`) — опровергнуто F11 (EMFILE на живом listener).
- «workerCooldowns без чистки — bounded» (`263-264`) — janitor появился (`main.go:4681-4688`, hourly), но жёсткого cap нет, а ключом может быть произвольный worker-домен (F18).

---

# Проверено и признано корректным

Чтобы ревью не выглядело как список страшилок, вот что проверено отдельно и **нормально**:

- **CTR/поток WSS:** `mtprotoPacketFramer.feed` (`4317`) XOR-ит только параллельный инспекционный буфер, а исходные зашифрованные байты пересылает verbatim — испортить пересылаемый поток состоянием шифра нельзя. `writeFull` (`5608`) / `readFrame` (`5621`) корректно обрабатывают short write, partial read, length-prefix и фрагментацию.
- **H2 sequencer:** `cf_h2.go:161-177,458` — один writer, монотонный уникальный seq, `respData % 4 == 0` (`219`), `replyCh`/`h2InFlight` cap 16, `defer bridgeCancel()`.
- **Пул сокетов:** `ws_pool.go:76-113` отбрасывает `r.Buffered() > 0` и пробует сокет на чужие байты; сокеты одноразовые → утечки состояния между клиентами нет.
- **Штрафы маршрутов:** `withBackgroundDial` (`ws_pool.go:159`) + `ctx.Err() != nil` → `shouldPenalizeRoute` (`4499`) не наказывает ни рефилы пула, ни проигравшие гонки. `raceCandidates` (`4739-4803`) имеет буферизованный `resCh`, `defer cancelAll()` и закрывает поздних победителей.
- **Ограниченные кэши (с janitor):** `doh.go:102-119` (TTL + 256→128, `http.Client{Timeout:2s}`), `cf_h2.go:46-55` (cap 8 + `CloseIdleConnections`, Timeout 65 s), `desktop.go:27-62` (`selfDialJanitor` 30 с), `redirect_windows.go:340-385` (`natJanitor`/`pruneFlows`, все 6 хендлов закрываются), `main.go:2285-2312` (`protectWarnings` cap 128), лог-dedupe (`63-65,378-448`, однопозиционный, под `logMu`), `sync.Pool` для буферов (`81-92`), `cfgFileCache` (~10 фиксированных ключей).
- **TLS/WS handshake:** `finishTLSAndUpgrade` закрывает `raw` на всех ошибочных путях (`5348,5357,5362`), снимает дедлайн на успехе (`5365`); `dialCFHost`/`dialCFWorker` отменяют контекст на каждой ветке (`5223,5234,5242,5499,5513`).
- **Allowlist воркера:** `worker/cloudflare-worker.js:12-22` точно совпадает со всеми `dcSpecs[].workerDst` (`main.go:4150-4176`) плюс testIP и DC203; токен проверяется (`40-42`), `destination not allowed` → 403. Контракт не разошёлся.
- **WebUI:** `webui.go:84-98` — проверка `Host`, `Origin`, `Sec-Fetch-Site`; `loopbackName` только 127.0.0.1 / localhost / ::1; `ReadHeaderTimeout: 5s`. CSRF/DNS-rebinding закрыты.
- **SOCKS5:** `socks.go:127` отклоняет любой не-Telegram destination независимо от порта; `handleCDN203` (`3695`) требует `isCDN203IP`. Открытого прокси нет.
- **WinDivert:** `prefixLast` bit-shift (`redirect_windows.go:406`) корректен; WinDivert-фильтры и NAT-таблица tear down идемпотентны.

---

# Порядок действий

1. **Немедленно (P0):** убрать `GOMEMLIMIT=48MiB` из `android/service.sh`, добавить проверку в `docs/RELEASING.md`, выпустить v0.1.10. Пока не сделано — любой Android-пользователь v0.1.7–v0.1.9 подвержен GC-спирали, несмотря на «исправленный» Go-код.
2. **До следующего релиза (P1):** F2 (TLS), F3 (wait limit), F4 (force_test_dc), F5 (GUI shutdown), F6 (DC ambiguity). F4 и F3 — прямое продолжение разбора логов 28.10, оба воспроизводимы без устройства.
3. **Батч надёжности (P2):** F7/F8 (единый graceful shutdown с отменой контекста пула и отказом от `os.Exit`), F9/F10 (вынести subprocess'ы из-под локов), F11 (backoff в accept), F12/F14 (IPv6-обход), F16/F17/F18 (кэши и rename).
4. **Косметика (P3):** закрыть 7 оставшихся пунктов плана от 03.11 одним коммитом `chore: drop dead code` + отдельным `refactor:` для D2/D3.
5. **Раскатка:** все Go-правки — в `dev`, затем cherry-pick в `android`/`win`/`linux`/`master` (проверено: маркеры присутствуют во всех пяти). `service.sh` правится только в `android`.

Ничего не менял в коде: запрос был на ревью. Репо после `fetch` остался с чистым рабочим деревом.
