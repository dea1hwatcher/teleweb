# Перепроверка код-ревью от 06.11.2026 — 07.11.2026

**Исходный отчёт:** `docs/CODE_REVIEW_2026-11-06.md` (база `dev` `5c2c4e1`, v0.1.9).
**Текущая база:** `dev` `55b773f`, HEAD всех веток подтянут (`git fetch --all --prune --tags`).
**Запрос:** перепроверить пункты, поскольку их «выполнял другой агент».

---

## Краткий вердикт

| Категория | Было в ревью | Закрыто | Осталось |
| :--- | ---: | ---: | ---: |
| **P0** | 1 | **1** | 0 |
| **P1** | 5 | 0 | **5** |
| **P2** | 14 | 0 | **14** |
| **P3** | 16 | 0 | **16** |
| Итого | 36 | **1** | **35** |

**Другой агент закрыл ровно один пункт — P0 (F1, `GOMEMLIMIT`).** Остальные 35 находок
подтверждены заново по исходникам на всех пяти ветках. Плюс сам фикс P0 привнёс
**одну новую проблему** (см. N1) и релиз v0.1.10 собран корректно.

---

## Что именно сделал тот агент

Все коммиты с 06.11 после моего ревью (по датам, без исторического расхождения веток):

| Коммит | Ветка | Содержание | Относится к ревью |
| :--- | :--- | :--- | :--- |
| `50c25d1` | android | `fix(android): stop exporting GOMEMLIMIT from service.sh` | ✅ **закрывает F1 (P0)** |
| `0082dd2` / `f13aedb` / `a8a89e4` / `6cc94d0` | dev / android / win / linux | `fix(core): keep the log tail out of status.json again` | ❌ отдельный регресс-фикс v0.1.9, **не из ревью** |
| `55b773f` / `73f365d` / `f112a44` / `5f99cf3` | dev / win / linux / master | `docs: make the GOMEMLIMIT grep a pre-release gate` | ⚠️ моя рекомендация, но **реализована с дефектом** (N1) |
| `8149a2f` + changelog-коммиты + `0d530e8` | android / win / linux / master | релиз **v0.1.10** (110), `update.json: v0.1.10` | ✅ следствие фикса F1 |

На `dev` с момента ревью всего **2 новых коммита** (`0082dd2`, `55b773f`) — ни один не
касается P1/P2/P3. Платформенные ветки уехали на v0.1.10, но только за счёт тех же
фиксов, черри-пикнутых своими хешами.

---

## F1 (P0) — ЗАКРЫТ, подтверждено end-to-end

`android/service.sh:63` теперь вместо экспорта содержит поясняющий комментарий:

```sh
# No GOMEMLIMIT here on purpose. A hard heap ceiling drove the collector into a
# death spiral on media bursts (the ~220% CPU incident on Realme), and the Go
# runtime honours this variable even though the code no longer sets it ...
export GOGC=50
```

Проверено на трёх уровнях:

1. `git show android:service.sh` — активного `export GOMEMLIMIT` нет, `GOGC=50` на месте.
2. Скачан и вскрыт **опубликованный** `teleweb-v0.1.10-multiarch.zip`
   (релиз `v0.1.10`, 2026-11-06T21:04:58Z, 14 ассетов): активного экспорта нет,
   `module.prop` = v0.1.10/110, 19 файлов.
3. `git grep -n "SetMemoryLimit" <ветка> -- 'src/*.go'` — в проде **0 вызовов**,
   только `main_test.go:209,211` (`debug.SetMemoryLimit(-1)` в регресс-тесте,
   который как раз сторожит повторное появление клампа).

То есть регрессия v0.1.7–v0.1.9 реально устранена в проде. **Это хорошая работа.**

### ⚠️ N1 (новое, P2): предрелизный gate в runbook невыполним

`docs/RELEASING.md:35` предписывает:

```
git grep -n GOMEMLIMIT android -- '*.sh'
```

и говорит «**должен быть пуст (комментарии не в счёт)**». Но `git grep` не знает,
что такое комментарий shell. Реальный результат на текущем `android`:

```
android:service.sh:63:# No GOMEMLIMIT here on purpose. A hard heap ceiling drove the collector into a
exit code = 0
```

То есть gate **всегда возвращает совпадение** и выглядит как провал — ровно из-за того
комментария, который тот же коммит добавил. Если кто-то последует инструкции буквально,
он решит, что регрессия вернулась, и начнёт «чинить» корректный скрипт.

Дополнительно: gate **не автоматизирован** — `git grep -l GOMEMLIMIT <ветка> -- '.github/*'`
пусто во всех четырёх релизных ветках. Это только текст в runbook, который человек
может пропустить (ровно так и случилось с v0.1.7–v0.1.9).

**Исправление (одна строка):** матчить только активный экспорт, например

```sh
git grep -nE '^\s*export\s+GOMEMLIMIT' android -- '*.sh'   # должен быть пуст
```

и добавить этот же шаг в `.github/workflows/release.yml` ветки `android` перед сборкой
zip (fail-fast). Тогда регрессия не пройдёт в CI ни при каком агенте.

---

## P1 — все 5 остаются открытыми

| ID | Текущее место (`dev`) | Статус и доказательство |
| :--- | :--- | :--- |
| **F2** | `main.go:5271` | `shouldSkipTLSVerify` по-прежнему `return !strings.EqualFold(host, sni)`; `finishTelegramWS`/`Path` передают `honorFrontingSNI=true`, прямой диалайл `:4989` идёт через них → `InsecureSkipVerify` на всех маршрутах при `fronting-sni`. |
| **F3** | `main.go:4453,4458`, `:4847` | `frontTimeoutPark = 5s`, `frontRetryWaitLimit = 2s`, guard `wait <= frontRetryWaitLimit` — без изменений. Парковка 5 с / 429-бэкофф 30 с по-прежнему пропускает ожидание. |
| **F4** | `main.go:3476`, `:4155,4161,4167`, `:4999` | `isTestDC := forceTestDCCached() \|\| dc >= 10000` применяется ко всем DC; `testIP` есть только у DC1–DC3; cf-фронты под `if !isTest`. Blackhole для DC4/DC5 сохраняется. |
| **F5** | `gui_native.go:109-152` | `cmdGui()` вызывает `startSignalLogger()` и **не** регистрирует ни одного хука (`grep registerShutdownHook gui_native.go` → пусто); `os.Exit(0)` на `:132,:149`. Демон+WinDivert остаются при Ctrl+C. |
| **F6** | `main.go:3296` + `:4153,4165` | `knownDCMap["149.154.174.100"] = 1`, при этом IP в `dcSpecs[1].candidates` и `dcSpecs[3].candidates`; guard `:3486` отбрасывает parsed DC. |

Подтверждено не только по маркерам, но и чтением тел функций — семантика не менялась.

## P2 — все 14 остаются

Маркеры присутствуют в `dev`, `android`, `win`, `linux`, `master` (где применим файл):

`F7` `initGlobalWsPool(context.Background())` (`main.go:3193`) · `F8` `runShutdownHooks(); os.Exit(0)`
(`main.go:521-528`) · `F9` `redirectorMu` вокруг `tryUnloadWinDivertService()` · `F10`
`dnsCacheMu.Lock()` на время `getprop` (`main.go:4037`) · `F11` accept-loop без backoff ·
`F12` лог IPv6-ошибки один раз (`main.go:2019`) + IPv4-only `rulesHealthy` · `F13` `defer closeBoth()`
на первом EOF · `F14` `pkt[6] != 6` и `escapes the tunnel` (fail-open NAT) · `F15`
`acquireCFDialSlot` только в `dialCFHost` · `F16` `_ = os.Rename` + `learnedDCDirty=false`
(`main.go:1934`) · `F17` `learnedDCs.Store` без cap/aggregate-check на загрузке · `F18`
`for len(routeHealth) > 256` только в hourly-свипе · `F19` `http.ListenAndServe(addr, nil)`
(`main.go:3010`) без таймаутов · `F20` `//go:build nativegui` без `windows`.

Windows-специфичные пункты (`F5`, `F9`, `F14`, `F20`) отсутствуют в `android`/`linux`
лишь потому, что там нет этих файлов — это ожидаемо, а не исправление.

## P3 — все 16 остаются

Дубли negative-cache (`cdn203FailBackoff` / `directDialFailBackoff`), каркас обоих релеев,
framer-дубль в `cf_h2.go:409-425` (комментарий на `:425` так и гласит
«like mtprotoPacketFramer.feed does»), три копии `subEmbedded`, `writeEnabled` == `writeFlag`,
неиспользуемые `colSecondary`/`colOutline`, дубли платформенных стабов
(`serverListening`/`startConsole` в трёх файлах), осиротевшие комментарии
(`win32_gui_windows.go:58`, `redirect_windows.go:588`), последняя строка `main.go:5712`,
phantom-пакет `:840`, устаревший комментарий cleanup `:2044`, двойной `closed.catch` в
`worker/cloudflare-worker.js:59,131`, `mediaForIP` без bootstrap-комментария.

## Статус `docs/FIX_PLAN_2026-11-03.md` — не изменился

Файл не трогали с коммита `f9cb069`. По-прежнему **11 из 18 закрыты**, 7 открыты:
`runIdleWatchdog` и `popPackets` отсутствуют в коде (3.4, 3.5), комментарий `mediaForIP`
не добавлен (3.6), `compile-time references` / `org.telegram.messenger.web` /
`does not install new IPv6 redirects` / двойной `catch` на месте (4.2–4.5).

---

## Валидация после чужих правок

| Проверка | Результат |
| :--- | :--- |
| `gofmt -l src/` | чисто |
| `go vet ./...` | чисто |
| `go test -count=1 ./...` | `ok teleweb 9.99s` |
| `git status --short` | только неотслеженный `docs/CODE_REVIEW_2026-11-06.md` |

Кросс-сборки и `-race` перепрогонять не стал: менялись только `service.sh`, `docs/` и
статусный оверлей, Go-код ядра в этих коммитах не затрагивался.

**Релиз v0.1.10 собран корректно:** 14 ассетов, notes подтянуты из changelog (про
`GOMEMLIMIT` и `status.json`), `update.json` на `master` = v0.1.10/110, раздел changelog
есть во всех четырёх ветках. Мелочь: `module.prop` на `master` всё ещё v0.1.8, на
`win`/`linux` v0.1.6 — косметика, эти ветки модуль не собирают.

---

## Итог и что делать дальше

1. **F1 закрыт и подтверждён в проде** — претензий нет.
2. **N1 починить обязательно**: заменить grep в `docs/RELEASING.md:35` на матч активного
   `export` и перенести проверку в `.github/workflows/release.yml` (`android`). Иначе gate
   либо всегда «красный», либо снова будет пропущен человеком.
3. **35 пунктов по-прежнему открыты.** Приоритет тот же: F2 (TLS), F3 (ожидание парковки),
   F4 (`force_test_dc`), F5 (shutdown GUI), F6 (DC), затем батч P2.
4. Все Go-фиксы раскатывать пятью cherry-pick'ами — маркеры присутствуют в `dev`,
   `android`, `win`, `linux`, `master`.
5. `docs/CODE_REVIEW_2026-11-06.md` остаётся **незакоммиченным** — тот агент его в git не
   добавил. Если отчёт нужен в репозитории, его надо закоммитить отдельно.

Ничего не менял: запрос был на перепроверку. Рабочее дерево не тронуто.

---

# Пункты реализованы — 07.11.2026 (коммиты на `dev`)

После перепроверки реализованы N1 и все пять P1. Каждый пункт закрыт на уровне
семантики кода, а не лога, и прикрыт регресс-тестом.

| ID | Коммит | Что сделано | Тест |
| :--- | :--- | :--- | :--- |
| **N1** | `3ce2d2f` | Шаблон gate заменён на `^[[:space:]]*export[[:space:]]+GOMEMLIMIT` (комментарий больше не срабатывает) и зашит шагом `Reject a forced GOMEMLIMIT` в workflow `release` — релиз с экспортом падает в CI | `TestLaunchScriptsDoNotExportGOMEMLIMIT` (skip вне android) |
| **F2** | `c4987f4` | Прямые диалы и worker больше не применяют fronting-sni (`finishTelegramWSPath` → `false`); CF-фронты сохраняют оверрайд, но вместо слепого `InsecureSkipVerify` подключён `verifyFrontingPeerChain` — цепочка обязана сойтись к системному хранилищу | `TestFrontingSNIScopedToFrontDials`, `TestFrontingPeerChainVerifierRejectsSelfSigned` |
| **F3** | `c4987f4` | `frontRetryWaitLimit = frontTimeoutPark` (5 s, был 2 s); пауза зажимается по остатку бюджета клиента с резервом 2 s; при полностью припаркованном пуле `frontCandidatesForRace` возвращает один фронт вместо схлопывания в direct-only | `TestClampFrontRetryWait`, `TestFrontCandidatesForRaceKeepsOneFrontWhenAllParked` |
| **F4** | `c4987f4` | `testDCRouting(dc, force, explicit)` применяет `force_test_dc` только к DC1–DC3; DC4/DC5 и явный тестовый тег без `testIP` уходят в production-маршрутизацию вместо нуля кандидатов; защитная нормализация и в `dialTelegramWS` | `TestTestDCRouting` |
| **F5** | `2ce0033` | `cmdGui` регистрирует `stopServer` + `trayCleanup` + single-instance как shutdown-хуки (через `sync.Once`); tray-quit и закрытие окна вызывают `runShutdownHooks` → демон, WinDivert и иконка трея больше не осиротевшие | `TestShutdownHooksRunOnce` (механизм; GUI-файл под `-tags nativegui`) |
| **F6** | `c4987f4` | `sharedIngressIPs` (вычисляется из `dcSpecs`) + `dcInitContradictsKnownIP`: для IP из нескольких DC-кандидатов (149.154.174.100) тег init-заголовка главнее маппинга; guard применяется и в `loadLearnedDCs` | `TestDCInitContradictsKnownIP` |

## Валидация

| Проверка | Результат |
| :--- | :--- |
| `gofmt -l src/` | чисто |
| `go vet ./...` | чисто |
| `go test -count=1 ./...` | `ok teleweb 9.4s` (97 PASS, 7 новых) |
| `go test -race -count=1 ./...` | `ok teleweb 13.5s` |
| кросс-сборки | windows amd64/386/arm64, linux amd64/arm64/arm, android arm64 — OK |
| `-tags nativegui` (windows/amd64) | OK |
| CI-gate против `android` | PASS (exit 1) |

Найденный в процессе дефект теста: `TestFrontCandidatesForRaceKeepsOneFrontWhenAllParked`
первый прогон падал, потому что в `frontCandidatesForRace` просачивалась DC-affinity,
оставшаяся от других тестов (здоровый preferred-фронт легитимно становился единственным
кандидатом). Тест изолирован через `dcDomainAffinityMu`.

## Раскатка и пуш — 07.11.2026

| Ветка | Диапазон | Cherry-picks | Примечание |
| :--- | :--- | :--- | :--- |
| `dev` | `55b773f..3ce2d2f` | исходные | base |
| `android` | `8149a2f..161b0a7` | core + CI-gate (GUI-коммит пропущен: нет `gui_native.go`) | gate в workflow `release` — там собирается модуль; runbook перенумерован (пункт 4) |
| `win` | `bed00ea..efa2783` | все три | без шага валидации module.prop (desktop-only); gate добавлен |
| `linux` | `00b6703..090a8ca` | core + CI-gate (GUI пропущен) | |
| `master` | `1f9941a..68fc987` | merge `dev` | чистый merge без конфликтов |

Все 5 веток запушены. CI после пуша: `desktop-build` master success, `desktop-build`
linux success, `desktop-e2e` linux success — код собирается в CI на всех затронутых
платформах. Специфика валидации по веткам: `android` и `linux` не содержат Windows-слоя,
поэтому хостовая сборка (GOOS=windows) у них не проходит — это свойство ветвей, а не
регресс; обе валидированы так же, как их собирает CI (`GOOS=linux` vet + test-binary).

Осталось:
- **Не выпущено**: версия не поднималась; следующий релиз (v0.1.11) подтянет всё сразу.
- P2/P3 из ревью (F7–F20, D1–D16) не тронуты.
- Оба отчёта (`docs/CODE_REVIEW_2026-11-06.md`, этот файл) остаются незакоммиченными.

---

# P2 и P3 реализованы — 07.11.2026 (`dev` `abd0aca`)

Закрыты все 14 пунктов P2 и 16 пунктов P3. Каждый P2-фикс проверен сборкой,
тестами и `-race`; для четырёх добавлены регресс-тесты.

## P2

| ID | Что сделано |
| :--- | :--- |
| **F7** | `initGlobalWsPool`/`startCFDomainsUpdater` получают отменяемый контекст; shutdown-хук делает `drainAll()` + отмену, прогревшие сокеты больше не живут до смерти процесса |
| **F8** | слушатели `ln`/`ln6` закрываются через хуки — graceful stop освобождает порты детерминированно, а не полагается на `os.Exit` |
| **F9** | `tryUnloadWinDivertService()` вынесен из-под `redirectorMu` — выгрузка драйвера через SCM/`sc.exe` больше не блокирует `startRedirector` и status/watchdog |
| **F10** | обнаружение DNS (`getprop` + `/etc/resolv.conf`) вынесено из-под `dnsCacheMu`; лок только на подмену кэша |
| **F11** | `acceptPause()`: закрытый listener останавливает цикл, EMFILE/ENFILE даёт паузу 50 мс вместо busy-spin; цикл `tcp6` больше не умирает на транзиентной ошибке |
| **F12** | ошибка `ip6tables` ставит флаг, watchdog ретраит раз в 5 минут (`retryFailedIPv6Rules`) вместо «IPv6 мимо WSS навсегда» |
| **F13** | `pipeTCPToTCP` делает `CloseWrite()` на EOF: half-close клиента больше не обрывает финальный ответ (WS-путь сохраняет полное закрытие — в WebSocket half-close невыразим) |
| **F14** | `ipv6TCPHeaderOffset()` обходит цепочку extension-заголовков (Hop-by-Hop, Routing, DestOpts, Fragment, AH); при исчерпании NAT-портов пакет **дропается** (`v6Drop`), а не утекает напрямую |
| **F15** | `dialCFWorker` берёт тот же `cfDialSem`, что и фронты |
| **F16** | провал `os.Rename` сохраняет `learnedDCDirty=true`, удаляет `.tmp` и пишет в лог |
| **F17** | `loadLearnedDCs` перепроверяет записи через `isTelegramAggregate` и ограничивает набор `learnedDCCap` (256) |
| **F18** | `routeHealthCap` + `capRouteHealthLocked`/`capFailMapLocked` на путях записи; `failCache.expireOlderThan` в свипе |
| **F19** | pprof-сервер получил `ReadHeaderTimeout`/`Read`/`Write`/`Idle` таймауты |
| **F20** | `gui_native.go` → `//go:build windows && nativegui` |

## P3

| ID | Что сделано |
| :--- | :--- |
| **D1** | `failCache` (mu + map + backoff + `size`/`clear`/`expireOlderThan`); `cdn203Fails` и `directDialFails` — его экземпляры |
| **D2** | `startIdleWatchdog()` — один тикер/идл-проверка на оба релея |
| **D3** | `popPackets()` — единый цикл кадрирования для WSS и H2; H2-путь теперь рвёт сессию на ошибке кадрирования вместо расшифровки мусора |
| **D4** | `subEmbedded` в одном `embed_sub_windows.go` вместо трёх копий |
| **D5** | `writeEnabled` → `writeFlag`; расхождение default у `readEnabled` задокументировано |
| **D6** | удалены неиспользуемые `colSecondary`/`colOutline` |
| **D7/D16** | связь `telegramV6` ↔ `telegramV6Subnets` описана комментарием |
| **D9** | удалён осиротевший комментарий `attachParentConsole` |
| **D10** | переписан устаревший док `v6CoverageNotice` |
| **D11** | удалена висячая последняя строка `main.go` |
| **D12** | удалён несуществующий пакет `org.telegram.messenger.web` |
| **D13** | переписан устаревший комментарий cleanup про IPv6 |
| **D15** | добавлен bootstrap-комментарий `mediaForIP` |
| **D14** | **не удалён, а задокументирован**: `upstream.closed.catch(() => {})` до апгрейда — это защита от unhandled rejection в окне между `connect` и обработчиком `shutdown(1011)`, а не дубль |
| **D8** | **частично**: `serverListening` в `sys_linux.go` намеренно читает `/proc/net/tcp` (проба создавала фейкового клиента в логе), поэтому три реализации не идентичны. Объединять windows+other ради 8 строк ценой нового build-tag файла — не стоит; оставлено с комментарием в отчёте |

## Валидация

| Проверка | Результат |
| :--- | :--- |
| `gofmt -l src/` | чисто |
| `go vet ./...` | чисто |
| `go test -count=1 ./...` | ok 9.2 s |
| `go test -race -count=1 ./...` | ok 13.1 s |
| кросс-сборки ×7 | OK (windows amd64/386/arm64, linux amd64/arm64/arm, android arm64) |
| `-tags nativegui` (windows/amd64) | OK |

Новые/обновлённые тесты: `TestParseTCPv6` (цепочки Hop-by-Hop и Fragment),
`TestV6LoopbackRewriteBothDirections`/`TestV6FiltersAndInterceptDecision` (переведены на
`v6Verdict`), `TestSweepRouteCaches_BoundedMapsAndH2Success` (через `failCache`).
