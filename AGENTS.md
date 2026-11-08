# AGENTS.md

Инструкции для AI-агентов и контрибьюторов, работающих с этим репозиторием.
Проект: **TeleWEB** — Go-демон, который прозрачно заворачивает трафик Telegram
(MTProto) в WebSocket-сессии через Cloudflare. Один и тот же Go-код живёт в пяти
ветках: Android-модуль (Magisk/KernelSU/APatch) и desktop (Windows/Linux).

Текущее состояние проекта, архитектура и история — в [MEMORY.md](MEMORY.md).
Релизный runbook — в [docs/RELEASING.md](docs/RELEASING.md).

---

## 1. Ветки — сначала прочитай это

Ветки **не мержатся между собой**, а черри-пикаются: один логический фикс живёт
в каждой ветке своим хешем (разные patch-id из-за смещений строк).

| Ветка | Роль | Содержит |
| :--- | :--- | :--- |
| `dev` | **основная рабочая ветка**. Всё новое делается здесь | полное кроссплатформенное дерево |
| `android` | модуль Magisk/KernelSU/APatch; **создаёт релиз** | без desktop-слоя |
| `win` | Windows desktop | без `redirect_windows.go`/`win32_gui_windows.go` |
| `linux` | Linux desktop | без Windows-слоя |
| `master` | витрина для устройств: `update.json` + `changelog.md` | = `dev` + merge-коммиты |

**Перед любой правкой выполни `git branch --show-current`.** Правка, сделанная
не в той ветке, стоит часа на переписывание истории (так уже случалось).

Порядок работы: правка в `dev` → коммит → cherry-pick (`-x`) в `android`/`win`/`linux`
→ `master` получает изменения мержем `dev`.

Чего в ветках **нет** (и это нормально, а не поломка):

- `android` и `linux` не содержат Windows-слоя: `redirect_windows.go`,
  `win32_gui_windows.go`, `embed_assets_windows_*.go`, `gui_native.go`.
  При черри-пике таких файлов git выдаёт `DU` — разрешай через
  `git rm --cached <path>` **и удаляй рабочую копию**: `git rm --cached` на файле,
  которого нет в HEAD, оставляет его как untracked.
- `dev` не содержит релизных метаданных: `module.prop`/`update.json` там
  заморожены на старой версии. Версия поднимается только в `android`.

---

## 2. Сборка и проверки

Всё живёт в `src/`. Минимальный набор перед коммитом:

```sh
cd src
gofmt -l .                 # должно быть пусто
go vet ./...
go test -count=1 ./...     # не из кэша: тесты кэшей и пулов
go test -race -count=1 ./...
```

Кросс-сборки (то, что реально собирает CI):

```sh
for spec in "windows amd64" "windows 386" "windows arm64" \
            "linux amd64" "linux arm64" "linux arm" "android arm64"; do
  set -- $spec
  GOOS=$1 GOARCH=$2 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /dev/null . || echo "FAIL $1/$2"
done
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags nativegui -o /dev/null .   # GUI
```

### Ловушка валидации платформенных ветвей

На `android` и `linux` **нельзя** запускать `go test`/`go vet` с хостовым
`GOOS=windows` (по умолчанию на Windows-машине): ветки не содержат Windows-слоя,
и сборка падает на `undefined: redirectorSupported`, `ensureRedirector`,
`stopRedirector` и т.п. Это свойство ветвей, а не регресс.

Валидируй так же, как это делает CI этих ветвей:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /dev/null .   # тип-чек тестов
```

---

## 3. Релиз

Полный runbook — `docs/RELEASING.md`. Кратко:

1. В `android`: поднять `module.prop` (`version`, `versionCode`), `update.json`,
   добавить раздел `### Изменения в vX.Y.Z:` первым в `changelog.md`.
2. Тот же раздел добавить в `changelog.md` веток `win`, `linux`, `master` —
   notes релиза собираются из changelog **своей** ветки и перезаписываются.
3. Коммит `chore: release vX.Y.Z` + тег `vX.Y.Z` в `android` → CI создаёт релиз
   и обновляет `update.json` на `master`.
4. `workflow_dispatch` workflow `release` в `win`, затем в `linux` с input `tag` —
   они прикрепляют desktop-ассеты.
5. Проверить, что в релизе **14 ассетов** (1 модуль + 9 Windows + 4 Linux).

**Пуш** (глобальный credential helper в неинтерактивной оболочке виснет):

```sh
GCM_INTERACTIVE=never GIT_TERMINAL_PROMPT=0 \
  git -c credential.helper=manager push origin <branch>
```

Секретов в репозитории нет и быть не должно: креды берутся из Git Credential
Manager, токены в файлы не пишутся.

---

## 4. Соглашения по коду

- Коммиты — conventional, **однострочный subject**; тело допустимо для крупных
  батчей. Подпись: `git commit -s`.
- Переводы строк — **только LF** (`.gitattributes` пинит `eol=lf`). Скрипты,
  пишущие файлы на Windows в текстовом режиме, добавляют CRLF; проверяй
  `tr -cd '\r' < file | wc -c` (должно быть 0). `grep` для поиска CR не годится.
- Документация и комментарии в коде — по-русски, идентификаторы — по-английски.
- Новый код идёт с регресс-тестом, если баг воспроизводим без устройства.

### Где что лежит

| Файл | Ответственность |
| :--- | :--- |
| `src/main.go` | ядро: перехват, диспетчеризация DC, WSS-релей, пул, маршруты, iptables, watchdog, API |
| `src/cf_h2.go` | H2 media bridge (POST на Cloudflare) |
| `src/ws_pool.go` | пул предпрогретых WSS-сокетов |
| `src/socks.go` | SOCKS5-листенер и allowlist Telegram-адресов |
| `src/doh.go`, `src/cf_update.go` | DoH-резолвинг, обновление списка фронтов |
| `src/redirect_windows.go` | WinDivert: перехват IPv4/IPv6, NAT-таблица |
| `src/sys_*.go`, `src/redirect_other.go` | платформенные примитивы |
| `src/gui_native.go`, `src/win32_gui_windows.go` | нативный GUI (`-tags nativegui`, только Windows) |
| `src/webui.go`, `webroot/` | WebUI и его API |
| `worker/cloudflare-worker.js` | собственный Cloudflare Worker (allowlist назначений) |
| `docs/` | runbook, диагностика, разборы инцидентов |

---

## 5. Жёсткие правила (нарушение = регресс в проде)

1. **Не экспортировать `GOMEMLIMIT`** в скриптах запуска. Рантайм уважает эту
   переменную, даже если код её не ставит: в v0.1.7–v0.1.9 из-за
   `export GOMEMLIMIT=48MiB` в `service.sh` демон уходил в GC-спираль (~220 % CPU).
   Единственная разрешённая ручка — `GOGC`. Проверка в CI:
   `git grep -nE '^[[:space:]]*export[[:space:]]+GOMEMLIMIT' -- '*.sh'` (пусто).
2. **Не отключать проверку TLS**. `InsecureSkipVerify` допустим только на
   Cloudflare-фронтах с явным `fronting-sni`, и там обязателен
   `verifyFrontingPeerChain` (цепочка до системного хранилища). Прямые диала и
   Worker проверяются всегда.
3. **Парковка фронтов не должна оставлять ноль кандидатов.**
   `frontCandidatesForRace` обязан вернуть хотя бы один фронт: иначе список
   схлопывается до direct-IP, которые в цензурируемой сети заблокированы.
4. **`force_test_dc` применяется только к DC, у которых есть `testIP`** (DC1–DC3).
   Для DC4/DC5 это гарантированный ноль маршрутов.
5. **Allowlist остаётся allowlist'ом.** SOCKS5 и `handleCDN203` не должны давать
   туннель на произвольный адрес: проверка `isTelegramEndpoint`/`isCDN203IP`
   обязательна. Это уже было P0-дырой (открытый прокси).
6. **IPv6-пакеты нельзя терять молча.** Если пакет является материалом для
   туннеля, но замапить его не удалось — он дропается (`v6Drop`), а не уходит
   напрямую: иначе трафик утекает мимо WSS.

---

## 6. Тесты: изоляция состояния

Пакет — один на всё приложение, поэтому глобальное состояние течёт между тестами.
Уже ловили: `TestFrontCandidatesForRaceKeepsOneFrontWhenAllParked` падал, потому
что `getDCDomainAffinity(2)` возвращал preferred-фронт, оставленный другим тестом.

Правило: тест, который читает глобальные кэши (`routeHealth`, `dcDomainAffinity`,
`cfDomains`, `learnedDCs`, `workerCooldowns`), обязан сначала их изолировать
(сохранить → очистить → `defer` восстановить).

---

## 7. Внешние репозитории

`upstream_regstar` (`Regstar2/tg-ws-proxy-android`) — **другая кодовая база**
с тегами до v1.11.x. Она не связана с этим деревом: не путать её теги и ветки
с нашими `v0.1.x` и не черри-пикать оттуда без явной задачи.
