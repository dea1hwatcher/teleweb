# MEMORY.md — состояние проекта TeleWEB

Активный снимок: **что собрано, что работает, где что лежит**. Инструкции по
работе с репозиторием — [AGENTS.md](AGENTS.md), порядок релиза —
[docs/RELEASING.md](docs/RELEASING.md), история fixes — [changelog.md](changelog.md).

Обновлено: **07.11.2026 → 15.11.2026**, текущий релиз **v0.2.3** (versionCode 203).

---

## 1. Что это

Go-демон `tgws`, прозрачно заворачивающий MTProto-трафик Telegram в WebSocket
через anycast-адреса Cloudflare и собственный Worker. Один исходник живёт в
пяти ветках: Android-модуль (Magisk/KernelSU/APatch/SukiSU) и desktop
(Windows, Linux). Ядро — `src/main.go`, всё в `package main`.

Два транспорта:
- **WSS-релей** (`src/main.go`, `src/ws_pool.go`) — основной путь, предпрогретый пул;
- **H2 media bridge** (`src/cf_h2.go`) — POST-мост для медиа через Cloudflare.

Перехват: `iptables`/`ip6tables` на Android/Linux, WinDivert на Windows
(`src/redirect_windows.go`). WebUI — `src/webui.go` + `webroot/`.

## 2. Ветки и версии (на 15.11.2026)

| Ветка | HEAD | Роль |
| :--- | :--- | :--- |
| `dev` | `acd4d73b` | основная рабочая; полное кроссплатформенное дерево |
| `android` | `2047b544` | модуль, создаёт релиз; `module.prop` = v0.2.3/203 |
| `win` | `2dabc71a` | Windows desktop |
| `linux` | `54e16082` | Linux desktop |
| `master` | `7ddde431` | витрина: `update.json` v0.2.3/203 + changelog |

Все пять веток синхронны с `origin` (fetch 18.11.2026), рабочее дерево чистое.
Последний тег — `v0.2.3` (15.11.2026). `module.prop` на `master` намеренно
заморожен на v0.2.2 — обновляет только `update.json`, это не рассинхрон.

Ветки **не мержатся**, а черри-пикаются (`-x`) из `dev`; `master` получает
изменения мержем `dev`. Подробности — раздел 1 в `AGENTS.md`.

### Дополнительные remote'ы (не наши релизы)

`upstream_flowseal`, `upstream_mirrly`, `upstream_regstar`,
`upstream_spatiumstas`, `upstream_valnesfjord` — **чужие кодовые базы** со
своими тегами (вплоть до v2.7.0 в локальном пространстве тегов). Не путать с
нашими `v0.1.x`/`v0.2.x`, не черри-пикать без явной задачи.

## 3. Вехи

| Версия | Дата | Суть |
| :--- | :--- | :--- |
| v0.1.7–v0.1.9 | 31.10–06.11 | регресс `GOMEMLIMIT=48MiB` в `service.sh` → GC-спираль ~220 % CPU |
| v0.1.10 | 06.11 | убрали экспорт; остался `GOGC=50` + CI-gate |
| v0.1.11 | 07.11 | P1 (TLS/фронты/GUI) + P2 (F7–F20) + P3 (D1–D16), 14 ассетов |
| v0.1.12 | 07.11 | нативный WinUI 3 на Windows, отказ от WebUI на десктопе |
| v0.1.13 | 08.11 | hotspot/tethering, актуальные CIDR, обход RU PoP |
| v0.1.14 | 09.11 | H2-медиа, User CA, WSS-races, DNS-приватность, обучение DC |
| v0.2.0 | 10.11 | circuit breaker для медиа, изоляция локальных outage, zero-copy |
| v0.2.1 | 10.11 | исключён зонд `194.221.250.50/32`, fast-fail для non-MTProto |
| v0.2.2 | 12.11 | режимы скрытия по таксономии bindhosts, фикс Android 17 / KSU Next |
| v0.2.3 | 15.11 | коды CF 1015/1027, PoP SVO/ROV/KZN, guard CDN203, backoff+jitter |

Разборы: `docs/CODE_REVIEW_2026-11-06.md`, `docs/CODE_REVIEW_RECHECK_2026-11-07.md`,
план — `docs/FIX_PLAN_2026-11-03.md` (все закоммичены).

## 4. Жёсткие инварианты (кратко)

1. **Никакого активного `export GOMEMLIMIT`** в `.sh` — только `GOGC`.
   Gate: `git grep -nE '^\s*export\s+GOMEMLIMIT' -- '*.sh'` → пусто.
2. **TLS не отключать**: `InsecureSkipVerify` только на фронтах с `fronting-sni`
   и обязательной проверкой цепочки; прямые диалы и Worker — всегда с проверкой.
3. **Парковка фронтов не оставляет ноль кандидатов** (`frontCandidatesForRace`).
4. **`force_test_dc` только для DC1–DC3** (есть `testIP`), иначе чёрная дыра.
5. **Allowlist остаётся allowlist'ом**: `isTelegramEndpoint`/`isCDN203IP`
   обязательны в SOCKS5 и `handleCDN203` (была P0-дыра открытого прокси).
6. **IPv6-пакеты не утекают молча**: не замапированный материал → `v6Drop`.

Полный список — раздел 5 `AGENTS.md`.

## 5. Тесты и состояния

Пакет один на всё приложение → глобалы текут между тестами. Тесты, трогающие
`routeHealth`, `dcDomainAffinity`, `cfDomains`, `learnedDCs`, `workerCooldowns`,
`domainLastPoP`, `globalMediaCircuitBreaker`, обязаны сохранить/очистить/восстановить
состояние через `defer`. Не использовать `time.Sleep` для ожидания таймаутов —
синхронизироваться на `<-ctx.Done()`.

Проверка перед коммитом: `gofmt -l .`, `go vet ./...`, `go test -count=1 ./...`,
`go test -race -count=1 ./...`, кросс-сборки ×7 + `-tags nativegui`.
На `android`/`linux` с Windows-хоста проверять через `GOOS=linux go vet` +
`GOOS=linux go test -c` (отсутствие Windows-слоя — свойство ветки).

## 6. Окружение

LF только (`.gitattributes`), CRLF проверять `tr -cd '\r' < file | wc -c`.
`python` здесь не понимает `/tmp` — временные файлы писать в рабочую папку.
Пуш: `GCM_INTERACTIVE=never GIT_TERMINAL_PROMPT=0 git -c credential.helper=manager push origin <branch>`.
`present_files` может добавлять `data-page-node-id` в HTML и срезать хвост
длинных `.md` — перед показом делать копию и сверять после.
