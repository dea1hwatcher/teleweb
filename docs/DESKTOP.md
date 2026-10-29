# TeleWEB для Windows и Linux

Порты сохраняют тот же WSS-движок, что и Android-модуль (парсинг MTProto obfuscated init, Happy Eyeballs racing, Multi-DoH, HTTP/2-медиа, Cloudflare Worker), но заменяют платформенный слой перехвата и интеграции.

## Что общего и что отличается

| Слой | Android модуль | Windows порт | Linux порт |
| :--- | :--- | :--- | :--- |
| Перехват | `iptables` + `-m owner --uid-owner` | WinDivert (подписанный драйвер), NAT `srcPort → исходный DC` | `iptables REDIRECT` с исключением root |
| Исходный адрес | `SO_ORIGINAL_DST` | NAT-таблица редиректора | `SO_ORIGINAL_DST` |
| Область перехвата | только UID клиентов Telegram | весь локальный TCP к подсетям Telegram | весь локальный TCP к подсетям Telegram (кроме root) |
| Демон/супервизор | `service.sh` + watchdog | служба Windows (`sc`) + watchdog | systemd-юнит + watchdog |
| WebUI | `ksu.exec` из Magisk/KernelSU | HTTP на loopback | HTTP на loopback |
| Конфиг/состояние | `/data/adb/teleweb` | `%ProgramData%\teleweb` | `/var/lib/teleweb` |

Порт демона `17841` (127.0.0.1), SOCKS5 — `17845`, WebUI — `17842`.

## Windows

Требования: Windows 10/11, права администратора для прозрачного режима.

Пакеты собираются под **x64 (amd64)**, **x86 (386)** и **ARM64**:

| Сборка | Прозрачный режим | SOCKS-режим |
| :--- | :--- | :--- |
| `tgws-windows-amd64.exe` | да (WinDivert) | да |
| `tgws-windows-386.exe` | да (WinDivert; работает и на x64 Windows) | да |
| `tgws-windows-arm64.exe` | нет — WinDivert без ARM64-драйвера | да |

**Один файл — весь билд.** `tgws-windows-<arch>.exe` — самодостаточный: WebUI и драйвер WinDivert встроены внутрь бинаря. При первом запуске прозрачного режима драйвер извлекается в `%ProgramData%\teleweb\driver\` (или `%LOCALAPPDATA%\teleweb` без прав администратора). Рядом с exe ничего докладывать не нужно; если же `WinDivert.dll` лежит рядом с exe, используется она (совместимость с zip-пакетом).

```powershell
# установка (служба + автозапуск), из распакованного пакета:
powershell -ExecutionPolicy Bypass -File .\install.ps1

# или просто запустите exe (двойной клик) — откроется GUI в браузере:
.\tgws-windows-amd64.exe

# прозрачный режим вручную без GUI:
.\tgws-windows-amd64.exe boot
.\tgws-windows-amd64.exe stop
```

**GUI (нативное окно).** Запуск exe без аргументов или `tgws gui` открывает нативное окно (Gio, горизонтальная компоновка: слева метрики, справа DC-матрица и журнал). Кнопка «Запустить/Остановить» управляет транспортом; данные обновляются раз в 1.5 с. Нативный GUI встроен в Windows-бинарники; для headless/браузерного варианта остался `tgws webui [addr]` (на Linux пока он же — нативное окно требует Vulkan/CGO).

**Пул сокетов.** На десктопе по умолчанию выключен (`pool_size` отсутствует = 0): сессии 1:1 с соединениями клиента, никаких предпрогретых десятков сокетов при старте. На Android сохранено прежнее поведение (2 на DC). Включить/настроить — файл `pool_size` (0–4).

Как это работает: редиректор на WinDivert перехватывает исходящие TCP-пакеты к подсетям Telegram DC, подменяет адреса на `127.0.0.1` с уникальным NAT-портом, демон находит по этому порту исходный DC и туннелирует поток в WSS. Обратные пакеты переписываются так, что клиент видит исходный адрес Telegram. Собственные WSS-подключения демона исключены из перехвата (порты регистрируются до отправки SYN).

Режим без драйвера (не требует прав администратора):

```powershell
tgws.exe socks 127.0.0.1:17845
# в Telegram Desktop: Настройки → Продвинутые → Тип подключения → SOCKS5, 127.0.0.1:17845
```

Ограничения:
- только IPv4 (как и в Android-версии);
- Windows ARM64: WinDivert не имеет ARM64-драйвера — доступен только SOCKS-режим (см. таблицу выше);
- UDP/звонки не перехватываются (как и в Android-версии, где UDP пропускается для STUN/TURN);
- **CDN203** (медиа-агрегаты `91.105.192.0/23`, порт 80/443) туннелируется прямым TCP passthrough. Если провайдер блокирует этот диапазон, демон закрывает такие соединения мгновенно (отрицательный кэш 30 с, в логе — строка `CDN203 ... unreachable on the direct path`), чтобы ретраи клиента не плодили сессии. Для работы медиа через блокировку настройте собственный Cloudflare Worker (см. `docs/WORKER_SETUP.md`) — тогда CDN203 пойдёт через WSS-релей воркера.

Антивирусы иногда настороженно относятся к WinDivert (на нём работают GoodbyeDPI, Netch и др.); драйвер подписан мейнтейнером WinDivert.

## Linux

Требования: systemd-дистрибутив, root, iptables (на nft-системах — `iptables-nft`).

```bash
sudo ./install.sh            # ставит /usr/local/bin/tgws, systemd-юнит, запускает
tgws status
tgws webui 127.0.0.1:17842   # WebUI на loopback
tgws socks 127.0.0.1:17845   # альтернатива без root для самого перехвата
```

Правила: `-t nat OUTPUT: -m owner ! --uid-owner 0 -j TELEWEB`, цепочка `TELEWEB` редиректит TCP к подсетям Telegram на `127.0.0.1:17841`. Исключение root обязательно: демон сам открывает WSS-соединения к Telegram, и без исключения его трафик попал бы в собственный редирект (петля). Запускайте Telegram Desktop от обычного пользователя.

Проверка правил и остановка:

```bash
sudo iptables -t nat -L OUTPUT -v -n | head
sudo systemctl stop teleweb   # ExecStopPost: tgws stop (снимает iptables-правила)
```

## Сборка из исходников

```powershell
# Windows/Linux пакеты в dist/ (Windows-хост)
powershell -ExecutionPolicy Bypass -File .\build_desktop.ps1
```

```bash
# Linux (или кросс-сборка с любой ОС)
cd src
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o tgws .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o tgws.exe .
```

Проверка парсеров и инвариантов движка — `tgws check`; юнит-тесты — `go test ./...` в `src/`.

## Проверка Linux-порта в Docker

В репозитории есть готовый харнесс `desktop/linux/docker-e2e/`: внутри образа собирается `tgws`, гоняются `go vet`/`go test`, затем в привилегированном контейнере запускается `tgws run`, устанавливаются iptables-правила и не-root клиент подключается к `149.154.167.220:443` — успех фиксируется по строке `-> DC2 ... via WSS` в логе демона.

```bash
# локально (нужен запущенный Docker с поддержкой --privileged)
sh desktop/linux/docker-e2e/run.sh
# либо вручную
docker build -t teleweb-e2e -f desktop/linux/docker-e2e/Dockerfile .
docker run --rm --privileged teleweb-e2e
```

Либо через GitHub Actions: workflow `desktop-e2e` (workflow_dispatch), логи выкладываются артефактом.

## Управление

| Команда | Назначение |
| :--- | :--- |
| `tgws run` | foreground-супервизор (systemd / ручной запуск) |
| `tgws boot` / `stop` / `ensure` | как в Android-версии |
| `tgws status` | JSON-снимок состояния (в т.ч. поле `redirector`) |
| `tgws socks [addr]` | SOCKS5-листенер без перехвата |
| `tgws webui [addr]` | WebUI + локальный API-мост |
| `tgws svc-install` / `svc-uninstall` / `svc-run` | служба Windows |
| `tgws api <base64-json>` | API для WebUI/скриптов |
| `tgws check` | самотесты парсеров |

Конфигурационные файлы (`pool_size`, `doh_enabled`, `custom-cf-worker`, `dc-override` и т.д.) — те же, что описаны в основном README, в директории состояния платформы.
