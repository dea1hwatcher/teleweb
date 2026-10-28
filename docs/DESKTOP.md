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

Требования: Windows 10/11 x64, права администратора, `WinDivert.dll` + `WinDivert64.sys` рядом с `tgws.exe` (входят в пакет).

```powershell
# установка (служба + автозапуск), из распакованного пакета:
powershell -ExecutionPolicy Bypass -File .\install.ps1

# проверка
& "$env:ProgramData\teleweb\tgws.exe" status

# WebUI
& "$env:ProgramData\teleweb\tgws.exe" webui 127.0.0.1:17842
```

Как это работает: редиректор на WinDivert перехватывает исходящие TCP-пакеты к подсетям Telegram DC, подменяет адреса на `127.0.0.1` с уникальным NAT-портом, демон находит по этому порту исходный DC и туннелирует поток в WSS. Обратные пакеты переписываются так, что клиент видит исходный адрес Telegram. Собственные WSS-подключения демона исключены из перехвата (порты регистрируются до отправки SYN).

Режим без драйвера (не требует прав администратора):

```powershell
tgws.exe socks 127.0.0.1:17845
# в Telegram Desktop: Настройки → Продвинутые → Тип подключения → SOCKS5, 127.0.0.1:17845
```

Ограничения:
- только IPv4 (как и в Android-версии);
- Windows ARM64: WinDivert не имеет ARM64-драйвера — доступен только SOCKS-режим;
- UDP/звонки не перехватываются (как и в Android-версии, где UDP пропускается для STUN/TURN).

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
