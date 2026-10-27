# TeleWEB

<img align='right' src='icon.png' width='220px' alt="TeleWEB Icon">

Полнофункциональный прозрачный WSS-обходчик блокировок Telegram для Android.

[![KernelSU](https://img.shields.io/badge/KernelSU-Supported-brightgreen.svg)](https://github.com/tiann/KernelSU)
[![Magisk](https://img.shields.io/badge/Magisk-Supported-blue.svg)](https://github.com/topjohnwu/Magisk)
[![APatch](https://img.shields.io/badge/APatch-Supported-orange.svg)](https://github.com/bmax121/APatch)
[![Release](https://img.shields.io/github/v/release/dea1hwatcher/teleweb?label=Release)](https://github.com/dea1hwatcher/teleweb/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

Модуль предназначен для прозрачного перехвата и обхода блокировок дата-центров Telegram (DC1–DC5) нативно на уровне ядра через `iptables nat REDIRECT` в зашифрованные WebSocket-сессии (WSS). В отличие от классических VPN-приложений (V2Ray, Clash, ByeDPI и др.), этот метод **не создает виртуального сетевого интерфейса (tun)**, не требует настройки прокси внутри мессенджера, не расходует дополнительный заряд батареи и не режет скорость соединения.

## Особенности

* **Нативный перехват без VPN (`iptables REDIRECT`)**: перенаправление трафика ядра Linux только для установленных клиентов Telegram на локальный порт `17841`. Никаких VPN-интерфейсов (`tun0`), полная совместимость с любыми внешними VPN-приложениями.
* **Пул предпрогретых сокетов (WsPool)**: фоновое поддержание пула готовых WSS-сессий (от 1 до 8 сокетов) с Keep-Alive пингами каждые 15 секунд. Обеспечивает мгновенный отклик (0 мс задержки) при открытии каналов, чатов и медиа сразу после включения экрана.
* **Happy Eyeballs v2 Connection Racing**: параллельный запуск соединения по всем доступным маршрутам (Direct KWS, Cloudflare Domain Fronting, Custom Worker) со ступенчатым стартом (stagger 250 мс) — мгновенный выбор маршрута с минимальной задержкой рукопожатия и автоотмена проигравших попыток.
* **Multi-DoH Racing**: параллельное защищенное разрешение доменов через Google, Cloudflare и Quad9 DoH с внутренним LRU-кэшем (до 256 записей) для обхода DNS-блокировок и DNS poisoning со стороны провайдеров.
* **HTTP/2 мультиплексирование медиа**: одновременная параллельная загрузка «тяжелых» медиа-файлов через мультиплексированные HTTP/2 потоки без создания очередей и без блокировки основного канала сообщений.
* **Защита голосовых и видеозвонков (VoIP Protection)**: автоматический пропуск STUN/TURN пакетов (UDP) мимо перехвата во избежание задержек и разрывов аудио/видеосвязи.
* **Автообнаружение любых клиентов Telegram**: официальный Telegram, Telegram X, Nekogram, Forkgram, Cherrygram, Ayugram, MDGram, Swiftgram, Turbotel и любые сторонние сборки определяются автоматически по установленным пакетам.
* **Cgroup Unfreezer & Anti-Freeze Watchdog**: защита демона `tgws` от завершения системой (`oom_score_adj = -1000`) и автоматический вывод фоновых процессов клиентов Telegram из `cgroup freezer` для гарантированной доставки уведомлений в режиме глубокого сна (Doze).
* **WebUI Material Design 3 Expressive**: светлая, тёмная и AMOLED-тема.
* **Управление из терминала**: консольная утилита `tgws` (`tgws status`, `tgws boot`, `tgws stop`, `tgws ensure`, `tgws check`) для полного контроля из Termux или root-оболочки.

## Требования

1. Установленный **KernelSU**, **APatch** или **Magisk** (v20.4+).
2. Архитектура процессора: **ARM64** (`arm64-v8a`), **ARM** (`armeabi-v7a`), **x86**, **x86_64**.
3. Версия системы: **Android 8.0 — 16+**.

## Также поддерживается:

- [KsuWebUI](https://github.com/5ec1cff/KsuWebUIStandalone)
- [WebUI-X](https://github.com/MMRLApp/WebUI-X-Portable)
- [MMRL](https://github.com/MMRLApp/MMRL)

## Установка

1. Скачайте актуальный архив `teleweb-v...-multiarch.zip` из раздела [Releases](https://github.com/dea1hwatcher/teleweb/releases/latest).
2. Установите модуль через Ваш root-менеджер (Magisk, KernelSU, APatch или MMRL).
3. Перезагрузите устройство.
4. Служба запустится автоматически при загрузке системы, определит установленные клиенты Telegram и настроит правила iptables.

## Конфигурация и рабочие файлы

Модуль хранит настройки и состояние в изолированной директории `/data/adb/teleweb/`:

| Файл / Параметр | Назначение |
| :--- | :--- |
| `cf-domains` | Пользовательский список Cloudflare-доменов для Domain Fronting |
| `custom-cf-domain` | Пользовательский приоритетный Cloudflare-домен |
| `custom-cf-worker` | Адрес кастомного Cloudflare Worker шлюза |
| `pool_size` | Размер пула предпрогретых WSS-сокетов (`0` — отключено, `1`–`8` активных) |
| `dc203_direct_tcp` | Режим работы CDN203 (`1` — прямой TCP pass-through, `0` — через WSS) |
| `doh_enabled` | Использование Multi-DoH резолвера (`1` — включено, `0` — системный DNS) |
| `h2_media_enabled` | Мультиплексирование медиа через HTTP/2 (`1` — включено, `0` — выключено) |
| `dc-override` | Ручные переопределения IP-адресов дата-центров Telegram |
| `route-cache.json` | Персистентный кэш быстрых и проверенных WSS-маршрутов |
| `status.json` | Атомарный снимок состояния службы и метрик для WebUI |
| `tgws.log` | Основной журнал сетевых событий, WSS-маршрутов и ошибок |
| `supervisor.log` | Журнал загрузки службы и фонового супервизора |

## Управление через CLI

Модуль предоставляет удобный интерфейс командной строки через глобальный симлинк `/system/bin/tgws` (или `/data/adb/modules/teleweb/bin/tgws`):

```bash
# Проверка текущего статуса службы, клиентов и сетевой статистики
su -c tgws status

# Запуск службы перехвата (правила iptables + демон + watchdog)
su -c tgws boot

# Остановка перехвата и корректная очистка правил iptables
su -c tgws stop

# Проверка работоспособности и автоматическое восстановление (supervisor)
su -c tgws ensure

# Тестирование парсеров MTProto и внутренних инвариантов
su -c tgws check
```

## Собственный Cloudflare Worker Gateway

Для максимальной стабильности и надежного обхода жестких блокировок вы можете развернуть собственный шлюз в Cloudflare Workers:

1. Откройте панель Cloudflare Dashboard ➔ **Workers & Pages** ➔ **Create Worker**.
2. Вставьте код из файла [`worker/cloudflare-worker.js`](worker/cloudflare-worker.js).
3. Нажмите **Deploy**.
4. Скопируйте полученный домен (например, `my-tg-gateway.user.workers.dev`).
5. В WebUI TeleWEB откройте вкладку **«Маршрутизация»**, укажите адрес воркера в поле **«Кастомный Cloudflare Worker»** и сохраните изменения.

> **Рекомендуется: защита воркера токеном.** Без токена ваш воркер — открытый релей, которым может пользоваться кто угодно. В настройках воркера добавьте переменную окружения `TELEWEB_TOKEN` (произвольный секрет), а в поле воркера в WebUI укажите адрес вместе с токеном: `my-tg-gateway.user.workers.dev?token=ВАШ_СЕКРЕТ`. TeleWEB автоматически передаст его в запросах.

## Сборка из исходников

Для сборки проекта требуется **Go 1.24+** и **Python 3**. Сборка мультиархитектурных бинарников (`ARM64`, `ARM`, `x86`, `x86_64`) и упаковка zip-модуля автоматизированы:

```powershell
# Полная сборка бинарников под все архитектуры и создание готового zip-модуля:
python .\package_zip.py

# Или через PowerShell скрипт:
powershell -ExecutionPolicy Bypass -File .\build_all.ps1

# Опциональные флаги package_zip.py:
#   --skip-build   - пропустить компиляцию Go и только переупаковать zip
#   --build-only   - только скомпилировать бинарники без создания zip
```

## Благодарности

* [amurcanov/tg-ws-proxy-android](https://github.com/amurcanov/tg-ws-proxy-android) — за концепцию прозрачного WSS-модуля для Android.
* [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) — за исследования протокола MTProto и наработку Cloudflare-инфраструктуры.
* [nfqws2-android](https://github.com/Dea1hwa1cher/nfqws2-android) — за идеи в MD3e WebUI.
* Разработчикам [KernelSU](https://github.com/tiann/kernelSU), [Magisk](https://github.com/topjohnwu/magisk) и [APatch](https://github.com/bmax121/APatch).
