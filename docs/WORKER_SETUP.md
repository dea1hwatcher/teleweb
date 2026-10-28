# Свой Cloudflare Worker для TeleWEB

Инструкция по развёртыванию собственного шлюза. Зачем: встроенные домены (`kws<N>.<domain>.co.uk`) ходят через **общий** публичный воркер, который под нагрузкой отдаёт `HTTP 503` — это и есть причина обрывов в логах от 28.10.2026. Свой воркер даёт собственный лимит и предсказуемость.

## Как это работает

```
Telegram-клиент
   ↓ (uid клиента)
iptables nat REDIRECT → 127.0.0.1:17841 (tgws)
   ↓ MTProto init, определение DC
wss://<твой-воркер>/apiws?dst=<IP Telegram>&dc=<N>&token=<секрет>
   ↓ Cloudflare Worker
connect({hostname: dst, port: 443})  ← cloudflare:sockets
   ↓
Telegram DC
```

Для DPI это обычный HTTPS к Cloudflare. Воркер не расшифровывает трафик: он просто перекладывает байты между WebSocket и TCP-сокетом к Telegram.

## Что понадобится

- аккаунт Cloudflare (бесплатного плана достаточно);
- файл [`worker/cloudflare-worker.js`](../worker/cloudflare-worker.js) из репозитория;
- доступ к WebUI модуля на телефоне.

## Шаг 1. Создать Worker

1. Открыть [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages**.
2. **Create** → **Workers** → **Start with Hello World**.
3. Имя, например `teleweb-gw` → **Deploy**.

## Шаг 2. Вставить код

1. **Edit code**.
2. Удалить шаблон целиком.
3. Вставить содержимое `worker/cloudflare-worker.js`.
4. **Deploy**.

`import { connect } from "cloudflare:sockets"` работает только в Workers. В Pages Functions этот модуль недоступен, поэтому создавать нужно именно Worker.

## Шаг 3. Задать токен

Без токена воркер — открытый релей: любой, кто узнал адрес, будет гонять через него трафик за твой счёт (и abuse-жалобы прилетят на твой аккаунт).

1. В воркере: **Settings** → **Variables and Secrets** → **Add**.
2. **Type: Secret** (не Plaintext), **Name**: `TELEWEB_TOKEN`.
3. **Value**: случайная строка, например из `openssl rand -hex 24` или 32 символа из генератора паролей.
4. **Save and Deploy**.

Токен проверяется так: `url.searchParams.get("token") !== env.TELEWEB_TOKEN` → `403 forbidden`.

## Шаг 4. Записать адрес и проверить, что воркер жив

Адрес вида `<имя>.<сабдомен>.workers.dev`, например `teleweb-gw.username.workers.dev`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://teleweb-gw.username.workers.dev/apiws
```

Ожидаемый ответ — **426** (`expected a websocket upgrade`): значит воркер задеплоен, код на месте, маршрут `/apiws` слушается. Проверка идёт до проверки токена, поэтому секрет для неё не нужен.

Расшифровка кодов: `404` — не тот путь или деплой не прошёл; `1101`/`522` — воркер упал (смотри **Logs** в панели); таймаут — домен недоступен из твоей сети (см. раздел про `workers.dev`).

## Шаг 5. Прописать воркер в TeleWEB

1. WebUI → вкладка **«Маршрутизация»**.
2. Поле **«Шлюз Cloudflare Worker (cloudflare:sockets)»** → вписать адрес вместе с токеном:

```
teleweb-gw.username.workers.dev?token=ТВОЙ_СЕКРЕТ
```

3. Включить тумблер **«Форсировать Cloudflare (CF Priority)»** — тогда воркер пробуется первым, а не в конце очереди.
4. **Сохранить**.

Мелочи, которые экономят время:

- `https://` / `wss://` в начале можно писать — схема срезается автоматически;
- токен идёт **в query через `?`**, не в пути и не отдельным полем;
- перезапуск демона не нужен: адрес читается из `/data/adb/teleweb/custom-cf-worker` и подхватывается в течение ~2 секунд.

## Шаг 6. Убедиться, что трафик пошёл через воркер

В WebUI: `ws` больше нуля, `trafficUp`/`trafficDown` растут.

В логе `/data/adb/teleweb/tgws.log` (или `su -c tgws status`) должны появиться строки с `cf-worker`:

```
DC2 media=false Happy Eyeballs winner: cf-worker (teleweb-gw.username.workers.dev)
conn #12 149.154.167.51:5222 -> DC2 media=false via WSS (cf-worker (teleweb-gw.username.workers.dev)) [CF-Ray: … HEL]
```

Если в кандидатах видны только `cf-domain (...)` и `direct (...)`, а `cf-worker` нет — адрес не сохранился или пустой. Проверить файл:

```bash
su -c cat /data/adb/teleweb/custom-cf-worker
```

## Если `workers.dev` не открывается

`*.workers.dev` у части провайдеров режется по SNI, и тогда воркер не поможет, хотя сам работает. Решение — свой домен:

1. Домен должен обслуживаться Cloudflare (NS переведены на Cloudflare).
2. В воркере: **Settings** → **Domains & Routes** → **Add** → **Custom domain** → `tg.example.com`.
3. В WebUI указать `tg.example.com?token=ТВОЙ_СЕКРЕТ`.

Проверка доступности из мобильной сети:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://tg.example.com/apiws
```

## Контракт воркера (если правишь код)

| Что | Значение |
| :--- | :--- |
| Путь | `/apiws` (тестовые DC — `/apiws_test`) |
| Query | `dst=<IP Telegram>`, `dc=<N>`, `token=<TELEWEB_TOKEN>` |
| Заголовки | `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Protocol: binary` |
| Успех | `101` + `Sec-WebSocket-Protocol: binary` |
| Ошибки | `403` токен/`dst`, `400` нет subprotocol `binary`, `404` путь, `426` не Upgrade, `502`/`504` не удалось подключиться к Telegram |

`ALLOWED_DESTINATIONS` в воркере — белый список адресов, куда разрешено подключаться. Он должен совпадать с `dcSpecs[*].workerDst` и `testIP` из `src/main.go`:

| DC | адрес в белом списке |
| :--- | :--- |
| DC1 | `149.154.175.50` (тест `149.154.175.10`) |
| DC2 | `149.154.167.51`, `149.154.167.220` (тест `149.154.167.40`) |
| DC3 | `149.154.175.100` (тест `149.154.175.117`) |
| DC4 | `149.154.167.91` |
| DC5 | `149.154.171.5` |
| CDN203 | `91.105.192.100` |

Поменяешь таблицу в Go — правь и воркер, иначе получишь `403 destination not allowed`.

## Подводные камни

1. **Лимит бесплатного плана — 100 000 запросов в сутки.** Один WebSocket-апгрейд = один запрос, дальше соединение живёт долго. При `pool_size = 2` и обычной переписке запас большой, но при постоянном онлайне на нескольких устройствах можно упереться. Платный план ($5/мес) снимает ограничение.
2. **429 от воркера.** Модуль уважает `Retry-After` и паркует хост: в логе `worker <host> is in rate limit cooldown`. Это не поломка, а защита от долбёжки.
3. **Тестовые DC.** У DC4 и DC5 нет `testIP`, поэтому с включённым тумблером «Тестовые датацентры» воркер для них бесполезен. Держать тумблер выключенным.
4. **Пул сокетов.** Со своим воркером `pool_size` можно вернуть в 2: на публичном флоте я советовал 0, потому что там пул только усиливал шторм 503. Здесь причина устранена.
5. **Приватность.** Воркер видит метаданные (какой IP Telegram, объём, тайминги), но не содержимое: MTProto шифруется на клиенте.
6. **Не публикуй адрес с токеном** — это ключ к твоему воркеру и твоему лимиту.

## Диагностика

| Симптом | Причина | Что делать |
| :--- | :--- | :--- |
| `403 forbidden` в логах воркера | не совпал `token` | сверить Secret и query в WebUI |
| `403 destination not allowed` | `dst` не в белом списке | синхронизировать `ALLOWED_DESTINATIONS` с `dcSpecs` |
| `400 binary websocket subprotocol required` | клиент не передал `Sec-WebSocket-Protocol: binary` | используется не TeleWEB или переписан handshake |
| `502` / `504` | Cloudflare не смог открыть TCP к IP Telegram | повторить, проверить другой DC; при постоянстве — IP сменился |
| `426` на `curl` | запрос без `Upgrade` | это норма, воркер жив |
| В логе модуля только `cf-domain`/`direct` | воркер не сконфигурирован | проверить `custom-cf-worker`, включить CF Priority |
| `no available routes` | все кандидаты в парковке/кулдауне | посмотреть, не в кулдауне ли воркер (429) |
