### Изменения в v0.1.0:

- Начальный публичный мультиархитектурный релиз TeleWEB (ARM64, ARM, x86, x86_64)
- Нативный перехват TCP-трафика Telegram через iptables REDIRECT без создания VPN-интерфейса (tun0)
- Пул предпрогретых WSS-сокетов (WsPool) с Keep-Alive для мгновенного отклика (0 мс)
- Happy Eyeballs v2 параллельный рейсинг маршрутов (Direct KWS, Cloudflare Domain Fronting, Worker)
- Multi-DoH рейсер (Google, Cloudflare, Quad9) с защитой от DNS-спуфинга
- HTTP/2 медиа-мультиплексор для параллельной быстрой загрузки медиа
- Direct TCP pass-through туннель для Telegram CDN203 с переключателем в WebUI
- Защита голосовых и видеозвонков (VoIP STUN/TURN bypass)
- Экспоненциальный Route Backoff (от 30 секунд до 30 минут) при сетевых сбоях
- Zero-leak архитектура памяти с ограниченными кэшами и сжатием MTProto фреймов
- Автономный Material Design 3 Expressive WebUI с Monet-палитрой и поддержкой жестов
- Встроенный механизм обновления модуля для KernelSU, Magisk, APatch и MMRL
