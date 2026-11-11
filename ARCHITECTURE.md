# Техническая архитектура Privacy Sentinel (Android 17 / API 37)

## 1. Четырёхуровневая схема взаимодействия

```text
┌────────────────────────────────────────────────────────────────────────────┐
│  Уровень 4: Web UI (module/webroot/) — Obsidian Matte & Nordic Ceramic     │
│   • Контур А: window.ksu.exec() -> sentinelctl -> UNIX sentinel.sock       │
│   • Контур Б: http://127.0.0.1:18917/api/v1/* (X-Sentinel-Token 256-bit)   │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │ JSON-RPC & SSE
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  Уровень 1: Ядро и нативный демон sentineld (C++20 epoll, UID 0)           │
│   • cgroup v2: /sys/fs/cgroup/privacy_sentinel (вне MemoryLimiter A17)     │
│   • Кольцевой буфер RAM: 15 000 событий                                    │
│   • Read-only Shared Policy Bitmap: /data/adb/privacy_sentinel/run/policy  │
│   • Netfilter: Linux 5.10 iptables SENTINEL_* + nftables fallback          │
│   • Deep Sleep Socket Killer: NETLINK_SOCK_DIAG + SOCK_DESTROY             │
│   • Transparent SOCKS5 Relay: 127.0.0.1:19040 (SO_ORIGINAL_DST, без tun0)  │
└──────────────┬──────────────────────────────────────────┬──────────────────┘
               │ mmap(PROT_READ) + SOCK_DGRAM             │ mmap(PROT_READ) + SOCK_DGRAM
               ▼                                          ▼
┌─────────────────────────────────────────┐ ┌────────────────────────────────┐
│  Уровень 2: Zygisk Native (API v5 C++)  │ │ Уровень 3: Vector (API 102)    │
│   • Zero-Touch DLCLOSE (PIF/TrickyStore)│ │  • system_server IPC & IFW     │
│   • Mount Namespace Sandbox (/sdcard)   │ │  • Android 17 Allow/Deny UI    │
│   • PLT: connect, sendto, getaddrinfo   │ │  • HMAC/Ephemeral/Custom Spoof │
│   • PLT: openat, libbinder transact     │ │  • Zero-PCM Mic (ViPER4A safe) │
└─────────────────────────────────────────┘ └────────────────────────────────┘
```

## 2. Бюджет памяти и защита от Android 17 `MemoryLimiter`
* Демон `sentineld` исполняется под `UID 0` вне дерева `/sys/fs/cgroup/uid_*`, благодаря чему ядерный сервис `MemoryLimiter` (ограничивающий `memory.high` и `memory.swap.max` только для `UID >= 10000`) его не затрагивает.
* Внутри клиентских процессов (`UID >= 10000`) чтение политики происходит без аллокаций и IPC через `mmap(..., PROT_READ, MAP_SHARED)` общей таблицы `SentinelPolicyShm` размером ~128 КБ (чистая файловая страница, не увеличивающая `AnonSwap`).
* Отправка телеметрии выполняется через `sendto(..., MSG_DONTWAIT | MSG_NOSIGNAL)` в датаграммный UNIX-сокет: при любой перегрузке вызов завершается мгновенно без блокировки потока приложения.
