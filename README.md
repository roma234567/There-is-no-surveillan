# Privacy Sentinel (`v1.0.0-garnet`)

Комплексный модуль защиты конфиденциальности, межпроцессного фаервола, ядерной песочницы и подмены идентификаторов для **Android 17 (API 37) / HyperOS 4**.  
Спроектирован и оптимизирован под **POCO X6 5G (`garnet`, `arm64-v8a`, ядро Linux `5.10`)** и стек **BakaSU (KernelSU + встроенный SuSFS) + Zygisk Next + Vector (LibXposed API 102)**.

---

## Ключевые возможности

### 1. Живой Радар активности и Web UI (2 дизайна, RU/EN, 100% кастомные SVG)
* **Кольцевой буфер в RAM на `15 000` событий** — мгновенная скорость, нулевой износ UFS-накопителя, отсутствие фонового Android-приложения.
* **Два строгих дизайна без неона** с переключением в один клик:
  1. **Obsidian Matte («Обсидиан»)** — тактический матовый графит с приглушённой семантической палитрой.
  2. **Nordic Ceramic («Керамика»)** — швейцарская светло-каменная приборная панель с высокой читаемостью при дневном свете.
* **Полностью векторная SVG-графика** (без эмодзи и внешних CDN — 100% offline): кастомные иллюстрации радара, категорий угроз, аппаратного силуэта `garnet` и уникальных SVG-монограмм пакетов.
* **Двухконтурный транспорт**:
  * **Контур А (Stealth / Zero-Port)**: прямой мост `window.ksu.exec` $\rightarrow$ `sentinelctl` $\rightarrow$ защищённый UNIX-сокет `/data/adb/privacy_sentinel/run/sentinel.sock` (работает в BakaSU Manager и KsuWebUI без единого открытого порта и обходит `USE_LOOPBACK_INTERFACE` в Android 17).
  * **Контур Б (Local REST + SSE)**: встроенный неблокирующий `epoll` сервер строго на `127.0.0.1:18917`, защищённый 256-битным токеном `X-Sentinel-Token`.

### 2. Фаервол Linux 5.10, Deep Sleep (3 режима) и живые окна разрешений Android 17
* **Адаптивный движок Netfilter**: изолированные цепочки `SENTINEL_OUT`, `SENTINEL_SLEEP`, `SENTINEL_PROXY` для ядра Linux `5.10` (`iptables -w` / `ip6tables -w`) с авто-поддержкой `nftables` (`table inet privacy_sentinel`) без конфликта с `netd` и `MiuiNetworkManagement`.
* **Автообрыв соединений при выключении экрана (Deep Sleep)** с 3 режимами:
  1. *Отключать только выбранные приложения*;
  2. *Отключать все, кроме выбранных (Белый список)*;
  3. *Отключать вообще все пользовательские приложения*.
  При входе в сон демон мгновенно разрывает уже установленные TCP/UDP-сессии через ядерный `NETLINK_SOCK_DIAG` (`SOCK_DESTROY`).
* **Интерактивный системный диалог Allow / Deny (как в системе)**: если заблокированное или изолированное приложение пытается выйти в сеть или разбудить чужой сервис, `system_server` (и открытый WebUI) показывает системное окно с выбором: **Разрешить (90 сек)** / **Разрешить всегда** / **Подменить данные (Spoof)** / **Запретить (Silent Drop)**.
* **Двухуровневая ядерная Песочница (Sandbox)**: приватный `Mount Namespace` (`unshare(CLONE_NEWNS)`) в Zygote до специализации процесса с подменой `/storage/emulated/0` на изолированный каталог `/data/media/0/.sentinel_sandbox/<pkg>`.

### 3. Трёхслойный перехват и блокировка IPC (Intent + Binder)
1. **AOSP `IntentFirewall` (`/data/system/ifw/privacy_sentinel.xml`)** — нативная блокировка `BOOT_COMPLETED`, автозапуска и нежелательных связок внутри `ActivityManagerService`.
2. **Vector (LibXposed API 102) в `system_server`** — перехват `broadcastIntentWithFeature`, `startServiceLocked`, `bindServiceLocked`, `ContentProviderHelper` с режимом **Silent Drop** по умолчанию (или возвратом `SecurityException` по настройке) и поддержкой матрицы `Caller -> Target + Action`.
3. **Zygisk PLT-хук `libbinder.so` (`IPCThreadState::transact`)** — мониторинг прямых низкоуровневых Binder-транзакций.

### 4. Анти-Шпион, Data Spoofing и встроенный прозрачный SOCKS5 / Tor релей
* **Режимы подмены на выбор для каждого пакета**: *Без подмены*, *Постоянная маска пакета (HMAC-SHA256)*, *Случайный отпечаток при каждом запуске* или *Ручной профиль* (`IMEI` с валидацией алгоритмом Луна, `ANDROID_ID`, `Wi-Fi MAC`, `GPS` с естественным микро-джиттером, фильтрация списка установленных приложений и маскировка `WebView` / `DisplayMetrics`).
* **Фоновая защита микрофона, камеры и буфера обмена**: заполнение буфера `AudioRecord.read()` нулевыми PCM-отсчётами в фоне (**не трогает `AudioTrack` и `AudioEffect` — 100% совместимо с ViPER4Android!**), блокировка `CameraManager.openCamera()` и пустой `ClipData` в фоне.
* **Per-App подмена IP без глобального VPN**: прямо в демон `sentineld` встроен прозрачный релей `TCP -> SOCKS5` (`127.0.0.1:19040` с `SO_ORIGINAL_DST` и защитой от утечек `QUIC UDP/443` и `IPv6`). Достаточно указать любой `SOCKS5` или локальный `Tor (127.0.0.1:9050)` — никакого `VpnService` и интерфейса `tun0`, поэтому **Play Integrity Fix (v4.9)** и банковские приложения не видят VPN.

---

## Совместимость с активными модулями (Zero-Touch)

| Модуль / Среда | Механизм совместимости |
| :--- | :--- |
| **BakaSU + SuSFS** | Автоматическая регистрация путей `/data/adb/privacy_sentinel` в `ksu_susfs add_sus_path` в `post-fs-data.sh`. |
| **Play Integrity Fix v4.9 & Tricky Store** | Авточтение `/data/adb/tricky_store/target.txt`, `GMS` и `Play Store` $\rightarrow$ вызов `DLCLOSE_MODULE_LIBRARY` в Zygisk (0 следов в `/proc/self/maps`). |
| **Vector (LibXposed API 102)** | Современный формат `META-INF/xposed/module.prop` (`minApiVersion=102`, `exceptionMode=protective`, `autoHotReload=true`). |
| **OverlayFS** | Флаг `skip_mount` — модуль не модифицирует раздел `/system`. |
| **ViPER4Android** | Перехватывается исключительно захват `AudioRecord`; тракт воспроизведения и эффектов не затрагивается. |
| **Yet Another Bootloop Protector (YABP)** | Счётчик `boot_attempts` в `post-fs-data.sh` с авто-включением `Safe Bypass` при незавершённой загрузке и сбросом в `boot-completed.sh`. |

---

## Сборка и тестирование

### 1. Готовая автосборка через GitHub Actions (APK + NDK `arm64-v8a` + Flashable `.zip`)
При каждом пуше workflow `.github/workflows/build-module.yml` автоматически:
1. Прогоняет интеграционные тесты C++20 демона `sentineld`;
2. Компилирует `sentineld`, `sentinelctl` и `zygisk/arm64-v8a.so` через **Android NDK r27c**;
3. Собирает `PrivacySentinelVector.apk` под **LibXposed API 102** (JDK 21 + Gradle);
4. Упаковывает готовый к прошивке архив `PrivacySentinel-v1.0.0-arm64-garnet-bakaSU-a17.zip` в раздел **Artifacts**.

### 2. Локальная сборка и тесты демона
```bash
make test
```

### 3. Установка на POCO X6 5G (`garnet`, BakaSU)
1. Прошейте `PrivacySentinel-v1.0.0-arm64-garnet-bakaSU-a17.zip` через **BakaSU Manager**.
2. Перезагрузите устройство.
3. Откройте менеджер **Vector** и убедитесь, что модуль `Privacy Sentinel (Vector API 102)` активирован для `System Framework (android)` и нужных пользовательских приложений.
4. Откройте карточку модуля в **BakaSU Manager** (или **KsuWebUI**) для запуска Web UI.
