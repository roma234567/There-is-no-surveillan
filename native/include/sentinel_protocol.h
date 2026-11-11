#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Privacy Sentinel — Shared Binary Protocol & Policy MMap Layout
 * Target: Android 17 (API 37) / HyperOS 4 / Linux 5.10+ (arm64-v8a & x86_64)
 * Root Stack: BakaSU (KernelSU + SuSFS) + Zygisk Next + Vector (LibXposed 102)
 * ============================================================================ */

#define SENTINEL_VERSION_STR          "1.0.0-garnet"
#define SENTINEL_PROTOCOL_MAGIC       0x50534E54u /* "PSNT" */
#define SENTINEL_PROTOCOL_VERSION     1u

/* Ring buffer capacity requested in technical specification: 15,000 events */
#define SENTINEL_RING_CAPACITY        15000u

/* Default paths on Android root filesystem (overridable via env in host tests) */
#define SENTINEL_BASE_DIR             "/data/adb/privacy_sentinel"
#define SENTINEL_RUN_DIR              "/data/adb/privacy_sentinel/run"
#define SENTINEL_CTRL_SOCK_PATH       "/data/adb/privacy_sentinel/run/sentinel.sock"
#define SENTINEL_DGRAM_SOCK_PATH      "/data/adb/privacy_sentinel/run/telemetry.sock"
#define SENTINEL_POLICY_MMAP_PATH     "/data/adb/privacy_sentinel/run/policy.mmap"
#define SENTINEL_TOKEN_FILE_PATH      "/data/adb/privacy_sentinel/run/webui.token"
#define SENTINEL_CONFIG_FILE_PATH     "/data/adb/privacy_sentinel/config/rules.json"
#define SENTINEL_IFW_XML_PATH         "/data/system/ifw/privacy_sentinel.xml"

/* Local loopback endpoints */
#define SENTINEL_DEFAULT_HTTP_PORT    18917
#define SENTINEL_DEFAULT_TPROXY_PORT  19040
#define SENTINEL_DEFAULT_DNSTCP_PORT  19053

/* Strict hook timeout (milliseconds) — guarantees Fail-Open & zero ANR */
#define SENTINEL_HOOK_TIMEOUT_MS      5
#define SENTINEL_PROMPT_TIMEOUT_MS    12000

/* Threat Category Bitmasks (for App Cards & Event Filtering) */
enum SentinelCategory : uint16_t {
    CAT_NONE        = 0,
    CAT_NETWORK     = (1u << 0), /* Outbound/inbound TCP/UDP, pre-DoH/DoT DNS */
    CAT_DATA        = (1u << 1), /* Clipboard, Sensors, Contacts, SMS, Accounts, Logs, Media */
    CAT_AUTOSTART   = (1u << 2), /* BOOT_COMPLETED, ForegroundService, JobScheduler */
    CAT_DANGER      = (1u << 3), /* Root/su probe, /proc or /data/adb scan, Accessibility, BG Cam/Mic */
    CAT_IPC         = (1u << 4), /* Cross-app Intents, Service wakeups, ContentProvider, Binder */
    CAT_SANDBOX     = (1u << 5), /* Mount namespace / FS isolation event */
    CAT_PROXY       = (1u << 6)  /* Per-app SOCKS5/Tor relay event */
};

/* Event Severity */
enum SentinelSeverity : uint8_t {
    SEV_INFO        = 0,
    SEV_LOW         = 1,
    SEV_MEDIUM      = 2,
    SEV_HIGH        = 3,
    SEV_CRITICAL    = 4
};

/* Enforcement Action Taken */
enum SentinelAction : uint8_t {
    ACT_OBSERVED        = 0, /* Allowed & logged */
    ACT_SILENT_DROP     = 1, /* Blocked silently (empty/zero return) */
    ACT_REJECT_ERROR    = 2, /* Blocked with explicit error / SecurityException */
    ACT_SPOOFED         = 3, /* Intercepted & synthetic value returned */
    ACT_PROXIED         = 4, /* Redirected via per-app SOCKS5/Tor relay */
    ACT_SOCKET_KILLED   = 5, /* Terminated via NETLINK_SOCK_DIAG in Deep Sleep */
    ACT_PROMPT_ALLOWED  = 6, /* Allowed interactively by user via System Dialog */
    ACT_PROMPT_DENIED   = 7  /* Denied interactively by user via System Dialog */
};

/* Per-UID Policy Flags stored inside read-only mmap bitmap (zero-IPC hot path) */
enum SentinelUidFlags : uint32_t {
    POL_NONE                = 0,
    POL_EXEMPT_ZERO_TOUCH   = (1u << 0),  /* PIF / Tricky Store / GMS / DenyList: never hook */
    POL_BLOCK_NETWORK       = (1u << 1),  /* Full outbound block via iptables/nftables */
    POL_SLEEP_SELECTED      = (1u << 2),  /* Selected in Deep Sleep list (blacklist or whitelist) */
    POL_BLOCK_BG_IPC        = (1u << 3),  /* Block outgoing Intents / Service wakeups in background */
    POL_BLOCK_AUTOSTART     = (1u << 4),  /* Block BOOT_COMPLETED / Job / Sync autostart via IFW */
    POL_IPC_REJECT_EXPLICIT = (1u << 5),  /* 0 = Silent Drop (default), 1 = throw SecurityException */
    POL_SANDBOX_FS_L1       = (1u << 6),  /* Mount namespace + isolated /sdcard storage */
    POL_SANDBOX_KERNEL_L2   = (1u << 7),  /* L1 + /proc hide + strict UID net/IPC isolation */
    POL_ASK_INTERACTIVE     = (1u << 8),  /* Show Android 17 System Allow/Deny dialog on blocked action */
    POL_SPOOF_DETERMINISTIC = (1u << 9),  /* Per-package HMAC persistent device mask */
    POL_SPOOF_EPHEMERAL     = (1u << 10), /* Random device mask on every process spawn */
    POL_SPOOF_CUSTOM        = (1u << 11), /* Custom user-defined IMEI/MAC/GPS/Model profile */
    POL_ANTISPY_BG_MIC_CAM  = (1u << 12), /* Zero PCM frames on AudioRecord + block Camera in BG */
    POL_ANTISPY_BG_CLIP     = (1u << 13), /* Blank ClipboardData in background */
    POL_TRAP_ROOT_SCAN      = (1u << 14), /* Hide /proc, /data/adb, su & log scan attempt */
    POL_ROUTE_PROXY         = (1u << 15), /* Route TCP+DNS via built-in SOCKS5/Tor relay */
    POL_STRICT_KILLSWITCH   = (1u << 16)  /* Fail-closed kernel drop if proxy/daemon down */
};

/* Deep Sleep Disconnect Mode (Q17) */
enum SentinelSleepMode : uint8_t {
    SLEEP_MODE_OFF                  = 0,
    SLEEP_MODE_SELECTED_ONLY        = 1, /* Disconnect ONLY selected apps */
    SLEEP_MODE_ALL_EXCEPT_SELECTED  = 2, /* Disconnect ALL apps EXCEPT selected whitelist */
    SLEEP_MODE_ALL_APPS             = 3  /* Disconnect ALL user apps on screen-off */
};

/* Compact Lock-Free / Read-Only MMap Policy Table (indexed by appId = uid % 100000) */
#define SENTINEL_MAX_APP_IDS 32768u

struct SentinelPolicyShm {
    uint32_t magic;                         /* SENTINEL_PROTOCOL_MAGIC */
    uint32_t version;                       /* SENTINEL_PROTOCOL_VERSION */
    uint64_t generation;                    /* Incremented atomically on rule update */
    uint32_t global_master_seed;            /* Master seed for deterministic HMAC spoofing */
    uint8_t  global_profile;                /* 0 = Monitor, 1 = Balanced, 2 = Lockdown */
    uint8_t  safe_bypass_mode;              /* 1 = Bootloop watchdog triggered safe bypass */
    uint8_t  screen_sleeping;               /* 1 = Screen off / Deep Sleep active */
    uint8_t  sleep_mode;                    /* SentinelSleepMode */
    uint32_t uid_flags[SENTINEL_MAX_APP_IDS];
};

/* Compact Datagram Telemetry Packet sent over non-blocking SOCK_DGRAM (<= 512 bytes) */
struct SentinelTelemetryPacket {
    uint32_t magic;             /* SENTINEL_PROTOCOL_MAGIC */
    uint32_t uid;
    uint32_t pid;
    uint32_t target_uid;        /* For IPC/Binder calls, 0 otherwise */
    uint16_t category;          /* SentinelCategory bit */
    uint8_t  severity;          /* SentinelSeverity */
    uint8_t  action;            /* SentinelAction */
    uint8_t  is_background;     /* 1 if caller procState is background/cached */
    uint8_t  reserved[3];
    char     package_name[96];
    char     event_type[40];    /* e.g. "DNS_QUERY", "TCP_CONNECT", "IPC_SERVICE", "MIC_BG" */
    char     target[128];       /* e.g. "graph.facebook.com:443", "com.miui.analytics", "IMEI" */
    char     detail[160];       /* Extra metadata / descriptor / spoofed replacement */
};

#ifdef __cplusplus
}
#endif
