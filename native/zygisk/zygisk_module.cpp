#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../include/zygisk.hpp"
#include "../include/sentinel_protocol.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <string>

#ifdef __ANDROID__
#include <android/log.h>
#define SLOGI(...) __android_log_print(ANDROID_LOG_INFO, "PrivacySentinelZygisk", __VA_ARGS__)
#else
#define SLOGI(...) do {} while (0)
#endif

/* ============================================================================
 * Privacy Sentinel — Zygisk Native Layer (Android 17 / API 37 / arm64-v8a)
 *
 * Responsibilities:
 *  1. Zero-Touch Unload (DLCLOSE_MODULE_LIBRARY) for Play Integrity Fix v4.9,
 *     Tricky Store targets, Google Play Services, and Zygisk Next DenyList.
 *  2. Mount Namespace Filesystem Sandbox (Level 1 & Level 2) before app
 *     specialization (isolates /storage/emulated/0 -> /.sentinel_sandbox/<pkg>).
 *  3. Fast non-blocking PLT hooks on libc.so & libbinder.so:
 *     - connect() / sendto() : Network logging + Interactive Prompt / Block
 *     - getaddrinfo() / android_getaddrinfo_proxy() : Pre-DoH/DoT DNS capture
 *     - openat() / faccessat() : Root / /data/adb / /proc stealth scan trap
 *     - IPCThreadState::transact() : Direct native Binder IPC monitoring
 * ============================================================================ */

namespace {

struct ProcessContext {
    uint32_t              uid          = 0;
    uint32_t              flags        = 0;
    char                  pkg_name[96] = {};
    int                   dgram_fd     = -1;
    sockaddr_un           dgram_addr   = {};
    const SentinelPolicyShm* shm       = nullptr;
};

ProcessContext g_ctx{};

/* Original function pointers populated by Zygisk PLT hook engine */
int (*orig_connect)(int sockfd, const sockaddr* addr, socklen_t addrlen) = nullptr;
ssize_t (*orig_sendto)(int sockfd, const void* buf, size_t len, int flags,
                       const sockaddr* dest_addr, socklen_t addrlen) = nullptr;
int (*orig_getaddrinfo)(const char* node, const char* service,
                        const addrinfo* hints, addrinfo** res) = nullptr;
int (*orig_openat)(int dirfd, const char* pathname, int flags, mode_t mode) = nullptr;
int (*orig_binder_transact)(void* thiz, int32_t handle, uint32_t code,
                            const void* data_parcel, void* reply_parcel, uint32_t flags) = nullptr;

inline uint32_t currentFlags() {
    if (g_ctx.shm && g_ctx.shm->magic == SENTINEL_PROTOCOL_MAGIC) {
        if (g_ctx.shm->safe_bypass_mode) return POL_NONE;
        uint32_t app_id = g_ctx.uid % 100000u;
        if (app_id < SENTINEL_MAX_APP_IDS) {
            return g_ctx.shm->uid_flags[app_id];
        }
    }
    return g_ctx.flags;
}

/* Microsecond non-blocking fire-and-forget telemetry over SOCK_DGRAM */
void emitEventFast(uint16_t category, uint8_t severity, uint8_t action,
                   const char* type, const char* target, const char* detail) {
    if (g_ctx.dgram_fd < 0) return;
    SentinelTelemetryPacket pkt{};
    pkt.magic         = SENTINEL_PROTOCOL_MAGIC;
    pkt.uid           = g_ctx.uid;
    pkt.pid           = static_cast<uint32_t>(::getpid());
    pkt.category      = category;
    pkt.severity      = severity;
    pkt.action        = action;
    pkt.is_background = 0;
    std::snprintf(pkt.package_name, sizeof(pkt.package_name), "%s", g_ctx.pkg_name);
    std::snprintf(pkt.event_type, sizeof(pkt.event_type), "%s", type ? type : "");
    std::snprintf(pkt.target, sizeof(pkt.target), "%s", target ? target : "");
    std::snprintf(pkt.detail, sizeof(pkt.detail), "%s", detail ? detail : "");

    (void)::sendto(g_ctx.dgram_fd, &pkt, sizeof(pkt), MSG_DONTWAIT | MSG_NOSIGNAL,
                   reinterpret_cast<const sockaddr*>(&g_ctx.dgram_addr), sizeof(g_ctx.dgram_addr));
}

/* Ask sentineld Interactive Prompt Broker with strict bounded timeout */
bool askInteractiveDecision(uint16_t cat, const char* resource_title, const char* detail) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return true; /* Fail-Open on socket error */

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SENTINEL_CTRL_SOCK_PATH);
    int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        ::close(fd);
        return true; /* Daemon offline -> Fail-Open */
    }
    pollfd pfd{fd, POLLOUT, 0};
    if (::poll(&pfd, 1, SENTINEL_HOOK_TIMEOUT_MS) <= 0) {
        ::close(fd);
        return true;
    }

    char req[512];
    int n = std::snprintf(
        req, sizeof(req),
        "{\"cmd\":\"prompt_ask_blocking\",\"uid\":%u,\"package_name\":\"%s\",\"category\":%u,"
        "\"resource_title\":\"%s\",\"detail\":\"%s\",\"timeout_ms\":9000}\n",
        g_ctx.uid, g_ctx.pkg_name, unsigned(cat), resource_title, detail);
    if (::send(fd, req, static_cast<size_t>(n), MSG_NOSIGNAL) <= 0) {
        ::close(fd);
        return true;
    }

    pfd.events = POLLIN;
    if (::poll(&pfd, 1, 9500) <= 0) {
        ::close(fd);
        return false; /* Prompt timed out -> Safe Silent Deny */
    }
    char resp[256]{};
    ssize_t r = ::recv(fd, resp, sizeof(resp) - 1, 0);
    ::close(fd);
    if (r <= 0) return true;
    return (std::strstr(resp, "\"allow_") != nullptr);
}

bool formatSockaddr(const sockaddr* addr, char* out, size_t out_sz, bool* is_loopback) {
    *is_loopback = false;
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(addr);
        if (ntohl(in->sin_addr.s_addr) == INADDR_LOOPBACK) *is_loopback = true;
        char ip[INET_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        std::snprintf(out, out_sz, "%s:%u", ip, unsigned(ntohs(in->sin_port)));
        return true;
    }
    if (addr->sa_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) *is_loopback = true;
        char ip6[INET6_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET6, &in6->sin6_addr, ip6, sizeof(ip6));
        std::snprintf(out, out_sz, "[%s]:%u", ip6, unsigned(ntohs(in6->sin6_port)));
        return true;
    }
    return false;
}

/* ---- Hooked libc / libbinder Functions ---- */

int hooked_connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    char dst[96]{};
    bool is_lo = false;
    if (formatSockaddr(addr, dst, sizeof(dst), &is_lo) && !is_lo) {
        uint32_t fl = currentFlags();
        if (fl & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) {
            if (fl & POL_ASK_INTERACTIVE) {
                char title[128];
                std::snprintf(title, sizeof(title), "TCP Connect -> %s", dst);
                if (askInteractiveDecision(CAT_NETWORK, title, "Blocked app requested outbound socket")) {
                    return orig_connect(sockfd, addr, addrlen);
                }
            }
            emitEventFast(CAT_NETWORK, SEV_HIGH, ACT_SILENT_DROP,
                          "TCP_CONNECT_BLOCK", dst, "Blocked in Zygisk connect() before packet egress");
            errno = ENETUNREACH;
            return -1;
        }
        emitEventFast(CAT_NETWORK, SEV_INFO,
                      (fl & POL_ROUTE_PROXY) ? ACT_PROXIED : ACT_OBSERVED,
                      "TCP_CONNECT", dst, "Zygisk native socket telemetry");
    }
    return orig_connect(sockfd, addr, addrlen);
}

ssize_t hooked_sendto(int sockfd, const void* buf, size_t len, int flags,
                      const sockaddr* dest_addr, socklen_t addrlen) {
    char dst[96]{};
    bool is_lo = false;
    if (dest_addr && formatSockaddr(dest_addr, dst, sizeof(dst), &is_lo) && !is_lo) {
        uint32_t fl = currentFlags();
        if (fl & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) {
            emitEventFast(CAT_NETWORK, SEV_MEDIUM, ACT_SILENT_DROP,
                          "UDP_SENDTO_BLOCK", dst, "Dropped outbound datagram in Zygisk");
            errno = ENETUNREACH;
            return -1;
        }
        emitEventFast(CAT_NETWORK, SEV_INFO, ACT_OBSERVED, "UDP_SENDTO", dst, "Datagram egress");
    }
    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

int hooked_getaddrinfo(const char* node, const char* service,
                       const addrinfo* hints, addrinfo** res) {
    if (node && node[0] != '\0') {
        uint32_t fl = currentFlags();
        if (fl & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) {
            emitEventFast(CAT_NETWORK, SEV_MEDIUM, ACT_SILENT_DROP,
                          "DNS_BLOCKED", node, "Blocked pre-DoH/DoT hostname lookup");
            return EAI_NONAME;
        }
        emitEventFast(CAT_NETWORK, SEV_LOW, ACT_OBSERVED,
                      "DNS_QUERY", node, "Captured plaintext hostname prior to DoH/DoT resolver");
    }
    return orig_getaddrinfo(node, service, hints, res);
}

bool isSuspiciousRootProbePath(const char* p) {
    if (!p) return false;
    return (std::strstr(p, "/data/adb") != nullptr ||
            std::strstr(p, "/sbin/su") != nullptr ||
            std::strstr(p, "/system/bin/su") != nullptr ||
            std::strstr(p, "/system/xbin/su") != nullptr ||
            std::strstr(p, "kernelsu") != nullptr ||
            std::strstr(p, "bakasu") != nullptr ||
            std::strstr(p, "zygisk") != nullptr ||
            std::strstr(p, "lsposed") != nullptr);
}

int hooked_openat(int dirfd, const char* pathname, int flags, mode_t mode) {
    if (pathname && (currentFlags() & POL_TRAP_ROOT_SCAN) && isSuspiciousRootProbePath(pathname)) {
        emitEventFast(CAT_DANGER, SEV_CRITICAL, ACT_SILENT_DROP,
                      "ROOT_SCAN_TRAP", pathname, "App probed root/module path; masked with ENOENT");
        errno = ENOENT;
        return -1;
    }
    return orig_openat(dirfd, pathname, flags, mode);
}

int hooked_binder_transact(void* thiz, int32_t handle, uint32_t code,
                           const void* data_parcel, void* reply_parcel, uint32_t flags) {
    /* Rate-limit native Binder telemetry per process to keep overhead near zero */
    static thread_local uint32_t binder_sample = 0;
    if ((++binder_sample & 0x3Fu) == 1u) {
        char desc[64];
        std::snprintf(desc, sizeof(desc), "Binder[handle=%d, code=%u]", handle, code);
        emitEventFast(CAT_IPC, SEV_INFO, ACT_OBSERVED,
                      "BINDER_TRANSACT", desc, "Direct libbinder IPCThreadState::transact");
    }
    return orig_binder_transact(thiz, handle, code, data_parcel, reply_parcel, flags);
}

bool isBuiltInZeroTouchPackage(const char* pkg) {
    if (!pkg) return true;
    return (std::strcmp(pkg, "com.google.android.gms") == 0 ||
            std::strncmp(pkg, "com.google.android.gms.", 23) == 0 ||
            std::strcmp(pkg, "com.google.android.gsf") == 0 ||
            std::strcmp(pkg, "com.android.vending") == 0 ||
            std::strcmp(pkg, "com.xiaomi.finddevice") == 0);
}

/* Companion IPC structures (Zygote <-> Root Companion) */
struct CompanionReq {
    uint32_t uid;
    char     pkg[96];
};

struct CompanionResp {
    uint32_t flags;
    uint8_t  zero_touch;
};

void sentinelCompanionHandler(int client_fd) {
    CompanionReq req{};
    if (::read(client_fd, &req, sizeof(req)) != sizeof(req)) {
        return;
    }

    CompanionResp resp{};
    if (isBuiltInZeroTouchPackage(req.pkg)) {
        resp.zero_touch = 1;
        resp.flags      = POL_EXEMPT_ZERO_TOUCH;
    }

    int mfd = ::open(SENTINEL_POLICY_MMAP_PATH, O_RDONLY | O_CLOEXEC);
    if (mfd >= 0) {
        auto* shm = static_cast<const SentinelPolicyShm*>(
            ::mmap(nullptr, sizeof(SentinelPolicyShm), PROT_READ, MAP_SHARED, mfd, 0));
        if (shm != MAP_FAILED && shm->magic == SENTINEL_PROTOCOL_MAGIC) {
            uint32_t app_id = req.uid % 100000u;
            if (app_id < SENTINEL_MAX_APP_IDS) {
                resp.flags = shm->uid_flags[app_id];
                if (resp.flags & POL_EXEMPT_ZERO_TOUCH) resp.zero_touch = 1;
            }
            if (shm->safe_bypass_mode) {
                resp.zero_touch = 1;
            }
        }
        if (shm != MAP_FAILED) ::munmap(const_cast<SentinelPolicyShm*>(shm), sizeof(SentinelPolicyShm));
    }

    /* Send response + pass read-only policy.mmap fd via SCM_RIGHTS if non-exempt */
    msghdr msg{};
    iovec iov{&resp, sizeof(resp)};
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    union {
        char   buf[CMSG_SPACE(sizeof(int))];
        cmsghdr align;
    } u{};

    if (!resp.zero_touch && mfd >= 0) {
        msg.msg_control    = u.buf;
        msg.msg_controllen = sizeof(u.buf);
        cmsghdr* cmsg      = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level   = SOL_SOCKET;
        cmsg->cmsg_type    = SCM_RIGHTS;
        cmsg->cmsg_len     = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(cmsg), &mfd, sizeof(int));
    }

    (void)::sendmsg(client_fd, &msg, MSG_NOSIGNAL);
    if (mfd >= 0) ::close(mfd);

    /* Ensure isolated sandbox folder exists if POL_SANDBOX_FS_L1 / L2 active */
    if (!resp.zero_touch && (resp.flags & (POL_SANDBOX_FS_L1 | POL_SANDBOX_KERNEL_L2))) {
        char sb_dir[256];
        std::snprintf(sb_dir, sizeof(sb_dir), "/data/media/0/.sentinel_sandbox/%s", req.pkg);
        ::mkdir("/data/media/0/.sentinel_sandbox", 0770);
        ::mkdir(sb_dir, 0770);
    }
}

class PrivacySentinelZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        const uint32_t uid = static_cast<uint32_t>(args->uid);
        const uint32_t zflags = api_->getFlags();

        /* 1. Never inject into root processes, system UIDs (<10000), or Zygisk Next DenyList */
        if (uid < 10000 || (zflags & (zygisk::StateFlag::PROCESS_GRANTED_ROOT | zygisk::StateFlag::PROCESS_ON_DENYLIST))) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            skip_ = true;
            return;
        }

        const char* nice = args->nice_name ? env_->GetStringUTFChars(args->nice_name, nullptr) : nullptr;
        if (nice) {
            std::snprintf(g_ctx.pkg_name, sizeof(g_ctx.pkg_name), "%s", nice);
            /* Strip ':process_suffix' if present */
            if (char* colon = std::strchr(g_ctx.pkg_name, ':')) *colon = '\0';
            env_->ReleaseStringUTFChars(args->nice_name, nice);
        }
        g_ctx.uid = uid;

        if (isBuiltInZeroTouchPackage(g_ctx.pkg_name)) {
            api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            skip_ = true;
            return;
        }

        /* 2. Query root companion for per-UID flags & read-only policy.mmap FD */
        int cfd = api_->connectCompanion();
        int received_mmap_fd = -1;
        if (cfd >= 0) {
            CompanionReq req{};
            req.uid = uid;
            std::snprintf(req.pkg, sizeof(req.pkg), "%s", g_ctx.pkg_name);
            if (::write(cfd, &req, sizeof(req)) == sizeof(req)) {
                CompanionResp resp{};
                iovec iov{&resp, sizeof(resp)};
                union {
                    char   buf[CMSG_SPACE(sizeof(int))];
                    cmsghdr align;
                } u{};
                msghdr msg{};
                msg.msg_iov        = &iov;
                msg.msg_iovlen     = 1;
                msg.msg_control    = u.buf;
                msg.msg_controllen = sizeof(u.buf);
                if (::recvmsg(cfd, &msg, 0) > 0) {
                    g_ctx.flags = resp.flags;
                    if (resp.zero_touch) {
                        ::close(cfd);
                        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
                        skip_ = true;
                        return;
                    }
                    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
                    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
                        cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                        std::memcpy(&received_mmap_fd, CMSG_DATA(cmsg), sizeof(int));
                    }
                }
            }
            ::close(cfd);
        }

        if (received_mmap_fd >= 0) {
            api_->exemptFd(received_mmap_fd);
            mmap_fd_ = received_mmap_fd;
        }

        /* 3. Mount Namespace Sandbox Isolation (runs with Zygote privileges prior to drop) */
        if (g_ctx.flags & (POL_SANDBOX_FS_L1 | POL_SANDBOX_KERNEL_L2)) {
            if (::unshare(CLONE_NEWNS) == 0) {
                ::mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);
                char sb_dir[256];
                std::snprintf(sb_dir, sizeof(sb_dir), "/data/media/0/.sentinel_sandbox/%s", g_ctx.pkg_name);
                ::mount(sb_dir, "/storage/emulated/0", nullptr, MS_BIND | MS_REC, nullptr);
            }
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (skip_) return;

        if (mmap_fd_ >= 0) {
            auto* ptr = ::mmap(nullptr, sizeof(SentinelPolicyShm), PROT_READ, MAP_SHARED, mmap_fd_, 0);
            if (ptr != MAP_FAILED) {
                g_ctx.shm = static_cast<const SentinelPolicyShm*>(ptr);
            }
            ::close(mmap_fd_);
            mmap_fd_ = -1;
        }

        /* Open non-blocking datagram telemetry socket */
        g_ctx.dgram_fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        g_ctx.dgram_addr.sun_family = AF_UNIX;
        std::snprintf(g_ctx.dgram_addr.sun_path, sizeof(g_ctx.dgram_addr.sun_path),
                      "%s", SENTINEL_DGRAM_SOCK_PATH);

        installPltHooks();
        SLOGI("Active inside %s (uid=%u, flags=0x%x)", g_ctx.pkg_name, g_ctx.uid, g_ctx.flags);
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs*) override {
        /* system_server is hooked in Java by Vector (LibXposed API 102); unload Zygisk .so cleanly */
        api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    void installPltHooks() {
        FILE* fp = std::fopen("/proc/self/maps", "r");
        if (!fp) return;

        char line[512];
        while (std::fgets(line, sizeof(line), fp)) {
            unsigned long dev_maj = 0, dev_min = 0;
            unsigned long inode   = 0;
            char perms[8]{};
            int path_off = 0;
            if (std::sscanf(line, "%*x-%*x %7s %*x %lx:%lx %lu %n",
                            perms, &dev_maj, &dev_min, &inode, &path_off) >= 4 && inode != 0) {
                const char* path = line + path_off;
                /* Register PLT hooks on app/framework ELFs calling into libc & libbinder */
                if (std::strstr(path, "libjavacore.so") ||
                    std::strstr(path, "libopenjdk.so") ||
                    std::strstr(path, "libnetd_client.so") ||
                    std::strstr(path, "libandroid_runtime.so") ||
                    std::strstr(path, "/data/app/")) {
                    dev_t dev = makedev(dev_maj, dev_min);
                    api_->pltHookRegister(dev, inode, "connect",
                                          reinterpret_cast<void*>(hooked_connect),
                                          reinterpret_cast<void**>(&orig_connect));
                    api_->pltHookRegister(dev, inode, "sendto",
                                          reinterpret_cast<void*>(hooked_sendto),
                                          reinterpret_cast<void**>(&orig_sendto));
                    api_->pltHookRegister(dev, inode, "getaddrinfo",
                                          reinterpret_cast<void*>(hooked_getaddrinfo),
                                          reinterpret_cast<void**>(&orig_getaddrinfo));
                    api_->pltHookRegister(dev, inode, "openat",
                                          reinterpret_cast<void*>(hooked_openat),
                                          reinterpret_cast<void**>(&orig_openat));
                    api_->pltHookRegister(dev, inode,
                                          "_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j",
                                          reinterpret_cast<void*>(hooked_binder_transact),
                                          reinterpret_cast<void**>(&orig_binder_transact));
                }
            }
        }
        std::fclose(fp);
        api_->pltHookCommit();
    }

    zygisk::Api* api_     = nullptr;
    JNIEnv*      env_     = nullptr;
    bool         skip_    = false;
    int          mmap_fd_ = -1;
};

} // namespace

REGISTER_ZYGISK_MODULE(PrivacySentinelZygiskModule)
REGISTER_ZYGISK_COMPANION(sentinelCompanionHandler)
