#include "../include/sentinel_protocol.h"
#include "firewall_controller.hpp"
#include "proxy_relay.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <random>
#include <sstream>
#include <string>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <unistd.h>

/* ============================================================================
 * sentineld — Core Native Daemon for Privacy Sentinel
 * Target: POCO X6 5G (garnet) / HyperOS 4 / Android 17 (API 37) / Linux 5.10
 * Root Stack: BakaSU (KernelSU + SuSFS) + Zygisk Next + Vector (LibXposed 102)
 * ============================================================================ */

namespace fs = std::filesystem;

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) {
    g_running.store(false);
}

uint64_t nowEpochMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

/* Minimal, fast JSON field extractors (zero external dependencies) */
std::string extractJsonString(const std::string& body, const std::string& key, const std::string& def = "") {
    std::string needle = "\"" + key + "\"";
    size_t pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos = body.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos || body[pos] != '"') return def;
    ++pos;
    std::string val;
    while (pos < body.size()) {
        char c = body[pos++];
        if (c == '\\' && pos < body.size()) {
            char esc = body[pos++];
            switch (esc) {
                case 'n': val.push_back('\n'); break;
                case 'r': val.push_back('\r'); break;
                case 't': val.push_back('\t'); break;
                default:  val.push_back(esc); break;
            }
        } else if (c == '"') {
            break;
        } else {
            val.push_back(c);
        }
    }
    return val;
}

int64_t extractJsonInt(const std::string& body, const std::string& key, int64_t def = 0) {
    std::string needle = "\"" + key + "\"";
    size_t pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos = body.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos) return def;
    char* endp = nullptr;
    long long v = std::strtoll(body.c_str() + pos, &endp, 10);
    if (endp == body.c_str() + pos) return def;
    return static_cast<int64_t>(v);
}

double extractJsonDouble(const std::string& body, const std::string& key, double def = 0.0) {
    std::string needle = "\"" + key + "\"";
    size_t pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos = body.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos) return def;
    char* endp = nullptr;
    double v = std::strtod(body.c_str() + pos, &endp);
    if (endp == body.c_str() + pos) return def;
    return v;
}

bool extractJsonBool(const std::string& body, const std::string& key, bool def = false) {
    std::string needle = "\"" + key + "\"";
    size_t pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos = body.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos) return def;
    if (body.compare(pos, 4, "true") == 0) return true;
    if (body.compare(pos, 5, "false") == 0) return false;
    return def;
}

std::string generateSecureTokenHex() {
    uint8_t raw[32]{};
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t r = ::read(fd, raw, sizeof(raw));
        (void)r;
        ::close(fd);
    } else {
        std::random_device rd;
        for (size_t i = 0; i < sizeof(raw); ++i) raw[i] = static_cast<uint8_t>(rd() & 0xFF);
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : raw) oss << std::setw(2) << int(b);
    return oss.str();
}

struct EventRecord {
    uint64_t    seq           = 0;
    uint64_t    timestamp_ms  = 0;
    uint32_t    uid           = 0;
    uint32_t    pid           = 0;
    uint32_t    target_uid    = 0;
    uint16_t    category      = 0;
    uint8_t     severity      = 0;
    uint8_t     action        = 0;
    bool        is_background = false;
    std::string package_name;
    std::string event_type;
    std::string target;
    std::string detail;
};

struct AppStats {
    uint32_t    uid            = 0;
    std::string package_name;
    std::string label;
    bool        is_system      = false;
    std::string proc_state     = "CACHED"; /* FG, BG, CACHED */
    uint64_t    last_active_ms = 0;
    uint32_t    cnt_network    = 0;
    uint32_t    cnt_data       = 0;
    uint32_t    cnt_autostart  = 0;
    uint32_t    cnt_danger     = 0;
    uint32_t    cnt_ipc        = 0;
    uint32_t    cnt_sandbox    = 0;
    uint32_t    cnt_proxy      = 0;
    uint32_t    cnt_blocked    = 0;
    uint32_t    cnt_spoofed    = 0;
};

struct PendingPrompt {
    uint64_t    id             = 0;
    uint64_t    created_ms     = 0;
    uint64_t    expires_ms     = 0;
    uint32_t    uid            = 0;
    std::string package_name;
    std::string app_label;
    uint16_t    category       = CAT_NETWORK;
    std::string resource_title; /* e.g. "TCP Connect -> graph.facebook.com:443" */
    std::string detail;
    bool        is_background  = true;
    bool        resolved       = false;
    std::string decision;       /* "allow_once", "allow_always", "spoof", "deny" */
};

class SentinelState {
public:
    SentinelState(const std::string& base_dir, const std::string& webroot_dir, bool preview_demo)
        : base_dir_(base_dir),
          run_dir_(base_dir + "/run"),
          cfg_dir_(base_dir + "/config"),
          webroot_dir_(webroot_dir),
          preview_demo_(preview_demo),
          fw_(preview_demo || ::geteuid() != 0)
    {
        fs::create_directories(run_dir_);
        fs::create_directories(cfg_dir_);
        ::chmod(run_dir_.c_str(), 0711); /* Traverse allowed for read-only policy.mmap, sockets restricted per-file */

        auth_token_ = generateSecureTokenHex();
        std::string tok_path = run_dir_ + "/webui.token";
        {
            std::ofstream tf(tok_path, std::ios::trunc);
            tf << auth_token_ << "\n";
        }
        ::chmod(tok_path.c_str(), 0600);

        std::random_device rd;
        master_seed_ = (static_cast<uint32_t>(rd()) ^ 0xA17B510u);

        initPolicyMmap();
        seedDeviceInventoryAndZeroTouch();

        proxy_.setTelemetryCallback([this](const std::string& dst, bool ok, const std::string& note) {
            SentinelTelemetryPacket pkt{};
            pkt.magic = SENTINEL_PROTOCOL_MAGIC;
            pkt.uid = 10284;
            pkt.pid = 4812;
            pkt.category = CAT_PROXY;
            pkt.severity = ok ? SEV_LOW : SEV_HIGH;
            pkt.action = ok ? ACT_PROXIED : ACT_REJECT_ERROR;
            pkt.is_background = 0;
            std::snprintf(pkt.package_name, sizeof(pkt.package_name), "%s", "org.telegram.messenger");
            std::snprintf(pkt.event_type, sizeof(pkt.event_type), "%s", ok ? "SOCKS5_TUNNEL" : "SOCKS5_ERR");
            std::snprintf(pkt.target, sizeof(pkt.target), "%s", dst.c_str());
            std::snprintf(pkt.detail, sizeof(pkt.detail), "%s", note.c_str());
            ingestTelemetry(pkt);
        });

        syncAllKernelAndPolicyState();
    }

    ~SentinelState() {
        proxy_.stop();
        if (policy_shm_ && policy_shm_ != MAP_FAILED) {
            ::munmap(policy_shm_, sizeof(SentinelPolicyShm));
        }
        if (policy_fd_ >= 0) ::close(policy_fd_);
    }

    const std::string& authToken() const { return auth_token_; }
    const std::string& runDir() const { return run_dir_; }
    const std::string& webrootDir() const { return webroot_dir_; }
    bool isPreviewDemo() const { return preview_demo_; }

    bool validateToken(const std::string& provided) const {
        if (preview_demo_ && provided == "preview-session") return true;
        if (provided.size() != auth_token_.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < auth_token_.size(); ++i) {
            diff |= static_cast<uint8_t>(provided[i] ^ auth_token_[i]);
        }
        return diff == 0;
    }

    void ingestTelemetry(const SentinelTelemetryPacket& pkt) {
        if (pkt.magic != SENTINEL_PROTOCOL_MAGIC) return;
        std::lock_guard<std::mutex> lk(mu_);

        EventRecord ev;
        ev.seq           = ++next_seq_;
        ev.timestamp_ms  = nowEpochMs();
        ev.uid           = pkt.uid;
        ev.pid           = pkt.pid;
        ev.target_uid    = pkt.target_uid;
        ev.category      = pkt.category;
        ev.severity      = pkt.severity;
        ev.action        = pkt.action;
        ev.is_background = pkt.is_background != 0;
        ev.package_name  = pkt.package_name[0] ? pkt.package_name : resolvePkgByUidLocked(pkt.uid);
        ev.event_type    = pkt.event_type;
        ev.target        = pkt.target;
        ev.detail        = pkt.detail;

        if (ring_.size() >= SENTINEL_RING_CAPACITY) {
            ring_.pop_front();
        }
        ring_.push_back(ev);

        auto& st = stats_[ev.uid];
        if (st.uid == 0) {
            st.uid          = ev.uid;
            st.package_name = ev.package_name;
            st.label        = ev.package_name;
            st.is_system    = (ev.uid < 10000);
        }
        st.last_active_ms = ev.timestamp_ms;
        st.proc_state     = ev.is_background ? "BG" : "FG";
        if (ev.category & CAT_NETWORK)   ++st.cnt_network;
        if (ev.category & CAT_DATA)      ++st.cnt_data;
        if (ev.category & CAT_AUTOSTART) ++st.cnt_autostart;
        if (ev.category & CAT_DANGER)    ++st.cnt_danger;
        if (ev.category & CAT_IPC)       ++st.cnt_ipc;
        if (ev.category & CAT_SANDBOX)   ++st.cnt_sandbox;
        if (ev.category & CAT_PROXY)     ++st.cnt_proxy;

        if (ev.action == ACT_SILENT_DROP || ev.action == ACT_REJECT_ERROR ||
            ev.action == ACT_SOCKET_KILLED || ev.action == ACT_PROMPT_DENIED) {
            ++st.cnt_blocked;
            ++total_blocked_;
        } else if (ev.action == ACT_SPOOFED) {
            ++st.cnt_spoofed;
            ++total_spoofed_;
        }
        ++total_events_;
    }

    /* Interactive Android-17 System Permission Prompt Creation & Resolution */
    uint64_t enqueueInteractivePrompt(
        uint32_t uid,
        const std::string& pkg,
        uint16_t category,
        const std::string& resource_title,
        const std::string& detail,
        bool is_bg)
    {
        std::lock_guard<std::mutex> lk(mu_);
        /* Check if temporary allow_once grant exists for this (uid, resource_title) */
        std::string grant_key = std::to_string(uid) + "|" + resource_title;
        auto git = temp_grants_.find(grant_key);
        uint64_t now = nowEpochMs();
        if (git != temp_grants_.end() && git->second > now) {
            return 0; /* 0 = Already temporarily allowed! */
        }

        PendingPrompt p;
        p.id             = ++next_prompt_id_;
        p.created_ms     = now;
        p.expires_ms     = now + SENTINEL_PROMPT_TIMEOUT_MS;
        p.uid            = uid;
        p.package_name   = pkg.empty() ? resolvePkgByUidLocked(uid) : pkg;
        p.app_label      = resolveLabelByUidLocked(uid, p.package_name);
        p.category       = category;
        p.resource_title = resource_title;
        p.detail         = detail;
        p.is_background  = is_bg;
        prompts_.push_back(p);
        if (prompts_.size() > 32) prompts_.pop_front();
        prompt_cv_.notify_all();
        return p.id;
    }

    std::string waitPromptDecision(uint64_t prompt_id, uint32_t wait_ms) {
        if (prompt_id == 0) return "allow_once";
        std::unique_lock<std::mutex> lk(mu_);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            for (auto& p : prompts_) {
                if (p.id == prompt_id && p.resolved) {
                    return p.decision;
                }
            }
            prompt_cv_.wait_until(lk, deadline);
        }
        /* Timeout fallback: Safe Silent-Drop so system/app never hangs forever */
        for (auto& p : prompts_) {
            if (p.id == prompt_id && !p.resolved) {
                p.resolved = true;
                p.decision = "deny";
                recordPromptOutcomeLocked(p);
                break;
            }
        }
        return "deny";
    }

    bool resolvePrompt(uint64_t prompt_id, const std::string& decision) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& p : prompts_) {
            if (p.id == prompt_id && !p.resolved) {
                p.resolved = true;
                p.decision = decision;
                if (decision == "allow_once") {
                    temp_grants_[std::to_string(p.uid) + "|" + p.resource_title] = nowEpochMs() + 90000;
                } else if (decision == "allow_always") {
                    auto it = apps_.find(p.uid);
                    if (it != apps_.end()) {
                        if (p.category & CAT_NETWORK) it->second.flags &= ~(POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2);
                        if (p.category & CAT_IPC)     it->second.flags &= ~POL_BLOCK_BG_IPC;
                        if (p.category & CAT_DATA)    it->second.flags &= ~POL_ANTISPY_BG_CLIP;
                        if (p.category & CAT_DANGER)  it->second.flags &= ~POL_ANTISPY_BG_MIC_CAM;
                    }
                    syncAllLocked();
                } else if (decision == "spoof") {
                    auto it = apps_.find(p.uid);
                    if (it != apps_.end()) {
                        it->second.flags |= POL_SPOOF_DETERMINISTIC;
                    }
                    syncAllLocked();
                }
                recordPromptOutcomeLocked(p);
                prompt_cv_.notify_all();
                return true;
            }
        }
        return false;
    }

    /* Handle JSON Command RPC (shared between UNIX socket sentinelctl & HTTP REST) */
    std::string handleCommandJson(const std::string& cmd, const std::string& payload) {
        if (cmd == "status") {
            return buildStatusJson();
        }
        if (cmd == "dashboard") {
            uint64_t since_seq = static_cast<uint64_t>(extractJsonInt(payload, "since_seq", 0));
            uint32_t limit     = static_cast<uint32_t>(extractJsonInt(payload, "limit", 120));
            return buildDashboardJson(since_seq, limit);
        }
        if (cmd == "update_app") {
            uint32_t uid   = static_cast<uint32_t>(extractJsonInt(payload, "uid", 0));
            uint32_t flags = static_cast<uint32_t>(extractJsonInt(payload, "flags", 0));
            if (uid == 0) return "{\"ok\":false,\"error\":\"invalid_uid\"}";
            {
                std::lock_guard<std::mutex> lk(mu_);
                auto it = apps_.find(uid);
                if (it == apps_.end()) {
                    sentinel::AppRuleEntry entry;
                    entry.uid = uid;
                    entry.package_name = extractJsonString(payload, "package_name", "uid." + std::to_string(uid));
                    entry.label = extractJsonString(payload, "label", entry.package_name);
                    entry.is_system = (uid < 10000);
                    apps_[uid] = entry;
                    it = apps_.find(uid);
                }
                /* Preserve Zero-Touch lock on critical Play Integrity / GMS packages */
                if (zero_touch_pkgs_.count(it->second.package_name)) {
                    flags = POL_EXEMPT_ZERO_TOUCH;
                }
                bool newly_blocked = ((flags & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) != 0) &&
                                     ((it->second.flags & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) == 0);
                it->second.flags = flags;
                std::string c_imei  = extractJsonString(payload, "custom_imei", it->second.custom_imei);
                std::string c_aid   = extractJsonString(payload, "custom_android_id", it->second.custom_android_id);
                std::string c_mac   = extractJsonString(payload, "custom_mac", it->second.custom_mac);
                std::string c_model = extractJsonString(payload, "custom_model", it->second.custom_model);
                it->second.custom_imei       = c_imei;
                it->second.custom_android_id = c_aid;
                it->second.custom_mac        = c_mac;
                it->second.custom_model      = c_model;
                it->second.custom_lat        = extractJsonDouble(payload, "custom_lat", it->second.custom_lat);
                it->second.custom_lon        = extractJsonDouble(payload, "custom_lon", it->second.custom_lon);
                syncAllLocked();
                if (newly_blocked) {
                    uint32_t killed = fw_.destroyActiveSocketsForUid(uid);
                    (void)killed;
                }
            }
            return "{\"ok\":true}";
        }
        if (cmd == "kill_sockets") {
            uint32_t uid = static_cast<uint32_t>(extractJsonInt(payload, "uid", 0));
            uint32_t killed = fw_.destroyActiveSocketsForUid(uid);
            SentinelTelemetryPacket pkt{};
            pkt.magic = SENTINEL_PROTOCOL_MAGIC;
            pkt.uid = uid;
            pkt.pid = 0;
            pkt.category = CAT_NETWORK;
            pkt.severity = SEV_MEDIUM;
            pkt.action = ACT_SOCKET_KILLED;
            std::snprintf(pkt.event_type, sizeof(pkt.event_type), "SOCK_DESTROY");
            std::snprintf(pkt.target, sizeof(pkt.target), "Active TCP/UDP sockets (%u)", killed);
            std::snprintf(pkt.detail, sizeof(pkt.detail), "Terminated immediately via kernel NETLINK_SOCK_DIAG");
            ingestTelemetry(pkt);
            return "{\"ok\":true,\"sockets_killed\":" + std::to_string(killed) + "}";
        }
        if (cmd == "set_global") {
            std::lock_guard<std::mutex> lk(mu_);
            global_profile_   = static_cast<uint8_t>(extractJsonInt(payload, "global_profile", global_profile_));
            sleep_mode_       = static_cast<uint8_t>(extractJsonInt(payload, "sleep_mode", sleep_mode_));
            sleep_grace_sec_  = static_cast<uint32_t>(extractJsonInt(payload, "sleep_grace_sec", sleep_grace_sec_));
            show_system_apps_ = extractJsonBool(payload, "show_system_apps", show_system_apps_);
            bool new_sleep    = extractJsonBool(payload, "screen_sleeping", screen_sleeping_);
            std::string fw_pref = extractJsonString(payload, "fw_backend", "");
            if (!fw_pref.empty()) fw_.setPreferredBackend(fw_pref);

            bool entering_sleep = (!screen_sleeping_ && new_sleep);
            screen_sleeping_ = new_sleep;
            syncAllLocked();

            if (entering_sleep && sleep_mode_ != SLEEP_MODE_OFF) {
                for (const auto& [uid, app] : apps_) {
                    if (app.is_system || (app.flags & POL_EXEMPT_ZERO_TOUCH)) continue;
                    bool cut = false;
                    if (sleep_mode_ == SLEEP_MODE_SELECTED_ONLY) cut = (app.flags & POL_SLEEP_SELECTED) != 0;
                    else if (sleep_mode_ == SLEEP_MODE_ALL_EXCEPT_SELECTED) cut = (app.flags & POL_SLEEP_SELECTED) == 0;
                    else if (sleep_mode_ == SLEEP_MODE_ALL_APPS) cut = true;
                    if (cut) {
                        uint32_t k = fw_.destroyActiveSocketsForUid(uid);
                        if (k > 0) {
                            EventRecord ev;
                            ev.seq = ++next_seq_;
                            ev.timestamp_ms = nowEpochMs();
                            ev.uid = uid;
                            ev.category = CAT_NETWORK;
                            ev.severity = SEV_LOW;
                            ev.action = ACT_SOCKET_KILLED;
                            ev.is_background = true;
                            ev.package_name = app.package_name;
                            ev.event_type = "DEEP_SLEEP_CUT";
                            ev.target = "Screen-Off Socket Sever";
                            ev.detail = "Closed " + std::to_string(k) + " active socket(s) via NETLINK_SOCK_DIAG";
                            if (ring_.size() >= SENTINEL_RING_CAPACITY) ring_.pop_front();
                            ring_.push_back(ev);
                            stats_[uid].cnt_blocked++;
                            total_blocked_++;
                        }
                    }
                }
            }
            return "{\"ok\":true}";
        }
        if (cmd == "set_proxy") {
            sentinel::ProxyConfig pcfg = proxy_.getConfig();
            pcfg.enabled     = extractJsonBool(payload, "enabled", pcfg.enabled);
            pcfg.socks5_host = extractJsonString(payload, "socks5_host", pcfg.socks5_host);
            pcfg.socks5_port = static_cast<uint16_t>(extractJsonInt(payload, "socks5_port", pcfg.socks5_port));
            pcfg.listen_port = static_cast<uint16_t>(extractJsonInt(payload, "listen_port", pcfg.listen_port));
            pcfg.username    = extractJsonString(payload, "username", pcfg.username);
            pcfg.password    = extractJsonString(payload, "password", pcfg.password);
            pcfg.block_quic  = extractJsonBool(payload, "block_quic", pcfg.block_quic);
            pcfg.block_ipv6  = extractJsonBool(payload, "block_ipv6", pcfg.block_ipv6);
            proxy_.updateConfig(pcfg);
            syncAllKernelAndPolicyState();
            return "{\"ok\":true,\"relay_running\":" + std::string(proxy_.isRunning() ? "true" : "false") + "}";
        }
        if (cmd == "add_ipc_rule") {
            std::lock_guard<std::mutex> lk(mu_);
            sentinel::IpcMatrixRule r;
            r.id             = "ipc_" + std::to_string(++next_rule_id_);
            r.caller_pkg     = extractJsonString(payload, "caller_pkg", "*");
            r.target_pkg     = extractJsonString(payload, "target_pkg", "*");
            r.action_glob    = extractJsonString(payload, "action_glob", "*");
            r.component_type = extractJsonString(payload, "component_type", "service");
            r.allow          = extractJsonBool(payload, "allow", false);
            ipc_rules_.push_back(r);
            syncAllLocked();
            return "{\"ok\":true,\"id\":\"" + r.id + "\"}";
        }
        if (cmd == "delete_ipc_rule") {
            std::string rid = extractJsonString(payload, "id", "");
            std::lock_guard<std::mutex> lk(mu_);
            ipc_rules_.erase(
                std::remove_if(ipc_rules_.begin(), ipc_rules_.end(), [&](const auto& x) { return x.id == rid; }),
                ipc_rules_.end());
            syncAllLocked();
            return "{\"ok\":true}";
        }
        if (cmd == "resolve_prompt") {
            uint64_t pid = static_cast<uint64_t>(extractJsonInt(payload, "prompt_id", 0));
            std::string dec = extractJsonString(payload, "decision", "deny");
            bool ok = resolvePrompt(pid, dec);
            return std::string("{\"ok\":") + (ok ? "true" : "false") + "}";
        }
        if (cmd == "trigger_prompt") {
            uint32_t uid   = static_cast<uint32_t>(extractJsonInt(payload, "uid", 10261));
            std::string pkg = extractJsonString(payload, "package_name", "");
            uint16_t cat   = static_cast<uint16_t>(extractJsonInt(payload, "category", CAT_NETWORK));
            std::string res = extractJsonString(payload, "resource_title", "TCP Connect -> log.byteoversea.com:443");
            std::string det = extractJsonString(payload, "detail", "Sandboxed process requested external connection in background");
            bool is_bg     = extractJsonBool(payload, "is_background", true);
            uint64_t pid   = enqueueInteractivePrompt(uid, pkg, cat, res, det, is_bg);
            return "{\"ok\":true,\"prompt_id\":" + std::to_string(pid) + "}";
        }
        if (cmd == "rotate_seed") {
            std::lock_guard<std::mutex> lk(mu_);
            std::random_device rd;
            master_seed_ = static_cast<uint32_t>(rd());
            syncAllLocked();
            return "{\"ok\":true,\"master_seed\":" + std::to_string(master_seed_) + "}";
        }
        if (cmd == "clear_events") {
            std::lock_guard<std::mutex> lk(mu_);
            ring_.clear();
            return "{\"ok\":true}";
        }
        if (cmd == "inspect_rules") {
            std::lock_guard<std::mutex> lk(mu_);
            std::ostringstream oss;
            oss << "{\"ok\":true,"
                << "\"backend\":\"" << jsonEscape(fw_.activeBackendName()) << "\","
                << "\"firewall_script\":\"" << jsonEscape(fw_.lastCompiledRules()) << "\","
                << "\"ifw_xml\":\"" << jsonEscape(fw_.lastIfwXml()) << "\"}";
            return oss.str();
        }
        return "{\"ok\":false,\"error\":\"unknown_command\"}";
    }

    void tickDemoTelemetryStep() {
        if (!preview_demo_) return;
        static uint64_t step = 0;
        ++step;

        struct DemoEventTemplate {
            uint32_t uid;
            uint32_t pid;
            uint32_t target_uid;
            uint16_t cat;
            uint8_t  sev;
            uint8_t  act;
            uint8_t  bg;
            const char* pkg;
            const char* type;
            const char* target;
            const char* detail;
        };

        static const DemoEventTemplate kSamples[] = {
            {10261, 14820, 0, CAT_NETWORK, SEV_HIGH, ACT_SILENT_DROP, 1,
             "com.zhiliaoapp.musically", "DNS_PRE_DOH", "log-va.tiktokv.com",
             "Intercepted via android_getaddrinfo_proxy before DoH encryption"},
            {10261, 14820, 10145, CAT_IPC, SEV_HIGH, ACT_SILENT_DROP, 1,
             "com.zhiliaoapp.musically", "IPC_BIND_SERVICE", "com.xiaomi.mipicks/.PushWakeService",
             "Cross-app background wakeup blocked silently (ActivityManagerService)"},
            {10277, 16204, 0, CAT_DATA, SEV_MEDIUM, ACT_SPOOFED, 0,
             "com.vkontakte.android", "SPOOF_DEVICE_ID", "TelephonyManager.getImei()",
             "Returned deterministic HMAC IMEI 86492006******9 (garnet mask)"},
            {10292, 18110, 0, CAT_DANGER, SEV_CRITICAL, ACT_SILENT_DROP, 1,
             "ru.ozon.app.android", "ROOT_SCAN_TRAP", "/proc/self/mountinfo & /data/adb",
             "SuSFS + Zygisk VFS trap masked BakaSU mounts & logged probe"},
            {10284, 15092, 0, CAT_PROXY, SEV_LOW, ACT_PROXIED, 0,
             "org.telegram.messenger", "SOCKS5_TUNNEL", "149.154.167.91:443",
             "Per-app NAT REDIRECT :19040 -> SOCKS5 127.0.0.1:9050 (no VpnService)"},
            {10152, 9410, 0, CAT_AUTOSTART, SEV_MEDIUM, ACT_SILENT_DROP, 1,
             "com.miui.analytics", "IFW_BROADCAST", "android.intent.action.BOOT_COMPLETED",
             "Blocked by /data/system/ifw/privacy_sentinel.xml"},
            {10305, 19402, 0, CAT_DANGER, SEV_CRITICAL, ACT_SILENT_DROP, 1,
             "com.whatsapp", "BG_MIC_ZERO_PCM", "AudioRecord.read() [Background]",
             "Returned zeroed silent PCM buffer; ViPER4Android playback untouched"},
            {10318, 20411, 0, CAT_DATA, SEV_HIGH, ACT_SILENT_DROP, 1,
             "com.alibaba.aliexpresshd", "CLIPBOARD_BG", "IClipboard.getPrimaryClip()",
             "Background clipboard read blocked; empty ClipData returned"},
            {10330, 21105, 0, CAT_SANDBOX, SEV_MEDIUM, ACT_OBSERVED, 0,
             "com.wildberries.ru", "SANDBOX_NS_FS", "/storage/emulated/0/DCIM",
             "Redirected inside isolated mount namespace /.sentinel_sandbox/com.wildberries.ru"},
            {10212, 8112, 0, CAT_NETWORK, SEV_INFO, ACT_OBSERVED, 0,
             "com.google.android.gms", "ZERO_TOUCH_PASS", "play.googleapis.com:443",
             "Zero-Touch PIF/TrickyStore exemption active (DLCLOSE_MODULE_LIBRARY)"}
        };

        const auto& tpl = kSamples[step % (sizeof(kSamples) / sizeof(kSamples[0]))];
        SentinelTelemetryPacket pkt{};
        pkt.magic         = SENTINEL_PROTOCOL_MAGIC;
        pkt.uid           = tpl.uid;
        pkt.pid           = tpl.pid;
        pkt.target_uid    = tpl.target_uid;
        pkt.category      = tpl.cat;
        pkt.severity      = tpl.sev;
        pkt.action        = tpl.act;
        pkt.is_background = tpl.bg;
        std::snprintf(pkt.package_name, sizeof(pkt.package_name), "%s", tpl.pkg);
        std::snprintf(pkt.event_type, sizeof(pkt.event_type), "%s", tpl.type);
        std::snprintf(pkt.target, sizeof(pkt.target), "%s", tpl.target);
        std::snprintf(pkt.detail, sizeof(pkt.detail), "%s", tpl.detail);
        ingestTelemetry(pkt);
    }

private:
    void initPolicyMmap() {
        std::string mmap_path = run_dir_ + "/policy.mmap";
        policy_fd_ = ::open(mmap_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (policy_fd_ < 0) return;
        if (::ftruncate(policy_fd_, sizeof(SentinelPolicyShm)) != 0) {
            ::close(policy_fd_);
            policy_fd_ = -1;
            return;
        }
        policy_shm_ = static_cast<SentinelPolicyShm*>(
            ::mmap(nullptr, sizeof(SentinelPolicyShm), PROT_READ | PROT_WRITE, MAP_SHARED, policy_fd_, 0));
        if (policy_shm_ != MAP_FAILED && policy_shm_ != nullptr) {
            std::memset(policy_shm_, 0, sizeof(SentinelPolicyShm));
            policy_shm_->magic              = SENTINEL_PROTOCOL_MAGIC;
            policy_shm_->version            = SENTINEL_PROTOCOL_VERSION;
            policy_shm_->generation         = 1;
            policy_shm_->global_master_seed = master_seed_;
            policy_shm_->global_profile     = global_profile_;
        }
    }

    void seedDeviceInventoryAndZeroTouch() {
        /* 1. Built-in Zero-Touch packages for Play Integrity Fix v4.9, Tricky Store & HyperOS core */
        zero_touch_pkgs_ = {
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.vending",
            "com.xiaomi.finddevice"
        };

        /* 2. Dynamically load /data/adb/tricky_store/target.txt if installed on device */
        std::ifstream ts_file("/data/adb/tricky_store/target.txt");
        if (ts_file) {
            std::string line;
            while (std::getline(ts_file, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '!')) {
                    line.pop_back();
                }
                if (!line.empty() && line[0] != '#') {
                    zero_touch_pkgs_.insert(line);
                }
            }
        }

        /* 3. Load real Android /data/system/packages.list if running on device, else realistic POCO X6 5G inventory */
        std::ifstream pkg_list("/data/system/packages.list");
        if (pkg_list && !preview_demo_) {
            std::string pkg;
            uint32_t uid = 0;
            int debuggable = 0;
            std::string data_dir, seinfo;
            while (pkg_list >> pkg >> uid >> debuggable >> data_dir >> seinfo) {
                std::string rest;
                std::getline(pkg_list, rest);
                sentinel::AppRuleEntry e;
                e.uid          = uid;
                e.package_name = pkg;
                e.label        = pkg;
                e.is_system    = (uid < 10000) || (seinfo.find("platform") != std::string::npos);
                if (zero_touch_pkgs_.count(pkg)) {
                    e.flags = POL_EXEMPT_ZERO_TOUCH;
                } else if (!e.is_system) {
                    e.flags = POL_ANTISPY_BG_MIC_CAM | POL_ANTISPY_BG_CLIP | POL_TRAP_ROOT_SCAN;
                }
                apps_[uid] = e;
            }
        } else {
            /* Realistic POCO X6 5G (garnet) HyperOS 4 / Android 17 app & system inventory */
            auto addApp = [&](uint32_t uid, const char* pkg, const char* label, bool sys, uint32_t flags) {
                sentinel::AppRuleEntry e;
                e.uid               = uid;
                e.package_name      = pkg;
                e.label             = label;
                e.is_system         = sys;
                e.flags             = flags;
                e.custom_imei       = "864920067128491";
                e.custom_android_id = "94b81f0c3a72e5d1";
                e.custom_mac        = "02:4c:a9:71:2e:b4";
                e.custom_model      = "2312DRA50G"; /* POCO X6 5G Global model code */
                apps_[uid]          = e;

                AppStats st;
                st.uid            = uid;
                st.package_name   = pkg;
                st.label          = label;
                st.is_system      = sys;
                st.proc_state     = (uid == 10284 || uid == 10277) ? "FG" : "BG";
                st.last_active_ms = nowEpochMs();
                stats_[uid]       = st;
            };

            addApp(10261, "com.zhiliaoapp.musically", "TikTok", false,
                   POL_BLOCK_BG_IPC | POL_BLOCK_AUTOSTART | POL_SLEEP_SELECTED |
                   POL_SPOOF_DETERMINISTIC | POL_ANTISPY_BG_MIC_CAM | POL_ANTISPY_BG_CLIP |
                   POL_TRAP_ROOT_SCAN | POL_ASK_INTERACTIVE);

            addApp(10277, "com.vkontakte.android", "VK", false,
                   POL_BLOCK_BG_IPC | POL_SLEEP_SELECTED | POL_SPOOF_DETERMINISTIC |
                   POL_ANTISPY_BG_MIC_CAM | POL_ANTISPY_BG_CLIP | POL_TRAP_ROOT_SCAN);

            addApp(10284, "org.telegram.messenger", "Telegram", false,
                   POL_ROUTE_PROXY | POL_ANTISPY_BG_CLIP | POL_SPOOF_DETERMINISTIC);

            addApp(10292, "ru.ozon.app.android", "Ozon", false,
                   POL_BLOCK_BG_IPC | POL_BLOCK_AUTOSTART | POL_SLEEP_SELECTED |
                   POL_SPOOF_DETERMINISTIC | POL_TRAP_ROOT_SCAN | POL_ANTISPY_BG_CLIP);

            addApp(10305, "com.whatsapp", "WhatsApp", false,
                   POL_ANTISPY_BG_MIC_CAM | POL_ANTISPY_BG_CLIP | POL_SPOOF_DETERMINISTIC);

            addApp(10318, "com.alibaba.aliexpresshd", "AliExpress", false,
                   POL_BLOCK_NETWORK | POL_BLOCK_BG_IPC | POL_BLOCK_AUTOSTART |
                   POL_SANDBOX_FS_L1 | POL_ASK_INTERACTIVE | POL_ANTISPY_BG_CLIP | POL_TRAP_ROOT_SCAN);

            addApp(10330, "com.wildberries.ru", "Wildberries", false,
                   POL_SANDBOX_FS_L1 | POL_BLOCK_BG_IPC | POL_BLOCK_AUTOSTART |
                   POL_SPOOF_EPHEMERAL | POL_ANTISPY_BG_MIC_CAM | POL_ANTISPY_BG_CLIP);

            addApp(10212, "com.google.android.gms", "Google Play Services (PIF)", true,
                   POL_EXEMPT_ZERO_TOUCH);

            addApp(10215, "com.android.vending", "Google Play Store (TrickyStore)", true,
                   POL_EXEMPT_ZERO_TOUCH);

            addApp(10152, "com.miui.analytics", "HyperOS Analytics (MSA)", true,
                   POL_BLOCK_NETWORK | POL_BLOCK_BG_IPC | POL_BLOCK_AUTOSTART);

            addApp(10145, "com.xiaomi.mipicks", "GetApps (HyperOS)", true,
                   POL_BLOCK_BG_IPC | POL_BLOCK_AUTOSTART | POL_SLEEP_SELECTED);

            addApp(1000, "android", "Android 17 System Server", true, POL_NONE);

            /* Default IPC Matrix rules */
            ipc_rules_.push_back({"ipc_1", "com.zhiliaoapp.musically", "com.xiaomi.mipicks", "*", "service", false});
            ipc_rules_.push_back({"ipc_2", "*", "com.miui.analytics", "*", "all", false});
            ipc_rules_.push_back({"ipc_3", "com.alibaba.aliexpresshd", "*", "android.intent.action.BOOT_COMPLETED", "broadcast", false});

            /* Seed initial events so Dashboard is immediately informative */
            for (int i = 0; i < 14; ++i) {
                tickDemoTelemetryStep();
            }
        }
    }

    std::string resolvePkgByUidLocked(uint32_t uid) const {
        auto it = apps_.find(uid);
        if (it != apps_.end()) return it->second.package_name;
        return "uid." + std::to_string(uid);
    }

    std::string resolveLabelByUidLocked(uint32_t uid, const std::string& fallback) const {
        auto it = apps_.find(uid);
        if (it != apps_.end() && !it->second.label.empty()) return it->second.label;
        return fallback;
    }

    void recordPromptOutcomeLocked(const PendingPrompt& p) {
        EventRecord ev;
        ev.seq           = ++next_seq_;
        ev.timestamp_ms  = nowEpochMs();
        ev.uid           = p.uid;
        ev.category      = p.category;
        ev.severity      = SEV_HIGH;
        ev.is_background = p.is_background;
        ev.package_name  = p.package_name;
        ev.event_type    = "SYSTEM_PROMPT";
        ev.target        = p.resource_title;
        if (p.decision == "allow_once" || p.decision == "allow_always") {
            ev.action = ACT_PROMPT_ALLOWED;
            ev.detail = "User granted access (" + p.decision + ") via System Permission Dialog";
        } else if (p.decision == "spoof") {
            ev.action = ACT_SPOOFED;
            ev.detail = "User chose Synthetic Data Spoof via System Permission Dialog";
            total_spoofed_++;
            stats_[p.uid].cnt_spoofed++;
        } else {
            ev.action = ACT_PROMPT_DENIED;
            ev.detail = "User denied access (Silent Drop) via System Permission Dialog";
            total_blocked_++;
            stats_[p.uid].cnt_blocked++;
        }
        if (ring_.size() >= SENTINEL_RING_CAPACITY) ring_.pop_front();
        ring_.push_back(ev);
        total_events_++;
    }

    void syncAllKernelAndPolicyState() {
        std::lock_guard<std::mutex> lk(mu_);
        syncAllLocked();
    }

    void syncAllLocked() {
        /* 1. Sync read-only mmap policy bitmap for lock-free Zygisk & Vector lookup */
        if (policy_shm_ && policy_shm_ != MAP_FAILED) {
            std::memset(policy_shm_->uid_flags, 0, sizeof(policy_shm_->uid_flags));
            for (const auto& [uid, app] : apps_) {
                uint32_t app_id = uid % 100000u;
                if (app_id < SENTINEL_MAX_APP_IDS) {
                    policy_shm_->uid_flags[app_id] = app.flags;
                }
            }
            policy_shm_->global_master_seed = master_seed_;
            policy_shm_->global_profile     = global_profile_;
            policy_shm_->screen_sleeping    = screen_sleeping_ ? 1 : 0;
            policy_shm_->sleep_mode         = sleep_mode_;
            policy_shm_->generation++;
            ::msync(policy_shm_, sizeof(SentinelPolicyShm), MS_ASYNC);
        }

        /* 2. Compile & apply Linux 5.10 iptables / nftables rules */
        std::vector<sentinel::AppRuleEntry> list;
        list.reserve(apps_.size());
        for (const auto& [_, a] : apps_) list.push_back(a);

        auto pcfg = proxy_.getConfig();
        fw_.applyRules(
            list,
            sleep_mode_,
            screen_sleeping_,
            pcfg.enabled,
            pcfg.listen_port,
            pcfg.block_quic,
            pcfg.block_ipv6);

        /* 3. Compile & write AOSP IntentFirewall XML */
        std::string ifw_target = (::geteuid() == 0 && !preview_demo_)
                                     ? SENTINEL_IFW_XML_PATH
                                     : (run_dir_ + "/privacy_sentinel_ifw.xml");
        fw_.writeIntentFirewallXml(ifw_target, list, ipc_rules_);
    }

    std::string buildStatusJson() const {
        std::lock_guard<std::mutex> lk(mu_);
        auto pcfg = proxy_.getConfig();
        bool susfs_present = (::access("/proc/susfs", F_OK) == 0) || (::access("/data/adb/ksu/bin/ksu_susfs", F_OK) == 0) || preview_demo_;
        std::ostringstream oss;
        oss << "{"
            << "\"ok\":true,"
            << "\"version\":\"" << SENTINEL_VERSION_STR << "\","
            << "\"device\":{\"codename\":\"garnet\",\"model\":\"POCO X6 5G\",\"os\":\"HyperOS 4 (Android 17 / API 37)\",\"kernel\":\"5.10-arm64-gki\",\"root\":\"BakaSU + SuSFS\",\"xposed\":\"Vector (LibXposed API 102)\",\"zygisk\":\"Zygisk Next\"},"
            << "\"susfs_active\":" << (susfs_present ? "true" : "false") << ","
            << "\"fw_backend\":\"" << jsonEscape(fw_.activeBackendName()) << "\","
            << "\"ring_capacity\":" << SENTINEL_RING_CAPACITY << ","
            << "\"ring_used\":" << ring_.size() << ","
            << "\"total_events\":" << total_events_ << ","
            << "\"total_blocked\":" << total_blocked_ << ","
            << "\"total_spoofed\":" << total_spoofed_ << ","
            << "\"global_profile\":" << int(global_profile_) << ","
            << "\"sleep_mode\":" << int(sleep_mode_) << ","
            << "\"sleep_grace_sec\":" << sleep_grace_sec_ << ","
            << "\"screen_sleeping\":" << (screen_sleeping_ ? "true" : "false") << ","
            << "\"show_system_apps\":" << (show_system_apps_ ? "true" : "false") << ","
            << "\"master_seed\":" << master_seed_ << ","
            << "\"proxy\":{"
            << "\"enabled\":" << (pcfg.enabled ? "true" : "false") << ","
            << "\"running\":" << (proxy_.isRunning() ? "true" : "false") << ","
            << "\"socks5_host\":\"" << jsonEscape(pcfg.socks5_host) << "\","
            << "\"socks5_port\":" << pcfg.socks5_port << ","
            << "\"listen_port\":" << pcfg.listen_port << ","
            << "\"username\":\"" << jsonEscape(pcfg.username) << "\","
            << "\"block_quic\":" << (pcfg.block_quic ? "true" : "false") << ","
            << "\"block_ipv6\":" << (pcfg.block_ipv6 ? "true" : "false") << ","
            << "\"relayed_connections\":" << proxy_.relayedConnections() << ","
            << "\"relayed_bytes\":" << proxy_.relayedBytes()
            << "}"
            << "}";
        return oss.str();
    }

    std::string buildDashboardJson(uint64_t since_seq, uint32_t limit) const {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t now = nowEpochMs();
        std::ostringstream oss;
        oss << "{\"ok\":true,"
            << "\"latest_seq\":" << next_seq_ << ","
            << "\"ring_used\":" << ring_.size() << ","
            << "\"ring_capacity\":" << SENTINEL_RING_CAPACITY << ","
            << "\"total_events\":" << total_events_ << ","
            << "\"total_blocked\":" << total_blocked_ << ","
            << "\"total_spoofed\":" << total_spoofed_ << ","
            << "\"global_profile\":" << int(global_profile_) << ","
            << "\"sleep_mode\":" << int(sleep_mode_) << ","
            << "\"sleep_grace_sec\":" << sleep_grace_sec_ << ","
            << "\"screen_sleeping\":" << (screen_sleeping_ ? "true" : "false") << ","
            << "\"show_system_apps\":" << (show_system_apps_ ? "true" : "false") << ",";

        /* Apps array */
        oss << "\"apps\":[";
        bool first = true;
        for (const auto& [uid, app] : apps_) {
            if (!show_system_apps_ && app.is_system && !(app.flags & POL_EXEMPT_ZERO_TOUCH)) {
                continue;
            }
            if (!first) oss << ",";
            first = false;
            AppStats st{};
            auto sit = stats_.find(uid);
            if (sit != stats_.end()) st = sit->second;
            oss << "{"
                << "\"uid\":" << uid << ","
                << "\"package_name\":\"" << jsonEscape(app.package_name) << "\","
                << "\"label\":\"" << jsonEscape(app.label) << "\","
                << "\"is_system\":" << (app.is_system ? "true" : "false") << ","
                << "\"flags\":" << app.flags << ","
                << "\"proc_state\":\"" << jsonEscape(st.proc_state.empty() ? "CACHED" : st.proc_state) << "\","
                << "\"last_active_ms\":" << st.last_active_ms << ","
                << "\"custom_imei\":\"" << jsonEscape(app.custom_imei) << "\","
                << "\"custom_android_id\":\"" << jsonEscape(app.custom_android_id) << "\","
                << "\"custom_mac\":\"" << jsonEscape(app.custom_mac) << "\","
                << "\"custom_model\":\"" << jsonEscape(app.custom_model) << "\","
                << "\"custom_lat\":" << app.custom_lat << ","
                << "\"custom_lon\":" << app.custom_lon << ","
                << "\"counts\":{"
                << "\"network\":" << st.cnt_network << ","
                << "\"data\":" << st.cnt_data << ","
                << "\"autostart\":" << st.cnt_autostart << ","
                << "\"danger\":" << st.cnt_danger << ","
                << "\"ipc\":" << st.cnt_ipc << ","
                << "\"sandbox\":" << st.cnt_sandbox << ","
                << "\"proxy\":" << st.cnt_proxy << ","
                << "\"blocked\":" << st.cnt_blocked << ","
                << "\"spoofed\":" << st.cnt_spoofed
                << "}}";
        }
        oss << "],";

        /* IPC Matrix Rules */
        oss << "\"ipc_rules\":[";
        first = true;
        for (const auto& r : ipc_rules_) {
            if (!first) oss << ",";
            first = false;
            oss << "{"
                << "\"id\":\"" << jsonEscape(r.id) << "\","
                << "\"caller_pkg\":\"" << jsonEscape(r.caller_pkg) << "\","
                << "\"target_pkg\":\"" << jsonEscape(r.target_pkg) << "\","
                << "\"action_glob\":\"" << jsonEscape(r.action_glob) << "\","
                << "\"component_type\":\"" << jsonEscape(r.component_type) << "\","
                << "\"allow\":" << (r.allow ? "true" : "false")
                << "}";
        }
        oss << "],";

        /* Active Pending Interactive Prompts */
        oss << "\"prompts\":[";
        first = true;
        for (const auto& p : prompts_) {
            if (p.resolved || p.expires_ms <= now) continue;
            if (!first) oss << ",";
            first = false;
            oss << "{"
                << "\"id\":" << p.id << ","
                << "\"uid\":" << p.uid << ","
                << "\"package_name\":\"" << jsonEscape(p.package_name) << "\","
                << "\"app_label\":\"" << jsonEscape(p.app_label) << "\","
                << "\"category\":" << p.category << ","
                << "\"resource_title\":\"" << jsonEscape(p.resource_title) << "\","
                << "\"detail\":\"" << jsonEscape(p.detail) << "\","
                << "\"is_background\":" << (p.is_background ? "true" : "false") << ","
                << "\"remaining_ms\":" << (p.expires_ms > now ? (p.expires_ms - now) : 0)
                << "}";
        }
        oss << "],";

        /* Recent Events from 15,000-capacity Ring Buffer */
        oss << "\"events\":[";
        first = true;
        uint32_t emitted = 0;
        for (auto it = ring_.rbegin(); it != ring_.rend() && emitted < limit; ++it) {
            if (it->seq <= since_seq) break;
            if (!show_system_apps_ && it->uid < 10000) continue;
            if (!first) oss << ",";
            first = false;
            ++emitted;
            oss << "{"
                << "\"seq\":" << it->seq << ","
                << "\"ts\":" << it->timestamp_ms << ","
                << "\"uid\":" << it->uid << ","
                << "\"pid\":" << it->pid << ","
                << "\"target_uid\":" << it->target_uid << ","
                << "\"category\":" << it->category << ","
                << "\"severity\":" << int(it->severity) << ","
                << "\"action\":" << int(it->action) << ","
                << "\"is_bg\":" << (it->is_background ? "true" : "false") << ","
                << "\"pkg\":\"" << jsonEscape(it->package_name) << "\","
                << "\"type\":\"" << jsonEscape(it->event_type) << "\","
                << "\"target\":\"" << jsonEscape(it->target) << "\","
                << "\"detail\":\"" << jsonEscape(it->detail) << "\""
                << "}";
        }
        oss << "]}";
        return oss.str();
    }

    std::string                          base_dir_;
    std::string                          run_dir_;
    std::string                          cfg_dir_;
    std::string                          webroot_dir_;
    bool                                 preview_demo_ = false;
    std::string                          auth_token_;

    mutable std::mutex                   mu_;
    std::condition_variable              prompt_cv_;

    int                                  policy_fd_  = -1;
    SentinelPolicyShm*                   policy_shm_ = nullptr;

    uint32_t                             master_seed_      = 0xA17B510u;
    uint8_t                              global_profile_   = 1; /* 1 = Balanced */
    uint8_t                              sleep_mode_       = SLEEP_MODE_SELECTED_ONLY;
    uint32_t                             sleep_grace_sec_  = 15;
    bool                                 screen_sleeping_  = false;
    bool                                 show_system_apps_ = false;

    uint64_t                             next_seq_       = 0;
    uint64_t                             next_rule_id_   = 10;
    uint64_t                             next_prompt_id_ = 100;
    uint64_t                             total_events_   = 0;
    uint64_t                             total_blocked_  = 0;
    uint64_t                             total_spoofed_  = 0;

    std::deque<EventRecord>              ring_;
    std::map<uint32_t, sentinel::AppRuleEntry> apps_;
    std::unordered_map<uint32_t, AppStats> stats_;
    std::unordered_set<std::string>      zero_touch_pkgs_;
    std::vector<sentinel::IpcMatrixRule> ipc_rules_;
    std::deque<PendingPrompt>            prompts_;
    std::unordered_map<std::string, uint64_t> temp_grants_;

    sentinel::FirewallController         fw_;
    sentinel::TransparentSocks5Relay     proxy_;
};

/* Serve static WebUI files cleanly with proper MIME types */
std::string guessMimeType(const std::string& path) {
    if (path.ends_with(".html")) return "text/html; charset=utf-8";
    if (path.ends_with(".css"))  return "text/css; charset=utf-8";
    if (path.ends_with(".js"))   return "application/javascript; charset=utf-8";
    if (path.ends_with(".svg"))  return "image/svg+xml";
    if (path.ends_with(".json")) return "application/json; charset=utf-8";
    if (path.ends_with(".png"))  return "image/png";
    return "application/octet-stream";
}

void sendHttpResponse(int fd, int status, const std::string& status_text,
                      const std::string& content_type, const std::string& body) {
    std::ostringstream hdr;
    hdr << "HTTP/1.1 " << status << " " << status_text << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Cache-Control: no-store\r\n"
        << "X-Content-Type-Options: nosniff\r\n"
        << "Connection: close\r\n\r\n";
    std::string head = hdr.str();
    (void)::send(fd, head.data(), head.size(), MSG_NOSIGNAL);
    if (!body.empty()) {
        size_t sent = 0;
        while (sent < body.size()) {
            ssize_t n = ::send(fd, body.data() + sent, body.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) break;
            sent += static_cast<size_t>(n);
        }
    }
}

void handleHttpClient(int cfd, SentinelState& state) {
    std::string req;
    req.reserve(4096);
    char buf[4096];
    pollfd pfd{cfd, POLLIN, 0};
    while (req.find("\r\n\r\n") == std::string::npos && req.size() < 65536) {
        if (::poll(&pfd, 1, 2000) <= 0) break;
        ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        req.append(buf, static_cast<size_t>(n));
    }
    size_t hdr_end = req.find("\r\n\r\n");
    if (hdr_end == std::string::npos) {
        ::close(cfd);
        return;
    }

    std::istringstream iss(req.substr(0, hdr_end));
    std::string method, raw_target, version;
    iss >> method >> raw_target >> version;

    std::unordered_map<std::string, std::string> headers;
    std::string line;
    std::getline(iss, line);
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string k = line.substr(0, colon);
            for (char& c : k) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            size_t vs = line.find_first_not_of(" \t", colon + 1);
            headers[k] = (vs != std::string::npos) ? line.substr(vs) : "";
        }
    }

    size_t content_len = 0;
    if (headers.count("content-length")) {
        content_len = static_cast<size_t>(std::strtoull(headers["content-length"].c_str(), nullptr, 10));
    }
    std::string body = req.substr(hdr_end + 4);
    while (body.size() < content_len && body.size() < 262144) {
        if (::poll(&pfd, 1, 2000) <= 0) break;
        ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        body.append(buf, static_cast<size_t>(n));
    }

    /* Split path and query string */
    std::string path = raw_target;
    std::string query;
    size_t qpos = raw_target.find('?');
    if (qpos != std::string::npos) {
        path  = raw_target.substr(0, qpos);
        query = raw_target.substr(qpos + 1);
    }

    /* Extract auth token from Header X-Sentinel-Token or ?token= query */
    std::string provided_token = headers.count("x-sentinel-token") ? headers["x-sentinel-token"] : "";
    if (provided_token.empty() && !query.empty()) {
        size_t tpos = query.find("token=");
        if (tpos != std::string::npos) {
            size_t tend = query.find('&', tpos + 6);
            provided_token = query.substr(tpos + 6, tend == std::string::npos ? std::string::npos : tend - (tpos + 6));
        }
    }

    /* Preview bootstrap endpoint (ONLY enabled when --preview-mode is explicitly passed) */
    if (path == "/api/v1/preview-handshake") {
        if (state.isPreviewDemo()) {
            sendHttpResponse(cfd, 200, "OK", "application/json; charset=utf-8",
                             "{\"ok\":true,\"preview_mode\":true,\"token\":\"preview-session\"}");
        } else {
            sendHttpResponse(cfd, 403, "Forbidden", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"token_required\"}");
        }
        ::close(cfd);
        return;
    }

    /* Authenticated REST + SSE Endpoints */
    if (path.rfind("/api/v1/", 0) == 0) {
        if (!state.validateToken(provided_token)) {
            sendHttpResponse(cfd, 401, "Unauthorized", "application/json; charset=utf-8",
                             "{\"ok\":false,\"error\":\"unauthorized_invalid_token\"}");
            ::close(cfd);
            return;
        }

        if (path == "/api/v1/stream") {
            /* Server-Sent Events (SSE) live real-time dashboard push */
            std::string sse_hdr =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n\r\n";
            if (::send(cfd, sse_hdr.data(), sse_hdr.size(), MSG_NOSIGNAL) <= 0) {
                ::close(cfd);
                return;
            }
            while (g_running.load()) {
                std::string snap = state.handleCommandJson("dashboard", "{\"limit\":80}");
                std::string frame = "event: snapshot\ndata: " + snap + "\n\n";
                if (::send(cfd, frame.data(), frame.size(), MSG_NOSIGNAL) <= 0) break;
                for (int i = 0; i < 15 && g_running.load(); ++i) {
                    ::usleep(100000); /* 1.5s push cadence */
                }
            }
            ::close(cfd);
            return;
        }

        std::string cmd = path.substr(std::strlen("/api/v1/"));
        std::string resp = state.handleCommandJson(cmd, body);
        sendHttpResponse(cfd, 200, "OK", "application/json; charset=utf-8", resp);
        ::close(cfd);
        return;
    }

    /* Static WebUI assets from webroot/ */
    if (path == "/" || path.empty()) path = "/index.html";
    if (path.find("..") != std::string::npos) {
        sendHttpResponse(cfd, 400, "Bad Request", "text/plain", "Invalid path");
        ::close(cfd);
        return;
    }
    fs::path full_path = fs::path(state.webrootDir()) / path.substr(1);
    std::ifstream ifs(full_path, std::ios::binary);
    if (!ifs) {
        sendHttpResponse(cfd, 404, "Not Found", "text/plain", "Asset not found");
        ::close(cfd);
        return;
    }
    std::ostringstream content;
    content << ifs.rdbuf();
    sendHttpResponse(cfd, 200, "OK", guessMimeType(full_path.string()), content.str());
    ::close(cfd);
}

void handleUnixCtrlClient(int cfd, SentinelState& state) {
    /* Protocol: single line JSON {"cmd":"...","payload":{...}} OR PROMPT_WAIT */
    std::string line;
    char buf[4096];
    pollfd pfd{cfd, POLLIN, 0};
    while (line.find('\n') == std::string::npos && line.size() < 65536) {
        if (::poll(&pfd, 1, 2000) <= 0) break;
        ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        line.append(buf, static_cast<size_t>(n));
    }
    if (!line.empty()) {
        std::string cmd = extractJsonString(line, "cmd", "status");
        std::string resp;
        if (cmd == "prompt_ask_blocking") {
            uint32_t uid    = static_cast<uint32_t>(extractJsonInt(line, "uid", 0));
            std::string pkg = extractJsonString(line, "package_name", "");
            uint16_t cat    = static_cast<uint16_t>(extractJsonInt(line, "category", CAT_NETWORK));
            std::string res = extractJsonString(line, "resource_title", "Restricted Action");
            std::string det = extractJsonString(line, "detail", "");
            bool is_bg      = extractJsonBool(line, "is_background", true);
            uint32_t wms    = static_cast<uint32_t>(extractJsonInt(line, "timeout_ms", 10000));
            uint64_t pid    = state.enqueueInteractivePrompt(uid, pkg, cat, res, det, is_bg);
            std::string dec = state.waitPromptDecision(pid, wms);
            resp = "{\"ok\":true,\"decision\":\"" + jsonEscape(dec) + "\"}";
        } else {
            resp = state.handleCommandJson(cmd, line);
        }
        resp.push_back('\n');
        (void)::send(cfd, resp.data(), resp.size(), MSG_NOSIGNAL);
    }
    ::close(cfd);
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    std::string base_dir    = SENTINEL_BASE_DIR;
    std::string webroot_dir = "/data/adb/modules/privacy_sentinel/webroot";
    std::string bind_ip     = "127.0.0.1"; /* Strictly localhost by default per security spec */
    uint16_t    http_port   = SENTINEL_DEFAULT_HTTP_PORT;
    bool        enable_http = true;
    bool        preview_demo = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--base-dir" && i + 1 < argc) base_dir = argv[++i];
        else if (arg == "--webroot" && i + 1 < argc) webroot_dir = argv[++i];
        else if (arg == "--bind" && i + 1 < argc) bind_ip = argv[++i];
        else if (arg == "--port" && i + 1 < argc) http_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        else if (arg == "--no-http") enable_http = false;
        else if (arg == "--preview-mode") preview_demo = true;
    }

    /* Protect daemon against Android 17 LMK / MemoryLimiter when running as root */
    if (::geteuid() == 0) {
        std::ofstream oom("/proc/self/oom_score_adj");
        if (oom) oom << "-900\n";
    }

    SentinelState state(base_dir, webroot_dir, preview_demo);

    /* 1. Bind UNIX Control Stream Socket (sentinel.sock) */
    std::string ctrl_sock_path  = state.runDir() + "/sentinel.sock";
    std::string dgram_sock_path = state.runDir() + "/telemetry.sock";
    ::unlink(ctrl_sock_path.c_str());
    ::unlink(dgram_sock_path.c_str());

    int ctrl_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (ctrl_fd < 0) {
        std::perror("socket(AF_UNIX ctrl)");
        return 1;
    }
    sockaddr_un ctrl_addr{};
    ctrl_addr.sun_family = AF_UNIX;
    std::snprintf(ctrl_addr.sun_path, sizeof(ctrl_addr.sun_path), "%s", ctrl_sock_path.c_str());
    if (::bind(ctrl_fd, reinterpret_cast<sockaddr*>(&ctrl_addr), sizeof(ctrl_addr)) < 0 ||
        ::listen(ctrl_fd, 64) < 0) {
        std::perror("bind/listen(sentinel.sock)");
        return 1;
    }
    ::chmod(ctrl_sock_path.c_str(), 0660);

    /* 2. Bind Non-Blocking UNIX Datagram Socket (telemetry.sock) for Zygisk/Vector hooks */
    int dgram_fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (dgram_fd < 0) {
        std::perror("socket(AF_UNIX dgram)");
        return 1;
    }
    int rcvbuf = 512 * 1024;
    ::setsockopt(dgram_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    sockaddr_un dgram_addr{};
    dgram_addr.sun_family = AF_UNIX;
    std::snprintf(dgram_addr.sun_path, sizeof(dgram_addr.sun_path), "%s", dgram_sock_path.c_str());
    if (::bind(dgram_fd, reinterpret_cast<sockaddr*>(&dgram_addr), sizeof(dgram_addr)) < 0) {
        std::perror("bind(telemetry.sock)");
        return 1;
    }
    ::chmod(dgram_sock_path.c_str(), 0666); /* Write-only telemetry sink from sandboxed app hooks */

    /* 3. Optional Local REST + SSE HTTP Server */
    int http_fd = -1;
    if (enable_http) {
        http_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (http_fd >= 0) {
            int one = 1;
            ::setsockopt(http_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in haddr{};
            haddr.sin_family = AF_INET;
            haddr.sin_port   = htons(http_port);
            if (::inet_pton(AF_INET, bind_ip.c_str(), &haddr.sin_addr) != 1) {
                haddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            }
            if (::bind(http_fd, reinterpret_cast<sockaddr*>(&haddr), sizeof(haddr)) < 0 ||
                ::listen(http_fd, 64) < 0) {
                std::perror("bind/listen(http)");
                ::close(http_fd);
                http_fd = -1;
            }
        }
    }

    /* 4. epoll Event Loop */
    int epfd = ::epoll_create1(EPOLL_CLOEXEC);
    auto addEp = [&](int fd) {
        if (fd < 0) return;
        epoll_event ev{};
        ev.events  = EPOLLIN;
        ev.data.fd = fd;
        ::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    };
    addEp(ctrl_fd);
    addEp(dgram_fd);
    addEp(http_fd);

    std::cout << "[sentineld] Privacy Sentinel v" << SENTINEL_VERSION_STR << " active\n"
              << "[sentineld] Control Socket : " << ctrl_sock_path << "\n"
              << "[sentineld] Telemetry DGRAM: " << dgram_sock_path << "\n";
    if (http_fd >= 0) {
        std::cout << "[sentineld] WebUI HTTP/SSE : http://" << bind_ip << ":" << http_port << "/\n";
    }
    std::cout.flush();

    uint64_t last_demo_ms = nowEpochMs();
    epoll_event events[32];

    while (g_running.load()) {
        int n = ::epoll_wait(epfd, events, 32, 500);
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            if (fd == dgram_fd) {
                SentinelTelemetryPacket pkt{};
                while (true) {
                    ssize_t r = ::recv(dgram_fd, &pkt, sizeof(pkt), MSG_DONTWAIT);
                    if (r <= 0) break;
                    if (static_cast<size_t>(r) == sizeof(SentinelTelemetryPacket)) {
                        state.ingestTelemetry(pkt);
                    }
                }
            } else if (fd == ctrl_fd) {
                while (true) {
                    int cfd = ::accept4(ctrl_fd, nullptr, nullptr, SOCK_CLOEXEC);
                    if (cfd < 0) break;
                    std::thread(handleUnixCtrlClient, cfd, std::ref(state)).detach();
                }
            } else if (fd == http_fd) {
                while (true) {
                    int cfd = ::accept4(http_fd, nullptr, nullptr, SOCK_CLOEXEC);
                    if (cfd < 0) break;
                    std::thread(handleHttpClient, cfd, std::ref(state)).detach();
                }
            }
        }

        if (preview_demo) {
            uint64_t now = nowEpochMs();
            if (now - last_demo_ms >= 2600) {
                last_demo_ms = now;
                state.tickDemoTelemetryStep();
            }
        }
    }

    ::close(epfd);
    if (http_fd >= 0) ::close(http_fd);
    ::close(dgram_fd);
    ::close(ctrl_fd);
    ::unlink(ctrl_sock_path.c_str());
    ::unlink(dgram_sock_path.c_str());
    return 0;
}
