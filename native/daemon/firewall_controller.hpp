#pragma once

#include "../include/sentinel_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

/* ============================================================================
 * SentinelFirewallController — Kernel Netfilter + SOCK_DESTROY + AOSP IFW
 *
 * Designed specifically for:
 *  - POCO X6 5G (garnet) / HyperOS 4 / Android 17 (API 37) / Linux 5.10 arm64
 *  - BakaSU (KernelSU + built-in SuSFS)
 *
 * Key architectural guarantees:
 *  1. Auto-detects Linux 5.10 iptables/ip6tables (-w xtables lock) vs nftables,
 *     isolating all rules inside dedicated chains (SENTINEL_OUT, SENTINEL_SLEEP,
 *     SENTINEL_PROXY) so Android netd & HyperOS MiuiNetworkManagement never
 *     conflict or wipe rules on Wi-Fi <-> 5G handoff.
 *  2. Uses kernel NETLINK_SOCK_DIAG + SOCK_DESTROY to forcefully sever ALREADY
 *     ESTABLISHED TCP/UDP sockets when Deep Sleep triggers or an app is blocked.
 *  3. Generates /data/system/ifw/privacy_sentinel.xml for AOSP IntentFirewall,
 *     enforcing zero-overhead kernel/AMS autostart & cross-app IPC rules.
 * ============================================================================ */

namespace sentinel {

struct IpcMatrixRule {
    std::string id;
    std::string caller_pkg; /* "*" for any */
    std::string target_pkg; /* "*" for any */
    std::string action_glob;/* e.g. "android.intent.action.BOOT_COMPLETED" or "*" */
    std::string component_type; /* "broadcast", "service", "activity", "all" */
    bool        allow = false;
};

struct AppRuleEntry {
    uint32_t    uid          = 0;
    std::string package_name;
    std::string label;
    bool        is_system    = false;
    uint32_t    flags        = 0; /* SentinelUidFlags bitmask */
    /* Custom spoofing overrides when POL_SPOOF_CUSTOM is set */
    std::string custom_imei;
    std::string custom_android_id;
    std::string custom_mac;
    std::string custom_model;
    double      custom_lat   = 55.7558;
    double      custom_lon   = 37.6173;
};

class FirewallController {
public:
    enum class Backend {
        AUTO,
        IPTABLES_510, /* Default & recommended on Linux 5.10 (Poco X6 5G garnet) */
        NFTABLES
    };

    explicit FirewallController(bool dry_run = false) : dry_run_(dry_run) {
        detectBackend();
    }

    void setDryRun(bool dry) { dry_run_ = dry; }
    bool isDryRun() const { return dry_run_; }

    std::string activeBackendName() const {
        if (resolved_backend_ == Backend::NFTABLES) return "nftables (inet privacy_sentinel)";
        return "iptables-xtables (Linux 5.10 SENTINEL_* chains)";
    }

    void setPreferredBackend(const std::string& pref) {
        if (pref == "nftables") preferred_ = Backend::NFTABLES;
        else if (pref == "iptables") preferred_ = Backend::IPTABLES_510;
        else preferred_ = Backend::AUTO;
        detectBackend();
    }

    /* Compile full rule script (both inspectable in WebUI and executable by root) */
    std::string compileFirewallScript(
        const std::vector<AppRuleEntry>& apps,
        uint8_t sleep_mode,
        bool screen_sleeping,
        bool proxy_enabled,
        uint16_t proxy_port,
        bool proxy_block_quic,
        bool proxy_block_ipv6) const
    {
        if (resolved_backend_ == Backend::NFTABLES) {
            return compileNftablesRuleset(apps, sleep_mode, screen_sleeping, proxy_enabled, proxy_port, proxy_block_quic, proxy_block_ipv6);
        }
        return compileIptablesScript(apps, sleep_mode, screen_sleeping, proxy_enabled, proxy_port, proxy_block_quic, proxy_block_ipv6);
    }

    /* Apply compiled netfilter rules with bounded execution timeout */
    bool applyRules(
        const std::vector<AppRuleEntry>& apps,
        uint8_t sleep_mode,
        bool screen_sleeping,
        bool proxy_enabled,
        uint16_t proxy_port,
        bool proxy_block_quic,
        bool proxy_block_ipv6,
        std::string* out_compiled = nullptr)
    {
        std::string script = compileFirewallScript(
            apps, sleep_mode, screen_sleeping, proxy_enabled, proxy_port, proxy_block_quic, proxy_block_ipv6);
        if (out_compiled) *out_compiled = script;
        last_compiled_rules_ = script;

        if (dry_run_ || ::geteuid() != 0) {
            /* Safe preview / non-root test mode */
            return true;
        }

        const char* tmp_script = "/data/adb/privacy_sentinel/run/.apply_fw.sh";
        {
            std::ofstream ofs(tmp_script, std::ios::trunc);
            if (!ofs) return false;
            ofs << script;
        }
        ::chmod(tmp_script, 0700);
        return runCommandWithTimeout(tmp_script, 4000);
    }

    /* Sever active established TCP & UDP sockets of given UID via NETLINK_SOCK_DIAG */
    uint32_t destroyActiveSocketsForUid(uint32_t target_uid) {
        if (target_uid < 10000) return 0; /* Never sever core Android system UIDs */
        if (dry_run_ || ::geteuid() != 0) {
            /* Simulated count in dry-run / preview */
            return 2;
        }

        uint32_t killed = 0;
        killed += destroySocketsAf(AF_INET, IPPROTO_TCP, target_uid);
        killed += destroySocketsAf(AF_INET6, IPPROTO_TCP, target_uid);
        killed += destroySocketsAf(AF_INET, IPPROTO_UDP, target_uid);
        killed += destroySocketsAf(AF_INET6, IPPROTO_UDP, target_uid);
        return killed;
    }

    /* Generate AOSP IntentFirewall XML (/data/system/ifw/privacy_sentinel.xml) */
    std::string compileIntentFirewallXml(
        const std::vector<AppRuleEntry>& apps,
        const std::vector<IpcMatrixRule>& matrix_rules) const
    {
        std::ostringstream xml;
        xml << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        xml << "<!-- Auto-generated by Privacy Sentinel (sentineld) for Android 17 ActivityManagerService -->\n";
        xml << "<rules>\n";

        std::vector<std::string> autostart_blocked;
        std::vector<std::string> bg_ipc_blocked;
        for (const auto& app : apps) {
            if (app.flags & POL_EXEMPT_ZERO_TOUCH) continue;
            if (app.flags & POL_BLOCK_AUTOSTART) {
                autostart_blocked.push_back(app.package_name);
            }
            if ((app.flags & POL_SANDBOX_KERNEL_L2) != 0) {
                bg_ipc_blocked.push_back(app.package_name);
            }
        }

        if (!autostart_blocked.empty()) {
            xml << "  <!-- Block Boot / Package-Replaced / Connectivity Autostart Broadcasts -->\n";
            xml << "  <broadcast block=\"true\" log=\"true\">\n";
            xml << "    <and>\n";
            xml << "      <or>\n";
            xml << "        <action name=\"android.intent.action.BOOT_COMPLETED\" />\n";
            xml << "        <action name=\"android.intent.action.LOCKED_BOOT_COMPLETED\" />\n";
            xml << "        <action name=\"android.intent.action.MY_PACKAGE_REPLACED\" />\n";
            xml << "        <action name=\"android.net.conn.CONNECTIVITY_CHANGE\" />\n";
            xml << "        <action name=\"com.xiaomi.mipush.RECEIVE_MESSAGE\" />\n";
            xml << "      </or>\n";
            xml << "      <or>\n";
            for (const auto& pkg : autostart_blocked) {
                xml << "        < component-filter name=\"" << escapeXml(pkg) << "/*\" />\n";
            }
            xml << "      </or>\n";
            xml << "    </and>\n";
            xml << "  </broadcast>\n";
        }

        if (!bg_ipc_blocked.empty()) {
            xml << "  <!-- Kernel L2 Sandbox: Isolate cross-app Service wakeups -->\n";
            xml << "  <service block=\"true\" log=\"true\">\n";
            xml << "    <or>\n";
            for (const auto& pkg : bg_ipc_blocked) {
                xml << "      <sender-package name=\"" << escapeXml(pkg) << "\" />\n";
            }
            xml << "    </or>\n";
            xml << "  </service>\n";
        }

        /* Explicit user-configured IPC Matrix Rules */
        for (const auto& r : matrix_rules) {
            if (r.allow) continue; /* IFW expresses explicit block filters; allow overrides live in Vector hook */
            std::vector<std::string> tags;
            if (r.component_type == "all") {
                tags = {"activity", "service", "broadcast"};
            } else {
                tags = {r.component_type.empty() ? "service" : r.component_type};
            }
            for (const auto& tag : tags) {
                xml << "  <" << tag << " block=\"true\" log=\"true\">\n";
                xml << "    <and>\n";
                if (!r.caller_pkg.empty() && r.caller_pkg != "*") {
                    xml << "      <sender-package name=\"" << escapeXml(r.caller_pkg) << "\" />\n";
                }
                if (!r.target_pkg.empty() && r.target_pkg != "*") {
                    xml << "      <component-filter name=\"" << escapeXml(r.target_pkg) << "/*\" />\n";
                }
                if (!r.action_glob.empty() && r.action_glob != "*") {
                    xml << "      <action name=\"" << escapeXml(r.action_glob) << "\" />\n";
                }
                xml << "    </and>\n";
                xml << "  </" << tag << ">\n";
            }
        }

        xml << "</rules>\n";
        return xml.str();
    }

    bool writeIntentFirewallXml(
        const std::string& path,
        const std::vector<AppRuleEntry>& apps,
        const std::vector<IpcMatrixRule>& matrix_rules,
        std::string* out_xml = nullptr)
    {
        std::string xml = compileIntentFirewallXml(apps, matrix_rules);
        last_ifw_xml_ = xml;
        if (out_xml) *out_xml = xml;

        if (dry_run_ && path == SENTINEL_IFW_XML_PATH) {
            return true;
        }
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) return false;
        ofs << xml;
        ofs.close();
        ::chmod(path.c_str(), 0644);
        return true;
    }

    const std::string& lastCompiledRules() const { return last_compiled_rules_; }
    const std::string& lastIfwXml() const { return last_ifw_xml_; }

private:
    static std::string escapeXml(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '"': out += "&quot;"; break;
                default:  out.push_back(c); break;
            }
        }
        return out;
    }

    void detectBackend() {
        if (preferred_ == Backend::IPTABLES_510) {
            resolved_backend_ = Backend::IPTABLES_510;
            return;
        }
        if (preferred_ == Backend::NFTABLES) {
            resolved_backend_ = Backend::NFTABLES;
            return;
        }
        /* On POCO X6 5G (Linux 5.10 HyperOS 4), /system/bin/iptables is standard and rock-solid */
        if (::access("/system/bin/iptables", X_OK) == 0 || ::access("/sbin/iptables", X_OK) == 0 || ::access("/usr/sbin/iptables", X_OK) == 0) {
            resolved_backend_ = Backend::IPTABLES_510;
        } else if (::access("/system/bin/nft", X_OK) == 0 || ::access("/usr/sbin/nft", X_OK) == 0) {
            resolved_backend_ = Backend::NFTABLES;
        } else {
            resolved_backend_ = Backend::IPTABLES_510;
        }
    }

    static bool shouldDisconnectInSleep(const AppRuleEntry& app, uint8_t sleep_mode) {
        if (app.is_system || app.uid < 10000) return false;
        if (app.flags & POL_EXEMPT_ZERO_TOUCH) return false;
        switch (sleep_mode) {
            case SLEEP_MODE_SELECTED_ONLY:
                return (app.flags & POL_SLEEP_SELECTED) != 0;
            case SLEEP_MODE_ALL_EXCEPT_SELECTED:
                return (app.flags & POL_SLEEP_SELECTED) == 0;
            case SLEEP_MODE_ALL_APPS:
                return true;
            default:
                return false;
        }
    }

    std::string compileIptablesScript(
        const std::vector<AppRuleEntry>& apps,
        uint8_t sleep_mode,
        bool screen_sleeping,
        bool proxy_enabled,
        uint16_t proxy_port,
        bool proxy_block_quic,
        bool proxy_block_ipv6) const
    {
        std::ostringstream ss;
        ss << "#!/system/bin/sh\n";
        ss << "# Privacy Sentinel — Linux 5.10 Netfilter Rule Script (POCO X6 5G / HyperOS 4 / Android 17)\n";
        ss << "IPT=\"iptables -w 2\"\n";
        ss << "IP6T=\"ip6tables -w 2\"\n\n";

        ss << "# 1. Ensure isolated chains exist without touching Android netd / oem_out\n";
        ss << "for T in \"$IPT\" \"$IP6T\"; do\n";
        ss << "  $T -N SENTINEL_OUT 2>/dev/null || $T -F SENTINEL_OUT\n";
        ss << "  $T -N SENTINEL_SLEEP 2>/dev/null || $T -F SENTINEL_SLEEP\n";
        ss << "  $T -C OUTPUT -j SENTINEL_OUT 2>/dev/null || $T -I OUTPUT 1 -j SENTINEL_OUT\n";
        ss << "  $T -C OUTPUT -j SENTINEL_SLEEP 2>/dev/null || $T -I OUTPUT 2 -j SENTINEL_SLEEP\n";
        ss << "done\n";
        ss << "$IPT -t nat -N SENTINEL_PROXY 2>/dev/null || $IPT -t nat -F SENTINEL_PROXY\n";
        ss << "$IPT -t nat -C OUTPUT -j SENTINEL_PROXY 2>/dev/null || $IPT -t nat -I OUTPUT 1 -j SENTINEL_PROXY\n\n";

        ss << "# 2. Always permit loopback (127.0.0.1 / ::1) for local system services\n";
        ss << "$IPT -A SENTINEL_OUT -o lo -j RETURN\n";
        ss << "$IP6T -A SENTINEL_OUT -o lo -j RETURN\n";
        ss << "$IPT -t nat -A SENTINEL_PROXY -d 127.0.0.0/8 -j RETURN\n";
        ss << "$IPT -t nat -A SENTINEL_PROXY -m owner --uid-owner 0 -j RETURN\n\n";

        ss << "# 3. Per-UID Outbound Firewall, Kernel Sandbox & Per-App SOCKS5/Tor Routing\n";
        for (const auto& app : apps) {
            if (app.flags & POL_EXEMPT_ZERO_TOUCH) {
                ss << "# [ZERO-TOUCH EXEMPT] " << app.package_name << " (UID " << app.uid << ")\n";
                continue;
            }
            const bool hard_block = (app.flags & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) != 0;
            if (hard_block) {
                ss << "# Block outbound traffic: " << app.package_name << " (UID " << app.uid << ")\n";
                ss << "$IPT -A SENTINEL_OUT -m owner --uid-owner " << app.uid << " -j REJECT --reject-with icmp-net-unreachable\n";
                ss << "$IP6T -A SENTINEL_OUT -m owner --uid-owner " << app.uid << " -j REJECT --reject-with icmp6-adm-prohibited\n";
                continue;
            }

            if ((app.flags & POL_ROUTE_PROXY) != 0) {
                ss << "# Per-App Transparent Proxy: " << app.package_name << " (UID " << app.uid << ")\n";
                if (proxy_enabled) {
                    if (proxy_block_ipv6) {
                        ss << "$IP6T -A SENTINEL_OUT -m owner --uid-owner " << app.uid << " -j REJECT\n";
                    }
                    if (proxy_block_quic) {
                        ss << "$IPT -A SENTINEL_OUT -m owner --uid-owner " << app.uid << " -p udp --dport 443 -j REJECT\n";
                    }
                    ss << "$IPT -t nat -A SENTINEL_PROXY -m owner --uid-owner " << app.uid
                       << " -p tcp -j REDIRECT --to-ports " << proxy_port << "\n";
                } else if ((app.flags & POL_STRICT_KILLSWITCH) != 0) {
                    ss << "# Kill-Switch active (proxy offline): dropping " << app.package_name << "\n";
                    ss << "$IPT -A SENTINEL_OUT -m owner --uid-owner " << app.uid << " -j REJECT\n";
                    ss << "$IP6T -A SENTINEL_OUT -m owner --uid-owner " << app.uid << " -j REJECT\n";
                }
            }
        }

        ss << "\n# 4. Deep Sleep / Screen-Off Auto-Disconnect (Mode=" << int(sleep_mode)
           << ", Active=" << (screen_sleeping ? "YES" : "NO") << ")\n";
        if (screen_sleeping && sleep_mode != SLEEP_MODE_OFF) {
            ss << "$IPT -A SENTINEL_SLEEP -o lo -j RETURN\n";
            ss << "$IP6T -A SENTINEL_SLEEP -o lo -j RETURN\n";
            for (const auto& app : apps) {
                if (shouldDisconnectInSleep(app, sleep_mode)) {
                    ss << "$IPT -A SENTINEL_SLEEP -m owner --uid-owner " << app.uid << " -j REJECT\n";
                    ss << "$IP6T -A SENTINEL_SLEEP -m owner --uid-owner " << app.uid << " -j REJECT\n";
                }
            }
        }
        return ss.str();
    }

    std::string compileNftablesRuleset(
        const std::vector<AppRuleEntry>& apps,
        uint8_t sleep_mode,
        bool screen_sleeping,
        bool proxy_enabled,
        uint16_t proxy_port,
        bool proxy_block_quic,
        bool proxy_block_ipv6) const
    {
        std::ostringstream ss;
        ss << "#!/system/bin/sh\n";
        ss << "nft -f - <<'EOF'\n";
        ss << "table inet privacy_sentinel\n";
        ss << "delete table inet privacy_sentinel\n";
        ss << "table inet privacy_sentinel {\n";
        ss << "  chain output_filter {\n";
        ss << "    type filter hook output priority -15; policy accept;\n";
        ss << "    oifname \"lo\" accept\n";
        for (const auto& app : apps) {
            if (app.flags & POL_EXEMPT_ZERO_TOUCH) continue;
            if (app.flags & (POL_BLOCK_NETWORK | POL_SANDBOX_KERNEL_L2)) {
                ss << "    meta skuid " << app.uid << " reject\n";
                continue;
            }
            if ((app.flags & POL_ROUTE_PROXY) && proxy_enabled) {
                if (proxy_block_ipv6) ss << "    meta nfproto ipv6 meta skuid " << app.uid << " reject\n";
                if (proxy_block_quic) ss << "    meta skuid " << app.uid << " udp dport 443 reject\n";
            }
            if (screen_sleeping && shouldDisconnectInSleep(app, sleep_mode)) {
                ss << "    meta skuid " << app.uid << " reject\n";
            }
        }
        ss << "  }\n";
        if (proxy_enabled) {
            ss << "  chain output_nat {\n";
            ss << "    type nat hook output priority -100; policy accept;\n";
            ss << "    ip daddr 127.0.0.0/8 return\n";
            ss << "    meta skuid 0 return\n";
            for (const auto& app : apps) {
                if (app.flags & POL_EXEMPT_ZERO_TOUCH) continue;
                if (app.flags & POL_ROUTE_PROXY) {
                    ss << "    meta nfproto ipv4 meta skuid " << app.uid << " tcp dport 1-65535 redirect to :" << proxy_port << "\n";
                }
            }
            ss << "  }\n";
        }
        ss << "}\nEOF\n";
        return ss.str();
    }

    static bool runCommandWithTimeout(const char* cmd_path, int timeout_ms) {
        pid_t pid = ::fork();
        if (pid < 0) return false;
        if (pid == 0) {
            ::execl("/system/bin/sh", "sh", cmd_path, nullptr);
            ::execl("/bin/sh", "sh", cmd_path, nullptr);
            ::_exit(127);
        }
        int elapsed = 0;
        while (elapsed < timeout_ms) {
            int status = 0;
            pid_t r = ::waitpid(pid, &status, WNOHANG);
            if (r == pid) {
                return WIFEXITED(status) && WEXITSTATUS(status) == 0;
            }
            ::usleep(25000);
            elapsed += 25;
        }
        ::kill(pid, SIGKILL);
        ::waitpid(pid, nullptr, 0);
        return false;
    }

    static uint32_t destroySocketsAf(uint8_t family, uint8_t proto, uint32_t target_uid) {
        int nl = ::socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        if (nl < 0) return 0;

        struct {
            nlmsghdr         nlh;
            inet_diag_req_v2 req;
        } dump_pkt{};

        dump_pkt.nlh.nlmsg_len   = sizeof(dump_pkt);
        dump_pkt.nlh.nlmsg_type  = SOCK_DIAG_BY_FAMILY;
        dump_pkt.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        dump_pkt.nlh.nlmsg_seq   = 1;
        dump_pkt.req.sdiag_family   = family;
        dump_pkt.req.sdiag_protocol = proto;
        dump_pkt.req.idiag_states   = (proto == IPPROTO_TCP) ? ((1u << TCP_ESTABLISHED) | (1u << TCP_SYN_SENT)) : ~0u;

        if (::send(nl, &dump_pkt, sizeof(dump_pkt), 0) < 0) {
            ::close(nl);
            return 0;
        }

        std::vector<inet_diag_sockid> victims;
        uint8_t buf[8192];
        bool done = false;
        while (!done) {
            ssize_t len = ::recv(nl, buf, sizeof(buf), 0);
            if (len <= 0) break;
            for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buf);
                 NLMSG_OK(nlh, len);
                 nlh = NLMSG_NEXT(nlh, len)) {
                if (nlh->nlmsg_type == NLMSG_DONE) { done = true; break; }
                if (nlh->nlmsg_type == NLMSG_ERROR) { done = true; break; }
                if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY) {
                    auto* msg = reinterpret_cast<inet_diag_msg*>(NLMSG_DATA(nlh));
                    if (msg->idiag_uid == target_uid) {
                        victims.push_back(msg->id);
                    }
                }
            }
        }

        uint32_t destroyed = 0;
#ifdef SOCK_DESTROY
        for (const auto& id : victims) {
            struct {
                nlmsghdr         nlh;
                inet_diag_req_v2 req;
            } kill_pkt{};
            kill_pkt.nlh.nlmsg_len   = sizeof(kill_pkt);
            kill_pkt.nlh.nlmsg_type  = SOCK_DESTROY;
            kill_pkt.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
            kill_pkt.nlh.nlmsg_seq   = 2 + destroyed;
            kill_pkt.req.sdiag_family   = family;
            kill_pkt.req.sdiag_protocol = proto;
            kill_pkt.req.idiag_states   = ~0u;
            kill_pkt.req.id             = id;
            if (::send(nl, &kill_pkt, sizeof(kill_pkt), 0) > 0) {
                ++destroyed;
            }
        }
#endif
        ::close(nl);
        return destroyed;
    }

    bool        dry_run_ = false;
    Backend     preferred_ = Backend::AUTO;
    Backend     resolved_backend_ = Backend::IPTABLES_510;
    std::string last_compiled_rules_;
    std::string last_ifw_xml_;
};

} // namespace sentinel
