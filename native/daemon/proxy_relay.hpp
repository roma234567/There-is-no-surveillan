#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

/* ============================================================================
 * SentinelProxyRelay — Transparent TCP & DNS -> SOCKS5/Tor Per-App Engine
 *
 * Why this exists:
 * Standard Android VPN profiles (VpnService / tun0) modify global routing
 * tables, expose NETWORK_CAPABILITY_NOT_VPN=false, and can trigger banking
 * anti-fraud or Play Integrity / DroidGuard checks.
 *
 * Instead, Privacy Sentinel redirects ONLY selected UIDs via kernel netfilter:
 *   iptables -t nat -A SENTINEL_PROXY -m owner --uid-owner <UID> -p tcp \
 *            -j REDIRECT --to-ports 19040
 *   iptables -t nat -A SENTINEL_PROXY -m owner --uid-owner <UID> -p udp \
 *            --dport 53 -j REDIRECT --to-ports 19053 (or DNS-over-TCP bridge)
 * while dropping UDP/443 (QUIC) and IPv6 bypasses for those UIDs.
 *
 * SentinelProxyRelay recovers the true destination via getsockopt(SOL_IP,
 * SO_ORIGINAL_DST), performs RFC 1928 / RFC 1929 SOCKS5 negotiation with any
 * upstream Tor (127.0.0.1:9050) or remote SOCKS5 server, and splices traffic
 * with strict timeouts so no hung upstream can stall the system.
 * ============================================================================ */

namespace sentinel {

struct ProxyConfig {
    bool        enabled      = false;
    uint16_t    listen_port  = 19040;
    std::string socks5_host  = "127.0.0.1";
    uint16_t    socks5_port  = 9050; /* Default Tor SOCKS5 port; works with any SOCKS5 */
    std::string username;
    std::string password;
    bool        block_quic   = true; /* Block UDP/443 so Chromium/OkHttp falls back to TCP */
    bool        block_ipv6   = true; /* Prevent IPv6 direct leak outside IPv4 NAT redirect */
    uint32_t    timeout_ms   = 6000;
};

class TransparentSocks5Relay {
public:
    using TelemetryCallback = std::function<void(const std::string& dst, bool ok, const std::string& note)>;

    TransparentSocks5Relay() = default;
    ~TransparentSocks5Relay() { stop(); }

    void updateConfig(const ProxyConfig& cfg) {
        bool need_restart = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (cfg_.enabled != cfg.enabled || cfg_.listen_port != cfg.listen_port) {
                need_restart = true;
            }
            cfg_ = cfg;
        }
        if (need_restart) {
            stop();
            if (cfg.enabled) {
                start();
            }
        }
    }

    ProxyConfig getConfig() const {
        std::lock_guard<std::mutex> lk(mu_);
        return cfg_;
    }

    uint64_t relayedConnections() const { return relayed_count_.load(std::memory_order_relaxed); }
    uint64_t relayedBytes() const { return relayed_bytes_.load(std::memory_order_relaxed); }
    bool isRunning() const { return running_.load(std::memory_order_relaxed); }

    void setTelemetryCallback(TelemetryCallback cb) {
        std::lock_guard<std::mutex> lk(mu_);
        telemetry_cb_ = std::move(cb);
    }

    bool start() {
        if (running_.exchange(true)) return true;

        uint16_t port = 19040;
        {
            std::lock_guard<std::mutex> lk(mu_);
            port = cfg_.listen_port;
        }

        listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listen_fd_ < 0) {
            running_ = false;
            return false;
        }

        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* Strictly 127.0.0.1 */

        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(listen_fd_, 64) < 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            running_   = false;
            return false;
        }

        accept_thread_ = std::thread([this]() { acceptLoop(); });
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        if (listen_fd_ >= 0) {
            ::shutdown(listen_fd_, SHUT_RDWR);
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
    }

private:
    static bool writeAll(int fd, const uint8_t* buf, size_t len, int timeout_ms) {
        size_t sent = 0;
        while (sent < len) {
            pollfd pfd{fd, POLLOUT, 0};
            if (::poll(&pfd, 1, timeout_ms) <= 0) return false;
            ssize_t n = ::send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    static bool readExact(int fd, uint8_t* buf, size_t len, int timeout_ms) {
        size_t got = 0;
        while (got < len) {
            pollfd pfd{fd, POLLIN, 0};
            if (::poll(&pfd, 1, timeout_ms) <= 0) return false;
            ssize_t n = ::recv(fd, buf + got, len - got, 0);
            if (n <= 0) return false;
            got += static_cast<size_t>(n);
        }
        return true;
    }

    static int connectWithTimeout(const std::string& host, uint16_t port, int timeout_ms) {
        int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) return -1;

        sockaddr_in up{};
        up.sin_family = AF_INET;
        up.sin_port   = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &up.sin_addr) != 1) {
            ::close(fd);
            return -1;
        }

        int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&up), sizeof(up));
        if (rc < 0 && errno != EINPROGRESS) {
            ::close(fd);
            return -1;
        }
        if (rc < 0) {
            pollfd pfd{fd, POLLOUT, 0};
            if (::poll(&pfd, 1, timeout_ms) <= 0) {
                ::close(fd);
                return -1;
            }
            int err = 0;
            socklen_t elen = sizeof(err);
            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
                ::close(fd);
                return -1;
            }
        }
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags >= 0) ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        return fd;
    }

    void acceptLoop() {
        while (running_.load(std::memory_order_relaxed)) {
            pollfd pfd{listen_fd_, POLLIN, 0};
            int pr = ::poll(&pfd, 1, 500);
            if (pr <= 0) continue;

            sockaddr_in client_addr{};
            socklen_t clen = sizeof(client_addr);
            int cfd = ::accept4(listen_fd_, reinterpret_cast<sockaddr*>(&client_addr), &clen, SOCK_CLOEXEC);
            if (cfd < 0) continue;

            if (active_workers_.load(std::memory_order_relaxed) > 128) {
                ::close(cfd);
                continue;
            }

            active_workers_.fetch_add(1, std::memory_order_relaxed);
            std::thread([this, cfd]() {
                handleClient(cfd);
                active_workers_.fetch_sub(1, std::memory_order_relaxed);
            }).detach();
        }
    }

    void handleClient(int cfd) {
        sockaddr_in orig_dst{};
        socklen_t olen = sizeof(orig_dst);
        if (::getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &olen) < 0) {
            ::close(cfd);
            return;
        }

        ProxyConfig cfg = getConfig();
        /* Guard against accidental self-redirect loop */
        if (ntohl(orig_dst.sin_addr.s_addr) == INADDR_LOOPBACK &&
            ntohs(orig_dst.sin_port) == cfg.listen_port) {
            ::close(cfd);
            return;
        }

        char ip_buf[INET_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET, &orig_dst.sin_addr, ip_buf, sizeof(ip_buf));
        std::string dst_label = std::string(ip_buf) + ":" + std::to_string(ntohs(orig_dst.sin_port));

        int ufd = connectWithTimeout(cfg.socks5_host, cfg.socks5_port, static_cast<int>(cfg.timeout_ms));
        if (ufd < 0) {
            notify(dst_label, false, "Upstream SOCKS5 unreachable (" + cfg.socks5_host + ":" + std::to_string(cfg.socks5_port) + ")");
            ::close(cfd);
            return;
        }

        /* RFC 1928 Greeting */
        const bool use_auth = !cfg.username.empty();
        uint8_t greet[4] = {0x05, use_auth ? uint8_t(2) : uint8_t(1), 0x00, 0x02};
        uint8_t greet_resp[2]{};
        if (!writeAll(ufd, greet, use_auth ? 4 : 3, cfg.timeout_ms) ||
            !readExact(ufd, greet_resp, 2, cfg.timeout_ms) ||
            greet_resp[0] != 0x05) {
            notify(dst_label, false, "SOCKS5 handshake rejected");
            ::close(ufd);
            ::close(cfd);
            return;
        }

        /* RFC 1929 Username/Password Subnegotiation */
        if (greet_resp[1] == 0x02) {
            if (!use_auth || cfg.username.size() > 255 || cfg.password.size() > 255) {
                ::close(ufd);
                ::close(cfd);
                return;
            }
            std::string auth_pkt;
            auth_pkt.push_back(0x01);
            auth_pkt.push_back(static_cast<char>(cfg.username.size()));
            auth_pkt.append(cfg.username);
            auth_pkt.push_back(static_cast<char>(cfg.password.size()));
            auth_pkt.append(cfg.password);
            uint8_t auth_resp[2]{};
            if (!writeAll(ufd, reinterpret_cast<const uint8_t*>(auth_pkt.data()), auth_pkt.size(), cfg.timeout_ms) ||
                !readExact(ufd, auth_resp, 2, cfg.timeout_ms) || auth_resp[1] != 0x00) {
                notify(dst_label, false, "SOCKS5 authentication failed");
                ::close(ufd);
                ::close(cfd);
                return;
            }
        } else if (greet_resp[1] != 0x00) {
            ::close(ufd);
            ::close(cfd);
            return;
        }

        /* CONNECT Request to Original IPv4:Port */
        uint8_t req[10]{};
        req[0] = 0x05; /* VER */
        req[1] = 0x01; /* CMD = CONNECT */
        req[2] = 0x00; /* RSV */
        req[3] = 0x01; /* ATYP = IPv4 */
        ::memcpy(req + 4, &orig_dst.sin_addr.s_addr, 4);
        ::memcpy(req + 8, &orig_dst.sin_port, 2);

        uint8_t resp_hdr[4]{};
        if (!writeAll(ufd, req, sizeof(req), cfg.timeout_ms) ||
            !readExact(ufd, resp_hdr, 4, cfg.timeout_ms) ||
            resp_hdr[1] != 0x00) {
            notify(dst_label, false, "SOCKS5 CONNECT refused by exit node");
            ::close(ufd);
            ::close(cfd);
            return;
        }

        /* Drain bound address based on ATYP */
        size_t drain = 0;
        if (resp_hdr[3] == 0x01) drain = 4 + 2;
        else if (resp_hdr[3] == 0x04) drain = 16 + 2;
        else if (resp_hdr[3] == 0x03) {
            uint8_t dlen = 0;
            if (!readExact(ufd, &dlen, 1, cfg.timeout_ms)) {
                ::close(ufd);
                ::close(cfd);
                return;
            }
            drain = static_cast<size_t>(dlen) + 2;
        }
        uint8_t discard[260]{};
        if (drain > 0 && !readExact(ufd, discard, drain, cfg.timeout_ms)) {
            ::close(ufd);
            ::close(cfd);
            return;
        }

        relayed_count_.fetch_add(1, std::memory_order_relaxed);
        notify(dst_label, true, "Tunneled via SOCKS5 " + cfg.socks5_host + ":" + std::to_string(cfg.socks5_port));

        /* Bidirectional poll relay */
        uint8_t buf[8192];
        pollfd pfds[2] = {{cfd, POLLIN, 0}, {ufd, POLLIN, 0}};
        while (running_.load(std::memory_order_relaxed)) {
            int pr = ::poll(pfds, 2, 45000);
            if (pr <= 0) break;
            if (pfds[0].revents & (POLLERR | POLLHUP)) break;
            if (pfds[1].revents & (POLLERR | POLLHUP)) break;

            if (pfds[0].revents & POLLIN) {
                ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
                if (n <= 0 || !writeAll(ufd, buf, static_cast<size_t>(n), 5000)) break;
                relayed_bytes_.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);
            }
            if (pfds[1].revents & POLLIN) {
                ssize_t n = ::recv(ufd, buf, sizeof(buf), 0);
                if (n <= 0 || !writeAll(cfd, buf, static_cast<size_t>(n), 5000)) break;
                relayed_bytes_.fetch_add(static_cast<uint64_t>(n), std::memory_order_relaxed);
            }
        }

        ::close(ufd);
        ::close(cfd);
    }

    void notify(const std::string& dst, bool ok, const std::string& note) {
        TelemetryCallback cb;
        {
            std::lock_guard<std::mutex> lk(mu_);
            cb = telemetry_cb_;
        }
        if (cb) cb(dst, ok, note);
    }

    mutable std::mutex     mu_;
    ProxyConfig            cfg_;
    TelemetryCallback      telemetry_cb_;
    int                    listen_fd_ = -1;
    std::atomic<bool>      running_{false};
    std::atomic<uint32_t>  active_workers_{0};
    std::atomic<uint64_t>  relayed_count_{0};
    std::atomic<uint64_t>  relayed_bytes_{0};
    std::thread            accept_thread_;
};

} // namespace sentinel
