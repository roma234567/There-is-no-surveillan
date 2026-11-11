#include "../include/sentinel_protocol.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* ============================================================================
 * sentinelctl — Zero-Port Native Bridge CLI for KernelSU / BakaSU WebUI
 *
 * Usage from WebUI (window.ksu.exec):
 *   sentinelctl rpc '{"cmd":"dashboard","limit":80}'
 *   sentinelctl status
 *   sentinelctl token
 *   sentinelctl emit <uid> <pkg> <category_int> <type> <target> <detail>
 * ============================================================================ */

namespace {

int connectUnixWithTimeout(const std::string& sock_path, int timeout_ms) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path.c_str());

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    (void)timeout_ms;
    return fd;
}

} // namespace

int main(int argc, char** argv) {
    std::string base_dir = SENTINEL_BASE_DIR;
    if (const char* env_dir = std::getenv("SENTINEL_BASE_DIR")) {
        base_dir = env_dir;
    }

    int arg_idx = 1;
    if (argc >= 3 && std::string(argv[1]) == "--base-dir") {
        base_dir = argv[2];
        arg_idx  = 3;
    }

    std::string sub = (arg_idx < argc) ? argv[arg_idx] : "status";
    std::string ctrl_sock  = base_dir + "/run/sentinel.sock";
    std::string dgram_sock = base_dir + "/run/telemetry.sock";
    std::string token_file = base_dir + "/run/webui.token";

    if (sub == "token") {
        std::ifstream ifs(token_file);
        std::string tok;
        if (ifs >> tok) {
            std::cout << "{\"ok\":true,\"token\":\"" << tok << "\"}\n";
            return 0;
        }
        std::cout << "{\"ok\":false,\"error\":\"token_not_found\"}\n";
        return 1;
    }

    if (sub == "emit") {
        if (argc - arg_idx < 7) {
            std::cerr << "Usage: sentinelctl emit <uid> <pkg> <cat> <type> <target> <detail>\n";
            return 2;
        }
        SentinelTelemetryPacket pkt{};
        pkt.magic         = SENTINEL_PROTOCOL_MAGIC;
        pkt.uid           = static_cast<uint32_t>(std::strtoul(argv[arg_idx + 1], nullptr, 10));
        pkt.pid           = static_cast<uint32_t>(::getpid());
        pkt.category      = static_cast<uint16_t>(std::strtoul(argv[arg_idx + 3], nullptr, 10));
        pkt.severity      = SEV_MEDIUM;
        pkt.action        = ACT_OBSERVED;
        pkt.is_background = 1;
        std::snprintf(pkt.package_name, sizeof(pkt.package_name), "%s", argv[arg_idx + 2]);
        std::snprintf(pkt.event_type, sizeof(pkt.event_type), "%s", argv[arg_idx + 4]);
        std::snprintf(pkt.target, sizeof(pkt.target), "%s", argv[arg_idx + 5]);
        std::snprintf(pkt.detail, sizeof(pkt.detail), "%s", argv[arg_idx + 6]);

        int dfd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (dfd < 0) return 1;
        sockaddr_un daddr{};
        daddr.sun_family = AF_UNIX;
        std::snprintf(daddr.sun_path, sizeof(daddr.sun_path), "%s", dgram_sock.c_str());
        ssize_t s = ::sendto(dfd, &pkt, sizeof(pkt), MSG_DONTWAIT,
                             reinterpret_cast<sockaddr*>(&daddr), sizeof(daddr));
        ::close(dfd);
        std::cout << (s == sizeof(pkt) ? "{\"ok\":true}\n" : "{\"ok\":false}\n");
        return (s == sizeof(pkt)) ? 0 : 1;
    }

    std::string wire;
    if (sub == "rpc" && arg_idx + 1 < argc) {
        wire = argv[arg_idx + 1];
    } else if (sub == "status") {
        wire = "{\"cmd\":\"status\"}";
    } else if (sub == "dashboard") {
        wire = "{\"cmd\":\"dashboard\",\"limit\":80}";
    } else if (sub == "inspect_rules") {
        wire = "{\"cmd\":\"inspect_rules\"}";
    } else {
        wire = "{\"cmd\":\"" + sub + "\"}";
    }
    if (wire.empty() || wire.back() != '\n') wire.push_back('\n');

    int fd = connectUnixWithTimeout(ctrl_sock, 1500);
    if (fd < 0) {
        std::cout << "{\"ok\":false,\"error\":\"daemon_unreachable\"}\n";
        return 1;
    }

    if (::send(fd, wire.data(), wire.size(), MSG_NOSIGNAL) <= 0) {
        ::close(fd);
        std::cout << "{\"ok\":false,\"error\":\"send_failed\"}\n";
        return 1;
    }

    std::string out;
    char buf[8192];
    pollfd pfd{fd, POLLIN, 0};
    while (::poll(&pfd, 1, 2500) > 0) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        if (out.find('\n') != std::string::npos) break;
    }
    ::close(fd);

    if (out.empty()) {
        std::cout << "{\"ok\":false,\"error\":\"empty_response\"}\n";
        return 1;
    }
    std::cout << out;
    return 0;
}
