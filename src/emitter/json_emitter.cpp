#include "json_emitter.h"
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctime>

static std::mutex  snapshot_mutex;
static std::string latest_snapshot =
    "{\"timestamp\":0,\"fairness_index\":1.0,\"total_flows\":0,"
    "\"worst_hog\":\"\",\"hog_percent\":0.0,\"flows\":[],\"hosts\":[]}";

// ─── JSON string escaping ─────────────────────────────────────────────────────

static std::string jsonStr(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else                out += c;
    }
    out += "\"";
    return out;
}

// ─── buildJson ────────────────────────────────────────────────────────────────

std::string buildJson(
    const std::unordered_map<std::string, FlowStats>& flows,
    const FairnessReport&    report,
    const TrafficClassifier& classifier,
    const TopologyInferrer&  topology,
    const TCPStateTracker&   tcp_tracker)
{
    std::ostringstream j;
    j << std::fixed << std::setprecision(3);

    j << "{\n";
    j << "  \"timestamp\": "      << (double)time(nullptr)    << ",\n";
    j << "  \"fairness_index\": " << report.index             << ",\n";
    j << "  \"total_flows\": "    << report.total_flows        << ",\n";
    j << "  \"worst_hog\": "      << jsonStr(report.worst_hog)<< ",\n";
    j << "  \"hog_percent\": "    << report.hog_percent        << ",\n";

    // ── flows ──────────────────────────────────────────────────────────────
    j << "  \"flows\": [\n";
    bool first_flow = true;
    for (const auto& [key, flow] : flows) {
        if (!first_flow) j << ",\n";
        first_flow = false;

        ClassificationResult cls = classifier.classify(key);

        // look up TCP state for this flow (may be null if not yet tracked)
        const TCPFlowState* tcp = tcp_tracker.getState(key);

        j << "    {\n";
        j << "      \"key\": "          << jsonStr(key)          << ",\n";
        j << "      \"src_ip\": "       << jsonStr(flow.src_ip)  << ",\n";
        j << "      \"dst_ip\": "       << jsonStr(flow.dst_ip)  << ",\n";
        j << "      \"src_port\": "     << flow.src_port          << ",\n";
        j << "      \"dst_port\": "     << flow.dst_port          << ",\n";
        j << "      \"bytes\": "        << flow.total_bytes       << ",\n";
        j << "      \"packets\": "      << flow.packet_count      << ",\n";
        j << "      \"avg_rtt_ms\": "
          << (flow.rtt_samples > 0 ? flow.avg_rtt : -1.0)        << ",\n";
        j << "      \"max_rtt_ms\": "
          << (flow.rtt_samples > 0 ? flow.max_rtt : -1.0)        << ",\n";
        j << "      \"bufferbloat\": "
          << (flow.bufferbloat ? "true" : "false")                << ",\n";
        j << "      \"is_hog\": "
          << (key == report.worst_hog ? "true" : "false")         << ",\n";
        j << "      \"traffic_type\": " << jsonStr(cls.label)    << ",\n";
        j << "      \"confidence\": "
          << (int)(cls.confidence * 100)                          << ",\n";
        j << "      \"reason\": "       << jsonStr(cls.reason)   << ",\n";

        // ── TCP congestion state ─────────────────────────────────────────
        if (tcp && tcp->state != TCPState::UNKNOWN) {
            j << "      \"tcp_state\": "
              << jsonStr(tcpStateLabel(tcp->state))               << ",\n";
            j << "      \"tcp_state_color\": "
              << jsonStr(tcpStateColor(tcp->state))               << ",\n";
            j << "      \"bytes_in_flight\": "
              << std::setprecision(0) << tcp->bytes_in_flight     << ",\n";
            j << "      \"retransmissions\": "  << tcp->retransmissions   << ",\n";
            j << "      \"fast_recoveries\": "  << tcp->fast_recoveries   << ",\n";
            j << "      \"timeouts_count\": "   << tcp->timeouts_count    << ",\n";
            j << "      \"time_slow_start\": "
              << std::setprecision(1) << tcp->time_slow_start             << ",\n";
            j << "      \"time_cong_avoid\": "
              << tcp->time_cong_avoid                                      << ",\n";
            j << "      \"time_fast_recovery\": "
              << tcp->time_fast_recovery                                   << ",\n";

            // sawtooth history: compact array of [rel_t, bif_kb, state_label]
            j << "      \"cwnd_history\": [";
            bool first_pt = true;
            for (const auto& pt : tcp->history) {
                if (!first_pt) j << ",";
                first_pt = false;
                j << "[" << std::setprecision(2) << pt.t
                  << "," << std::setprecision(1) << (pt.bytes_in_flight / 1024.0)
                  << "," << jsonStr(tcpStateLabel(pt.state))
                  << "]";
            }
            j << "]\n";
        } else {
            // no TCP state yet — provide safe defaults
            j << "      \"tcp_state\": \"UNKNOWN\",\n";
            j << "      \"tcp_state_color\": \"#4E6380\",\n";
            j << "      \"bytes_in_flight\": 0,\n";
            j << "      \"retransmissions\": 0,\n";
            j << "      \"fast_recoveries\": 0,\n";
            j << "      \"timeouts_count\": 0,\n";
            j << "      \"time_slow_start\": 0.0,\n";
            j << "      \"time_cong_avoid\": 0.0,\n";
            j << "      \"time_fast_recovery\": 0.0,\n";
            j << "      \"cwnd_history\": []\n";
        }
        j << "    }";
    }
    j << "\n  ],\n";

    // ── topology hosts ─────────────────────────────────────────────────────
    j << "  \"hosts\": [\n";
    bool first_host = true;
    for (const auto& [ip, host] : topology.getHosts()) {
        if (!first_host) j << ",\n";
        first_host = false;
        j << "    {\n";
        j << "      \"ip\": "        << jsonStr(ip)              << ",\n";
        j << "      \"ttl\": "       << host.observed_ttl        << ",\n";
        j << "      \"hops\": "      << host.hops                << ",\n";
        j << "      \"os_guess\": "  << jsonStr(host.os_guess)   << ",\n";
        j << "      \"proximity\": " << jsonStr(host.proximity)  << ",\n";
        j << "      \"packets\": "   << host.packet_count        << "\n";
        j << "    }";
    }
    j << "\n  ]\n}";

    return j.str();
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

void updateSnapshot(const std::string& json) {
    std::lock_guard<std::mutex> lock(snapshot_mutex);
    latest_snapshot = json;
}

static void serverLoop(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return;
    listen(server_fd, 10);

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        char buf[1024] = {};
        read(client_fd, buf, sizeof(buf) - 1);

        std::string body;
        {
            std::lock_guard<std::mutex> lock(snapshot_mutex);
            body = latest_snapshot;
        }

        std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "\r\n" + body;

        write(client_fd, response.c_str(), response.size());
        close(client_fd);
    }
}

void startHttpServer(int port) {
    std::thread(serverLoop, port).detach();
}