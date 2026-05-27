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
static std::string latest_snapshot = "{}";

static std::string jsonStr(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string buildJson(
    const std::unordered_map<std::string, FlowStats>& flows,
    const FairnessReport& report,
    const TrafficClassifier& classifier,
    const TopologyInferrer& topology)
{
    std::ostringstream j;
    j << std::fixed << std::setprecision(3);

    j << "{\n";
    j << "  \"timestamp\": "     << (double)time(nullptr) << ",\n";
    j << "  \"fairness_index\": " << report.index          << ",\n";
    j << "  \"total_flows\": "    << report.total_flows     << ",\n";
    j << "  \"worst_hog\": "      << jsonStr(report.worst_hog) << ",\n";
    j << "  \"hog_percent\": "    << report.hog_percent     << ",\n";
    j << "  \"flows\": [\n";

    bool first = true;
    for (const auto& [key, flow] : flows) {
        if (!first) j << ",\n";
        first = false;

        // get classification for this flow
        ClassificationResult cls = classifier.classify(key);

        j << "    {\n";
        j << "      \"key\": "        << jsonStr(key)         << ",\n";
        j << "      \"src_ip\": "     << jsonStr(flow.src_ip) << ",\n";
        j << "      \"dst_ip\": "     << jsonStr(flow.dst_ip) << ",\n";
        j << "      \"src_port\": "   << flow.src_port        << ",\n";
        j << "      \"dst_port\": "   << flow.dst_port        << ",\n";
        j << "      \"bytes\": "      << flow.total_bytes     << ",\n";
        j << "      \"packets\": "    << flow.packet_count    << ",\n";
        j << "      \"avg_rtt_ms\": "
          << (flow.rtt_samples > 0 ? flow.avg_rtt : -1.0)    << ",\n";
        j << "      \"max_rtt_ms\": "
          << (flow.rtt_samples > 0 ? flow.max_rtt : -1.0)    << ",\n";
        j << "      \"bufferbloat\": "
          << (flow.bufferbloat ? "true" : "false")            << ",\n";
        j << "      \"is_hog\": "
          << (key == report.worst_hog ? "true" : "false")     << ",\n";
        j << "      \"traffic_type\": " << jsonStr(cls.label) << ",\n";
        j << "      \"confidence\": "
          << (int)(cls.confidence * 100)                      << ",\n";
        j << "      \"reason\": "    << jsonStr(cls.reason)   << "\n";
        j << "    }";
    }

    j << "\n  ],\n";

    // topology section
    j << "  \"hosts\": [\n";
    bool firstHost = true;
    for (const auto& [ip, host] : topology.getHosts()) {
        if (!firstHost) j << ",\n";
        firstHost = false;
        j << "    {\n";
        j << "      \"ip\": "        << jsonStr(ip)             << ",\n";
        j << "      \"ttl\": "       << host.observed_ttl       << ",\n";
        j << "      \"hops\": "      << host.hops               << ",\n";
        j << "      \"os_guess\": "  << jsonStr(host.os_guess)  << ",\n";
        j << "      \"proximity\": " << jsonStr(host.proximity) << ",\n";
        j << "      \"packets\": "   << host.packet_count       << "\n";
        j << "    }";
    }
    j << "\n  ]\n}";
    return j.str();
}

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