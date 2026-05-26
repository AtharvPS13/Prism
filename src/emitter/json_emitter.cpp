#include "json_emitter.h"
#include <sstream>
#include <iomanip>
#include <string>
#include <thread>
#include <mutex>
#include <netinet/in.h>    // sockaddr_in
#include <sys/socket.h>    // socket(), bind(), listen(), accept()
#include <unistd.h>        // close(), write()
#include <ctime>

// mutex protects the snapshot string
// main thread writes it, server thread reads it
static std::mutex      snapshot_mutex;
static std::string     latest_snapshot = "{}";

// helper: escape a string for JSON
static std::string jsonStr(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string buildJson(
    const std::unordered_map<std::string, FlowStats>& flows,
    const FairnessReport& report)
{
    std::ostringstream j;
    j << std::fixed << std::setprecision(3);

    j << "{\n";
    j << "  \"timestamp\": " << (double)time(nullptr) << ",\n";
    j << "  \"fairness_index\": " << report.index << ",\n";
    j << "  \"total_flows\": " << report.total_flows << ",\n";
    j << "  \"worst_hog\": " << jsonStr(report.worst_hog) << ",\n";
    j << "  \"hog_percent\": " << report.hog_percent << ",\n";
    j << "  \"flows\": [\n";

    bool first = true;
    for (const auto& [key, flow] : flows) {
        if (!first) j << ",\n";
        first = false;

        j << "    {\n";
        j << "      \"key\": "      << jsonStr(key)          << ",\n";
        j << "      \"src_ip\": "   << jsonStr(flow.src_ip)  << ",\n";
        j << "      \"dst_ip\": "   << jsonStr(flow.dst_ip)  << ",\n";
        j << "      \"src_port\": " << flow.src_port         << ",\n";
        j << "      \"dst_port\": " << flow.dst_port         << ",\n";
        j << "      \"bytes\": "    << flow.total_bytes      << ",\n";
        j << "      \"packets\": "  << flow.packet_count     << ",\n";
        j << "      \"avg_rtt_ms\": "
          << (flow.rtt_samples > 0 ? flow.avg_rtt : -1.0)   << ",\n";
        j << "      \"max_rtt_ms\": "
          << (flow.rtt_samples > 0 ? flow.max_rtt : -1.0)   << ",\n";
        j << "      \"bufferbloat\": "
          << (flow.bufferbloat ? "true" : "false")           << ",\n";
        j << "      \"is_hog\": "
          << (key == report.worst_hog ? "true" : "false")    << "\n";
        j << "    }";
    }

    j << "\n  ]\n}";
    return j.str();
}

void updateSnapshot(const std::string& json) {
    std::lock_guard<std::mutex> lock(snapshot_mutex);
    latest_snapshot = json;
}

// this runs in a background thread
// it's a minimal HTTP/1.1 server — just enough for React to fetch from
static void serverLoop(int port) {
    // Step 1: create a TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return;

    // allow reuse of port immediately after restart
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Step 2: bind to localhost:port
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return;

    // Step 3: listen for incoming connections
    listen(server_fd, 10);

    while (true) {
        // Step 4: accept a connection from React
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        // Step 5: read the HTTP request (we don't need to parse it)
        char buf[1024] = {};
        read(client_fd, buf, sizeof(buf) - 1);

        // Step 6: grab the latest snapshot safely
        std::string body;
        {
            std::lock_guard<std::mutex> lock(snapshot_mutex);
            body = latest_snapshot;
        }

        // Step 7: send HTTP response with CORS header
        // CORS allows React (on port 3000) to fetch from C++ (on port 8080)
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
    // launch server in background thread so main thread can keep capturing
    std::thread(serverLoop, port).detach();
}