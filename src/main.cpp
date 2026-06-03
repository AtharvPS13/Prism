#include "capture/packet_capture.h"
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include "analyser/classifier.h"
#include "analyser/topology.h"
#include "analyser/tcp_state.h"
#include "emitter/json_emitter.h"
#include "recorder/event_recorder.h"
#include "recorder/replay_engine.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>

// ─── global analysers ─────────────────────────────────────────────────────────

FlowTracker       tracker;
TrafficClassifier classifier;
TopologyInferrer  topology;
TCPStateTracker   tcp_tracker;   // NEW — TCP congestion state machine
EventRecorder     recorder;

// ─── flow key helper (same logic used everywhere) ────────────────────────────

static std::string makeFlowKey(const std::string& src_ip, int src_port,
                                const std::string& dst_ip, int dst_port)
{
    if (src_ip < dst_ip)
        return src_ip + ":" + std::to_string(src_port) +
               "<->" + dst_ip + ":" + std::to_string(dst_port);
    else
        return dst_ip + ":" + std::to_string(dst_port) +
               "<->" + src_ip + ":" + std::to_string(src_port);
}

// ─── per-packet callback ──────────────────────────────────────────────────────

void onPacket(const PacketInfo& pkt) {
    if (pkt.protocol != "TCP") return;

    tracker.processPacket(
        pkt.src_ip, pkt.dst_ip,
        pkt.src_port, pkt.dst_port,
        6,
        pkt.seq_num, pkt.ack_num,
        pkt.is_syn,  pkt.is_ack,
        pkt.size_bytes,
        pkt.timestamp
    );

    const std::string flow_key =
        makeFlowKey(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port);

    classifier.updateProfile(
        flow_key, pkt.src_ip, pkt.src_ip,
        pkt.size_bytes, pkt.timestamp);

    topology.observePacket(pkt.src_ip, pkt.ttl);

    // TCP congestion state machine — pass original direction info
    tcp_tracker.update(
        flow_key,
        pkt.src_ip,     // original src (not normalized) for direction detection
        pkt.seq_num,
        pkt.ack_num,
        pkt.is_syn,
        pkt.is_ack,
        pkt.size_bytes,
        pkt.timestamp
    );

    FairnessReport report = computeFairness(tracker.getFlows());

    const auto& flows = tracker.getFlows();
    auto it = flows.find(flow_key);
    if (it != flows.end()) {
        recorder.record(flow_key, it->second, report, pkt.timestamp);
    }

    // update dashboard every 10 packets to avoid flooding
    static int pkt_count = 0;
    if (++pkt_count % 10 == 0) {
        std::string json = buildJson(
            tracker.getFlows(), report,
            classifier, topology, tcp_tracker);
        updateSnapshot(json);
    }
}

// ─── replay JSON builder ──────────────────────────────────────────────────────

std::string buildReplayJson(const ReplayState& state) {
    std::ostringstream j;
    j << std::fixed;
    j << "{\n";
    j << "  \"replay\": true,\n";
    j << "  \"timestamp\": "       << state.timestamp                          << ",\n";
    j << "  \"fairness_index\": "  << std::setprecision(3) << state.fairness_index << ",\n";
    j << "  \"total_flows\": 1,\n";
    j << "  \"worst_hog\": \""     << state.flow_key                          << "\",\n";
    j << "  \"hog_percent\": "     << std::setprecision(1) << state.hog_percent    << ",\n";
    j << "  \"anomaly_active\": "  << (state.anomaly_active ? "true":"false") << ",\n";
    j << "  \"replay_progress\": " << state.total_events                      << ",\n";
    j << "  \"replay_total\": "    << state.total_in_file                     << ",\n";
    j << "  \"flows\": [{\n";
    j << "    \"key\": \""         << state.flow_key                          << "\",\n";
    j << "    \"src_ip\": \"replay\", \"dst_ip\": \"replay\",\n";
    j << "    \"src_port\": 0, \"dst_port\": 0,\n";
    j << "    \"bytes\": 0,\n";
    j << "    \"packets\": "       << state.total_events                      << ",\n";
    j << "    \"avg_rtt_ms\": "    << std::setprecision(1) << state.rtt_ms   << ",\n";
    j << "    \"max_rtt_ms\": "    << state.rtt_ms                            << ",\n";
    j << "    \"bufferbloat\": "   << (state.bufferbloat ? "true":"false")    << ",\n";
    j << "    \"is_hog\": true,\n";
    j << "    \"traffic_type\": \""<< state.event_label                      << "\",\n";
    j << "    \"confidence\": 100,\n";
    j << "    \"reason\": \"replayed from anomaly file\",\n";
    j << "    \"tcp_state\": \"UNKNOWN\",\n";
    j << "    \"tcp_state_color\": \"#4E6380\",\n";
    j << "    \"bytes_in_flight\": 0,\n";
    j << "    \"retransmissions\": 0, \"fast_recoveries\": 0,\n";
    j << "    \"timeouts_count\": 0,\n";
    j << "    \"time_slow_start\": 0.0, \"time_cong_avoid\": 0.0,\n";
    j << "    \"time_fast_recovery\": 0.0,\n";
    j << "    \"cwnd_history\": []\n";
    j << "  }],\n";
    j << "  \"hosts\": []\n}\n";
    return j.str();
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {

    // ── REPLAY MODE ──────────────────────────────────────────────────────
    if (argc >= 3 && std::string(argv[1]) == "--replay") {
        std::string replayFile = argv[2];
        double speed = 1.0;
        for (int i = 3; i < argc - 1; i++)
            if (std::string(argv[i]) == "--speed")
                speed = std::stod(argv[i+1]);

        startHttpServer(8080);
        std::cout << "Replay mode — open http://localhost:3000\n";
        std::cout << "Speed: " << speed << "x\n";

        ReplayEngine engine;
        if (!engine.loadFile(replayFile)) return 1;
        engine.printSummary();
        engine.replay(speed, [](const ReplayState& state) {
            updateSnapshot(buildReplayJson(state));
        });
        std::cout << "Replay done.\n";
        while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
        return 0;
    }

    // ── LIVE CAPTURE MODE ────────────────────────────────────────────────
    std::string liveInterface;
    for (int i = 1; i < argc - 1; i++)
        if (std::string(argv[i]) == "--live")
            liveInterface = argv[i+1];

    startHttpServer(8080);

    if (!liveInterface.empty()) {
        std::cout << "Live capture on: " << liveInterface << "\n";
        std::cout << "Dashboard at http://localhost:3000\n";
        std::cout << "Press Ctrl+C to stop\n\n";
        startLiveCapture(liveInterface, onPacket);
        return 0;
    }

    // ── PCAP FILE MODE ───────────────────────────────────────────────────
    std::string pcapFile = "data/sample.pcap";
    std::cout << "HTTP server on http://localhost:8080\n";
    std::cout << "Analysing " << pcapFile << "...\n";
    startCapture(pcapFile, onPacket);

    tracker.printSummary();
    FairnessReport report = computeFairness(tracker.getFlows());
    printFairnessReport(report);
    classifier.printClassifications();
    topology.printTopology();
    tcp_tracker.printSummary();   // NEW — print TCP state summary

    std::cout << "\nAnomalies recorded: " << recorder.anomalyCount() << "\n";

    std::string json = buildJson(
        tracker.getFlows(), report,
        classifier, topology, tcp_tracker);
    updateSnapshot(json);

    std::cout << "\nServing at http://localhost:8080\n";
    std::cout << "Replay: ./build/network_monitor --replay <file.bin> --speed 0.1\n";
    std::cout << "Press Ctrl+C to stop.\n";

    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}