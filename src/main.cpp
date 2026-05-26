#include "capture/packet_capture.h"
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include "emitter/json_emitter.h"
#include <iostream>
#include <thread>
#include <chrono>

FlowTracker tracker;

void onPacket(const PacketInfo& pkt) {
    if (pkt.protocol != "TCP") return;
    tracker.processPacket(
        pkt.src_ip, pkt.dst_ip,
        pkt.src_port, pkt.dst_port,
        6,
        pkt.seq_num, pkt.ack_num,
        pkt.is_syn, pkt.is_ack,
        pkt.size_bytes,
        pkt.timestamp
    );
}

int main() {
    std::string pcapFile = "data/sample.pcap";

    // start HTTP server on port 8080 in background
    startHttpServer(8080);
    std::cout << "HTTP server running on http://localhost:8080\n";

    // run packet capture
    std::cout << "Analysing " << pcapFile << "...\n";
    startCapture(pcapFile, onPacket);

    // once capture is done, compute final stats
    tracker.printSummary();
    FairnessReport report = computeFairness(tracker.getFlows());
    printFairnessReport(report);

    // update the JSON snapshot so React can fetch it
    std::string json = buildJson(tracker.getFlows(), report);
    updateSnapshot(json);

    std::cout << "\nServing data at http://localhost:8080\n";
    std::cout << "Press Ctrl+C to stop.\n";

    // keep main thread alive so server keeps running
    while (true)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}