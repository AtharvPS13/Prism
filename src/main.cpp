#include "capture/packet_capture.h"
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include "analyser/classifier.h"
#include "emitter/json_emitter.h"
#include <iostream>
#include <thread>
#include <chrono>

FlowTracker       tracker;
TrafficClassifier classifier;

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

    std::string flow_key;
    if (pkt.src_ip < pkt.dst_ip)
        flow_key = pkt.src_ip + ":" + std::to_string(pkt.src_port) +
                   "<->" + pkt.dst_ip + ":" + std::to_string(pkt.dst_port);
    else
        flow_key = pkt.dst_ip + ":" + std::to_string(pkt.dst_port) +
                   "<->" + pkt.src_ip + ":" + std::to_string(pkt.src_port);

    classifier.updateProfile(
        flow_key,
        pkt.src_ip,
        pkt.src_ip,
        pkt.size_bytes,
        pkt.timestamp
    );
}

int main() {
    std::string pcapFile = "data/sample.pcap";

    startHttpServer(8080);
    std::cout << "HTTP server running on http://localhost:8080\n";

    std::cout << "Analysing " << pcapFile << "...\n";
    startCapture(pcapFile, onPacket);

    tracker.printSummary();

    FairnessReport report = computeFairness(tracker.getFlows());
    printFairnessReport(report);

    classifier.printClassifications();

    // pass classifier to buildJson
    std::string json = buildJson(tracker.getFlows(), report, classifier);
    updateSnapshot(json);

    std::cout << "\nServing data at http://localhost:8080\n";
    std::cout << "Press Ctrl+C to stop.\n";

    while (true)
        std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}