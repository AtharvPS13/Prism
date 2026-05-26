#include "capture/packet_capture.h"
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include <iostream>

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
    std::cout << "Analysing " << pcapFile << "...\n";
    startCapture(pcapFile, onPacket);

    // print flow level details
    tracker.printSummary();

    // print fairness analysis across all flows
    FairnessReport report = computeFairness(tracker.getFlows());
    printFairnessReport(report);

    return 0;
}