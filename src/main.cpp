#include "capture/packet_capture.h"
#include <iostream>

// this is the function we pass to startCapture
// it gets called once per packet with the parsed info
void onPacket(const PacketInfo& pkt) {
    std::cout << "[" << pkt.protocol << "] "
              << pkt.src_ip << " -> " << pkt.dst_ip
              << "  (" << pkt.size_bytes << " bytes)\n";
}

int main() {
    std::string pcapFile = "data/sample.pcap";
    std::cout << "Reading packets from " << pcapFile << "...\n\n";
    startCapture(pcapFile, onPacket);
    return 0;
}