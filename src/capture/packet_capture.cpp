#include "packet_capture.h"
#include <pcap.h>
#include <netinet/ip.h>      // struct iphdr — maps raw bytes to IP header fields
#include <netinet/tcp.h>     // struct tcphdr — we'll use this in Week 2
#include <arpa/inet.h>       // inet_ntoa() — converts IP from binary to "192.168.x.x" string
#include <iostream>

// libpcap calls this function automatically for every packet it reads
// - userData:   anything we want to pass through (our callback function)
// - pkthdr:     metadata — timestamp, packet length
// - packet:     the raw bytes of the actual packet
static void pcapHandler(u_char* userData,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet)
{
    // Step 1: skip the ethernet header (always exactly 14 bytes)
    // everything after byte 14 is the IP header
    const int ETHERNET_HEADER_SIZE = 14;
    if (pkthdr->len < ETHERNET_HEADER_SIZE) return; // packet too small, skip

    // Step 2: cast raw bytes to iphdr struct
    // this is the "struct trick" — the bytes in memory match the IP header layout exactly
    // so we just tell C++ "treat this memory address as an iphdr struct"
    const struct iphdr* ip = (struct iphdr*)(packet + ETHERNET_HEADER_SIZE);

    // Step 3: fill in our PacketInfo
    PacketInfo info;

    // inet_ntoa converts binary IP (4 bytes) to human readable string
    // ip->saddr and ip->daddr are source and destination IP addresses
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->saddr;
    dst_addr.s_addr = ip->daddr;
    info.src_ip   = inet_ntoa(src_addr);
    info.dst_ip   = inet_ntoa(dst_addr);
    info.size_bytes = pkthdr->len;

    // Step 4: check protocol number
    // 6 = TCP, 17 = UDP — these are standard numbers defined in the IP spec
    // this is exactly what you study in Computer Networks
    if      (ip->protocol == 6)  info.protocol = "TCP";
    else if (ip->protocol == 17) info.protocol = "UDP";
    else                         info.protocol = "OTHER";

    // Step 5: call the user's callback with this packet's info
    // userData is actually a pointer to the callback function we were given
    auto* cb = (void (*)(const PacketInfo&))userData;
    cb(info);
}

void startCapture(const std::string& filepath,
                  void (*callback)(const PacketInfo&))
{
    char errbuf[PCAP_ERRBUF_SIZE]; // libpcap writes error messages here

    // open the .pcap file for reading (not live capture — no admin needed)
    pcap_t* handle = pcap_open_offline(filepath.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Could not open file: " << errbuf << "\n";
        return;
    }

    // tell libpcap: read every packet, call pcapHandler each time
    // we pass our callback as userData so pcapHandler can forward it
    pcap_loop(handle, 0, pcapHandler, (u_char*)callback);

    pcap_close(handle);
    std::cout << "Capture complete.\n";
}