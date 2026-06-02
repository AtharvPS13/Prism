#include "packet_capture.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>

static void pcapHandler(u_char* userData,
                        const struct pcap_pkthdr* pkthdr,
                        const u_char* packet)
{
    const int ETHERNET_HEADER_SIZE = 14;
    if (pkthdr->len < ETHERNET_HEADER_SIZE) return;

    const struct iphdr* ip =
        (struct iphdr*)(packet + ETHERNET_HEADER_SIZE);

    PacketInfo info;

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->saddr;
    dst_addr.s_addr = ip->daddr;
    info.src_ip     = inet_ntoa(src_addr);
    info.dst_ip     = inet_ntoa(dst_addr);
    info.size_bytes = pkthdr->len;
    info.ttl        = ip->ttl;
    info.timestamp  = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1e6;

    int ip_header_len = ip->ihl * 4;

    if (ip->protocol == 6) {
        info.protocol = "TCP";
        const struct tcphdr* tcp =
            (struct tcphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
        info.src_port = ntohs(tcp->source);
        info.dst_port = ntohs(tcp->dest);
        info.seq_num  = ntohl(tcp->seq);
        info.ack_num  = ntohl(tcp->ack_seq);
        info.is_syn   = tcp->syn;
        info.is_ack   = tcp->ack;
    } else if (ip->protocol == 17) {
        info.protocol = "UDP";
        const struct udphdr* udp =
            (struct udphdr*)(packet + ETHERNET_HEADER_SIZE + ip_header_len);
        info.src_port = ntohs(udp->source);
        info.dst_port = ntohs(udp->dest);
    } else {
        info.protocol = "OTHER";
    }

    auto* cb = (void (*)(const PacketInfo&))userData;
    cb(info);
}

void startCapture(const std::string& filepath,
                  void (*callback)(const PacketInfo&))
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filepath.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Could not open file: " << errbuf << "\n";
        return;
    }
    pcap_loop(handle, 0, pcapHandler, (u_char*)callback);
    pcap_close(handle);
    std::cout << "Capture complete.\n";
}

void startLiveCapture(const std::string& interface,
                      void (*callback)(const PacketInfo&))
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(
        interface.c_str(),
        65535,
        1,
        1000,
        errbuf
    );

    if (!handle) {
        std::cerr << "Cannot open interface " << interface
                  << ": " << errbuf << "\n";
        std::cerr << "Try running with: sudo ./build/network_monitor "
                  << "--live " << interface << "\n";
        return;
    }

    std::cout << "Capturing live on " << interface << "...\n";
    pcap_loop(handle, 0, pcapHandler, (u_char*)callback);
    pcap_close(handle);
}