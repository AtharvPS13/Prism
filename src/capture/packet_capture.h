#pragma once
#include <string>
#include <cstdint>

// expanded PacketInfo — now includes TCP-level details
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    int         size_bytes;
    int         src_port  = 0;
    int         dst_port  = 0;
    uint32_t    seq_num   = 0;  // TCP sequence number
    uint32_t    ack_num   = 0;  // TCP acknowledgement number
    bool        is_syn    = false; // SYN flag set?
    bool        is_ack    = false; // ACK flag set?
    double      timestamp = 0.0;   // packet arrival time in seconds
};

void startCapture(const std::string& filepath,
                  void (*callback)(const PacketInfo&));