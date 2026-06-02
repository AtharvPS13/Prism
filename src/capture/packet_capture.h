#pragma once
#include <string>
#include <cstdint>

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    int         size_bytes;
    int         src_port  = 0;
    int         dst_port  = 0;
    uint32_t    seq_num   = 0;
    uint32_t    ack_num   = 0;
    bool        is_syn    = false;
    bool        is_ack    = false;
    double      timestamp = 0.0;
    int         ttl       = 0;
};

void startCapture(const std::string& filepath,
                  void (*callback)(const PacketInfo&));

void startLiveCapture(const std::string& interface,
                      void (*callback)(const PacketInfo&));