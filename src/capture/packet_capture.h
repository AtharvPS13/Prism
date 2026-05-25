#pragma once
#include <string>

// This is the interface for our capture module.
// The rest of the program only needs to call startCapture()
// and give it a function to call for each packet found.

struct PacketInfo {
    std::string src_ip;      // who sent this packet
    std::string dst_ip;      // who it was going to
    std::string protocol;    // TCP, UDP, or OTHER
    int size_bytes;          // total size of the packet
};

// callback = a function YOU provide that gets called for every packet
// this way the capture module doesn't need to know what you do with packets
void startCapture(const std::string& filepath,
                  void (*callback)(const PacketInfo&));