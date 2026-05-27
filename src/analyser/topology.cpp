#include "topology.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <vector>  

int TopologyInferrer::guessInitialTTL(int observed_ttl) {
    // standard initial TTL values used by operating systems
    // we pick whichever standard value is closest to but >= observed
    // because TTL can only decrease, never increase
    const int standards[] = {32, 64, 128, 255};

    for (int s : standards) {
        if (observed_ttl <= s) return s;
    }
    return 255;
}

std::string TopologyInferrer::guessOS(int initial_ttl) {
    switch (initial_ttl) {
        case 32:  return "Windows (old)";
        case 64:  return "Linux / Android / macOS";
        case 128: return "Windows";
        case 255: return "Router / Network device";
        default:  return "Unknown";
    }
}

std::string TopologyInferrer::guessProximity(int hops) {
    if (hops <= 1)  return "Same subnet";
    if (hops <= 3)  return "Local network (LAN)";
    if (hops <= 8)  return "Regional (ISP level)";
    if (hops <= 15) return "Internet (same country)";
    return "Internet (international)";
}

void TopologyInferrer::observePacket(const std::string& src_ip, int ttl) {
    if (ttl <= 0 || ttl > 255) return;

    HostInfo& host = hosts[src_ip];
    host.ip = src_ip;
    host.packet_count++;

    // use the minimum TTL observed for this host
    // minimum TTL = packet that took the longest path = most accurate hop count
    // we only update if this is the first packet or TTL is lower than before
    if (host.observed_ttl == 0 || ttl < host.observed_ttl) {
        host.observed_ttl = ttl;
        host.initial_ttl  = guessInitialTTL(ttl);
        host.hops         = host.initial_ttl - ttl;
        host.os_guess     = guessOS(host.initial_ttl);
        host.proximity    = guessProximity(host.hops);
    }
}

const std::unordered_map<std::string, HostInfo>&
TopologyInferrer::getHosts() const {
    return hosts;
}

void TopologyInferrer::printTopology() const {
    std::cout << "\n========== NETWORK TOPOLOGY ==========\n";
    std::cout << std::left
              << std::setw(20) << "Host IP"
              << std::setw(8)  << "TTL"
              << std::setw(8)  << "Hops"
              << std::setw(26) << "OS guess"
              << std::setw(28) << "Proximity"
              << "Packets\n";
    std::cout << std::string(100, '-') << "\n";

    // sort by hops so closest devices appear first
    std::vector<const HostInfo*> sorted;
    for (const auto& [ip, host] : hosts)
        sorted.push_back(&host);

    std::sort(sorted.begin(), sorted.end(),
        [](const HostInfo* a, const HostInfo* b) {
            return a->hops < b->hops;
        });

    for (const HostInfo* host : sorted) {
        std::cout << std::left
                  << std::setw(20) << host->ip
                  << std::setw(8)  << host->observed_ttl
                  << std::setw(8)  << host->hops
                  << std::setw(26) << host->os_guess
                  << std::setw(28) << host->proximity
                  << host->packet_count << "\n";
    }
    std::cout << "=======================================\n";
}