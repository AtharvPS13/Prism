#pragma once
#include <string>
#include <unordered_map>

// what we know about one remote host
struct HostInfo {
    std::string ip;
    int         observed_ttl  = 0;    // TTL value we actually saw
    int         initial_ttl   = 0;    // what it probably started at
    int         hops          = 0;    // how many routers between us
    std::string os_guess;             // Linux, Windows, macOS, Router
    std::string proximity;            // same LAN, regional, internet etc
    int         packet_count  = 0;    // how many packets seen from this host
};

class TopologyInferrer {
public:
    // call for every incoming packet (packets coming TO us)
    // src_ip = who sent it, ttl = TTL value in the IP header
    void observePacket(const std::string& src_ip, int ttl);

    // print topology summary to terminal
    void printTopology() const;

    // get all hosts (for JSON emitter)
    const std::unordered_map<std::string, HostInfo>& getHosts() const;

private:
    std::unordered_map<std::string, HostInfo> hosts;

    // guess the starting TTL based on observed TTL
    // real TTL values cluster near these standard values
    static int guessInitialTTL(int observed_ttl);

    // guess OS from initial TTL
    static std::string guessOS(int initial_ttl);

    // guess proximity from hop count
    static std::string guessProximity(int hops);
};