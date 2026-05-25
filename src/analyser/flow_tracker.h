#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>    // add this line — defines uint32_t

// one entry per packet timestamp we're waiting to match with an ACK
struct PendingPacket {
    uint32_t seq_num;       // sequence number we sent
    double   timestamp;     // when we sent it (in seconds)
};

// all stats we track for one flow (one TCP connection)
struct FlowStats {
    std::string src_ip;
    std::string dst_ip;
    int         src_port;
    int         dst_port;
    long        total_bytes    = 0;   // total data transferred
    int         packet_count   = 0;   // how many packets seen
    double      avg_rtt        = 0.0; // running average RTT in ms
    double      max_rtt        = 0.0; // worst RTT seen
    bool        bufferbloat    = false; // did we detect bufferbloat?
    int         rtt_samples    = 0;   // how many RTT measurements taken

    // packets we sent but haven't seen ACK for yet
    std::vector<PendingPacket> pending;
};

class FlowTracker {
public:
    // call this for every packet — updates flow stats
    void processPacket(
        const std::string& src_ip,
        const std::string& dst_ip,
        int src_port,
        int dst_port,
        int protocol,
        uint32_t seq_num,
        uint32_t ack_num,
        bool is_syn,
        bool is_ack,
        int size_bytes,
        double timestamp
    );

    // returns all flows seen so far
    const std::unordered_map<std::string, FlowStats>& getFlows() const;

    // print a summary of all flows to terminal
    void printSummary() const;

private:
    std::unordered_map<std::string, FlowStats> flows;

    // build a unique key for this flow from its 5-tuple
    std::string makeFlowKey(const std::string& src_ip,
                            const std::string& dst_ip,
                            int src_port, int dst_port);
};