#include "flow_tracker.h"
#include <iostream>
#include <iomanip>
#include <cmath>

// builds a unique string key for a flow from its 5-tuple
// we sort src and dst so that A->B and B->A map to the same flow
// because both directions are part of the same TCP connection
std::string FlowTracker::makeFlowKey(const std::string& src_ip,
                                      const std::string& dst_ip,
                                      int src_port, int dst_port)
{
    // always put the lexicographically smaller IP first
    // so "192.168.1.1:80 <-> 10.0.0.1:5000" and
    //    "10.0.0.1:5000 <-> 192.168.1.1:80" get the same key
    if (src_ip < dst_ip)
        return src_ip + ":" + std::to_string(src_port) +
               "<->" + dst_ip + ":" + std::to_string(dst_port);
    else
        return dst_ip + ":" + std::to_string(dst_port) +
               "<->" + src_ip + ":" + std::to_string(src_port);
}

void FlowTracker::processPacket(
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
    double timestamp)
{
    // Step 1: find or create the flow entry for this packet
    std::string key = makeFlowKey(src_ip, dst_ip, src_port, dst_port);
    FlowStats& flow = flows[key]; // creates new entry if key doesn't exist

    // Step 2: initialise flow info on first packet
    if (flow.packet_count == 0) {
        flow.src_ip   = src_ip;
        flow.dst_ip   = dst_ip;
        flow.src_port = src_port;
        flow.dst_port = dst_port;
    }

    // Step 3: update basic stats
    flow.total_bytes  += size_bytes;
    flow.packet_count += 1;

    // Step 4: RTT measurement
    // when we see a SYN (new connection starting), record it as pending
    // we're waiting for the ACK that matches this sequence number
    if (is_syn && !is_ack) {
        PendingPacket p;
        p.seq_num   = seq_num;
        p.timestamp = timestamp;
        flow.pending.push_back(p);
    }

    // when we see an ACK, try to match it to a pending SYN
    // ack_num in TCP means "I received everything up to this seq number"
    // so we look for a pending packet whose seq_num matches ack_num - 1
    if (is_ack && !flow.pending.empty()) {
        for (auto it = flow.pending.begin(); it != flow.pending.end(); ++it) {
            if (it->seq_num + 1 == ack_num) {
                // found the match — calculate RTT in milliseconds
                double rtt_ms = (timestamp - it->timestamp) * 1000.0;

                // only count realistic RTT values
                // negative = clock issue, >10000ms = stale entry
                if (rtt_ms > 0 && rtt_ms < 10000) {
                    flow.rtt_samples++;

                    // running average: avg = avg + (new - avg) / count
                    // this is called Welford's online algorithm
                    // we use it because we don't store all RTT values
                    flow.avg_rtt += (rtt_ms - flow.avg_rtt) / flow.rtt_samples;

                    // track worst RTT seen
                    if (rtt_ms > flow.max_rtt)
                        flow.max_rtt = rtt_ms;

                    // bufferbloat detection:
                    // if current RTT is more than 3x the average
                    // the buffer is filling up — this is the bufferbloat signature
                    if (flow.rtt_samples > 3 && rtt_ms > 3.0 * flow.avg_rtt)
                        flow.bufferbloat = true;
                }

                // remove this pending entry — it's been matched
                flow.pending.erase(it);
                break;
            }
        }
    }
}

const std::unordered_map<std::string, FlowStats>& FlowTracker::getFlows() const
{
    return flows;
}

void FlowTracker::printSummary() const
{
    std::cout << "\n========== FLOW SUMMARY ==========\n";
    std::cout << std::left
              << std::setw(22) << "Flow"
              << std::setw(10) << "Packets"
              << std::setw(12) << "Bytes"
              << std::setw(12) << "Avg RTT"
              << std::setw(12) << "Max RTT"
              << "Bufferbloat\n";
    std::cout << std::string(80, '-') << "\n";

    for (const auto& [key, flow] : flows) {
        std::cout << std::left
                  << std::setw(22) << key
                  << std::setw(10) << flow.packet_count
                  << std::setw(12) << flow.total_bytes
                  << std::setw(12) << (flow.rtt_samples > 0
                                       ? std::to_string((int)flow.avg_rtt) + "ms"
                                       : "n/a")
                  << std::setw(12) << (flow.rtt_samples > 0
                                       ? std::to_string((int)flow.max_rtt) + "ms"
                                       : "n/a")
                  << (flow.bufferbloat ? "YES ⚠" : "no") << "\n";
    }
    std::cout << "==================================\n";
}