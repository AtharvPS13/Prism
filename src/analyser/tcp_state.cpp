#include "tcp_state.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>

// ─── label + color helpers ────────────────────────────────────────────────────

std::string tcpStateLabel(TCPState s) {
    switch (s) {
        case TCPState::SLOW_START:    return "SLOW_START";
        case TCPState::CONG_AVOID:    return "CONG_AVOID";
        case TCPState::FAST_RECOVERY: return "FAST_RECOVERY";
        case TCPState::TIMEOUT:       return "TIMEOUT";
        default:                      return "UNKNOWN";
    }
}

std::string tcpStateColor(TCPState s) {
    switch (s) {
        case TCPState::SLOW_START:    return "#10B981"; // green
        case TCPState::CONG_AVOID:    return "#3B82F6"; // blue
        case TCPState::FAST_RECOVERY: return "#EF4444"; // red
        case TCPState::TIMEOUT:       return "#6B7280"; // gray
        default:                      return "#4E6380";
    }
}

// ─── private helpers ──────────────────────────────────────────────────────────

void TCPStateTracker::transitionTo(
    TCPFlowState& fs, TCPState next, double timestamp)
{
    if (fs.state == next) return;

    // accumulate time spent in the current state before leaving it
    if (fs.state_entry_time > 0.0 && timestamp > fs.state_entry_time) {
        double dur = timestamp - fs.state_entry_time;
        switch (fs.state) {
            case TCPState::SLOW_START:    fs.time_slow_start    += dur; break;
            case TCPState::CONG_AVOID:    fs.time_cong_avoid    += dur; break;
            case TCPState::FAST_RECOVERY: fs.time_fast_recovery += dur; break;
            default: break;
        }
    }

    fs.state            = next;
    fs.state_entry_time = timestamp;
}

void TCPStateTracker::recordHistory(TCPFlowState& fs, double timestamp)
{
    // relative time from first packet — keeps chart scale readable
    double rel_t = timestamp - fs.flow_start_time;

    if (!fs.history.empty()) {
        const CwndPoint& last = fs.history.back();
        double bif_delta = std::abs(fs.bytes_in_flight - last.bytes_in_flight);
        // only record if bytes_in_flight changed enough OR state changed
        if (bif_delta < MIN_BIF_CHANGE && fs.state == last.state) return;
    }

    // cap history — erase oldest point (O(n) but fine for 80 elements)
    if ((int)fs.history.size() >= MAX_HISTORY) {
        fs.history.erase(fs.history.begin());
    }

    fs.history.push_back({ rel_t, fs.bytes_in_flight, fs.state });
}

// ─── main update function ─────────────────────────────────────────────────────

void TCPStateTracker::update(
    const std::string& flow_key,
    const std::string& src_ip,
    uint32_t           seq_num,
    uint32_t           ack_num,
    bool               is_syn,
    bool               is_ack,
    int                size_bytes,
    double             timestamp)
{
    TCPFlowState& fs = states[flow_key];

    // ── first packet for this flow ────────────────────────────────────────
    if (fs.flow_start_time == 0.0) {
        fs.flow_start_time  = timestamp;
        fs.state_entry_time = timestamp;
        fs.last_packet_time = timestamp;
    }

    // ── establish sender_ip from the first SYN (most reliable) ───────────
    // SYN without ACK = opening a new connection = this src is the client/sender
    if (is_syn && !is_ack && fs.sender_ip.empty()) {
        fs.sender_ip = src_ip;
        transitionTo(fs, TCPState::SLOW_START, timestamp);
    }

    // fallback: if no SYN captured, treat first packet's src as sender
    if (fs.sender_ip.empty()) {
        fs.sender_ip = src_ip;
        transitionTo(fs, TCPState::SLOW_START, timestamp);
    }

    // ── timeout detection ─────────────────────────────────────────────────
    // if a long gap occurs between packets, the RTO likely fired
    if (fs.last_packet_time > 0.0 && fs.state != TCPState::UNKNOWN) {
        double gap = timestamp - fs.last_packet_time;
        // RTO_MAX_GAP_S: ignore long gaps from sparse pcap files
        if (gap > RTO_TIMEOUT_S && gap < RTO_MAX_GAP_S) {
            fs.ssthresh        = std::max(fs.bytes_in_flight / 2.0, 2.0 * MSS);
            fs.bytes_in_flight = MSS;   // cwnd reset to 1 MSS on timeout
            transitionTo(fs, TCPState::SLOW_START, timestamp);
            fs.timeouts_count++;
            fs.dup_ack_count = 0;
            recordHistory(fs, timestamp);
        }
    }
    fs.last_packet_time = timestamp;

    // ── direction ─────────────────────────────────────────────────────────
    bool is_forward = (src_ip == fs.sender_ip);

    // approximate payload size — subtract IP+TCP header overhead
    // this gives a rough estimate; not perfect but good enough for cwnd inference
    int payload = size_bytes - IP_TCP_HEADER_SIZE;
    if (payload < 0) payload = 0;

    // ── FORWARD direction: data packets (sender → receiver) ──────────────
    if (is_forward && payload > 0) {

        uint32_t pkt_end = seq_num + static_cast<uint32_t>(payload);

        if (!fs.snd_initialized) {
            // first data packet — initialize snd_nxt
            fs.snd_nxt        = pkt_end;
            fs.snd_initialized = true;

        } else if (seqDiff(pkt_end, fs.snd_nxt) > 0) {
            // new data — advance the send window
            fs.snd_nxt = pkt_end;

        } else if (payload > 0) {
            // seq_num is behind snd_nxt — this is a retransmission
            fs.retransmissions++;
        }

        // update bytes-in-flight estimate whenever snd_una is known
        if (fs.snd_initialized && fs.snd_una > 0) {
            int32_t bif = seqDiff(fs.snd_nxt, fs.snd_una);
            fs.bytes_in_flight = (bif > 0) ? static_cast<double>(bif) : 0.0;
        }
    }

    // ── BACKWARD direction: ACK packets (receiver → sender) ──────────────
    else if (!is_forward && is_ack && !is_syn) {

        if (ack_num == fs.prev_ack && fs.prev_ack > 0) {
            // ── duplicate ACK ─────────────────────────────────────────────
            fs.dup_ack_count++;

            if (fs.dup_ack_count == DUP_ACK_THRESHOLD) {
                // 3 dup ACKs = TCP infers packet loss without waiting for RTO
                // halve ssthresh, enter fast recovery
                fs.ssthresh = std::max(fs.bytes_in_flight / 2.0, 2.0 * MSS);
                transitionTo(fs, TCPState::FAST_RECOVERY, timestamp);
                fs.fast_recoveries++;
                recordHistory(fs, timestamp);
            }

        } else if (seqDiff(ack_num, fs.snd_una) > 0 || fs.snd_una == 0) {
            // ── new ACK: receiver confirmed new data ──────────────────────

            // exit fast recovery on the first new ACK (all holes filled)
            if (fs.state == TCPState::FAST_RECOVERY) {
                // cwnd set to ssthresh after fast recovery (RFC 5681)
                fs.bytes_in_flight = fs.ssthresh;
                transitionTo(fs, TCPState::CONG_AVOID, timestamp);
            }

            fs.dup_ack_count = 0;
            fs.prev_ack      = ack_num;
            fs.snd_una       = ack_num;

            // recompute bytes in flight with updated snd_una
            if (fs.snd_initialized) {
                int32_t bif = seqDiff(fs.snd_nxt, fs.snd_una);
                fs.bytes_in_flight = (bif > 0) ? static_cast<double>(bif) : 0.0;
            }

            // slow start → congestion avoidance transition
            // happens when cwnd reaches or exceeds ssthresh
            if (fs.state == TCPState::SLOW_START &&
                fs.bytes_in_flight >= fs.ssthresh)
            {
                transitionTo(fs, TCPState::CONG_AVOID, timestamp);
            }
        }
    }

    // ── record sawtooth history for chart ─────────────────────────────────
    if (fs.state != TCPState::UNKNOWN) {
        recordHistory(fs, timestamp);
    }
}

// ─── accessors ────────────────────────────────────────────────────────────────

const TCPFlowState* TCPStateTracker::getState(const std::string& key) const {
    auto it = states.find(key);
    return (it != states.end()) ? &it->second : nullptr;
}

const std::unordered_map<std::string, TCPFlowState>&
TCPStateTracker::getAllStates() const {
    return states;
}

// ─── terminal summary ─────────────────────────────────────────────────────────

void TCPStateTracker::printSummary() const {
    std::cout << "\n========== TCP CONGESTION STATE MACHINE ==========\n";
    std::cout << std::left
              << std::setw(42) << "Flow"
              << std::setw(16) << "State"
              << std::setw(12) << "BIF (KB)"
              << std::setw(8)  << "Retr"
              << std::setw(8)  << "FRec"
              << "Timeouts\n";
    std::cout << std::string(95, '-') << "\n";

    for (const auto& [key, fs] : states) {
        if (fs.state == TCPState::UNKNOWN) continue;
        std::cout << std::left
                  << std::setw(42) << key.substr(0, 41)
                  << std::setw(16) << tcpStateLabel(fs.state)
                  << std::setw(12) << std::fixed << std::setprecision(1)
                                   << fs.bytes_in_flight / 1024.0
                  << std::setw(8)  << fs.retransmissions
                  << std::setw(8)  << fs.fast_recoveries
                  << fs.timeouts_count << "\n";
    }
    std::cout << "==================================================\n";
}