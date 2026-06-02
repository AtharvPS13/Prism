#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <cmath>

// ─────────────────────────────────────────────────────────────────────────────
// TCP Congestion State Machine
//
// Reconstructs TCP's internal congestion control state from passive packet
// observation — no kernel modification, no active probing.
//
// The four states TCP moves through during a connection:
//   SLOW_START    : cwnd grows exponentially (doubles per RTT)
//   CONG_AVOID    : cwnd grows linearly (+1 MSS per RTT)
//   FAST_RECOVERY : 3 dup ACKs detected — cwnd halved, loss recovery
//   TIMEOUT       : RTO fired — cwnd reset to 1 MSS, back to slow start
// ─────────────────────────────────────────────────────────────────────────────

enum class TCPState : uint8_t {
    UNKNOWN,        // not enough data yet to determine state
    SLOW_START,     // exponential growth
    CONG_AVOID,     // linear growth
    FAST_RECOVERY,  // loss recovery (3 dup ACKs)
    TIMEOUT,        // severe loss (RTO timeout)
};

// human-readable label for each state
std::string tcpStateLabel(TCPState s);

// hex color for dashboard badge
std::string tcpStateColor(TCPState s);

// ─── one point in the sawtooth chart ─────────────────────────────────────────

struct CwndPoint {
    double   t;               // relative timestamp (seconds from flow start)
    double   bytes_in_flight; // estimated congestion window (bytes)
    TCPState state;           // TCP state at this moment
};

// ─── per-flow state machine ───────────────────────────────────────────────────

struct TCPFlowState {
    TCPState state          = TCPState::UNKNOWN;
    std::string sender_ip;  // which IP is the TCP sender (client side)

    // ── sequence number tracking (forward direction: sender → receiver) ──
    uint32_t snd_nxt        = 0;    // highest seq+payload seen going forward
    bool     snd_initialized = false;

    // ── ACK tracking (backward direction: receiver → sender) ────────────
    uint32_t snd_una        = 0;    // highest ACK number seen (unacknowledged up to here)
    uint32_t prev_ack       = 0;    // previous ACK value (for dup ACK detection)
    int      dup_ack_count  = 0;    // consecutive duplicate ACKs seen

    // ── congestion window estimate ───────────────────────────────────────
    double   bytes_in_flight = 0.0; // estimated cwnd = snd_nxt - snd_una
    double   ssthresh        = 65535.0; // slow start threshold

    // ── event counters ───────────────────────────────────────────────────
    int      retransmissions  = 0;
    int      fast_recoveries  = 0;
    int      timeouts_count   = 0;

    // ── timing ───────────────────────────────────────────────────────────
    double   flow_start_time  = 0.0; // timestamp of first packet (for relative t)
    double   last_packet_time = 0.0;
    double   state_entry_time = 0.0;

    // ── time spent in each state (seconds) ───────────────────────────────
    double   time_slow_start    = 0.0;
    double   time_cong_avoid    = 0.0;
    double   time_fast_recovery = 0.0;

    // ── sawtooth chart data (capped at MAX_HISTORY points) ───────────────
    std::vector<CwndPoint> history;
};

// ─── tracker class ────────────────────────────────────────────────────────────

class TCPStateTracker {
public:
    // Call this for every TCP packet from onPacket().
    // src_ip/dst_ip are the ORIGINAL packet direction (not normalized).
    void update(
        const std::string& flow_key,  // normalized key (same as FlowTracker)
        const std::string& src_ip,    // who sent this packet
        uint32_t           seq_num,
        uint32_t           ack_num,
        bool               is_syn,
        bool               is_ack,
        int                size_bytes, // total packet size
        double             timestamp
    );

    // get state for one flow (returns nullptr if not found)
    const TCPFlowState* getState(const std::string& flow_key) const;

    // get all states (for JSON emitter)
    const std::unordered_map<std::string, TCPFlowState>& getAllStates() const;

    // print terminal summary
    void printSummary() const;

private:
    std::unordered_map<std::string, TCPFlowState> states;

    // transition to a new state, updating time-in-state accounting
    void transitionTo(TCPFlowState& fs, TCPState next, double timestamp);

    // add a point to the sawtooth history if bytes_in_flight changed enough
    void recordHistory(TCPFlowState& fs, double timestamp);

    // safe sequence number arithmetic — handles 32-bit wrap-around
    // returns positive if 'newer' is ahead of 'older' (modulo 2^32)
    static int32_t seqDiff(uint32_t newer, uint32_t older) {
        return static_cast<int32_t>(newer - older);
    }

    // ── tuning constants ──────────────────────────────────────────────────
    static constexpr int    DUP_ACK_THRESHOLD  = 3;    // dup ACKs before fast recovery
    static constexpr double RTO_TIMEOUT_S      = 3.0;  // seconds gap = timeout
    static constexpr double RTO_MAX_GAP_S      = 30.0; // ignore gaps > 30s (sparse pcap)
    static constexpr int    MAX_HISTORY        = 80;   // max sawtooth chart points
    static constexpr double MIN_BIF_CHANGE     = 512.0; // min bytes change to record
    static constexpr double MSS                = 1460.0; // max segment size
    static constexpr int    IP_TCP_HEADER_SIZE = 40;   // rough header overhead
};