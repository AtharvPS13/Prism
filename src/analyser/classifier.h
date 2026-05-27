#pragma once
#include <string>
#include <vector>
#include "flow_tracker.h"

// traffic type labels
enum class TrafficType {
    STREAMING,
    BROWSING,
    FILE_TRANSFER,
    GAMING,
    VOIP,
    UNKNOWN
};

// classification result for one flow
struct ClassificationResult {
    TrafficType type;
    std::string label;       // human readable e.g. "STREAMING"
    std::string reason;      // why we classified it this way
    double      confidence;  // 0.0 to 1.0
};

// extended flow stats we track for classification
// these go on top of what FlowTracker already tracks
struct FlowProfile {
    // packet size tracking
    double avg_packet_size    = 0.0;
    double min_packet_size    = 9999.0;
    double max_packet_size    = 0.0;

    // direction tracking
    // "forward" = src_ip → dst_ip (client to server)
    // "backward" = dst_ip → src_ip (server to client)
    long   forward_bytes      = 0;
    long   backward_bytes     = 0;
    int    forward_packets    = 0;
    int    backward_packets   = 0;

    // inter-arrival time tracking (time between packets in ms)
    double avg_iat            = 0.0;  // inter-arrival time
    double last_packet_time   = 0.0;
    int    iat_samples        = 0;

    // small packet ratio (packets under 100 bytes / total packets)
    int    small_packet_count = 0;
};

class TrafficClassifier {
public:
    // update profile for a flow with a new packet
    void updateProfile(
        const std::string& flow_key,
        const std::string& src_ip,
        const std::string& flow_src_ip, // original src of this flow
        int    size_bytes,
        double timestamp
    );

    // classify a flow based on its profile
    ClassificationResult classify(const std::string& flow_key) const;

    // classify all flows and return results
    std::vector<std::pair<std::string, ClassificationResult>> classifyAll() const;

    // print classification summary to terminal
    void printClassifications() const;

    // get profile for a specific flow (for JSON emitter)
    const FlowProfile* getProfile(const std::string& key) const;

private:
    std::unordered_map<std::string, FlowProfile> profiles;
};