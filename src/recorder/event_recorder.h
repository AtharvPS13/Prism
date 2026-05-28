#pragma once
#include "ring_buffer.h"
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include <string>
#include <unordered_map>
#include <atomic>

// how many events = 60 seconds at roughly 1000 events/sec
// conservative estimate — real networks may have more or fewer
constexpr uint64_t EVENTS_PER_60S = 60000;

// anomaly thresholds
constexpr double RTT_SPIKE_MULTIPLIER = 5.0;  // RTT > 5x average = anomaly
constexpr double FAIRNESS_THRESHOLD   = 0.6;  // below 0.6 = unfair anomaly

class EventRecorder {
public:
    EventRecorder();

    // call after every flow update
    // records RTT, fairness, bufferbloat events into ring buffer
    // automatically checks for anomalies and saves if detected
    void record(
        const std::string&     flow_key,
        const FlowStats&       flow,
        const FairnessReport&  fairness,
        double                 timestamp
    );

    // how many anomaly files have been saved so far
    int anomalyCount() const { return anomaly_count.load(); }

    // get reference to ring buffer (for replay engine)
    RingBuffer& getBuffer() { return buffer; }

private:
    RingBuffer buffer;

    // track per-flow baseline RTT for spike detection
    // key = flow_key, value = baseline RTT in ms
    std::unordered_map<std::string, double> baseline_rtt;

    // cooldown: don't save anomaly file more than once per 30 seconds
    double last_anomaly_time = 0.0;
    constexpr static double ANOMALY_COOLDOWN = 30.0;

    std::atomic<int> anomaly_count{0};

    // saves last EVENTS_PER_60S events to a binary file
    void saveAnomaly(double timestamp);

    // builds a short flow key that fits in 13 bytes
    static void packFlowKey(const std::string& key, char* dst);
};