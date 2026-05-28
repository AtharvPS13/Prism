#include "event_recorder.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

EventRecorder::EventRecorder() {}

// truncate flow key to fit in 13 bytes
// we take last 12 chars (most unique part = port numbers) + null
void EventRecorder::packFlowKey(const std::string& key, char* dst) {
    memset(dst, 0, 13);
    if (key.size() <= 12) {
        strncpy(dst, key.c_str(), 12);
    } else {
        // take the last 12 chars — contains port numbers
        // which uniquely identify the flow
        strncpy(dst, key.c_str() + key.size() - 12, 12);
    }
}

void EventRecorder::record(
    const std::string&    flow_key,
    const FlowStats&      flow,
    const FairnessReport& fairness,
    double                timestamp)
{
    // --- record RTT event ---
    if (flow.rtt_samples > 0) {
        NetworkEvent e;
        e.timestamp  = timestamp;
        e.event_type = EV_RTT;
        e.metric     = flow.avg_rtt;
        packFlowKey(flow_key, e.flow_key);
        buffer.write(e);

        // update baseline RTT for this flow
        // baseline = slow moving average (only update every 10 samples)
        if (baseline_rtt.find(flow_key) == baseline_rtt.end()) {
            baseline_rtt[flow_key] = flow.avg_rtt;
        } else if (flow.rtt_samples % 10 == 0) {
            // slowly update baseline so we don't chase spikes
            baseline_rtt[flow_key] = baseline_rtt[flow_key] * 0.9
                                   + flow.avg_rtt * 0.1;
        }
    }

    // --- record fairness event ---
    {
        NetworkEvent e;
        e.timestamp  = timestamp;
        e.event_type = EV_FAIRNESS;
        e.metric     = fairness.index;
        memset(e.flow_key, 0, 13);
        strncpy(e.flow_key, "fairness", 8);
        buffer.write(e);
    }

    // --- record bufferbloat event if detected ---
    if (flow.bufferbloat) {
        NetworkEvent e;
        e.timestamp  = timestamp;
        e.event_type = EV_BUFFERBLOAT;
        e.metric     = flow.avg_rtt;
        packFlowKey(flow_key, e.flow_key);
        buffer.write(e);
    }

    // --- record hog event if this flow is the hog ---
    if (flow_key == fairness.worst_hog && fairness.hog_percent > 60.0) {
        NetworkEvent e;
        e.timestamp  = timestamp;
        e.event_type = EV_HOG_DETECTED;
        e.metric     = fairness.hog_percent;
        packFlowKey(flow_key, e.flow_key);
        buffer.write(e);
    }

    // --- anomaly detection ---
    bool anomaly = false;
    std::string reason;

    // check 1: RTT spike — current RTT > 5x baseline
    if (flow.rtt_samples > 0 &&
        baseline_rtt.count(flow_key) &&
        baseline_rtt[flow_key] > 0)
    {
        double spike_ratio = flow.avg_rtt / baseline_rtt[flow_key];
        if (spike_ratio > RTT_SPIKE_MULTIPLIER) {
            anomaly = true;
            reason  = "RTT spike: " + std::to_string((int)flow.avg_rtt)
                    + "ms (baseline: "
                    + std::to_string((int)baseline_rtt[flow_key]) + "ms)";
        }
    }

    // check 2: fairness dropped below threshold
    if (fairness.index < FAIRNESS_THRESHOLD && fairness.total_flows > 1) {
        anomaly = true;
        reason  = "Fairness dropped to "
                + std::to_string(fairness.index).substr(0,5);
    }

    // check 3: bufferbloat detected
    if (flow.bufferbloat) {
        anomaly = true;
        reason  = "Bufferbloat on flow " + flow_key;
    }

    // --- save anomaly if detected and cooldown has passed ---
    if (anomaly && (timestamp - last_anomaly_time) > ANOMALY_COOLDOWN) {
        // write anomaly start marker into buffer first
        NetworkEvent marker;
        marker.timestamp  = timestamp;
        marker.event_type = EV_ANOMALY_START;
        marker.metric     = 0.0;
        memset(marker.flow_key, 0, 13);
        buffer.write(marker);

        std::cout << "\n[ANOMALY DETECTED] " << reason
                  << " — saving last 60s to disk...\n";

        saveAnomaly(timestamp);
        last_anomaly_time = timestamp;
    }
}

void EventRecorder::saveAnomaly(double timestamp) {
    // build filename: anomaly_2026_05_27_14_32_05.bin
    std::time_t t = (std::time_t)timestamp;
    std::tm*    tm_info = std::localtime(&t);
    std::ostringstream fname;
    fname << "anomaly_"
          << std::put_time(tm_info, "%Y_%m_%d_%H_%M_%S")
          << ".bin";

    // grab last 60 seconds of events from ring buffer
    auto* buf = new NetworkEvent[EVENTS_PER_60S];
    uint64_t count = buffer.getLastN(buf, EVENTS_PER_60S);

    // write to binary file
    // format: [uint64_t count][NetworkEvent × count]
    std::ofstream f(fname.str(), std::ios::binary);
    if (!f) {
        std::cerr << "Failed to open " << fname.str() << " for writing\n";
        delete[] buf;
        return;
    }

    // write header: how many events follow
    f.write(reinterpret_cast<char*>(&count), sizeof(uint64_t));

    // write all events as raw binary
    f.write(reinterpret_cast<char*>(buf), count * sizeof(NetworkEvent));
    f.close();

    delete[] buf;
    anomaly_count++;

    std::cout << "[SAVED] " << fname.str()
              << " (" << count << " events, "
              << (count * sizeof(NetworkEvent) / 1024) << " KB)\n";
}