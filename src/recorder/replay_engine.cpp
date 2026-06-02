#include "replay_engine.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstring>

bool ReplayEngine::loadFile(const std::string& path) {
    filepath = path;
    events.clear();

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Cannot open file: " << path << "\n";
        return false;
    }

    // read header: number of events
    uint64_t count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(uint64_t));

    if (count == 0 || count > 1000000) {
        std::cerr << "Invalid event count in file: " << count << "\n";
        return false;
    }

    // read all events
    events.resize(count);
    f.read(reinterpret_cast<char*>(events.data()),
           count * sizeof(NetworkEvent));

    if (!f) {
        std::cerr << "File read failed — truncated?\n";
        return false;
    }

    f.close();
    std::cout << "Loaded " << count << " events from " << path << "\n";
    return true;
}

std::string ReplayEngine::eventLabel(uint8_t type) {
    switch (type) {
        case EV_RTT:           return "RTT";
        case EV_FAIRNESS:      return "FAIRNESS";
        case EV_BUFFERBLOAT:   return "BUFFERBLOAT";
        case EV_HOG_DETECTED:  return "HOG";
        case EV_ANOMALY_START: return "ANOMALY_START";
        default:               return "UNKNOWN";
    }
}

void ReplayEngine::printSummary() const {
    if (events.empty()) {
        std::cout << "No events loaded.\n";
        return;
    }

    std::cout << "\n========== ANOMALY FILE SUMMARY ==========\n";
    std::cout << "File:         " << filepath << "\n";
    std::cout << "Events:       " << events.size() << "\n";

    // count event types
    int rtt_count = 0, fair_count = 0,
        bloat_count = 0, hog_count = 0, anomaly_count = 0;

    double min_rtt = 99999, max_rtt = 0;
    double min_fair = 1.0,  max_fair = 0.0;

    for (const auto& e : events) {
        switch (e.event_type) {
            case EV_RTT:
                rtt_count++;
                if (e.metric < min_rtt) min_rtt = e.metric;
                if (e.metric > max_rtt) max_rtt = e.metric;
                break;
            case EV_FAIRNESS:
                fair_count++;
                if (e.metric < min_fair) min_fair = e.metric;
                if (e.metric > max_fair) max_fair = e.metric;
                break;
            case EV_BUFFERBLOAT:   bloat_count++;   break;
            case EV_HOG_DETECTED:  hog_count++;     break;
            case EV_ANOMALY_START: anomaly_count++; break;
        }
    }

    double duration = events.back().timestamp - events.front().timestamp;

    std::cout << "Duration:     " << std::fixed << std::setprecision(1)
              << duration << " seconds\n";
    std::cout << "RTT events:   " << rtt_count
              << " (min: " << (int)min_rtt
              << "ms, max: " << (int)max_rtt << "ms)\n";
    std::cout << "Fairness:     " << fair_count
              << " snapshots (min: " << std::setprecision(3) << min_fair
              << ", max: " << max_fair << ")\n";
    std::cout << "Bufferbloat:  " << bloat_count << " events\n";
    std::cout << "Hog events:   " << hog_count << "\n";
    std::cout << "Anomaly markers: " << anomaly_count << "\n";
    std::cout << "==========================================\n";
}

void ReplayEngine::replay(double speed, ReplayCallback callback) {
    if (events.empty()) {
        std::cout << "No events to replay.\n";
        return;
    }

    std::cout << "\n[REPLAY] Starting at " << speed << "x speed...\n";
    std::cout << "[REPLAY] " << events.size()
              << " events — press Ctrl+C to stop\n\n";

    // track running state across events
    double   current_fairness  = 1.0;
    double   current_rtt       = 0.0;
    double   current_hog       = 0.0;
    bool     current_bloat     = false;
    bool     anomaly_active    = false;
    std::string current_flow   = "";

    for (size_t i = 0; i < events.size(); i++) {
        const NetworkEvent& e = events[i];

        // update running state based on event type
        switch (e.event_type) {
            case EV_RTT:
                current_rtt  = e.metric;
                current_flow = std::string(e.flow_key, 13);
                // trim null bytes from flow key
                current_flow = current_flow.substr(
                    0, current_flow.find('\0'));
                break;
            case EV_FAIRNESS:
                current_fairness = e.metric;
                break;
            case EV_BUFFERBLOAT:
                current_bloat = true;
                break;
            case EV_HOG_DETECTED:
                current_hog = e.metric;
                break;
            case EV_ANOMALY_START:
                anomaly_active = true;
                std::cout << "[REPLAY] *** ANOMALY WINDOW ***\n";
                break;
        }

        // build replay state for this moment
        ReplayState state;
        state.timestamp      = e.timestamp;
        state.fairness_index = current_fairness;
        state.rtt_ms         = current_rtt;
        state.hog_percent    = current_hog;
        state.bufferbloat    = current_bloat;
        state.anomaly_active = anomaly_active;
        state.total_events   = (int)(i + 1);
        state.total_in_file  = (int)events.size();
        state.flow_key       = current_flow;
        state.event_label    = eventLabel(e.event_type);

        // call the callback — this updates the HTTP snapshot
        callback(state);

        // print progress every 10 events
        if (i % 10 == 0) {
            std::cout << "\r[REPLAY] " << (i+1) << "/" << events.size()
                      << "  RTT: " << std::setw(6) << (int)current_rtt
                      << "ms  Fairness: " << std::fixed
                      << std::setprecision(3) << current_fairness
                      << "  " << (anomaly_active ? "⚠ ANOMALY" : "normal")
                      << "      " << std::flush;
        }

        // wait before next event based on speed
        if (i + 1 < events.size()) {
            double dt = events[i+1].timestamp - events[i].timestamp;

            // clamp dt — ignore gaps larger than 5 seconds
            // (these happen between unrelated packets in a pcap)
            if (dt > 0 && dt < 5.0) {
                // dt / speed = how long to actually wait
                // speed=0.1 → wait 10x longer (slow motion)
                // speed=10  → wait 10x shorter (fast forward)
                auto wait_us = (uint64_t)(dt / speed * 1e6);
                std::this_thread::sleep_for(
                    std::chrono::microseconds(wait_us));
            }
        }
    }

    std::cout << "\n[REPLAY] Complete. "
              << events.size() << " events replayed.\n";
}