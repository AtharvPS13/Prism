#pragma once
#include "ring_buffer.h"
#include <string>
#include <vector>
#include <functional>

// replay state — what the dashboard sees at any point during replay
struct ReplayState {
    double   timestamp;
    double   fairness_index;
    double   rtt_ms;           // RTT of the most recent flow event
    double   hog_percent;      // bandwidth hog percentage
    bool     bufferbloat;      // is bufferbloat active right now?
    bool     anomaly_active;   // are we in the anomaly window?
    int      total_events;     // how many events replayed so far
    int      total_in_file;    // total events in the file
    std::string flow_key;      // which flow this event belongs to
    std::string event_label;   // human readable event type
};

// callback type — called for each event during replay
// the caller (main.cpp) uses this to update the HTTP snapshot
using ReplayCallback = std::function<void(const ReplayState&)>;

class ReplayEngine {
public:
    // load a .bin anomaly file
    // returns false if file can't be opened or is invalid
    bool loadFile(const std::string& filepath);

    // replay all events at given speed
    // speed = 1.0 → real time
    // speed = 0.1 → 10x slow motion
    // speed = 10.0 → 10x fast forward
    // callback is called for each event
    void replay(double speed, ReplayCallback callback);

    // how many events are in the loaded file
    int eventCount() const { return events.size(); }

    // print a summary of the file contents
    void printSummary() const;

private:
    std::vector<NetworkEvent> events;
    std::string               filepath;

    // convert event_type byte to human readable string
    static std::string eventLabel(uint8_t type);
};