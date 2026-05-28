#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>

// one event stored in the ring buffer
// exactly 30 bytes — fixed size is critical for the binary file format
// fixed size means: position of event N = N * 30 bytes from file start
// no dynamic allocation, no pointers, pure value type
#pragma pack(push, 1)   // tell compiler: no padding between fields
struct NetworkEvent {
    double   timestamp;    // 8 bytes — when this event happened (seconds)
    uint8_t  event_type;   // 1 byte  — what kind of event (see EventType below)
    char     flow_key[13]; // 13 bytes — which flow this belongs to (truncated)
    double   metric;       // 8 bytes  — the value (RTT in ms, fairness score, etc)
};                         // total: 8+1+13+8 = 30 bytes exactly
#pragma pack(pop)

// event types — each maps to a different anomaly or measurement
enum EventType : uint8_t {
    EV_RTT          = 1,   // RTT measurement for a flow
    EV_FAIRNESS     = 2,   // Jain fairness index snapshot
    EV_BUFFERBLOAT  = 3,   // bufferbloat detected on a flow
    EV_HOG_DETECTED = 4,   // bandwidth hog identified
    EV_ANOMALY_START= 5,   // anomaly threshold crossed — trigger save
};

// how many events we keep in memory at once
// 200000 events × 30 bytes = 6MB RAM
constexpr uint64_t RING_BUFFER_SIZE = 200000;

class RingBuffer {
public:
    RingBuffer();

    // called by capture thread — writes one event
    // never blocks — if full, overwrites oldest event
    void write(const NetworkEvent& event);

    // called by analyser thread — reads one event
    // returns false if nothing to read
    bool read(NetworkEvent& out);

    // how many unread events are currently in the buffer
    uint64_t available() const;

    // copy the last N events into dst array (for anomaly dump)
    // returns how many events were actually copied
    uint64_t getLastN(NetworkEvent* dst, uint64_t n) const;

    // total events written since start (never resets)
    uint64_t totalWritten() const;

private:
    // the actual circular array — 6MB on the stack would overflow
    // so we heap-allocate it once in the constructor
    NetworkEvent* slots;

    // two atomic integers — this is the ENTIRE thread-safety mechanism
    // write_head: how many events have been written total
    // read_head:  how many events have been consumed total
    // both only ever increase — we use modulo to find actual slot
    std::atomic<uint64_t> write_head;
    std::atomic<uint64_t> read_head;
};