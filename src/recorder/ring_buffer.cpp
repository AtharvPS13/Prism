#include "ring_buffer.h"
#include <algorithm>
#include <cstring>

RingBuffer::RingBuffer()
    : write_head(0), read_head(0)
{
    // heap allocate the slots array — 6MB
    // we do this once at startup and never resize
    slots = new NetworkEvent[RING_BUFFER_SIZE];
    memset(slots, 0, sizeof(NetworkEvent) * RING_BUFFER_SIZE);
}

void RingBuffer::write(const NetworkEvent& event)
{
    // Step 1: find which slot to write into
    // write_head keeps growing forever (never resets)
    // modulo maps it to 0..RING_BUFFER_SIZE-1
    uint64_t pos = write_head.load(std::memory_order_relaxed)
                   % RING_BUFFER_SIZE;

    // Step 2: write the event into that slot
    // this is safe because only the write thread touches write_head
    slots[pos] = event;

    // Step 3: increment write_head atomically
    // memory_order_release means: all writes above this line
    // are visible to other threads before they see the new write_head
    // this is the key guarantee that makes lock-free safe
    write_head.fetch_add(1, std::memory_order_release);
}

bool RingBuffer::read(NetworkEvent& out)
{
    uint64_t w = write_head.load(std::memory_order_acquire);
    uint64_t r = read_head.load(std::memory_order_relaxed);

    // nothing to read — buffer is empty
    if (r >= w) return false;

    // find which slot to read from
    uint64_t pos = r % RING_BUFFER_SIZE;
    out = slots[pos];

    // move read head forward
    read_head.fetch_add(1, std::memory_order_release);
    return true;
}

uint64_t RingBuffer::available() const
{
    uint64_t w = write_head.load(std::memory_order_acquire);
    uint64_t r = read_head.load(std::memory_order_acquire);
    return (w > r) ? (w - r) : 0;
}

uint64_t RingBuffer::getLastN(NetworkEvent* dst, uint64_t n) const
{
    // this is the anomaly dump function
    // called when we need to save the last 60 seconds to disk
    // we copy the most recent N events from the ring buffer

    uint64_t w = write_head.load(std::memory_order_acquire);

    // how many events do we actually have?
    uint64_t total = std::min(w, RING_BUFFER_SIZE);

    // how many can we copy?
    uint64_t count = std::min(n, total);

    // start from (w - count) — the oldest event we want
    uint64_t start = w - count;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t pos = (start + i) % RING_BUFFER_SIZE;
        dst[i] = slots[pos];
    }

    return count;
}

uint64_t RingBuffer::totalWritten() const
{
    return write_head.load(std::memory_order_relaxed);
}