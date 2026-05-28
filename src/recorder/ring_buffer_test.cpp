#include "ring_buffer.h"
#include <iostream>
#include <thread>
#include <cassert>

// test 1: basic write and read
void testBasic() {
    RingBuffer rb;

    NetworkEvent e;
    e.timestamp  = 1.0;
    e.event_type = EV_RTT;
    e.metric     = 42.5;
    strncpy(e.flow_key, "test_flow", 13);

    rb.write(e);

    NetworkEvent out;
    bool ok = rb.read(out);

    assert(ok);
    assert(out.metric == 42.5);
    assert(out.event_type == EV_RTT);
    std::cout << "test 1 passed: basic write/read\n";
}

// test 2: buffer wraps around correctly
void testWrapAround() {
    RingBuffer rb;

    // write more than RING_BUFFER_SIZE events
    // old ones should be overwritten silently
    for (uint64_t i = 0; i < RING_BUFFER_SIZE + 100; i++) {
        NetworkEvent e;
        e.timestamp  = (double)i;
        e.event_type = EV_RTT;
        e.metric     = (double)i;
        strncpy(e.flow_key, "wrap_test", 13);
        rb.write(e);
    }

    assert(rb.totalWritten() == RING_BUFFER_SIZE + 100);
    std::cout << "test 2 passed: wrap around\n";
}

// test 3: two threads writing and reading simultaneously
void testConcurrent() {
    RingBuffer rb;
    const int COUNT = 10000;
    int read_count = 0;

    // writer thread
    std::thread writer([&]() {
        for (int i = 0; i < COUNT; i++) {
            NetworkEvent e;
            e.timestamp  = (double)i;
            e.event_type = EV_RTT;
            e.metric     = (double)i;
            strncpy(e.flow_key, "concurrent", 13);
            rb.write(e);
        }
    });

    // reader thread
    std::thread reader([&]() {
        NetworkEvent out;
        while (read_count < COUNT) {
            if (rb.read(out)) read_count++;
        }
    });

    writer.join();
    reader.join();

    assert(read_count == COUNT);
    std::cout << "test 3 passed: concurrent write/read (" 
              << COUNT << " events)\n";
}

// test 4: getLastN copies correct events
void testGetLastN() {
    RingBuffer rb;

    for (int i = 0; i < 1000; i++) {
        NetworkEvent e;
        e.timestamp  = (double)i;
        e.event_type = EV_RTT;
        e.metric     = (double)i;
        strncpy(e.flow_key, "lastn_test", 13);
        rb.write(e);
    }

    NetworkEvent dst[100];
    uint64_t got = rb.getLastN(dst, 100);

    assert(got == 100);
    // last event should have metric = 999
    assert(dst[99].metric == 999.0);
    std::cout << "test 4 passed: getLastN copies last 100 events correctly\n";
}

int main() {
    std::cout << "=== Ring Buffer Tests ===\n";
    testBasic();
    testWrapAround();
    testConcurrent();
    testGetLastN();
    std::cout << "=== All tests passed ===\n";
    return 0;
}