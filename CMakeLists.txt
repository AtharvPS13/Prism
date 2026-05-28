cmake_minimum_required(VERSION 3.10)
project(network_monitor)

set(CMAKE_CXX_STANDARD 17)

find_library(PCAP_LIB pcap REQUIRED)

add_executable(network_monitor
    src/main.cpp
    src/capture/packet_capture.cpp
    src/analyser/flow_tracker.cpp
    src/analyser/fairness.cpp
    src/analyser/classifier.cpp
    src/analyser/topology.cpp
    src/emitter/json_emitter.cpp
    src/recorder/ring_buffer.cpp
    src/recorder/event_recorder.cpp
)

add_executable(ring_buffer_test
    src/recorder/ring_buffer_test.cpp
    src/recorder/ring_buffer.cpp
)

target_include_directories(network_monitor PRIVATE src)
target_include_directories(ring_buffer_test PRIVATE src/recorder)
target_link_libraries(network_monitor ${PCAP_LIB} pthread)
target_link_libraries(ring_buffer_test pthread)