cmake_minimum_required(VERSION 3.10)
project(network_monitor)

set(CMAKE_CXX_STANDARD 17)

# find libpcap on the system
find_library(PCAP_LIB pcap REQUIRED)

add_executable(network_monitor
    src/main.cpp
    src/capture/packet_capture.cpp
)

target_include_directories(network_monitor PRIVATE src)
target_link_libraries(network_monitor ${PCAP_LIB})