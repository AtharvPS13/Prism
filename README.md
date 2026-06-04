# Prism 🔬

**Passive network monitor that reconstructs what your network is doing from the inside.**

Prism sits silently on your network, reads packets that are already flowing, and tells you:
which device is hogging bandwidth, whether your router buffer is filling up, what TCP's
congestion algorithm is doing inside every connection, and what each device's network topology
looks like - all without sending a single packet or needing admin access.

> Built in C++ with a React dashboard. Runs on any Linux machine connected to your network.

<!-- ![dashboard screenshot](docs/dashboard.png) -->

---

## Why this exists

College WiFi gets painfully slow during exam season. The admin had no tools to diagnose it
cheaply. Every existing tool either required admin access to the router, sent active probes,
or needed expensive hardware.

Prism runs on a laptop, reads traffic that's already there, and finds the problem in seconds.

---

## What makes it different

**1. TCP Congestion State Machine**
Most monitoring tools show you bytes and RTT. Prism reconstructs TCP's *internal* congestion
state - SLOW\_START, CONGESTION\_AVOIDANCE, FAST\_RECOVERY, TIMEOUT - purely from passive
sequence number observation. No kernel modification. No active probing. The sawtooth pattern
TCP is famous for, made visible in real time.

**2. Network Anomaly Recorder**
A lock-free ring buffer (implemented from scratch using two `std::atomic<uint64_t>` integers -
no mutex) records every network event continuously. When bufferbloat is detected, the last 60
seconds are automatically saved to a binary file. A replay engine lets you scrub through the
exact congestion event at any speed - like a flight data recorder for your network.

**3. Passive Topology Inference**
Prism infers how many network hops separate each device, and guesses its OS, purely from the
TTL field in IP headers - without sending a single ping or traceroute packet.

---

## Features

| Feature | How it works |
|---------|-------------|
| **RTT measurement** | Matches TCP sequence numbers with ACKs, timestamps the delta |
| **Bufferbloat detection** | Flags when RTT exceeds 3× per-flow baseline (the bufferbloat signature) |
| **Jain's Fairness Index** | O(n) single-pass computation across all flows |
| **Traffic classification** | STREAMING / GAMING / VOIP / BROWSING / FILE TRANSFER from packet size + direction ratios - no content inspection |
| **Topology inference** | OS guess + hop count from TTL values (Linux=64, Windows=128, Router=255) |
| **TCP state machine** | SLOW\_START → CONG\_AVOID → FAST\_RECOVERY → TIMEOUT inferred from dup ACK patterns and bytes-in-flight |
| **Lock-free ring buffer** | 200K events in 6MB RAM, two atomic integers, zero locks, concurrent read/write proven by tests |
| **Anomaly recorder** | Auto-saves last 60s on bufferbloat/fairness threshold breach |
| **Replay engine** | Variable-speed replay of saved anomalies with live dashboard |
| **Post-mortem report** | Root cause, impact numbers, plain-English explanation, fix recommendations |
| **HTTP server** | Built from raw POSIX sockets - no library |
| **React dashboard** | Live RTT history, fairness index, topology table, TCP sawtooth chart |

---

## Quick start

### Mock backend (no hardware needed)
```bash
git clone https://github.com/AtharvPS13/network-monitor
cd network-monitor

# terminal 1 - mock backend (Python, no install needed)
python3 mock_backend.py

# terminal 2 - React dashboard
cd dashboard && npm install && npm start
```
Open http://localhost:3000. Go to **Recordings** tab and click **▶ Analyse** on any anomaly.

---

### Live capture (Linux / WSL2)
```bash
# build C++ backend
sudo apt install -y g++ cmake libpcap-dev
mkdir build && cd build && cmake .. && make && cd ..

# run live capture on your network interface
sudo ./build/network_monitor --live eth0

# in another terminal
cd dashboard && npm start
```

---

### Replay a saved anomaly
```bash
# after an anomaly is auto-saved:
./build/network_monitor --replay anomaly_2026_05_30_14_32.bin --speed 0.1
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    network traffic (eth0)                   │
└───────────────────────┬─────────────────────────────────────┘
                        │  libpcap (passive - no packets sent)
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                   C++ capture engine                        │
│  packet_capture.cpp - parses IP + TCP headers               │
│  flow_tracker.cpp   - RTT, bufferbloat, Jain fairness       │
│  classifier.cpp     - traffic type from packet patterns     │
│  topology.cpp       - hops + OS from TTL values             │
│  tcp_state.cpp      - congestion state machine              │
└───────────────┬─────────────────────┬───────────────────────┘
                │                     │
                ▼                     ▼
┌──────────────────────┐   ┌──────────────────────────────────┐
│  ring_buffer.cpp     │   │  json_emitter.cpp                │
│  lock-free, atomic   │   │  raw POSIX HTTP server           │
│  200K events / 6MB   │   │  serves JSON on :8080            │
│                      │   └──────────────┬───────────────────┘
│  event_recorder.cpp  │                  │ fetch() every 2s
│  auto-saves anomalies│                  ▼
│                      │   ┌──────────────────────────────────┐
│  replay_engine.cpp   │   │  React dashboard (:3000)         │
│  variable-speed      │   │  RTT history · fairness · TCP    │
│  post-mortem report  │   │  sawtooth · topology · replay    │
└──────────────────────┘   └──────────────────────────────────┘
```

---

## The TCP Congestion State Machine

The most technically deep feature. TCP has an internal state machine inside every connection
that is normally invisible - it lives inside the kernel and nothing outside can observe it.

Prism reconstructs it passively from three signals:

```
bytes_in_flight  =  max_seq_seen  −  last_ack_received
                 ≈  congestion window (cwnd)

dup_ack_count    =  consecutive identical ACK numbers
                    ≥ 3  →  packet loss detected  →  FAST_RECOVERY

state            =  SLOW_START    (cwnd < ssthresh, exponential growth)
                    CONG_AVOID    (cwnd ≥ ssthresh, linear growth +1 MSS/RTT)
                    FAST_RECOVERY (3 dup ACKs, cwnd halved)
                    TIMEOUT       (no ACK for > RTO, cwnd → 1 MSS)
```

This is the same problem space Google's BBR algorithm addresses - BBR was built to improve
on the congestion control that Prism now makes visible.

---

## The Lock-Free Ring Buffer

The anomaly recorder uses a custom lock-free ring buffer. Two threads - capture (writer)
and analyser (reader) - share exactly two `std::atomic<uint64_t>` integers. No mutex.
No condition variable. No possible deadlock.

```cpp
// write (capture thread):
uint64_t pos = write_head.load() % BUFFER_SIZE;
slots[pos] = event;
write_head.fetch_add(1, memory_order_release);

// read (analyser thread):
if (read_head.load() >= write_head.load()) return; // empty
uint64_t pos = read_head.load() % BUFFER_SIZE;
out = slots[pos];
read_head.fetch_add(1, memory_order_release);
```

4 tests validate concurrent correctness including a 10,000-event concurrent stress test.

---

## Tech stack

**Backend (C++17)**
- `libpcap` - packet capture
- Raw POSIX sockets - HTTP server (no library)
- `std::atomic` - lock-free ring buffer
- `std::unordered_map` - O(1) flow lookup

**Dashboard (TypeScript + React)**
- `recharts` - RTT history, sawtooth chart, bar charts
- `fetch` API - polls C++ server every 2s

**Build**
- CMake
- WSL2 / Ubuntu

---

## Project structure

```
src/
├── capture/
│   └── packet_capture.cpp    raw socket + libpcap reader
├── analyser/
│   ├── flow_tracker.cpp      RTT, bufferbloat, Jain fairness
│   ├── classifier.cpp        traffic type classification
│   ├── topology.cpp          TTL-based topology inference
│   └── tcp_state.cpp         TCP congestion state machine ★
├── emitter/
│   └── json_emitter.cpp      HTTP server from raw sockets
├── recorder/
│   ├── ring_buffer.cpp       lock-free ring buffer ★
│   ├── event_recorder.cpp    anomaly detection + auto-save
│   └── replay_engine.cpp     variable-speed replay
└── main.cpp
dashboard/src/App.tsx          React dashboard
mock_backend.py                Python mock server for development
```

---
