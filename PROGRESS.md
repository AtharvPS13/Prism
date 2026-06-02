# NetMonitor — Progress & Resume File

## RESUME PROMPT — paste this at the start of a new conversation
I'm building a C++ + React network monitoring project called NetMonitor.
Repo: https://github.com/AtharvPS13/network-monitor
Local path (Windows WSL2): /mnt/f/A/Dev/network-monitor
FULLY WORKING:

C++ packet capture (libpcap, raw sockets) — src/capture/
Flow tracking + RTT measurement (TCP seq/ack matching) — src/analyser/flow_tracker.cpp
Bufferbloat detection (RTT > 3x baseline) — src/analyser/flow_tracker.cpp
Jain Fairness Index — src/analyser/fairness.cpp
Traffic classification (STREAMING/GAMING/VOIP/BROWSING/FILE TRANSFER) — src/analyser/classifier.cpp
Network topology inference from TTL — src/analyser/topology.cpp
HTTP JSON server on port 8080 (raw POSIX sockets, no library) — src/emitter/json_emitter.cpp
Lock-free ring buffer (std::atomic, no mutex, 4 passing tests) — src/recorder/ring_buffer.cpp
Event recorder (anomaly detection + auto binary file save) — src/recorder/event_recorder.cpp
Replay engine (variable speed playback) — src/recorder/replay_engine.cpp
React TypeScript dashboard (recharts, dark theme) — dashboard/src/App.tsx

THREE RUN MODES:

./build/network_monitor                              (pcap file)
sudo ./build/network_monitor --live eth0             (live capture)
./build/network_monitor --replay file.bin --speed 0.1 (replay)

BUILD: cd /mnt/f/A/Dev/network-monitor/build && make && cd ..
DASHBOARD: cd dashboard && npm start
WHAT'S NEXT:

Test on real traffic (sudo ./build/network_monitor --live eth0)
Write README.md with architecture diagram + GIF
Dockerize (docker run -p 8080:8080 --net=host atharv/network-monitor)
Unit tests for analyser modules

IDEAS NOTED FOR LATER (don't implement yet):

Idea 1: TCP Congestion State Machine (infer slow start/congestion avoidance from seq numbers)
Idea 3: Self-Calibrating SLO Engine (online distribution fitting + PELT change point detection)

CURRENT STATE: All working. Testing live traffic on eth0 (WSL2 connected to home router).

## File structure
src/
capture/  packet_capture.h/cpp     — libpcap reader + live capture
analyser/ flow_tracker.h/cpp       — RTT + bufferbloat
fairness.h/cpp           — Jain index
classifier.h/cpp         — traffic classification
topology.h/cpp           — TTL inference
emitter/  json_emitter.h/cpp       — HTTP server + JSON
recorder/ ring_buffer.h/cpp        — lock-free ring buffer
event_recorder.h/cpp     — anomaly detection + save
replay_engine.h/cpp      — variable speed replay
main.cpp                           — orchestrates everything
dashboard/src/App.tsx                — React dashboard
PROGRESS.md                         — this file

## Dashboard status
React TypeScript dashboard: COMPILES CLEAN — no errors.

Fixed: recharts Tooltip formatter type mismatch in both AreaChart (RTT history)
and BarChart (RTT per flow). Root cause: recharts Formatter<ValueType, NameType>
passes `string | number | array | undefined`, not just `number`. Fix was to drop
explicit type annotation and narrow at runtime:
  formatter={(v) => [`${typeof v === "number" ? Math.round(v) : 0}ms`, "RTT"]}

## Mock backend
File: mock_backend.py (project root)
Run: python3 mock_backend.py
Simulates C++ backend on port 8080 — realistic random flows, RTT drift,
congestion bursts, hog rotation, fairness index, topology.
Use for: dashboard dev, README GIF recording, demos without live network.

### Idea 2: Replay Engine Enhancements (IMPLEMENT THIS NEXT)
 
Current replay: linear playback, variable speed, anomaly window highlight.
Goal: turn it into a forensic + what-if analysis tool. Uniquely impressive
for Google SDE-1/SDE-2 because no student project does this.
 
#### Feature 2A — Seekable Binary Format with Index (foundational, do first)
 
Add a seek table to the binary file format so you can jump to any timestamp
instantly instead of reading linearly. Like video seeking.
 
Binary layout:
```
[HEADER]  magic bytes + version + event_count + index_count
[INDEX]   array of {timestamp_ms, byte_offset} every N events
[DATA]    raw event payloads
```
 
Implementation in: src/recorder/event_recorder.cpp (write side)
                   src/recorder/replay_engine.cpp (read/seek side)
 
New CLI:
```bash
./build/network_monitor --replay anomaly.bin --seek 00:01:30
```
 
Why it impresses: building a seekable binary format is what real databases
and video codecs do. Shows you think about file format design, not just logic.
 
#### Feature 2B — Forensic Timeline / Incident Report (do second)
 
After replay completes, auto-generate a structured incident report in the
dashboard and optionally as a text file. Format:
 
```
INCIDENT REPORT — anomaly_2024_05_30.bin
─────────────────────────────────────────
T-00:00  SLO breach — RTT exceeded 3x baseline
T-00:12  Jain index dropped below 0.70 (WARNING)
T-00:31  Jain index dropped below 0.40 (CRITICAL)
T-01:02  Hog identified: 52.84.15.100:443 (FILE TRANSFER)
T-01:45  Bufferbloat detected on 3 flows simultaneously
T-02:10  RTT peaked at 347ms (15x baseline of 22ms)
T-03:40  Recovery began — hog flow terminated
T-04:15  Network returned to baseline
─────────────────────────────────────────
ROOT CAUSE: FILE TRANSFER flow consumed 84% bandwidth
DURATION:   4 minutes 15 seconds
IMPACT:     VOIP RTT degraded 8x, GAMING RTT degraded 6x
```
 
New file: src/recorder/forensics.h/cpp
Dashboard: new card that appears after replay ends showing this report.
 
Why it impresses: this is exactly how Google SRE incident reports look.
Shows you understand production operations, not just code.
 
#### Feature 2C — Counterfactual / What-If Replay (most unique, do third)
 
Replay binary recording but apply a hypothetical intervention:
```bash
./build/network_monitor --replay anomaly.bin --cap-hog 20%
```
 
Engine re-runs same event sequence but caps the hog flow at 20% bandwidth.
Dashboard shows TWO lines on RTT chart:
  - Solid line: what actually happened
  - Dashed line: what would have happened with the cap applied
Shows counterfactual fairness index too — "if rate-limited, Jain would
have stayed at 0.94 instead of dropping to 0.38."
 
Why it impresses: no student project does counterfactual analysis. Shows
you understand the difference between observation and intervention — same
concept Google uses in A/B testing infra and traffic engineering.
 
#### Feature 2D — A-B Session Comparison (optional, do last)
 
```bash
./build/network_monitor --compare before.bin after.bin
```
 
Dashboard splits into two columns, both replaying in sync on the same
time axis. Good for "network before vs after router firmware update."
 
Why it impresses: immediately visually striking in a demo. Syncing two
event streams on the same timeline is non-trivial engineering.
 
#### Implementation priority for Idea 2:
1. Feature 2A (seekable binary) — foundational, enables 2C
2. Feature 2B (forensic report) — highest SRE signal, good demo moment
3. Feature 2C (counterfactual) — most unique, best conversation piece
4. Feature 2D (A-B compare) — optional stretch goal
---