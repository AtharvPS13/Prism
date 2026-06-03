#!/usr/bin/env python3
"""
NetMonitor Mock Backend — with TCP Congestion State Machine simulation
Endpoints:
  GET  /             — live snapshot
  GET  /anomalies    — list recordings
  POST /replay       — start replay
  POST /stop_replay  — back to live
"""

import json, random, time, threading, math
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── TCP state simulator per flow ────────────────────────────────────────────

class TCPFlowSim:
    """Simulates TCP congestion control to produce a realistic sawtooth chart."""
    MSS = 1460  # max segment size bytes

    def __init__(self, base_rtt: float):
        self.base_rtt     = base_rtt
        self.cwnd         = self.MSS * 2.0      # start at 2 MSS
        self.ssthresh     = 65535.0              # initial ssthresh
        self.state        = "SLOW_START"
        self.retrans      = 0
        self.fast_rec     = 0
        self.timeouts     = 0
        self.history      = []                   # list of [t, bif_kb, state]
        self.t            = 0.0                  # relative time
        self.dup_ack_left = 0                    # ticks remaining in fast recovery

    def tick(self, dt: float = 0.2):
        """Advance simulation by dt seconds (one RTT worth of ticks)."""
        self.t += dt

        if self.dup_ack_left > 0:
            # in fast recovery — cwnd climbs back
            self.dup_ack_left -= 1
            self.cwnd = min(self.cwnd + self.MSS, self.ssthresh * 1.5)
            if self.dup_ack_left == 0:
                self.cwnd  = self.ssthresh
                self.state = "CONG_AVOID"
        elif self.state == "SLOW_START":
            # exponential growth — double cwnd each RTT
            self.cwnd = min(self.cwnd * 2.0, self.ssthresh)
            if self.cwnd >= self.ssthresh:
                self.state = "CONG_AVOID"
        elif self.state == "CONG_AVOID":
            # linear growth — add 1 MSS per RTT
            self.cwnd += self.MSS

        # cap at a realistic maximum (e.g. 1MB)
        self.cwnd = min(self.cwnd, 1_048_576)

        # random packet loss event (~8% chance per tick in cong_avoid)
        if self.state == "CONG_AVOID" and random.random() < 0.08:
            self.ssthresh     = max(self.cwnd / 2.0, 2 * self.MSS)
            self.cwnd         = self.ssthresh
            self.state        = "FAST_RECOVERY"
            self.dup_ack_left = random.randint(3, 8)
            self.fast_rec    += 1
            self.retrans      += random.randint(1, 3)

        # record history (last 80 points)
        bif_kb = round(self.cwnd / 1024.0, 1)
        self.history.append([round(self.t, 2), bif_kb, self.state])
        if len(self.history) > 80:
            self.history.pop(0)

    def get_rtt(self) -> float:
        """RTT increases when cwnd is large (buffer filling)."""
        # simple model: RTT grows when cwnd exceeds ~32KB
        base = self.base_rtt
        if self.cwnd > 32768:
            extra = (self.cwnd - 32768) / 32768 * base * 0.8
            return base + extra + random.uniform(-2, 2)
        return base + random.uniform(-2, 2)


# ─── Traffic profiles ────────────────────────────────────────────────────────

PROFILES = [
    {"traffic_type": "STREAMING",     "port": 443,   "dst": "185.9.19.15",   "base_rtt": 30},
    {"traffic_type": "STREAMING",     "port": 443,   "dst": "54.230.12.88",  "base_rtt": 25},
    {"traffic_type": "GAMING",        "port": 3074,  "dst": "52.26.194.20",  "base_rtt": 18},
    {"traffic_type": "GAMING",        "port": 27015, "dst": "103.28.54.190", "base_rtt": 22},
    {"traffic_type": "VOIP",          "port": 5060,  "dst": "13.107.64.11",  "base_rtt": 12},
    {"traffic_type": "BROWSING",      "port": 443,   "dst": "142.250.77.78", "base_rtt": 20},
    {"traffic_type": "BROWSING",      "port": 80,    "dst": "93.184.216.34", "base_rtt": 28},
    {"traffic_type": "FILE TRANSFER", "port": 443,   "dst": "52.84.15.100",  "base_rtt": 45},
]

SRC_IP = "172.22.115.82"


# ─── Live simulation ──────────────────────────────────────────────────────────

class LiveFlow:
    def __init__(self, profile):
        self.profile  = profile
        self.src_port = random.randint(40000, 65000)
        self.bytes    = random.randint(20000, 300000)
        self.packets  = random.randint(80, 400)
        self.tcp      = TCPFlowSim(profile["base_rtt"])
        self.key      = f"flow_{id(self)}"

    def tick(self, is_hog: bool, in_congestion: bool):
        self.tcp.tick(0.25)
        rtt = self.tcp.get_rtt()
        if in_congestion and not is_hog:
            rtt *= random.uniform(1.5, 2.5)
        self.bytes   += random.randint(5000, 80000) if is_hog else random.randint(200, 8000)
        self.packets += random.randint(10, 80)      if is_hog else random.randint(1, 15)
        return rtt


class SimState:
    def __init__(self):
        self.flows           = []
        self.tick_n          = 0
        self.hog_idx         = 0
        self.congestion      = False
        self.congestion_left = 0
        profiles = random.sample(PROFILES, random.randint(4, 6))
        for p in profiles:
            self.flows.append(LiveFlow(p))
        self.hog_idx = random.randint(0, len(self.flows) - 1)

    def _update_congestion(self):
        if not self.congestion and random.random() < 0.06:
            self.congestion      = True
            self.congestion_left = random.randint(4, 12)
        if self.congestion:
            self.congestion_left -= 1
            if self.congestion_left <= 0:
                self.congestion = False

    def _maybe_reshuffle(self):
        if len(self.flows) < 8 and random.random() < 0.3:
            self.flows.append(LiveFlow(random.choice(PROFILES)))
        if len(self.flows) > 3 and random.random() < 0.2:
            idx = random.choice([i for i in range(len(self.flows)) if i != self.hog_idx])
            self.flows.pop(idx)
            self.hog_idx = self.hog_idx % len(self.flows)
        if random.random() < 0.15:
            self.hog_idx = random.randint(0, len(self.flows) - 1)

    def snapshot(self) -> dict:
        self.tick_n += 1
        self._update_congestion()
        if self.tick_n % 10 == 0:
            self._maybe_reshuffle()

        total_bytes = sum(f.bytes for f in self.flows) or 1
        flows_out   = []

        for i, f in enumerate(self.flows):
            is_hog = (i == self.hog_idx)
            rtt    = f.tick(is_hog, self.congestion)
            tcp    = f.tcp
            bloat  = rtt > f.profile["base_rtt"] * 3.0

            flows_out.append({
                "key":          f.key,
                "src_ip":       SRC_IP,
                "dst_ip":       f.profile["dst"],
                "src_port":     f.src_port,
                "dst_port":     f.profile["port"],
                "bytes":        f.bytes,
                "packets":      f.packets,
                "avg_rtt_ms":   round(rtt, 2),
                "max_rtt_ms":   round(rtt * 1.3, 2),
                "bufferbloat":  bloat,
                "is_hog":       is_hog,
                "traffic_type": f.profile["traffic_type"],
                "confidence":   round(random.uniform(0.78, 0.97), 2),
                "reason":       f"port {f.profile['port']} pattern",
                # TCP state machine fields
                "tcp_state":         tcp.state,
                "tcp_state_color":   {
                    "SLOW_START":    "#10B981",
                    "CONG_AVOID":    "#3B82F6",
                    "FAST_RECOVERY": "#EF4444",
                    "TIMEOUT":       "#6B7280",
                }.get(tcp.state, "#4E6380"),
                "bytes_in_flight":   round(tcp.cwnd),
                "retransmissions":   tcp.retrans,
                "fast_recoveries":   tcp.fast_rec,
                "timeouts_count":    tcp.timeouts,
                "time_slow_start":   0.0,
                "time_cong_avoid":   0.0,
                "time_fast_recovery": 0.0,
                "cwnd_history":      tcp.history[-50:],  # last 50 points
            })

        bw = [f.bytes for f in self.flows]
        n  = len(bw)
        fi = (sum(bw)**2) / (n * sum(x*x for x in bw)) if n else 1.0

        hog     = self.flows[self.hog_idx]
        hog_pct = hog.bytes / total_bytes * 100

        seen  = set()
        hosts = [{"ip": SRC_IP, "ttl": 64, "hops": 0,
                  "os_guess": "Linux", "proximity": "Same subnet",
                  "packets": sum(f.packets for f in self.flows)}]
        for f in self.flows:
            d = f.profile["dst"]
            if d in seen or len(hosts) >= 5: continue
            seen.add(d)
            ttl = random.randint(48, 62)
            hosts.append({"ip": d, "ttl": ttl, "hops": 64 - ttl,
                          "os_guess": "Linux / Android / macOS",
                          "proximity": "Internet (same country)",
                          "packets": f.packets})

        return {
            "timestamp":      int(time.time()),
            "fairness_index": round(fi, 4),
            "total_flows":    n,
            "worst_hog":      f"{SRC_IP}:{hog.src_port}<->{hog.profile['dst']}:{hog.profile['port']}",
            "hog_percent":    round(hog_pct, 2),
            "flows":          flows_out,
            "hosts":          hosts,
            "replay":         False,
        }


# ─── Pre-built anomaly recordings ────────────────────────────────────────────

def gen_recording(label, severity, seed):
    rng  = random.Random(seed)
    profiles = rng.sample(PROFILES, 4)
    mult = {"medium": 4, "high": 7, "critical": 12}[severity]
    seq  = []
    t0   = int(time.time()) - 90

    # create TCP sims for each flow
    sims = [TCPFlowSim(p["base_rtt"]) for p in profiles]
    bytes_list = [rng.randint(50000, 200000) for _ in profiles]
    hog_idx    = rng.randint(0, len(profiles) - 1)

    phases = [("normal",8),("building",15),("peak",18),("recovery",14)]
    tick   = 0

    for phase, count in phases:
        for step in range(count):
            frac = step / max(count - 1, 1)
            flows_out = []

            for i, (p, sim) in enumerate(zip(profiles, sims)):
                sim.tick(0.3)
                is_hog = (i == hog_idx)
                base   = p["base_rtt"]

                if phase == "normal":
                    rtt = base + rng.uniform(-2, 2)
                elif phase == "building":
                    rtt = base * (1 + frac * (mult * 0.5)) if is_hog else base * (1 + frac * 0.6)
                elif phase == "peak":
                    rtt = base * (mult + rng.uniform(-1,1)) if is_hog else base * (mult * 0.4 + rng.uniform(-2,2))
                else:
                    rtt = base * max(1, mult * (1-frac*0.8) * 0.5 + 1)

                rtt = max(1.0, rtt)
                bytes_list[i] += rng.randint(5000,80000) if is_hog else rng.randint(200,5000)

                bloat = rtt > base * 3.0
                flows_out.append({
                    "key":               f"flow_{i}_{severity}",
                    "src_ip":            SRC_IP,
                    "dst_ip":            p["dst"],
                    "src_port":          40000 + i * 1000,
                    "dst_port":          p["port"],
                    "bytes":             bytes_list[i],
                    "packets":           bytes_list[i] // 800,
                    "avg_rtt_ms":        round(rtt, 1),
                    "max_rtt_ms":        round(rtt * 1.3, 1),
                    "bufferbloat":       bloat,
                    "is_hog":            is_hog,
                    "traffic_type":      p["traffic_type"],
                    "confidence":        round(rng.uniform(0.78,0.97),2),
                    "reason":            f"port {p['port']} pattern",
                    "tcp_state":         sim.state,
                    "tcp_state_color":   {
                        "SLOW_START":    "#10B981",
                        "CONG_AVOID":    "#3B82F6",
                        "FAST_RECOVERY": "#EF4444",
                    }.get(sim.state, "#4E6380"),
                    "bytes_in_flight":   round(sim.cwnd),
                    "retransmissions":   sim.retrans,
                    "fast_recoveries":   sim.fast_rec,
                    "timeouts_count":    sim.timeouts,
                    "time_slow_start":   0.0,
                    "time_cong_avoid":   0.0,
                    "time_fast_recovery": 0.0,
                    "cwnd_history":      sim.history[-50:],
                })

            bw = bytes_list
            n  = len(bw)
            fi = (sum(bw)**2) / (n * sum(x*x for x in bw)) if n else 1.0
            hog_pct = bytes_list[hog_idx] / max(sum(bytes_list),1) * 100

            hosts = [{"ip": SRC_IP, "ttl": 64, "hops": 0,
                      "os_guess": "Linux", "proximity": "Same subnet",
                      "packets": sum(f["packets"] for f in flows_out)}]
            for f in flows_out[:3]:
                ttl = rng.randint(48, 62)
                hosts.append({"ip": f["dst_ip"], "ttl": ttl, "hops": 64-ttl,
                               "os_guess": "Linux / Android / macOS",
                               "proximity": "Internet (same country)",
                               "packets": f["packets"]})

            seq.append({
                "timestamp":      t0 + tick * 2,
                "fairness_index": round(fi, 4),
                "total_flows":    n,
                "worst_hog":      f"{SRC_IP}:4{hog_idx}000<->{profiles[hog_idx]['dst']}:{profiles[hog_idx]['port']}",
                "hog_percent":    round(hog_pct, 1),
                "flows":          flows_out,
                "hosts":          hosts,
                "replay":         True,
                "anomaly_active": phase == "peak",
                "phase":          phase,
            })
            tick += 1

    return seq


print("Generating anomaly recordings...")
RECORDINGS = [
    {"id":"anomaly_2026_05_30_02_15_00","label":"Streaming Hog","severity":"medium",
     "saved_at":int(time.time())-7200,  "_seq": gen_recording("Streaming Hog","medium",42)},
    {"id":"anomaly_2026_05_29_23_45_00","label":"Gaming Congestion","severity":"high",
     "saved_at":int(time.time())-28800, "_seq": gen_recording("Gaming Congestion","high",99)},
    {"id":"anomaly_2026_05_28_18_30_00","label":"Bandwidth Collapse","severity":"critical",
     "saved_at":int(time.time())-86400, "_seq": gen_recording("Bandwidth Collapse","critical",7)},
]
for r in RECORDINGS:
    r["events"]   = len(r["_seq"])
    r["duration"] = r["events"] * 2
    r["max_rtt"]  = max(
        max(f["avg_rtt_ms"] for f in s["flows"]) for s in r["_seq"]
    )
print(f"  {sum(r['events'] for r in RECORDINGS)} total replay events ready\n")


# ─── Server state ─────────────────────────────────────────────────────────────

live_state    = SimState()
lock          = threading.Lock()
replay_mode   = False
replay_seq    = []
replay_idx    = 0
replay_speed  = 1.0
replay_id     = ""
replay_last_t = 0.0


def advance_replay():
    global replay_idx, replay_last_t
    if not replay_mode or replay_idx >= len(replay_seq):
        return
    now     = time.time()
    elapsed = now - replay_last_t
    steps   = int(elapsed * replay_speed / 2.0)
    if steps > 0:
        replay_idx    = min(replay_idx + steps, len(replay_seq) - 1)
        replay_last_t = now


def current_snapshot():
    with lock:
        if replay_mode and replay_seq:
            advance_replay()
            snap = dict(replay_seq[min(replay_idx, len(replay_seq)-1)])
            snap["replay_progress"] = replay_idx + 1
            snap["replay_total"]    = len(replay_seq)
            snap["replay_id"]       = replay_id
            return snap
        return live_state.snapshot()


# ─── HTTP handler ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/anomalies":
            self._json({"recordings": [{
                "id":r["id"],"label":r["label"],"severity":r["severity"],
                "events":r["events"],"duration":r["duration"],
                "max_rtt":round(r["max_rtt"]),"saved_at":r["saved_at"],
            } for r in RECORDINGS]})
        else:
            self._json(current_snapshot())

    def do_POST(self):
        global replay_mode, replay_seq, replay_idx, replay_speed, replay_id, replay_last_t
        path = self.path.split("?")[0]
        body = self._body()
        if path == "/replay":
            rec_id = body.get("id","")
            speed  = float(body.get("speed", 1.0))
            for r in RECORDINGS:
                if r["id"] == rec_id:
                    with lock:
                        replay_seq    = r["_seq"]
                        replay_idx    = 0
                        replay_speed  = max(0.1, min(20.0, speed))
                        replay_id     = rec_id
                        replay_mode   = True
                        replay_last_t = time.time()
                    self._json({"status":"ok","id":rec_id,"speed":speed})
                    return
            self._json({"status":"error","msg":"not found"}, 404)
        elif path == "/stop_replay":
            with lock:
                replay_mode = False
                replay_seq  = []
                replay_idx  = 0
            self._json({"status":"ok"})
        else:
            self._json({"status":"error"}, 404)

    def log_message(self, fmt, *args):
        pass  # suppress per-request logs for clean terminal


if __name__ == "__main__":
    PORT = 8080
    print("=" * 55)
    print("  NetMonitor Mock Backend (with TCP state machine)")
    print(f"  http://localhost:{PORT}")
    print("  Start dashboard: cd dashboard && npm start")
    print("  Ctrl+C to stop")
    print("=" * 55)
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")