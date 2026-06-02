#!/usr/bin/env python3
"""
NetMonitor Mock Backend
========================
Simulates the C++ network monitor JSON server on port 8080.
Now supports UI-controlled replay via /anomalies, /replay, /stop_replay endpoints.

Run:  python3 mock_backend.py
Stop: Ctrl+C
"""

import json
import random
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── Realistic traffic profiles ────────────────────────────────────────────────

PROFILES = [
    {"traffic_type": "STREAMING",     "port": 443,   "dst": "185.9.19.15",    "base_rtt": 30},
    {"traffic_type": "STREAMING",     "port": 443,   "dst": "54.230.12.88",   "base_rtt": 25},
    {"traffic_type": "STREAMING",     "port": 1935,  "dst": "34.107.221.82",  "base_rtt": 38},
    {"traffic_type": "GAMING",        "port": 3074,  "dst": "52.26.194.20",   "base_rtt": 18},
    {"traffic_type": "GAMING",        "port": 27015, "dst": "103.28.54.190",  "base_rtt": 22},
    {"traffic_type": "GAMING",        "port": 7777,  "dst": "149.56.52.14",   "base_rtt": 15},
    {"traffic_type": "VOIP",          "port": 5060,  "dst": "13.107.64.11",   "base_rtt": 12},
    {"traffic_type": "BROWSING",      "port": 443,   "dst": "142.250.77.78",  "base_rtt": 20},
    {"traffic_type": "BROWSING",      "port": 80,    "dst": "93.184.216.34",  "base_rtt": 28},
    {"traffic_type": "FILE TRANSFER", "port": 443,   "dst": "52.84.15.100",   "base_rtt": 45},
]

SRC_IP = "172.22.115.82"

# ─── Anomaly sequence generator ───────────────────────────────────────────────

def generate_anomaly_sequence(severity="high"):
    """
    Generate a realistic anomaly sequence.
    Returns list of snapshot dicts representing events over time.
    Phases: normal → building → peak → recovery
    """
    rng = random.Random(42 if severity == "high" else 99 if severity == "medium" else 7)

    profiles_used = rng.sample(PROFILES, 5)

    # multipliers per severity
    peak_mult = {"critical": 12, "high": 7, "medium": 4}[severity]

    sequence = []

    def make_flows(rtts, hog_idx, bytes_list, bufferbloats):
        flows = []
        for i, p in enumerate(profiles_used):
            flows.append({
                "key":          f"flow_{i}_{severity}",
                "src_ip":       SRC_IP,
                "dst_ip":       p["dst"],
                "src_port":     40000 + i * 1000,
                "dst_port":     p["port"],
                "bytes":        bytes_list[i],
                "packets":      bytes_list[i] // 800,
                "avg_rtt_ms":   round(rtts[i], 1),
                "max_rtt_ms":   round(rtts[i] * 1.3, 1),
                "bufferbloat":  bufferbloats[i],
                "is_hog":       i == hog_idx,
                "traffic_type": p["traffic_type"],
                "confidence":   round(rng.uniform(0.78, 0.97), 2),
                "reason":       f"port {p['port']} pattern",
            })
        return flows

    def jain(bytes_list):
        s = sum(bytes_list)
        sq = sum(x*x for x in bytes_list)
        return (s*s) / (len(bytes_list) * sq) if sq > 0 else 1.0

    base_rtts  = [p["base_rtt"] for p in profiles_used]
    base_bytes = [rng.randint(50000, 200000) for _ in profiles_used]
    hog_idx    = rng.randint(0, len(profiles_used) - 1)
    t0         = int(time.time()) - 90  # recording was 90s ago

    n_phases = [("normal", 15), ("building", 20), ("peak", 20), ("recovery", 15)]
    tick = 0

    for phase, count in n_phases:
        for step in range(count):
            frac = step / max(count - 1, 1)
            rtts = []
            bytes_list = []
            bufferbloats = []

            for i, p in enumerate(profiles_used):
                base = base_rtts[i]
                is_h = (i == hog_idx)

                if phase == "normal":
                    r = base + rng.uniform(-2, 2)
                    b = base_bytes[i] + rng.randint(100, 2000)
                elif phase == "building":
                    mult = 1.0 + frac * (peak_mult * 0.6)
                    r = base * mult + rng.uniform(-3, 3) if is_h else base * (1.0 + frac * 0.8) + rng.uniform(-2, 2)
                    b = base_bytes[i] + rng.randint(5000, 50000) if is_h else base_bytes[i] + rng.randint(100, 1000)
                elif phase == "peak":
                    mult = peak_mult + rng.uniform(-1, 1)
                    r = base * mult + rng.uniform(-5, 10) if is_h else base * (1.0 + peak_mult * 0.4) + rng.uniform(-3, 5)
                    b = base_bytes[i] + rng.randint(20000, 100000) if is_h else base_bytes[i] + rng.randint(100, 500)
                else:  # recovery
                    mult = peak_mult * (1 - frac * 0.8) + 1
                    r = base * max(1, mult * 0.5) + rng.uniform(-2, 2)
                    b = base_bytes[i] + rng.randint(1000, 10000)

                r = max(1.0, r)
                rtts.append(r)
                bytes_list.append(int(b))
                bufferbloats.append(r > base * 3.0)
                base_bytes[i] = int(b)

            flows = make_flows(rtts, hog_idx, bytes_list, bufferbloats)
            fi    = jain(bytes_list)
            hog_b = bytes_list[hog_idx]
            hog_p = hog_b / sum(bytes_list) * 100 if sum(bytes_list) else 0

            hosts = [
                {"ip": SRC_IP, "ttl": 64, "hops": 0,
                 "os_guess": "Linux", "proximity": "Same subnet", "packets": sum(f["packets"] for f in flows)}
            ]
            for f in flows[:4]:
                ttl = rng.randint(48, 62)
                hosts.append({"ip": f["dst_ip"], "ttl": ttl, "hops": 64 - ttl,
                               "os_guess": "Linux / Android / macOS",
                               "proximity": "Internet (same country)", "packets": f["packets"]})

            sequence.append({
                "timestamp":     t0 + tick * 2,
                "fairness_index": round(fi, 4),
                "total_flows":   len(flows),
                "worst_hog":     f"{SRC_IP}:{40000 + hog_idx*1000}<->{profiles_used[hog_idx]['dst']}:{profiles_used[hog_idx]['port']}",
                "hog_percent":   round(hog_p, 1),
                "flows":         flows,
                "hosts":         hosts,
                "replay":        True,
                "anomaly_active": phase in ("peak",),
                "phase":         phase,
            })
            tick += 1

    return sequence


# ─── Pre-built recordings ──────────────────────────────────────────────────────

RECORDINGS = [
    {
        "id":       "anomaly_2026_05_30_02_15_00",
        "label":    "Streaming Hog",
        "severity": "medium",
        "events":   0,   # filled below
        "duration": 70,
        "max_rtt":  0,   # filled below
        "saved_at": int(time.time()) - 7200,
        "_seq":     None,
    },
    {
        "id":       "anomaly_2026_05_29_23_45_00",
        "label":    "Gaming + VoIP Congestion",
        "severity": "high",
        "events":   0,
        "duration": 70,
        "max_rtt":  0,
        "saved_at": int(time.time()) - 28800,
        "_seq":     None,
    },
    {
        "id":       "anomaly_2026_05_28_18_30_00",
        "label":    "Bandwidth Collapse",
        "severity": "critical",
        "events":   0,
        "duration": 70,
        "max_rtt":  0,
        "saved_at": int(time.time()) - 86400,
        "_seq":     None,
    },
]

# Pre-generate all sequences at startup
for rec in RECORDINGS:
    seq = generate_anomaly_sequence(rec["severity"])
    rec["_seq"]   = seq
    rec["events"] = len(seq)
    rec["max_rtt"] = max(
        max(f["avg_rtt_ms"] for f in snap["flows"]) for snap in seq
    )

print(f"  Generated {sum(r['events'] for r in RECORDINGS)} total replay events")


# ─── Live simulation state ─────────────────────────────────────────────────────

class Flow:
    def __init__(self, profile):
        self.profile   = profile
        self.src_port  = random.randint(40000, 65000)
        self.bytes     = random.randint(20000, 300000)
        self.packets   = random.randint(80, 400)
        self.rtt       = float(profile["base_rtt"]) + random.uniform(-4, 4)
        self.key       = f"flow_{id(self)}_{int(time.time())}"
        self.age       = 0

    def tick(self, is_hog, in_congestion):
        base  = self.profile["base_rtt"]
        noise = random.uniform(-2, 2)
        if is_hog and in_congestion:
            self.rtt = base * random.uniform(3.5, 5.5) + noise
        elif in_congestion:
            self.rtt = base * random.uniform(1.5, 2.8) + noise
        else:
            self.rtt = self.rtt * 0.80 + base * 0.20 + noise
            self.rtt = max(1.0, self.rtt)
        self.bytes   += random.randint(5000, 80000) if is_hog else random.randint(200, 8000)
        self.packets += random.randint(10, 80)      if is_hog else random.randint(1, 15)
        self.age     += 1


class SimState:
    def __init__(self):
        self.flows           = []
        self.tick_n          = 0
        self.hog_idx         = 0
        self.congestion      = False
        self.congestion_left = 0
        self._spawn_initial()

    def _spawn_initial(self):
        profiles = random.sample(PROFILES, random.randint(4, 7))
        for p in profiles:
            self.flows.append(Flow(p))
        self.hog_idx = random.randint(0, len(self.flows) - 1)

    def _maybe_add_flow(self):
        if len(self.flows) < 9 and random.random() < 0.35:
            self.flows.append(Flow(random.choice(PROFILES)))

    def _maybe_remove_flow(self):
        if len(self.flows) > 3 and random.random() < 0.25:
            removable = [i for i in range(len(self.flows)) if i != self.hog_idx]
            if removable:
                self.flows.pop(random.choice(removable))
                self.hog_idx = self.hog_idx % len(self.flows)

    def _maybe_rotate_hog(self):
        if random.random() < 0.20:
            self.hog_idx = random.randint(0, len(self.flows) - 1)

    def _update_congestion(self):
        if not self.congestion and random.random() < 0.06:
            self.congestion      = True
            self.congestion_left = random.randint(4, 12)
        if self.congestion:
            self.congestion_left -= 1
            if self.congestion_left <= 0:
                self.congestion = False

    def advance(self):
        self.tick_n += 1
        self._update_congestion()
        if self.tick_n % 10 == 0:
            self._maybe_add_flow()
            self._maybe_remove_flow()
            self._maybe_rotate_hog()
        for i, flow in enumerate(self.flows):
            flow.tick(i == self.hog_idx, self.congestion)

    def snapshot(self) -> dict:
        self.advance()
        total_bytes = sum(f.bytes for f in self.flows) or 1
        flows_out   = []
        for i, f in enumerate(self.flows):
            is_hog = (i == self.hog_idx)
            bufferbloat = f.rtt > f.profile["base_rtt"] * 3.0
            flows_out.append({
                "key":          f.key,
                "src_ip":       SRC_IP,
                "dst_ip":       f.profile["dst"],
                "src_port":     f.src_port,
                "dst_port":     f.profile["port"],
                "bytes":        f.bytes,
                "packets":      f.packets,
                "avg_rtt_ms":   round(f.rtt, 2),
                "max_rtt_ms":   round(f.rtt * 1.35, 2),
                "bufferbloat":  bufferbloat,
                "is_hog":       is_hog,
                "traffic_type": f.profile["traffic_type"],
                "confidence":   round(random.uniform(0.78, 0.99), 2),
                "reason":       f"port {f.profile['port']} pattern match",
            })
        bw = [f.bytes for f in self.flows]
        n  = len(bw)
        fi = (sum(bw) ** 2) / (n * sum(x*x for x in bw)) if n else 1.0
        hog     = self.flows[self.hog_idx]
        hog_pct = hog.bytes / total_bytes * 100
        hosts = [{"ip": SRC_IP, "ttl": 64, "hops": 0,
                  "os_guess": "Linux", "proximity": "Same subnet",
                  "packets": sum(f.packets for f in self.flows)}]
        seen = set()
        for f in self.flows:
            if f.profile["dst"] in seen or len(hosts) >= 5: continue
            seen.add(f.profile["dst"])
            ttl = random.randint(48, 62)
            hosts.append({"ip": f.profile["dst"], "ttl": ttl, "hops": 64 - ttl,
                          "os_guess": "Linux / Android / macOS",
                          "proximity": "Internet (same country)", "packets": f.packets})
        return {
            "timestamp":     int(time.time()),
            "fairness_index": round(fi, 4),
            "total_flows":   n,
            "worst_hog":     f"{SRC_IP}:{hog.src_port}<->{hog.profile['dst']}:{hog.profile['port']}",
            "hog_percent":   round(hog_pct, 2),
            "flows":         flows_out,
            "hosts":         hosts,
            "replay":        False,
        }


# ─── Global server state ──────────────────────────────────────────────────────

live_state    = SimState()
lock          = threading.Lock()

# Replay state
replay_mode   = False
replay_seq    = []          # list of snapshot dicts
replay_idx    = 0           # current position
replay_speed  = 1.0
replay_id     = ""
replay_last_t = 0.0         # wall-clock time of last advance


def advance_replay_if_needed():
    """Advance replay index based on elapsed wall time and speed."""
    global replay_idx, replay_last_t, replay_mode
    if not replay_mode or replay_idx >= len(replay_seq):
        return
    now = time.time()
    elapsed = now - replay_last_t
    # each event is ~2 seconds of simulated time; advance proportionally
    steps = int(elapsed * replay_speed / 2.0)
    if steps > 0:
        replay_idx = min(replay_idx + steps, len(replay_seq) - 1)
        replay_last_t = now
    if replay_idx >= len(replay_seq) - 1:
        # replay finished — stay on last frame, user must stop manually
        pass


def current_snapshot() -> dict:
    with lock:
        if replay_mode and replay_seq:
            advance_replay_if_needed()
            snap = dict(replay_seq[min(replay_idx, len(replay_seq)-1)])
            snap["replay_progress"] = replay_idx + 1
            snap["replay_total"]    = len(replay_seq)
            snap["replay_id"]       = replay_id
            return snap
        else:
            return live_state.snapshot()


def anomalies_list() -> dict:
    result = []
    for r in RECORDINGS:
        result.append({
            "id":       r["id"],
            "label":    r["label"],
            "severity": r["severity"],
            "events":   r["events"],
            "duration": r["duration"],
            "max_rtt":  round(r["max_rtt"], 0),
            "saved_at": r["saved_at"],
        })
    return {"recordings": result}


def start_replay(rec_id: str, speed: float):
    global replay_mode, replay_seq, replay_idx, replay_speed, replay_id, replay_last_t
    with lock:
        for r in RECORDINGS:
            if r["id"] == rec_id:
                replay_seq    = r["_seq"]
                replay_idx    = 0
                replay_speed  = max(0.1, min(20.0, speed))
                replay_id     = rec_id
                replay_mode   = True
                replay_last_t = time.time()
                return True
    return False


def stop_replay():
    global replay_mode, replay_seq, replay_idx
    with lock:
        replay_mode = False
        replay_seq  = []
        replay_idx  = 0


# ─── HTTP handler ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/anomalies":
            self._send_json(anomalies_list())
        else:
            self._send_json(current_snapshot())

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._read_body()

        if path == "/replay":
            rec_id = body.get("id", "")
            speed  = float(body.get("speed", 1.0))
            ok     = start_replay(rec_id, speed)
            if ok:
                self._send_json({"status": "ok", "id": rec_id, "speed": speed})
            else:
                self._send_json({"status": "error", "msg": "recording not found"}, 404)

        elif path == "/stop_replay":
            stop_replay()
            self._send_json({"status": "ok"})

        else:
            self._send_json({"status": "error", "msg": "unknown endpoint"}, 404)

    def log_message(self, fmt, *args):
        if live_state.tick_n % 15 == 0 or replay_mode:
            mode = f"REPLAY [{replay_id[:20]}] idx={replay_idx}" if replay_mode else "LIVE"
            print(f"  [{mode}]  tick={live_state.tick_n}")


if __name__ == "__main__":
    PORT = 8080
    print("=" * 55)
    print("  NetMonitor Mock Backend")
    print(f"  http://localhost:{PORT}")
    print()
    print("  Endpoints:")
    print("    GET  /             — live snapshot")
    print("    GET  /anomalies    — list recordings")
    print("    POST /replay       — start replay")
    print("    POST /stop_replay  — back to live")
    print()
    print("  Start dashboard:  cd dashboard && npm start")
    print("  Stop server:      Ctrl+C")
    print("=" * 55)
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")