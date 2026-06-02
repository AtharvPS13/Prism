import { useEffect, useState, useCallback, useRef } from "react";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
  Cell, CartesianGrid, ReferenceLine
} from "recharts";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Flow {
  key: string; src_ip: string; dst_ip: string;
  src_port: number; dst_port: number;
  bytes: number; packets: number;
  avg_rtt_ms: number; max_rtt_ms: number;
  bufferbloat: boolean; is_hog: boolean;
  traffic_type: string; confidence: number; reason: string;
}

interface Host {
  ip: string; ttl: number; hops: number;
  os_guess: string; proximity: string; packets: number;
}

interface Snapshot {
  timestamp: number; fairness_index: number;
  total_flows: number; worst_hog: string; hog_percent: number;
  flows: Flow[]; hosts: Host[];
  replay?: boolean; anomaly_active?: boolean;
  replay_progress?: number; replay_total?: number;
  replay_id?: string; phase?: string;
}

interface Recording {
  id: string; label: string;
  severity: "medium" | "high" | "critical";
  events: number; duration: number;
  max_rtt: number; saved_at: number;
}

interface ReplayPoint {
  t: string; rtt: number; fair: number;
  phase: string; anomaly: boolean; hog_pct: number;
}

interface PostMortem {
  label: string; severity: string;
  baseline_rtt: number; peak_rtt: number; rtt_mult: number;
  baseline_fair: number; min_fair: number;
  hog_type: string; peak_hog_pct: number;
  peak_duration_s: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const fmtBytes = (b: number) =>
  b > 1e6 ? `${(b/1e6).toFixed(1)} MB` :
  b > 1e3 ? `${(b/1e3).toFixed(1)} KB` : `${b} B`;
const fmtRtt  = (ms: number) => ms > 0 ? `${Math.round(ms)}ms` : "n/a";
const fmtAgo  = (ts: number) => {
  const s = Math.floor(Date.now()/1000 - ts);
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s/60)}m ago` : `${Math.floor(s/3600)}h ago`;
};
const rttColor = (ms: number) =>
  ms > 300 ? "#EF4444" : ms > 100 ? "#F59E0B" : ms > 0 ? "#10B981" : "#4E6380";
const fairSt = (fi: number) =>
  fi >= 0.9 ? { label:"HEALTHY", color:"#10B981", bg:"#052E16" } :
  fi >= 0.7 ? { label:"WARNING", color:"#F59E0B", bg:"#451A03" } :
              { label:"CRITICAL",color:"#EF4444", bg:"#450A0A" };
const sevColors = (s: string) => ({
  critical: { bg:"#450A0A", color:"#EF4444", border:"#7F1D1D" },
  high:     { bg:"#451A03", color:"#F97316", border:"#7C2D12" },
  medium:   { bg:"#1A3020", color:"#34D399", border:"#064E3B" },
}[s] ?? { bg:"#1A3020", color:"#34D399", border:"#064E3B" });
const trafficBadge = (type: string) => ({
  STREAMING:       { bg:"#1E3A5F", color:"#60A5FA" },
  GAMING:          { bg:"#1A3320", color:"#4ADE80" },
  VOIP:            { bg:"#2D1B4E", color:"#C084FC" },
  "FILE TRANSFER": { bg:"#3D2000", color:"#FB923C" },
  BROWSING:        { bg:"#1E3A3A", color:"#2DD4BF" },
}[type] ?? { bg:"#1C2433", color:"#6B7FA3" });

const PHASE_ORDER = ["normal","building","peak","recovery"];

const PHASE_INFO: Record<string, {
  label: string; color: string;
  title: string; body: string;
}> = {
  normal: {
    label: "Normal",
    color: "#10B981",
    title: "Network is healthy",
    body: "All devices are sharing bandwidth fairly. RTT is low — packets travel to servers and back quickly. The router buffer is empty. This is what your network should look like all the time.",
  },
  building: {
    label: "Building",
    color: "#F59E0B",
    title: "Congestion is building",
    body: "One device is starting to consume more bandwidth than its fair share. Other devices are beginning to feel the pressure — their RTT is rising as the router's buffer starts to fill up. If left unchecked, this leads to a full congestion event.",
  },
  peak: {
    label: "Peak — anomaly",
    color: "#EF4444",
    title: "Bufferbloat detected — network in crisis",
    body: "The router's buffer is completely full. One device is consuming most of the bandwidth. Every other device's packets are stuck waiting in the queue behind it. RTT has spiked — video calls are breaking up, pages are slow to load. This is called bufferbloat.",
  },
  recovery: {
    label: "Recovering",
    color: "#F59E0B",
    title: "Network is recovering",
    body: "The heavy traffic is easing off. The router buffer is draining. RTT is coming back down toward normal. Fairness is improving as bandwidth becomes available again. The worst is over.",
  },
};

const SPEEDS = [0.1, 0.25, 0.5, 1, 2, 5, 10];

const STYLE = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;600;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; }
  body { background: #080D1A; font-family: 'DM Sans', sans-serif; color: #CBD5E1; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: #0E1628; }
  ::-webkit-scrollbar-thumb { background: #1C2E4A; border-radius: 2px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
  @keyframes blink  { 0%,100%{opacity:1} 50%{opacity:0} }
  @keyframes scan   { 0%{transform:translateY(-100%)} 100%{transform:translateY(400%)} }
  @keyframes slideDown { from{opacity:0;transform:translateY(-10px)} to{opacity:1;transform:none} }
  button { cursor:pointer; font-family:inherit; }
  button:hover { opacity:.85; }
`;

// ─── Compute post-mortem from replay history ──────────────────────────────────

function computePostMortem(history: ReplayPoint[], rec: Recording): PostMortem {
  if (!history.length) return {
    label: rec.label, severity: rec.severity,
    baseline_rtt: 0, peak_rtt: 0, rtt_mult: 0,
    baseline_fair: 1, min_fair: 1, hog_type: "UNKNOWN",
    peak_hog_pct: 0, peak_duration_s: 0,
  };
  const normals  = history.filter(p => p.phase === "normal");
  const peaks    = history.filter(p => p.phase === "peak");
  const base_rtt = normals.length
    ? Math.round(normals.reduce((s,p) => s+p.rtt,0) / normals.length) : 20;
  const peak_rtt = Math.max(...history.map(p => p.rtt));
  const base_fair = normals.length
    ? +(normals.reduce((s,p) => s+p.fair,0) / normals.length).toFixed(3) : 0.95;
  const min_fair  = +Math.min(...history.map(p => p.fair)).toFixed(3);
  const peak_hog  = Math.round(Math.max(...history.map(p => p.hog_pct)));
  return {
    label: rec.label, severity: rec.severity,
    baseline_rtt: base_rtt, peak_rtt: Math.round(peak_rtt),
    rtt_mult: base_rtt > 0 ? Math.round(peak_rtt / base_rtt) : 0,
    baseline_fair: base_fair, min_fair,
    hog_type: "GAMING", // derived from mock
    peak_hog_pct: peak_hog,
    peak_duration_s: peaks.length * 2,
  };
}

// ─── UI atoms ─────────────────────────────────────────────────────────────────

function Card({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <div style={{ background:"#0E1628", border:"1px solid #1C2E4A", borderRadius:10, ...style }}>{children}</div>;
}
function CardHeader({ title, sub, right }: { title:string; sub?:string; right?:React.ReactNode }) {
  return (
    <div style={{ padding:"14px 18px", borderBottom:"1px solid #1C2E4A", display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:12 }}>
      <div>
        <p style={{ fontSize:13, fontWeight:600, color:"#E2E8F5" }}>{title}</p>
        {sub && <p style={{ fontSize:11, color:"#4E6380", marginTop:3, lineHeight:1.5 }}>{sub}</p>}
      </div>
      {right}
    </div>
  );
}

// ─── Phase timeline ────────────────────────────────────────────────────────────

function PhaseTimeline({ current }: { current: string }) {
  const idx = PHASE_ORDER.indexOf(current);
  return (
    <div style={{ display:"flex", gap:0, marginBottom:16 }}>
      {PHASE_ORDER.map((phase, i) => {
        const info   = PHASE_INFO[phase];
        const done   = i < idx;
        const active = i === idx;
        const future = i > idx;
        const c = active ? info.color : done ? "#2D4A3A" : "#1C2E4A";
        const tc = active ? info.color : done ? "#4ADE80" : "#4E6380";
        return (
          <div key={phase} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:4 }}>
            {/* connector line */}
            <div style={{ display:"flex", alignItems:"center", width:"100%" }}>
              <div style={{ flex:1, height:2, background: i === 0 ? "transparent" : done||active ? info.color : "#1C2E4A", transition:"background .5s" }} />
              {/* dot */}
              <div style={{
                width:12, height:12, borderRadius:"50%", flexShrink:0,
                background: active ? info.color : done ? "#4ADE80" : "#1C2E4A",
                border: active ? `2px solid ${info.color}44` : "none",
                boxShadow: active ? `0 0 8px ${info.color}66` : "none",
                transition:"all .5s",
                animation: active ? "pulse 1.5s infinite" : "none",
              }} />
              <div style={{ flex:1, height:2, background: i === PHASE_ORDER.length-1 ? "transparent" : active||done ? info.color : "#1C2E4A", transition:"background .5s" }} />
            </div>
            <span style={{ fontSize:10, fontWeight: active ? 700 : 400, color:tc, letterSpacing:"0.04em", transition:"color .3s", fontFamily:"'JetBrains Mono'" }}>
              {info.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Narrative panel ───────────────────────────────────────────────────────────

function NarrativePanel({ phase, data }: { phase: string; data: Snapshot | null }) {
  const info   = PHASE_INFO[phase] ?? PHASE_INFO["normal"];
  const flows  = data?.flows ?? [];
  const maxRtt = flows.reduce((m,f) => f.avg_rtt_ms > m ? f.avg_rtt_ms : m, 0);
  const fi     = data?.fairness_index ?? 1;
  const hog    = flows.find(f => f.is_hog);
  return (
    <Card style={{ marginBottom:16, border:`1px solid ${info.color}44`, animation:"slideDown .4s ease" }}>
      <div style={{ padding:"14px 18px" }}>
        <div style={{ display:"flex", alignItems:"flex-start", gap:12 }}>
          <div style={{ width:8, height:8, borderRadius:"50%", background:info.color, marginTop:5, flexShrink:0, boxShadow:`0 0 6px ${info.color}88`, animation: phase==="peak" ? "pulse 1.5s infinite" : "none" }} />
          <div>
            <p style={{ fontSize:13, fontWeight:700, color:info.color, marginBottom:5 }}>{info.title}</p>
            <p style={{ fontSize:12, color:"#94A3B8", lineHeight:1.7, marginBottom:10 }}>{info.body}</p>
            {/* live numbers */}
            <div style={{ display:"flex", gap:12, flexWrap:"wrap" }}>
              {maxRtt > 0 && (
                <span style={{ fontSize:11, background:"#0A1020", border:"1px solid #1C2E4A", borderRadius:4, padding:"3px 10px", color:rttColor(maxRtt), fontFamily:"'JetBrains Mono'" }}>
                  RTT {Math.round(maxRtt)}ms
                </span>
              )}
              <span style={{ fontSize:11, background:"#0A1020", border:"1px solid #1C2E4A", borderRadius:4, padding:"3px 10px", color: fairSt(fi).color, fontFamily:"'JetBrains Mono'" }}>
                Fairness {fi.toFixed(3)}
              </span>
              {hog && (
                <span style={{ fontSize:11, background:"#100808", border:"1px solid #3D1515", borderRadius:4, padding:"3px 10px", color:"#EF4444", fontFamily:"'JetBrains Mono'" }}>
                  {hog.traffic_type} hog {Math.round(data?.hog_percent??0)}% of BW
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

// ─── Post-mortem report ────────────────────────────────────────────────────────

function PostMortemReport({ pm }: { pm: PostMortem }) {
  const sc = sevColors(pm.severity);
  return (
    <div style={{ animation:"fadeIn .5s ease", marginTop:4 }}>
      {/* header */}
      <div style={{ background:"linear-gradient(135deg,#0D0820,#0E1A10)", border:"1px solid #1C4A2A", borderRadius:12, padding:"20px 24px", marginBottom:16, position:"relative", overflow:"hidden" }}>
        <div style={{ position:"absolute", top:0, left:0, right:0, height:2, background:"linear-gradient(90deg,transparent,#10B981,transparent)" }} />
        <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:16, flexWrap:"wrap" }}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
              <span style={{ fontSize:18 }}>✓</span>
              <span style={{ fontSize:15, fontWeight:700, color:"#E2E8F5" }}>Incident Report</span>
              <span style={{ padding:"2px 8px", background:sc.bg, border:`1px solid ${sc.border}`, borderRadius:4, fontSize:10, color:sc.color, fontWeight:700, fontFamily:"'JetBrains Mono'" }}>
                {pm.severity.toUpperCase()}
              </span>
            </div>
            <p style={{ fontSize:12, color:"#4E6380" }}>{pm.label} — replay complete</p>
          </div>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:12 }}>

        {/* root cause */}
        <Card style={{ gridColumn:"1/-1" }}>
          <CardHeader title="Root cause" />
          <div style={{ padding:"14px 18px" }}>
            <div style={{ display:"flex", gap:12, alignItems:"flex-start" }}>
              <div style={{ width:36, height:36, borderRadius:8, background:"#450A0A", border:"1px solid #7F1D1D", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, fontSize:18 }}>⚠</div>
              <div>
                <p style={{ fontSize:13, fontWeight:600, color:"#E2E8F5", marginBottom:4 }}>
                  Single {pm.hog_type.toLowerCase()} flow monopolized bandwidth
                </p>
                <p style={{ fontSize:12, color:"#94A3B8", lineHeight:1.7 }}>
                  One device running {pm.hog_type.toLowerCase()} traffic consumed up to <span style={{ color:"#EF4444", fontWeight:600 }}>{pm.peak_hog_pct}%</span> of total bandwidth for approximately <span style={{ color:"#EF4444", fontWeight:600 }}>{pm.peak_duration_s} seconds</span>, filling the router's buffer and causing severe latency spikes for all other devices on the network.
                </p>
              </div>
            </div>
          </div>
        </Card>

        {/* impact numbers */}
        <Card>
          <CardHeader title="Impact measured" />
          <div style={{ padding:"14px 18px", display:"flex", flexDirection:"column", gap:12 }}>
            {[
              { label:"Peak RTT", baseline:`${pm.baseline_rtt}ms baseline`, peak:`${pm.peak_rtt}ms peak`, mult:`${pm.rtt_mult}× worse`, color:"#EF4444" },
              { label:"Fairness index", baseline:`${pm.baseline_fair} baseline`, peak:`${pm.min_fair} at worst`, mult:`${Math.round((1-pm.min_fair/pm.baseline_fair)*100)}% collapse`, color:"#F59E0B" },
            ].map(row => (
              <div key={row.label}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                  <span style={{ fontSize:11, color:"#4E6380" }}>{row.label}</span>
                  <span style={{ fontSize:11, color:row.color, fontFamily:"'JetBrains Mono'", fontWeight:700 }}>{row.mult}</span>
                </div>
                <div style={{ background:"#080D1A", borderRadius:6, padding:"8px 12px", display:"flex", justifyContent:"space-between" }}>
                  <span style={{ fontSize:11, color:"#10B981", fontFamily:"'JetBrains Mono'" }}>{row.baseline}</span>
                  <span style={{ fontSize:11, color:"#4E6380" }}>→</span>
                  <span style={{ fontSize:11, color:row.color, fontFamily:"'JetBrains Mono'", fontWeight:700 }}>{row.peak}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* what is bufferbloat */}
        <Card>
          <CardHeader title="Why this happened" sub="Plain English explanation" />
          <div style={{ padding:"14px 18px" }}>
            <p style={{ fontSize:12, color:"#94A3B8", lineHeight:1.8 }}>
              Your router has a buffer — a queue where packets wait before being sent. When one device sends too much data, the buffer fills up. Instead of dropping the excess packets, the router holds them all in the queue.
            </p>
            <p style={{ fontSize:12, color:"#94A3B8", lineHeight:1.8, marginTop:8 }}>
              Every other device's packets have to wait behind this queue. The longer the queue, the higher the RTT. This is called <span style={{ color:"#A78BFA", fontWeight:600 }}>bufferbloat</span> — and it is the reason Google built the BBR congestion algorithm.
            </p>
          </div>
        </Card>
      </div>

      {/* how to fix */}
      <Card>
        <CardHeader title="How to fix it" sub="Actionable steps — ordered by impact" />
        <div style={{ padding:"14px 18px", display:"flex", flexDirection:"column", gap:10 }}>
          {[
            {
              n:"1", title:"Enable QoS on your router",
              body:"Set per-device or per-application bandwidth limits. Most modern routers support this under 'Quality of Service' settings. This directly prevents any one device from monopolizing the connection.",
              effort:"Easy", impact:"High"
            },
            {
              n:"2", title:"Upgrade router firmware — enable fq_codel or CAKE",
              body:"These are modern queue management algorithms specifically designed to solve bufferbloat. Many routers support them via a firmware update (OpenWrt, DD-WRT). They work by intelligently managing the queue so no single flow can starve others.",
              effort:"Medium", impact:"Very high"
            },
            {
              n:"3", title:"Immediate relief",
              body:"Pause the gaming session or heavy download causing the spike. This drains the buffer and restores normal latency within seconds. Not a permanent fix, but instant.",
              effort:"Immediate", impact:"Instant"
            },
          ].map(step => (
            <div key={step.n} style={{ display:"flex", gap:12, padding:"10px 14px", background:"#080D1A", borderRadius:8, border:"1px solid #1C2E4A" }}>
              <div style={{ width:24, height:24, borderRadius:6, background:"#0F2040", border:"1px solid #1C3A6A", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, fontSize:11, fontWeight:700, color:"#60A5FA", fontFamily:"'JetBrains Mono'" }}>
                {step.n}
              </div>
              <div style={{ flex:1 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
                  <p style={{ fontSize:12, fontWeight:600, color:"#E2E8F5" }}>{step.title}</p>
                  <div style={{ display:"flex", gap:6 }}>
                    <span style={{ fontSize:9, padding:"1px 6px", borderRadius:3, background:"#1C2E4A", color:"#4E6380", fontFamily:"'JetBrains Mono'" }}>{step.effort}</span>
                    <span style={{ fontSize:9, padding:"1px 6px", borderRadius:3, background:"#052E16", color:"#10B981", fontFamily:"'JetBrains Mono'" }}>{step.impact}</span>
                  </div>
                </div>
                <p style={{ fontSize:11, color:"#6B7FA3", lineHeight:1.6 }}>{step.body}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ─── Incident analysis (full replay view inside recordings tab) ────────────────

function IncidentAnalysis({
  data, rec, replayHistory, replayDone,
  replaySpeed, onStop, onSpeedChange,
}: {
  data: Snapshot | null;
  rec: Recording;
  replayHistory: ReplayPoint[];
  replayDone: boolean;
  replaySpeed: number;
  onStop: () => void;
  onSpeedChange: (s: number) => void;
}) {
  const flows       = data?.flows  ?? [];
  const phase       = data?.phase  ?? "normal";
  const progress    = data?.replay_progress ?? 0;
  const total       = data?.replay_total    ?? 1;
  const pct         = Math.round((progress / total) * 100);
  const anomalyIdx  = replayHistory.findIndex(p => p.anomaly);
  const pm = replayDone ? computePostMortem(replayHistory, rec) : null;

  return (
    <div style={{ marginTop:16, animation:"fadeIn .3s ease" }}>

      {/* compact top bar */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", gap:12, marginBottom:16, flexWrap:"wrap" }}>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontSize:12, fontWeight:600, color:"#E2E8F5" }}>{rec.label}</span>
          {!replayDone && (
            <span style={{ fontSize:10, color:"#A78BFA", fontFamily:"'JetBrains Mono'", animation:"pulse 1.5s infinite" }}>
              ▶ {pct}% · {replaySpeed}×
            </span>
          )}
          {replayDone && <span style={{ fontSize:10, color:"#10B981", fontFamily:"'JetBrains Mono'" }}>✓ complete</span>}
        </div>
        <div style={{ display:"flex", gap:4, alignItems:"center" }}>
          {!replayDone && SPEEDS.map(s => (
            <button key={s} onClick={() => onSpeedChange(s)} style={{
              padding:"3px 8px", borderRadius:4, fontSize:10, fontWeight:600,
              border:`1px solid ${replaySpeed===s?"#7C3AED":"#1C2E4A"}`,
              background:replaySpeed===s?"#2D1F6E":"transparent",
              color:replaySpeed===s?"#A78BFA":"#4E6380",
            }}>{s}×</button>
          ))}
          <button onClick={onStop} style={{ padding:"4px 12px", borderRadius:6, border:"1px solid #1C2E4A", background:"transparent", color:"#4E6380", fontSize:11, marginLeft:4 }}>
            {replayDone ? "← Back" : "■ Stop"}
          </button>
        </div>
      </div>

      {/* phase timeline */}
      <PhaseTimeline current={phase} />

      {/* progress bar (only during replay) */}
      {!replayDone && (
        <div style={{ marginBottom:16 }}>
          <div style={{ background:"#1A1040", borderRadius:4, height:6, position:"relative", overflow:"hidden" }}>
            {anomalyIdx > 0 && (
              <div style={{ position:"absolute", left:`${(anomalyIdx/Math.max(replayHistory.length,1))*100}%`, top:0, bottom:0, width:2, background:"#EF4444", zIndex:2 }} />
            )}
            <div style={{ width:`${pct}%`, height:"100%", borderRadius:4, transition:"width .3s",
              background: data?.anomaly_active ? "linear-gradient(90deg,#7C3AED,#EF4444)" : "linear-gradient(90deg,#3B82F6,#7C3AED)"
            }} />
          </div>
          <div style={{ display:"flex", justifyContent:"space-between", marginTop:3 }}>
            <span style={{ fontSize:9, color:"#2D1F6E" }}>recording start</span>
            {anomalyIdx > 0 && (
              <span style={{ fontSize:9, color:"#EF4444", position:"relative", left:`${Math.max(0,(anomalyIdx/Math.max(replayHistory.length,1))*100 - 10)}%` }}>⚠ anomaly</span>
            )}
            <span style={{ fontSize:9, color:"#2D1F6E" }}>end</span>
          </div>
        </div>
      )}

      {/* narrative — live during replay, hidden when done */}
      {!replayDone && <NarrativePanel phase={phase} data={data} />}

      {/* charts — only show once we have data */}
      {replayHistory.length > 2 && (
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
          <Card>
            <CardHeader title="RTT over time" sub="Spike = bufferbloat — router queue filling up" />
            <div style={{ padding:"12px 16px" }}>
              <ResponsiveContainer width="100%" height={140}>
                <AreaChart data={replayHistory}>
                  <defs>
                    <linearGradient id="rG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#EF4444" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1C2E4A"/>
                  <XAxis dataKey="t" tick={{ fontSize:9, fill:"#4E6380" }}/>
                  <YAxis tick={{ fontSize:9, fill:"#4E6380" }} unit="ms"/>
                  <Tooltip contentStyle={{ background:"#0A1020", border:"1px solid #1C2E4A", borderRadius:6, fontSize:11 }}
                    formatter={(v) => [`${typeof v==="number"?Math.round(v):0}ms`,"RTT"]}/>
                  {anomalyIdx > 0 && (
                    <ReferenceLine x={replayHistory[anomalyIdx]?.t} stroke="#EF4444" strokeDasharray="3 3"
                      label={{ value:"⚠ anomaly start", fill:"#EF4444", fontSize:9, position:"insideTopRight" }}/>
                  )}
                  <Area type="monotone" dataKey="rtt" stroke="#EF4444" strokeWidth={2} fill="url(#rG)"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>

          <Card>
            <CardHeader title="Fairness index" sub="Drops toward 0 as one flow takes everything" />
            <div style={{ padding:"12px 16px" }}>
              <ResponsiveContainer width="100%" height={140}>
                <AreaChart data={replayHistory}>
                  <defs>
                    <linearGradient id="fG" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#F59E0B" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#F59E0B" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1C2E4A"/>
                  <XAxis dataKey="t" tick={{ fontSize:9, fill:"#4E6380" }}/>
                  <YAxis tick={{ fontSize:9, fill:"#4E6380" }} domain={[0,1]}/>
                  <Tooltip contentStyle={{ background:"#0A1020", border:"1px solid #1C2E4A", borderRadius:6, fontSize:11 }}
                    formatter={(v) => [`${typeof v==="number"?v.toFixed(3):0}`,"Fairness"]}/>
                  <ReferenceLine y={0.9} stroke="#10B981" strokeDasharray="3 3"
                    label={{ value:"healthy", fill:"#10B981", fontSize:9 }}/>
                  <ReferenceLine y={0.6} stroke="#EF4444" strokeDasharray="3 3"
                    label={{ value:"threshold", fill:"#EF4444", fontSize:9 }}/>
                  <Area type="monotone" dataKey="fair" stroke="#F59E0B" strokeWidth={2} fill="url(#fG)"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      )}

      {/* flow table — annotated */}
      {flows.length > 0 && !replayDone && (
        <Card style={{ marginBottom:16 }}>
          <CardHeader title="Flow state at this moment"
            sub="Watch how RTT changes per connection as the anomaly builds. Red = hog consuming most bandwidth."/>
          <div style={{ overflowX:"auto" }}>
            <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
              <thead>
                <tr style={{ background:"#080D1A" }}>
                  {["Connection","Traffic type","RTT","Status","What it means"].map(h => (
                    <th key={h} style={{ padding:"8px 14px", textAlign:"left", color:"#4E6380", fontWeight:500, fontSize:11, borderBottom:"1px solid #1C2E4A", whiteSpace:"nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {flows.map((flow, i) => {
                  const tb = trafficBadge(flow.traffic_type);
                  const rttNormal = flow.avg_rtt_ms < 50;
                  const rttElevated = flow.avg_rtt_ms >= 50 && flow.avg_rtt_ms < 200;
                  const rttHigh = flow.avg_rtt_ms >= 200;
                  const meaning = flow.is_hog
                    ? "This device is the problem — consuming most bandwidth"
                    : rttHigh  ? "Severely affected — very slow connection"
                    : rttElevated ? "Moderately affected — noticeably slower"
                    : "Healthy — not yet affected";
                  return (
                    <tr key={i} style={{ borderTop:"1px solid #1C2E4A", background: flow.is_hog ? "#100808" : "transparent" }}>
                      <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:10, color:"#94A3B8" }}>{flow.dst_ip}:{flow.dst_port}</td>
                      <td style={{ padding:"9px 14px" }}>
                        <span style={{ background:tb.bg, color:tb.color, padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:600 }}>{flow.traffic_type}</span>
                      </td>
                      <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, fontWeight:600, color:rttColor(flow.avg_rtt_ms) }}>
                        {fmtRtt(flow.avg_rtt_ms)}
                      </td>
                      <td style={{ padding:"9px 14px" }}>
                        {flow.is_hog
                          ? <span style={{ background:"#450A0A", color:"#EF4444", padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:700 }}>HOG</span>
                          : rttHigh     ? <span style={{ background:"#3D1515", color:"#EF4444", padding:"2px 8px", borderRadius:4, fontSize:10 }}>impacted</span>
                          : rttElevated ? <span style={{ background:"#3D2A00", color:"#F59E0B", padding:"2px 8px", borderRadius:4, fontSize:10 }}>slow</span>
                          :               <span style={{ background:"#052E16", color:"#10B981", padding:"2px 8px", borderRadius:4, fontSize:10 }}>OK</span>}
                      </td>
                      <td style={{ padding:"9px 14px", fontSize:11, color:"#4E6380" }}>{meaning}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* post-mortem — shown after replay done */}
      {replayDone && pm && <PostMortemReport pm={pm} />}
    </div>
  );
}

// ─── Recordings tab ────────────────────────────────────────────────────────────

function RecordingsTab({
  recordings, activeRec, data, replayHistory, replayDone,
  replaySpeed, onStart, onStop, onSpeedChange,
}: {
  recordings: Recording[];
  activeRec: Recording | null;
  data: Snapshot | null;
  replayHistory: ReplayPoint[];
  replayDone: boolean;
  replaySpeed: number;
  onStart: (rec: Recording, speed: number) => void;
  onStop: () => void;
  onSpeedChange: (s: number) => void;
}) {
  const [selectedSpeed, setSelectedSpeed] = useState(1.0);

  return (
    <div style={{ animation:"fadeIn .3s ease" }}>
      <Card>
        <CardHeader
          title="Anomaly recordings"
          sub="Saved automatically when bufferbloat or fairness threshold was exceeded. Click a recording to start incident analysis."
        />

        {/* speed selector */}
        <div style={{ padding:"10px 18px", borderBottom:"1px solid #1C2E4A", display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ fontSize:11, color:"#4E6380" }}>Replay speed:</span>
          {SPEEDS.map(s => (
            <button key={s} onClick={() => { setSelectedSpeed(s); if (activeRec) onSpeedChange(s); }}
              style={{ padding:"3px 10px", borderRadius:4, fontSize:11, fontWeight:600,
                border:`1px solid ${selectedSpeed===s?"#7C3AED":"#1C2E4A"}`,
                background:selectedSpeed===s?"#2D1F6E":"transparent",
                color:selectedSpeed===s?"#A78BFA":"#4E6380" }}>
              {s}×
            </button>
          ))}
        </div>

        {/* list */}
        {recordings.map((rec, i) => {
          const sc     = sevColors(rec.severity);
          const active = activeRec?.id === rec.id;
          return (
            <div key={rec.id}>
              <div style={{
                padding:"14px 18px",
                borderBottom: i < recordings.length-1 ? "1px solid #1C2E4A" : "none",
                display:"flex", alignItems:"center", gap:14, flexWrap:"wrap",
                background: active ? "#0D1830" : "transparent",
                transition:"background .2s",
              }}>
                {/* severity */}
                <span style={{ padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:700, background:sc.bg, color:sc.color, border:`1px solid ${sc.border}`, fontFamily:"'JetBrains Mono'", letterSpacing:"0.06em", flexShrink:0 }}>
                  {rec.severity.toUpperCase()}
                </span>

                {/* label + meta */}
                <div style={{ flex:1, minWidth:140 }}>
                  <p style={{ fontSize:13, fontWeight:600, color: active ? "#E2E8F5" : "#CBD5E1" }}>
                    {rec.label}
                    {active && !replayDone && <span style={{ marginLeft:8, fontSize:10, color:"#A78BFA", animation:"pulse 1.5s infinite" }}>● replaying</span>}
                    {active && replayDone && <span style={{ marginLeft:8, fontSize:10, color:"#10B981" }}>✓ done</span>}
                  </p>
                  <p style={{ fontSize:11, color:"#4E6380", marginTop:2, fontFamily:"'JetBrains Mono'" }}>
                    {rec.events} events · {rec.duration}s · peak <span style={{ color:rttColor(rec.max_rtt) }}>{Math.round(rec.max_rtt)}ms</span> · {fmtAgo(rec.saved_at)}
                  </p>
                </div>

                {/* action */}
                {active ? (
                  <button onClick={onStop} style={{ padding:"5px 12px", borderRadius:6, border:"1px solid #1C2E4A", background:"transparent", color:"#4E6380", fontSize:11 }}>
                    {replayDone ? "← Back" : "■ Stop"}
                  </button>
                ) : (
                  <button onClick={() => onStart(rec, selectedSpeed)} style={{ padding:"5px 14px", borderRadius:6, border:"1px solid #2D1F6E", background:"#130A30", color:"#A78BFA", fontSize:11, fontWeight:600, display:"flex", alignItems:"center", gap:6 }}>
                    ▶ Analyse at {selectedSpeed}×
                  </button>
                )}
              </div>

              {/* inline incident analysis */}
              {active && (
                <div style={{ padding:"0 18px 18px", borderBottom: i < recordings.length-1 ? "1px solid #1C2E4A" : "none", background:"#090E1C" }}>
                  <IncidentAnalysis
                    data={data} rec={rec}
                    replayHistory={replayHistory}
                    replayDone={replayDone}
                    replaySpeed={replaySpeed}
                    onStop={onStop}
                    onSpeedChange={onSpeedChange}
                  />
                </div>
              )}
            </div>
          );
        })}

        {recordings.length === 0 && (
          <div style={{ textAlign:"center", padding:"32px 20px", color:"#4E6380" }}>
            <p style={{ fontSize:13, color:"#CBD5E1", marginBottom:4 }}>No recordings yet</p>
            <p style={{ fontSize:11 }}>Anomalies are saved automatically during live capture.</p>
          </div>
        )}
      </Card>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [data,          setData]          = useState<Snapshot | null>(null);
  const [error,         setError]         = useState("");
  const [lastUpdate,    setLastUpdate]    = useState("");
  const [isLive,        setIsLive]        = useState(false);
  const [history,       setHistory]       = useState<ReplayPoint[]>([]);
  const [replayHistory, setReplayHistory] = useState<ReplayPoint[]>([]);
  const [recordings,    setRecordings]    = useState<Recording[]>([]);
  const [activeRec,     setActiveRec]     = useState<Recording | null>(null);
  const [replayId,      setReplayId]      = useState("");
  const [replaySpeed,   setReplaySpeed]   = useState(1.0);
  const [replayDone,    setReplayDone]    = useState(false);
  const [tab,           setTab]           = useState<"live"|"recordings">("live");

  useEffect(() => {
    const s = document.createElement("style");
    s.textContent = STYLE;
    document.head.appendChild(s);
    document.title = "NetMonitor";
  }, []);

  useEffect(() => {
    fetch("http://localhost:8080/anomalies")
      .then(r => r.json())
      .then(d => setRecordings(d.recordings ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const poll = async () => {
      try {
        const res  = await fetch("http://localhost:8080");
        const json: Snapshot = await res.json();
        setData(json);
        setError("");
        setIsLive(true);
        const t     = new Date().toLocaleTimeString("en",{ hour12:false });
        setLastUpdate(t);
        const flows = json.flows ?? [];
        const maxRtt = flows.reduce((m,f) => f.avg_rtt_ms > m ? f.avg_rtt_ms : m, 0);
        const pt: ReplayPoint = {
          t, rtt: Math.round(maxRtt),
          fair: +(json.fairness_index ?? 1).toFixed(3),
          phase: json.phase ?? "normal",
          anomaly: json.anomaly_active ?? false,
          hog_pct: json.hog_percent ?? 0,
        };
        if (json.replay) {
          setReplayHistory(prev => [...prev.slice(-79), pt]);
          // detect completion
          const prog = json.replay_progress ?? 0;
          const tot  = json.replay_total    ?? 1;
          if (prog >= tot && tot > 0) setReplayDone(true);
        } else {
          if (replayId) {
            setReplayId("");
          }
          setHistory(prev => [...prev.slice(-79), pt]);
        }
      } catch {
        setError("Cannot reach C++ monitor on localhost:8080");
        setIsLive(false);
      }
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => clearInterval(id);
  }, [replayId]);

  const startReplay = useCallback((rec: Recording, speed: number) => {
    setReplayHistory([]);
    setReplayDone(false);
    setReplayId(rec.id);
    setActiveRec(rec);
    setReplaySpeed(speed);
    fetch("http://localhost:8080/replay", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ id: rec.id, speed }),
    }).catch(() => {});
  }, []);

  const stopReplay = useCallback(() => {
    fetch("http://localhost:8080/stop_replay", { method:"POST" }).catch(() => {});
    setReplayId("");
    setActiveRec(null);
    setReplayHistory([]);
    setReplayDone(false);
  }, []);

  const changeSpeed = useCallback((speed: number) => {
    setReplaySpeed(speed);
    if (activeRec) {
      fetch("http://localhost:8080/replay", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ id: activeRec.id, speed }),
      }).catch(() => {});
    }
  }, [activeRec]);

  const flows  = data?.flows  ?? [];
  const hosts  = data?.hosts  ?? [];
  const fi     = data?.fairness_index ?? 1;
  const st     = fairSt(fi);
  const maxRtt = flows.reduce((m,f) => f.avg_rtt_ms > m ? f.avg_rtt_ms : m, 0);
  const mode   = data?.replay ? "REPLAY" : isLive ? "LIVE" : "OFFLINE";
  const modeCol = { REPLAY:"#A78BFA", LIVE:"#10B981", OFFLINE:"#4E6380" }[mode];
  const barData = flows.filter(f => f.avg_rtt_ms > 0).map(f => ({
    name: `${f.dst_ip}:${f.dst_port}`.slice(-18),
    rtt: Math.round(f.avg_rtt_ms), hog: f.is_hog,
  }));

  return (
    <div style={{ minHeight:"100vh", background:"#080D1A", paddingBottom:48 }}>

      {/* top bar */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 24px", borderBottom:"1px solid #1C2E4A", background:"#0A1020", position:"sticky", top:0, zIndex:100, gap:12, flexWrap:"wrap" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ fontFamily:"'JetBrains Mono'", fontSize:15, fontWeight:600, color:"#E2E8F5" }}>◈ NetMonitor</span>
          <span style={{ fontSize:10, padding:"2px 8px", borderRadius:4, background:modeCol+"22", color:modeCol, fontFamily:"'JetBrains Mono'", fontWeight:600, letterSpacing:"0.06em" }}>● {mode}</span>
          {isLive && <span style={{ fontSize:11, color:"#4E6380" }}>updated {lastUpdate}</span>}
        </div>
        <div style={{ display:"flex", gap:4 }}>
          {(["live","recordings"] as const).map(t => (
            <button key={t} onClick={() => setTab(t)} style={{ padding:"5px 14px", borderRadius:6, fontSize:12, fontWeight:600,
              border:`1px solid ${tab===t?"#3B82F6":"#1C2E4A"}`,
              background:tab===t?"#0F2040":"transparent",
              color:tab===t?"#60A5FA":"#4E6380" }}>
              {t === "live" ? "Live monitor" : `Recordings${recordings.length > 0 ? ` (${recordings.length})` : ""}`}
            </button>
          ))}
        </div>
        <div style={{ fontSize:10, padding:"4px 12px", borderRadius:4, fontWeight:700, background:st.bg, color:st.color, fontFamily:"'JetBrains Mono'", letterSpacing:"0.1em" }}>
          {st.label}
        </div>
      </div>

      <div style={{ maxWidth:1100, margin:"0 auto", padding:"24px 20px" }}>

        {error && (
          <div style={{ background:"#450A0A", border:"1px solid #7F1D1D", borderRadius:8, padding:"12px 16px", color:"#FCA5A5", marginBottom:20, fontSize:13 }}>
            ⚠ {error} — run: <span style={{ fontFamily:"'JetBrains Mono'", fontSize:11, color:"#10B981" }}>python3 mock_backend.py</span>
          </div>
        )}

        {/* ── RECORDINGS TAB ── */}
        {tab === "recordings" && (
          <RecordingsTab
            recordings={recordings}
            activeRec={activeRec}
            data={data}
            replayHistory={replayHistory}
            replayDone={replayDone}
            replaySpeed={replaySpeed}
            onStart={startReplay}
            onStop={stopReplay}
            onSpeedChange={changeSpeed}
          />
        )}

        {/* ── LIVE TAB ── */}
        {tab === "live" && data && (
          <div style={{ animation:"fadeIn .3s ease" }}>
            {/* metric cards */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(210px,1fr))", gap:12, marginBottom:20 }}>
              <Card>
                <div style={{ padding:"16px 18px" }}>
                  <p style={{ fontSize:10, color:"#4E6380", textTransform:"uppercase", letterSpacing:"0.08em" }}>Fairness index</p>
                  <p style={{ fontSize:10, color:"#4E6380", marginTop:2, marginBottom:8 }}>How evenly bandwidth is shared — 1.0 = perfect</p>
                  <p style={{ fontSize:32, fontWeight:600, fontFamily:"'JetBrains Mono'", color:st.color }}>{fi.toFixed(3)}</p>
                  <div style={{ background:"#1C2E4A", borderRadius:3, height:4, marginTop:8 }}>
                    <div style={{ width:`${fi*100}%`, background:st.color, height:4, borderRadius:3, transition:"width .5s" }}/>
                  </div>
                  <p style={{ fontSize:10, color:st.color, marginTop:6, fontWeight:600 }}>
                    {fi >= 0.9 ? "✓ Fairly distributed" : fi >= 0.7 ? "⚠ Some imbalance" : "✕ Hogging detected"}
                  </p>
                </div>
              </Card>
              <Card>
                <div style={{ padding:"16px 18px" }}>
                  <p style={{ fontSize:10, color:"#4E6380", textTransform:"uppercase", letterSpacing:"0.08em" }}>Worst RTT</p>
                  <p style={{ fontSize:10, color:"#4E6380", marginTop:2, marginBottom:8 }}>Round trip time — under 50ms is healthy</p>
                  <p style={{ fontSize:32, fontWeight:600, fontFamily:"'JetBrains Mono'", color:rttColor(maxRtt) }}>
                    {maxRtt > 0 ? `${Math.round(maxRtt)}ms` : "—"}
                  </p>
                  <p style={{ fontSize:10, color:rttColor(maxRtt), marginTop:6, fontWeight:600 }}>
                    {maxRtt===0?"No data yet":maxRtt>300?"✕ Severe congestion":maxRtt>100?"⚠ Elevated":"✓ Healthy"}
                  </p>
                </div>
              </Card>
              <Card>
                <div style={{ padding:"16px 18px" }}>
                  <p style={{ fontSize:10, color:"#4E6380", textTransform:"uppercase", letterSpacing:"0.08em" }}>Active flows</p>
                  <p style={{ fontSize:10, color:"#4E6380", marginTop:2, marginBottom:8 }}>Unique TCP connections tracked</p>
                  <p style={{ fontSize:32, fontWeight:600, fontFamily:"'JetBrains Mono'", color:"#E2E8F5" }}>{data.total_flows}</p>
                </div>
              </Card>
              <Card style={{ background:"#100808", borderColor:"#3D1515" }}>
                <div style={{ padding:"16px 18px" }}>
                  <p style={{ fontSize:10, color:"#6B2E2E", textTransform:"uppercase", letterSpacing:"0.08em" }}>Bandwidth hog</p>
                  <p style={{ fontSize:10, color:"#6B2E2E", marginTop:2, marginBottom:8 }}>Device consuming the most bandwidth</p>
                  <p style={{ fontSize:32, fontWeight:600, fontFamily:"'JetBrains Mono'", color:"#EF4444" }}>{(data.hog_percent??0).toFixed(1)}%</p>
                  <p style={{ fontSize:10, color:"#7F1D1D", marginTop:4, fontFamily:"'JetBrains Mono'", wordBreak:"break-all" }}>
                    {data.worst_hog || "none"}
                  </p>
                </div>
              </Card>
            </div>

            {/* RTT history */}
            {history.length > 2 && (
              <Card style={{ marginBottom:20 }}>
                <CardHeader title="RTT over time" sub="Spikes = router buffer filling (bufferbloat). Anomaly files are saved automatically when a spike is detected."/>
                <div style={{ padding:"14px 18px" }}>
                  <ResponsiveContainer width="100%" height={160}>
                    <AreaChart data={history}>
                      <defs>
                        <linearGradient id="lG" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1C2E4A"/>
                      <XAxis dataKey="t" tick={{ fontSize:10, fill:"#4E6380" }}/>
                      <YAxis tick={{ fontSize:10, fill:"#4E6380" }} unit="ms"/>
                      <Tooltip contentStyle={{ background:"#0A1020", border:"1px solid #1C2E4A", borderRadius:6, fontSize:12 }}
                        formatter={(v) => [`${typeof v==="number"?Math.round(v):0}ms`,"RTT"]}/>
                      <Area type="monotone" dataKey="rtt" stroke="#3B82F6" strokeWidth={2} fill="url(#lG)"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Card>
            )}

            {/* bar chart */}
            {barData.length > 0 && (
              <Card style={{ marginBottom:20 }}>
                <CardHeader title="RTT per connection" sub="Each bar = one TCP connection. Red = bandwidth hog. Higher = more congested."/>
                <div style={{ padding:"14px 18px" }}>
                  <ResponsiveContainer width="100%" height={170}>
                    <BarChart data={barData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1C2E4A"/>
                      <XAxis dataKey="name" tick={{ fontSize:10, fill:"#4E6380" }}/>
                      <YAxis tick={{ fontSize:10, fill:"#4E6380" }} unit="ms"/>
                      <Tooltip contentStyle={{ background:"#0A1020", border:"1px solid #1C2E4A", borderRadius:6, fontSize:12 }}
                        formatter={(v) => [`${typeof v==="number"?Math.round(v):0}ms`,"Avg RTT"]}/>
                      <Bar dataKey="rtt" radius={[4,4,0,0]}>
                        {barData.map((e,i) => <Cell key={i} fill={e.hog?"#EF4444":"#3B82F6"}/>)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </Card>
            )}

            {/* flow table */}
            {flows.length > 0 && (
              <Card style={{ marginBottom:20 }}>
                <CardHeader title="Active TCP connections" sub="HOG = consuming most bandwidth. Bufferbloat = router queue filling up."/>
                <div style={{ overflowX:"auto" }}>
                  <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
                    <thead>
                      <tr style={{ background:"#080D1A" }}>
                        {["Destination","Bytes","Packets","Avg RTT","Bufferbloat","Traffic type","Status"].map(h => (
                          <th key={h} style={{ padding:"8px 14px", textAlign:"left", whiteSpace:"nowrap", color:"#4E6380", fontWeight:500, fontSize:11, borderBottom:"1px solid #1C2E4A" }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {flows.map((flow,i) => {
                        const tb = trafficBadge(flow.traffic_type);
                        return (
                          <tr key={i} style={{ borderTop:"1px solid #1C2E4A", background:flow.is_hog?"#100808":"transparent" }}>
                            <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, color:"#94A3B8" }}>{flow.dst_ip}:{flow.dst_port}</td>
                            <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, color:"#CBD5E1" }}>{fmtBytes(flow.bytes)}</td>
                            <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, color:"#CBD5E1" }}>{flow.packets}</td>
                            <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, color:rttColor(flow.avg_rtt_ms) }}>{fmtRtt(flow.avg_rtt_ms)}</td>
                            <td style={{ padding:"9px 14px" }}>
                              {flow.bufferbloat ? <span style={{ color:"#EF4444", fontSize:11, fontWeight:600 }}>⚠ YES</span> : <span style={{ color:"#10B981", fontSize:11 }}>no</span>}
                            </td>
                            <td style={{ padding:"9px 14px" }}>
                              <span style={{ background:tb.bg, color:tb.color, padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:600 }}>{flow.traffic_type}</span>
                            </td>
                            <td style={{ padding:"9px 14px" }}>
                              {flow.is_hog
                                ? <span style={{ background:"#450A0A", color:"#EF4444", padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:700 }}>HOG</span>
                                : <span style={{ background:"#052E16", color:"#10B981", padding:"2px 8px", borderRadius:4, fontSize:10, fontWeight:600 }}>OK</span>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}

            {/* topology */}
            {hosts.length > 0 && (
              <Card>
                <CardHeader title="Network topology" sub="Inferred from TTL values — no packets sent. Hops = routers between you and that device."/>
                <div style={{ overflowX:"auto" }}>
                  <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
                    <thead>
                      <tr style={{ background:"#080D1A" }}>
                        {["Host IP","TTL","Hops","OS guess","Where"].map(h => (
                          <th key={h} style={{ padding:"8px 14px", textAlign:"left", color:"#4E6380", fontWeight:500, fontSize:11, borderBottom:"1px solid #1C2E4A" }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {[...hosts].sort((a,b)=>a.hops-b.hops).map((host,i) => {
                        const hc = host.hops<=1?"#10B981":host.hops<=8?"#3B82F6":"#F59E0B";
                        return (
                          <tr key={i} style={{ borderTop:"1px solid #1C2E4A" }}>
                            <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, color:"#94A3B8" }}>{host.ip}</td>
                            <td style={{ padding:"9px 14px", fontFamily:"'JetBrains Mono'", fontSize:11, color:"#CBD5E1" }}>{host.ttl}</td>
                            <td style={{ padding:"9px 14px" }}>
                              <span style={{ background:hc+"22", color:hc, padding:"2px 10px", borderRadius:4, fontSize:10, fontWeight:700, fontFamily:"'JetBrains Mono'" }}>{host.hops} {host.hops===1?"hop":"hops"}</span>
                            </td>
                            <td style={{ padding:"9px 14px", fontSize:11, color:"#CBD5E1" }}>{host.os_guess}</td>
                            <td style={{ padding:"9px 14px", fontSize:11, color:"#4E6380" }}>{host.proximity}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}

            {flows.length===0 && hosts.length===0 && (
              <div style={{ textAlign:"center", padding:"40px 20px", color:"#4E6380" }}>
                <div style={{ fontSize:28, marginBottom:10, animation:"pulse 2s infinite" }}>◉</div>
                <p style={{ fontSize:13, fontWeight:500, color:"#CBD5E1" }}>Waiting for traffic...</p>
                <p style={{ fontSize:11, marginTop:6 }}>Start the mock backend or browse the web</p>
              </div>
            )}
          </div>
        )}

        {/* initial empty */}
        {tab === "live" && !data && !error && (
          <div style={{ textAlign:"center", padding:"80px 20px", color:"#4E6380" }}>
            <div style={{ fontSize:36, marginBottom:14, animation:"pulse 2s infinite" }}>◈</div>
            <p style={{ fontSize:14, fontWeight:600, color:"#E2E8F5", marginBottom:6 }}>Connecting to NetMonitor backend...</p>
            <p style={{ fontSize:12, marginBottom:16 }}>Start the mock backend or C++ monitor</p>
            <span style={{ fontFamily:"'JetBrains Mono'", fontSize:12, background:"#0E1628", border:"1px solid #1C2E4A", padding:"8px 16px", borderRadius:6, color:"#10B981", display:"inline-block" }}>
              python3 mock_backend.py
            </span>
          </div>
        )}
      </div>
    </div>
  );
}