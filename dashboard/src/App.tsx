import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

interface Flow {
  key: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  bytes: number;
  packets: number;
  avg_rtt_ms: number;
  max_rtt_ms: number;
  bufferbloat: boolean;
  is_hog: boolean;
  traffic_type: string;
  confidence: number;
  reason: string;
}

interface Host {
  ip: string;
  ttl: number;
  hops: number;
  os_guess: string;
  proximity: string;
  packets: number;
}

interface Snapshot {
  timestamp: number;
  fairness_index: number;
  total_flows: number;
  worst_hog: string;
  hog_percent: number;
  flows: Flow[];
  hosts: Host[];
}

function fairnessColor(index: number): string {
  if (index >= 0.9) return "#22c55e";
  if (index >= 0.7) return "#f59e0b";
  return "#ef4444";
}

function fmtBytes(b: number): string {
  if (b > 1_000_000) return (b / 1_000_000).toFixed(1) + " MB";
  if (b > 1_000)     return (b / 1_000).toFixed(1) + " KB";
  return b + " B";
}

function trafficColor(type: string): { bg: string; text: string } {
  switch (type) {
    case "STREAMING":     return { bg: "#eff6ff", text: "#1d4ed8" };
    case "GAMING":        return { bg: "#f0fdf4", text: "#15803d" };
    case "VOIP":          return { bg: "#fdf4ff", text: "#7e22ce" };
    case "FILE TRANSFER": return { bg: "#fff7ed", text: "#c2410c" };
    case "BROWSING":      return { bg: "#f0f9ff", text: "#0369a1" };
    default:              return { bg: "#f3f4f6", text: "#6b7280" };
  }
}

export default function App() {
  const [data, setData]             = useState<Snapshot | null>(null);
  const [error, setError]           = useState<string>("");
  const [lastUpdate, setLastUpdate] = useState<string>("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res  = await fetch("http://localhost:8080");
        const json: Snapshot = await res.json();
        setData(json);
        setError("");
        setLastUpdate(new Date().toLocaleTimeString());
      } catch {
        setError("Cannot reach C++ monitor on localhost:8080 — is it running?");
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const chartData = data?.flows
    .filter(f => f.avg_rtt_ms > 0)
    .map(f => ({
      name: f.dst_ip + ":" + f.dst_port,
      rtt:  Math.round(f.avg_rtt_ms),
      hog:  f.is_hog,
    })) ?? [];

  return (
    <div style={{ fontFamily: "sans-serif", padding: "24px",
                  maxWidth: "960px", margin: "0 auto" }}>

      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: 600, margin: 0 }}>
          Network Monitor
        </h1>
        <p style={{ color: "#6b7280", fontSize: "13px", margin: "4px 0 0" }}>
          {lastUpdate ? `Last updated: ${lastUpdate}` : "Connecting..."}
        </p>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: "#fef2f2", border: "1px solid #fca5a5",
                      borderRadius: "8px", padding: "12px 16px",
                      color: "#dc2626", marginBottom: "24px" }}>
          {error}
        </div>
      )}

      {data && (
        <>
          {/* Top stats */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr",
                        gap: "12px", marginBottom: "24px" }}>

            {/* Fairness */}
            <div style={{ background: "#f9fafb", borderRadius: "12px",
                          padding: "16px 20px", border: "1px solid #e5e7eb" }}>
              <p style={{ fontSize: "12px", color: "#6b7280", margin: "0 0 8px" }}>
                Fairness index
              </p>
              <p style={{ fontSize: "28px", fontWeight: 600, margin: 0,
                          color: fairnessColor(data.fairness_index) }}>
                {data.fairness_index.toFixed(3)}
              </p>
              <div style={{ background: "#e5e7eb", borderRadius: "4px",
                            height: "6px", marginTop: "8px" }}>
                <div style={{
                  width: (data.fairness_index * 100) + "%",
                  background: fairnessColor(data.fairness_index),
                  borderRadius: "4px", height: "6px",
                  transition: "width 0.5s ease"
                }}/>
              </div>
              <p style={{ fontSize: "11px", color: "#6b7280", margin: "6px 0 0" }}>
                {data.fairness_index >= 0.9 ? "Fair — well distributed"
                  : data.fairness_index >= 0.7 ? "Moderate — some imbalance"
                  : "Unfair — hogging detected"}
              </p>
            </div>

            {/* Active flows */}
            <div style={{ background: "#f9fafb", borderRadius: "12px",
                          padding: "16px 20px", border: "1px solid #e5e7eb" }}>
              <p style={{ fontSize: "12px", color: "#6b7280", margin: "0 0 8px" }}>
                Active flows
              </p>
              <p style={{ fontSize: "28px", fontWeight: 600, margin: 0 }}>
                {data.total_flows}
              </p>
              <p style={{ fontSize: "11px", color: "#6b7280", margin: "6px 0 0" }}>
                unique TCP connections
              </p>
            </div>

            {/* Hog */}
            <div style={{ background: "#fef2f2", borderRadius: "12px",
                          padding: "16px 20px", border: "1px solid #fca5a5" }}>
              <p style={{ fontSize: "12px", color: "#6b7280", margin: "0 0 8px" }}>
                Bandwidth hog
              </p>
              <p style={{ fontSize: "22px", fontWeight: 600, margin: 0,
                          color: "#dc2626" }}>
                {data.hog_percent.toFixed(1)}% of traffic
              </p>
              <p style={{ fontSize: "11px", color: "#6b7280", margin: "4px 0 0",
                          wordBreak: "break-all" }}>
                {data.worst_hog}
              </p>
            </div>
          </div>

          {/* RTT chart */}
          {chartData.length > 0 && (
            <div style={{ background: "#f9fafb", borderRadius: "12px",
                          padding: "16px 20px", border: "1px solid #e5e7eb",
                          marginBottom: "24px" }}>
              <p style={{ fontSize: "14px", fontWeight: 500, margin: "0 0 4px" }}>
                RTT per flow
              </p>
              <p style={{ fontSize: "12px", color: "#6b7280", margin: "0 0 16px" }}>
                Red = bandwidth hog, Purple = normal flow
              </p>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={chartData}>
                  <XAxis dataKey="name" tick={{ fontSize: 12 }}/>
                  <YAxis tick={{ fontSize: 12 }} unit="ms"/>
                  <Tooltip formatter={(v) => [v + "ms", "Avg RTT"]}/>
                  <Bar dataKey="rtt" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, i) => (
                      <Cell key={i} fill={entry.hog ? "#ef4444" : "#6366f1"}/>
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Flow table */}
          <div style={{ background: "#f9fafb", borderRadius: "12px",
                        border: "1px solid #e5e7eb", overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #e5e7eb" }}>
              <p style={{ fontSize: "14px", fontWeight: 500, margin: 0 }}>
                Flow details
              </p>
            </div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse",
                              fontSize: "13px" }}>
                <thead>
                  <tr style={{ background: "#f3f4f6" }}>
                    {["Flow", "Bytes", "Packets", "Avg RTT",
                      "Bufferbloat", "Type", "Confidence", "Status"]
                      .map(h => (
                        <th key={h} style={{ padding: "10px 16px", textAlign: "left",
                                             fontWeight: 500, color: "#374151",
                                             whiteSpace: "nowrap" }}>
                          {h}
                        </th>
                      ))}
                  </tr>
                </thead>
                <tbody>
                  {data.flows.map((flow, i) => {
                    const tc = trafficColor(flow.traffic_type);
                    return (
                      <tr key={i} style={{
                        borderTop: "1px solid #e5e7eb",
                        background: flow.is_hog ? "#fff7f7" : "white"
                      }}>
                        <td style={{ padding: "10px 16px", color: "#374151",
                                     wordBreak: "break-all", maxWidth: "180px" }}>
                          {flow.dst_ip}:{flow.dst_port}
                        </td>
                        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}>
                          {fmtBytes(flow.bytes)}
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          {flow.packets}
                        </td>
                        <td style={{ padding: "10px 16px", whiteSpace: "nowrap" }}>
                          {flow.avg_rtt_ms > 0
                            ? Math.round(flow.avg_rtt_ms) + "ms"
                            : "n/a"}
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          {flow.bufferbloat
                            ? <span style={{ color: "#dc2626", fontWeight: 500 }}>
                                YES ⚠
                              </span>
                            : <span style={{ color: "#22c55e" }}>no</span>}
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          <span style={{
                            background: tc.bg, color: tc.text,
                            padding: "2px 8px", borderRadius: "4px",
                            fontSize: "11px", fontWeight: 500,
                            whiteSpace: "nowrap"
                          }}>
                            {flow.traffic_type}
                          </span>
                        </td>
                        <td style={{ padding: "10px 16px", color: "#6b7280",
                                     fontSize: "12px" }}>
                          {flow.confidence > 0 ? flow.confidence + "%" : "—"}
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          {flow.is_hog
                            ? <span style={{ background: "#fef2f2", color: "#dc2626",
                                             padding: "2px 8px", borderRadius: "4px",
                                             fontSize: "11px", fontWeight: 500 }}>
                                HOG
                              </span>
                            : <span style={{ background: "#f0fdf4", color: "#16a34a",
                                             padding: "2px 8px", borderRadius: "4px",
                                             fontSize: "11px", fontWeight: 500 }}>
                                OK
                              </span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
          {/* Topology table */}
          {data.hosts && data.hosts.length > 0 && (
            <div style={{ background: "#f9fafb", borderRadius: "12px",
                          border: "1px solid #e5e7eb", overflow: "hidden",
                          marginTop: "24px" }}>
              <div style={{ padding: "16px 20px", borderBottom: "1px solid #e5e7eb" }}>
                <p style={{ fontSize: "14px", fontWeight: 500, margin: 0 }}>
                  Network topology
                </p>
                <p style={{ fontSize: "12px", color: "#6b7280", margin: "4px 0 0" }}>
                  Inferred from TTL values — no packets sent
                </p>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse",
                                fontSize: "13px" }}>
                  <thead>
                    <tr style={{ background: "#f3f4f6" }}>
                      {["Host IP", "TTL", "Hops", "OS guess", "Proximity", "Packets"]
                        .map(h => (
                          <th key={h} style={{ padding: "10px 16px", textAlign: "left",
                                               fontWeight: 500, color: "#374151",
                                               whiteSpace: "nowrap" }}>
                            {h}
                          </th>
                        ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[...data.hosts]
                      .sort((a, b) => a.hops - b.hops)
                      .map((host, i) => (
                        <tr key={i} style={{ borderTop: "1px solid #e5e7eb",
                                             background: "white" }}>
                          <td style={{ padding: "10px 16px", fontFamily: "monospace",
                                       color: "#374151" }}>
                            {host.ip}
                          </td>
                          <td style={{ padding: "10px 16px", color: "#6b7280" }}>
                            {host.ttl}
                          </td>
                          <td style={{ padding: "10px 16px" }}>
                            <span style={{
                              background: host.hops <= 1 ? "#f0fdf4"
                                        : host.hops <= 8 ? "#eff6ff" : "#fff7ed",
                              color: host.hops <= 1 ? "#15803d"
                                   : host.hops <= 8 ? "#1d4ed8" : "#c2410c",
                              padding: "2px 8px", borderRadius: "4px",
                              fontSize: "11px", fontWeight: 500
                            }}>
                              {host.hops} hops
                            </span>
                          </td>
                          <td style={{ padding: "10px 16px", color: "#374151" }}>
                            {host.os_guess}
                          </td>
                          <td style={{ padding: "10px 16px", color: "#6b7280" }}>
                            {host.proximity}
                          </td>
                          <td style={{ padding: "10px 16px", color: "#6b7280" }}>
                            {host.packets}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}