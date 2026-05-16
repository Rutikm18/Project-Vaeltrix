"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { Menu } from "lucide-react";
import { Sidebar } from "../components/Sidebar";

/* ─── Types ─── */
interface MetricCardData {
  label: string;
  value: number;
  accent: string;
  trend: number;
}

interface AttackPath {
  id: string;
  origin: string;
  target: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  confidence: number;
  status: "VALIDATED" | "SIMULATING" | "PENDING";
}

interface Agent {
  name: string;
  status: "ACTIVE" | "THINKING" | "IDLE";
  activity: string;
}

interface ProtocolData {
  name: string;
  value: number;
}

interface ZoneData {
  name: string;
  score: number;
}

interface EvidenceBreakdown {
  label: string;
  value: number;
}

/* ─── Data ─── */
const metrics: MetricCardData[] = [
  { label: "CRITICAL PATHS", value: 14, accent: "#FF4444", trend: 12 },
  { label: "VALIDATED EXPLOITS", value: 6, accent: "#00FF88", trend: -3 },
  { label: "AD ATTACK VECTORS", value: 3, accent: "#FF9900", trend: 5 },
  { label: "DETECTION GAPS", value: 9, accent: "#00D4FF", trend: 8 },
];

const attackPaths: AttackPath[] = [
  { id: "AP-001", origin: "WS-042", target: "DC01", severity: "CRITICAL", confidence: 97, status: "VALIDATED" },
  { id: "AP-002", origin: "SVC-SQL", target: "DOMAIN ADMIN", severity: "CRITICAL", confidence: 94, status: "VALIDATED" },
  { id: "AP-003", origin: "VLAN30", target: "VLAN10", severity: "HIGH", confidence: 88, status: "SIMULATING" },
  { id: "AP-004", origin: "WS-042", target: "10.10.10.0/24", severity: "HIGH", confidence: 82, status: "SIMULATING" },
  { id: "AP-005", origin: "INT-SEG", target: "NTLM-RELAY", severity: "MEDIUM", confidence: 71, status: "PENDING" },
];

const agents: Agent[] = [
  { name: "Recon Agent", status: "ACTIVE", activity: "Enumerating 10.10.10.0/24" },
  { name: "Exploit Agent", status: "THINKING", activity: "Validating Kerberoast path..." },
  { name: "Lateral Agent", status: "IDLE", activity: "Standby" },
  { name: "AD Trust Analyzer", status: "ACTIVE", activity: "Mapping corp.local trusts" },
  { name: "Stealth Agent", status: "ACTIVE", activity: "Profiling EDR baseline" },
];

const protocols: ProtocolData[] = [
  { name: "SMB", value: 78 },
  { name: "LDAP", value: 91 },
  { name: "Kerberos", value: 65 },
  { name: "RPC", value: 43 },
];

const zones: ZoneData[] = [
  { name: "DMZ", score: 94 },
  { name: "CORP", score: 71 },
  { name: "OT", score: 88 },
  { name: "MGMT", score: 96 },
];

const evidenceBreakdown: EvidenceBreakdown[] = [
  { label: "CRITICAL", value: 97 },
  { label: "HIGH", value: 88 },
  { label: "MEDIUM", value: 71 },
];

const tickerMessages = [
  "AP-001 VALIDATED — DC01 fully compromised path confirmed",
  "Kerberoast path svc_backup → Domain Admin — 94% confidence",
  "LLMNR poisoning active — credential relay window open",
];

/* ─── SLA Data ─── */
interface SlaFinding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: string;
  slaDeadline: string;
  hoursTotal: number;
}

const SLA_FINDINGS: SlaFinding[] = [
  { id: "VAPT-CRIT-001", title: "Unconstrained Kerberos Delegation on DC01",           severity: "CRITICAL", status: "OPEN",           slaDeadline: "2026-05-11T09:32:00Z", hoursTotal: 24  },
  { id: "VAPT-CRIT-002", title: "Kerberoastable svc_backup → Domain Admin",            severity: "CRITICAL", status: "IN_REVIEW",      slaDeadline: "2026-05-11T10:14:00Z", hoursTotal: 24  },
  { id: "VAPT-HIGH-001", title: "LLMNR/NBT-NS Poisoning — NTLM Credential Relay",      severity: "HIGH",     status: "IN_REMEDIATION", slaDeadline: "2026-05-13T11:05:00Z", hoursTotal: 72  },
  { id: "VAPT-HIGH-002", title: "Lateral Movement via WMI — WS-042 to CORP",           severity: "HIGH",     status: "OPEN",           slaDeadline: "2026-05-13T14:22:00Z", hoursTotal: 72  },
  { id: "VAPT-MED-001",  title: "Network Segmentation Bypass — VLAN30 to VLAN10",      severity: "MEDIUM",   status: "VERIFIED",       slaDeadline: "2026-05-18T09:15:00Z", hoursTotal: 168 },
];

const SEV_SLA_COLOR: Record<string, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676",
};

function getSlaInfo(f: SlaFinding) {
  const due = new Date(f.slaDeadline).getTime();
  const now = Date.now();
  const totalMs = f.hoursTotal * 3_600_000;
  const leftMs = due - now;
  const pct = Math.max(0, Math.min(100, (leftMs / totalMs) * 100));
  const breached = now > due;
  const hoursLeft = Math.max(0, leftMs / 3_600_000);
  let color = "#00E676";
  if (breached || pct < 10) color = "#FF1744";
  else if (pct < 25) color = "#FF6D00";
  else if (pct < 50) color = "#FFD600";
  const label = breached ? "BREACHED" : hoursLeft < 24 ? `${Math.round(hoursLeft)}h left` : `${Math.round(hoursLeft / 24)}d left`;
  return { pct, breached, color, label, hoursLeft };
}

/* ─── Helpers ─── */
const severityColor = (s: AttackPath["severity"]) => {
  switch (s) {
    case "CRITICAL":
      return "#FF4444";
    case "HIGH":
      return "#FF9900";
    case "MEDIUM":
      return "#FFD500";
    default:
      return "#3D7A94";
  }
};

const statusColor = (s: AttackPath["status"]) => {
  switch (s) {
    case "VALIDATED":
      return "rgba(0,255,136,0.15)";
    case "SIMULATING":
      return "rgba(255,153,0,0.15)";
    case "PENDING":
      return "rgba(61,122,148,0.15)";
  }
};

const statusTextColor = (s: AttackPath["status"]) => {
  switch (s) {
    case "VALIDATED":
      return "#00FF88";
    case "SIMULATING":
      return "#FF9900";
    case "PENDING":
      return "#3D7A94";
  }
};

const barColor = (v: number) => {
  if (v >= 90) return "#00FF88";
  if (v >= 70) return "#00D4FF";
  if (v >= 50) return "#FF9900";
  return "#FF4444";
};

/* ─── Components ─── */

function StatusDot({ status }: { status: Agent["status"] }) {
  const color = status === "ACTIVE" ? "#00FF88" : status === "THINKING" ? "#FF9900" : "#3D7A94";
  return (
    <span
      className={status === "ACTIVE" || status === "THINKING" ? "animate-pulse-dot" : ""}
      style={{
        display: "inline-block",
        width: 7,
        height: 7,
        borderRadius: "50%",
        background: color,
        flexShrink: 0,
      }}
    />
  );
}

function ConfidenceBar({ value }: { value: number }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, width: 80 }}>
      <span
        style={{
          display: "inline-block",
          width: `${value}%`,
          height: 3,
          background: barColor(value),
          borderRadius: 1,
          minWidth: 2,
        }}
      />
    </div>
  );
}

/* ─── Main Page ─── */
export default function Dashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sessionTime, setSessionTime] = useState(0);
  const [tickerIndex, setTickerIndex] = useState(0);
  const [utcTime, setUtcTime] = useState("");
  const [agentsOnline, setAgentsOnline] = useState(3);
  const [criticalCount, setCriticalCount] = useState(4);
  const [opsActive, setOpsActive] = useState(3);

  /* Session Timer */
  useEffect(() => {
    const interval = setInterval(() => {
      setSessionTime((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const formatSessionTime = useCallback((seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }, []);

  /* Ticker */
  useEffect(() => {
    const interval = setInterval(() => {
      setTickerIndex((prev) => (prev + 1) % tickerMessages.length);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  /* UTC Clock */
  useEffect(() => {
    const update = () => {
      setUtcTime(new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  /* Simulated live metrics */
  useEffect(() => {
    const interval = setInterval(() => {
      setAgentsOnline((prev) => {
        const change = Math.random() > 0.7 ? (Math.random() > 0.5 ? 1 : -1) : 0;
        return Math.max(1, Math.min(5, prev + change));
      });
    }, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: "#050A0E",
        fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
        overflow: "hidden",
      }}
    >
      {/* ─── Mobile Sidebar Overlay ─── */}
      {sidebarOpen && (
        <div
          className="md:hidden"
          onClick={() => setSidebarOpen(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(5,10,14,0.75)", zIndex: 40 }}
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* ─── Main Content Wrapper ─── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* ─── Top Navbar ─── */}
        <header
          style={{
            height: 52,
            borderBottom: "1px solid #1A3A50",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 20px",
            flexShrink: 0,
            background: "#050A0E",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {/* Hamburger */}
            <button
              className="md:hidden"
              onClick={() => setSidebarOpen(true)}
              style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}
            >
              <Menu size={20} color="#00D4FF" />
            </button>
            <span
              style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 18,
                color: "#00D4FF",
                letterSpacing: 3,
              }}
            >
              ADVERSA
            </span>
            <span style={{ color: "#1A3A50", fontSize: 14 }}>|</span>
            <span
              style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 11,
                color: "#3D7A94",
              }}
            >
              AI OFFENSIVE BRAIN v0.9.1
            </span>
            <span
              className="animate-pulse-dot"
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "#00FF88",
                marginLeft: 8,
              }}
            />
            <span
              style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 11,
                color: "#00FF88",
                marginLeft: 4,
              }}
            >
              ONLINE
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>
              AGENTS {agentsOnline}/5
            </span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>
              SESSION {formatSessionTime(sessionTime)}
            </span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF4444" }}>
              CRITICAL {criticalCount}
            </span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900" }}>
              OPS ACTIVE {opsActive}
            </span>
          </div>
        </header>

        {/* ─── Main Content ─── */}
        <main
          style={{
            flex: 1,
            overflowY: "auto",
            padding: 20,
          }}
        >
          {/* SECTION A — Metric Cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: 16,
              marginBottom: 20,
            }}
          >
            {metrics.map((m) => (
              <div
                key={m.label}
                style={{
                  background: "#0D1B26",
                  border: "1px solid #1A3A50",
                  borderRadius: 6,
                  padding: "16px 20px",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    position: "absolute",
                    bottom: 0,
                    left: 0,
                    right: 0,
                    height: 2,
                    background: m.accent,
                  }}
                />
                <div
                  style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 10,
                    color: "#3D7A94",
                    textTransform: "uppercase",
                    letterSpacing: 1,
                    marginBottom: 8,
                  }}
                >
                  {m.label}
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                  }}
                >
                  <span
                    style={{
                      fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
                      fontSize: 28,
                      fontWeight: 700,
                      color: m.accent,
                      lineHeight: 1,
                    }}
                  >
                    {m.value}
                  </span>
                  <span
                    style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 11,
                      color: m.trend >= 0 ? "#00FF88" : "#FF4444",
                    }}
                  >
                    {m.trend >= 0 ? "↑" : "↓"} {Math.abs(m.trend)}%
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* SECTION SLA — SLA Tracking Dashboard */}
          {(() => {
            const breachedItems = SLA_FINDINGS.filter((f) => getSlaInfo(f).breached);
            const riskItems     = SLA_FINDINGS.filter((f) => { const s = getSlaInfo(f); return !s.breached && s.pct < 25; });
            const upcoming48h   = SLA_FINDINGS.filter((f) => { const s = getSlaInfo(f); return !s.breached && s.hoursLeft <= 48; });
            const byStatus: Record<string, { on: number; breached: number }> = {};
            for (const f of SLA_FINDINGS) {
              const s = getSlaInfo(f);
              if (!byStatus[f.severity]) byStatus[f.severity] = { on: 0, breached: 0 };
              s.breached ? byStatus[f.severity].breached++ : byStatus[f.severity].on++;
            }
            return (
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", letterSpacing: 2, marginBottom: 10 }}>SLA TRACKING</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10, marginBottom: 14 }}>
                  {[
                    { label: "SLA BREACHED",    value: breachedItems.length, color: "#FF1744", pulse: breachedItems.length > 0 },
                    { label: "BREACH RISK",      value: riskItems.length,     color: "#FF6D00", pulse: false },
                    { label: "DUE IN 48H",       value: upcoming48h.length,   color: "#FFD600", pulse: false },
                    { label: "ON TRACK",         value: SLA_FINDINGS.filter((f) => !getSlaInfo(f).breached && getSlaInfo(f).pct >= 25).length, color: "#00E676", pulse: false },
                  ].map((m) => (
                    <div key={m.label} style={{ background: "#0D1B26", border: `1px solid ${m.color}25`, borderRadius: 6, padding: "12px 14px", position: "relative", overflow: "hidden" }}>
                      <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 2, background: m.color }} />
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", letterSpacing: 1, marginBottom: 6 }}>{m.label}</div>
                      <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 26, fontWeight: 700, color: m.color, lineHeight: 1 }} className={m.pulse ? "animate-glow-critical" : ""}>
                        {m.value}
                      </div>
                    </div>
                  ))}
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 0.55fr", gap: 12 }}>
                  {/* Left: finding-level SLA status */}
                  <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                    <div style={{ padding: "10px 14px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", letterSpacing: 1 }}>
                      FINDING SLA STATUS
                    </div>
                    <div style={{ padding: "4px 0" }}>
                      {SLA_FINDINGS.map((f) => {
                        const s = getSlaInfo(f);
                        return (
                          <div key={f.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 14px", borderBottom: "1px solid rgba(26,58,80,0.25)" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: SEV_SLA_COLOR[f.severity], width: 58, flexShrink: 0 }}>{f.severity}</span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 12, color: "#C8E8F0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.title}</div>
                              <div style={{ height: 2, background: "#1A3A50", borderRadius: 1, marginTop: 4, overflow: "hidden" }}>
                                <div className={s.breached ? "sla-pulse" : "progress-bar-fill"} style={{ height: "100%", width: `${s.pct}%`, background: s.color, borderRadius: 1 }} />
                              </div>
                            </div>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: s.color, flexShrink: 0, minWidth: 72, textAlign: "right" }}>{s.label}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Right: SLA by severity */}
                  <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                    <div style={{ padding: "10px 14px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", letterSpacing: 1 }}>
                      SLA BY SEVERITY
                    </div>
                    <div style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 14 }}>
                      {(["CRITICAL", "HIGH", "MEDIUM"] as const).map((sev) => {
                        const stats = byStatus[sev] ?? { on: 0, breached: 0 };
                        const total = stats.on + stats.breached;
                        const pct = total === 0 ? 100 : Math.round((stats.on / total) * 100);
                        return (
                          <div key={sev}>
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: SEV_SLA_COLOR[sev] }}>{sev}</span>
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: pct === 100 ? "#00E676" : pct === 0 ? "#FF1744" : "#FFD600" }}>{pct}% on-time</span>
                            </div>
                            <div style={{ height: 4, background: "#1A3A50", borderRadius: 2, overflow: "hidden" }}>
                              <div className="progress-bar-fill" style={{ height: "100%", width: `${pct}%`, background: pct === 100 ? "#00E676" : pct === 0 ? "#FF1744" : "#FFD600", borderRadius: 2 }} />
                            </div>
                            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginTop: 3 }}>
                              {stats.breached > 0 ? `${stats.breached} breached` : "No breaches"} · {total} total
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* SECTION B — Two Columns */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 0.4fr",
              gap: 16,
              marginBottom: 20,
            }}
          >
            {/* LEFT: Attack Paths Table */}
            <div
              style={{
                background: "#0D1B26",
                border: "1px solid #1A3A50",
                borderRadius: 6,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "12px 16px",
                  borderBottom: "1px solid #1A3A50",
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#C8E8F0",
                  letterSpacing: 1,
                }}
              >
                ATTACK PATHS
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["PATH ID", "ORIGIN → TARGET", "SEVERITY", "CONFIDENCE", "STATUS"].map((h) => (
                        <th
                          key={h}
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: "#3D7A94",
                            textTransform: "uppercase",
                            letterSpacing: 1,
                            padding: "10px 12px",
                            textAlign: "left",
                            borderBottom: "1px solid #1A3A50",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {attackPaths.map((path, i) => (
                      <tr
                        key={path.id}
                        style={{
                          transition: "background 0.15s ease",
                        }}
                        className="hover:bg-[rgba(0,212,255,0.02)]"
                      >
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 11,
                            color: "#00D4FF",
                            borderBottom: i < attackPaths.length - 1 ? "1px solid rgba(26,58,80,0.3)" : "none",
                          }}
                        >
                          {path.id}
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 11,
                            color: "#C8E8F0",
                            borderBottom: i < attackPaths.length - 1 ? "1px solid rgba(26,58,80,0.3)" : "none",
                            whiteSpace: "nowrap",
                          }}
                        >
                          <span style={{ color: "#3D7A94" }}>{path.origin}</span>
                          <span style={{ color: "#1A3A50", margin: "0 6px" }}>→</span>
                          <span style={{ color: "#C8E8F0" }}>{path.target}</span>
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            borderBottom: i < attackPaths.length - 1 ? "1px solid rgba(26,58,80,0.3)" : "none",
                          }}
                        >
                          <span
                            style={{
                              fontFamily: "'Share Tech Mono', monospace",
                              fontSize: 10,
                              padding: "2px 8px",
                              borderRadius: 4,
                              background: `${severityColor(path.severity)}15`,
                              color: severityColor(path.severity),
                              letterSpacing: 0.5,
                            }}
                          >
                            {path.severity}
                          </span>
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            borderBottom: i < attackPaths.length - 1 ? "1px solid rgba(26,58,80,0.3)" : "none",
                          }}
                        >
                          <ConfidenceBar value={path.confidence} />
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            borderBottom: i < attackPaths.length - 1 ? "1px solid rgba(26,58,80,0.3)" : "none",
                          }}
                        >
                          <span
                            style={{
                              fontFamily: "'Share Tech Mono', monospace",
                              fontSize: 10,
                              padding: "2px 8px",
                              borderRadius: 4,
                              background: statusColor(path.status),
                              color: statusTextColor(path.status),
                              letterSpacing: 0.5,
                            }}
                          >
                            {path.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* RIGHT: Multi-Agent Framework */}
            <div
              style={{
                background: "#0D1B26",
                border: "1px solid #1A3A50",
                borderRadius: 6,
                overflow: "hidden",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div
                style={{
                  padding: "12px 16px",
                  borderBottom: "1px solid #1A3A50",
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#C8E8F0",
                  letterSpacing: 1,
                }}
              >
                MULTI-AGENT FRAMEWORK
              </div>
              <div style={{ padding: "8px 0", flex: 1 }}>
                {agents.map((agent, i) => (
                  <div
                    key={agent.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: "10px 16px",
                      borderBottom: i < agents.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none",
                      transition: "background 0.15s ease",
                      cursor: "default",
                    }}
                    className="hover:bg-[rgba(0,212,255,0.02)]"
                  >
                    <StatusDot status={agent.status} />
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div
                        style={{
                          fontFamily: "'Share Tech Mono', monospace",
                          fontSize: 12,
                          color: "#C8E8F0",
                          letterSpacing: 0.3,
                        }}
                      >
                        {agent.name}
                      </div>
                      <div
                        style={{
                          fontFamily: "'Share Tech Mono', monospace",
                          fontSize: 10,
                          color: "#3D7A94",
                          marginTop: 2,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {agent.activity}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* SECTION C — Three Columns */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: 16,
            }}
          >
            {/* Col 1 — Protocol Abuse Engine */}
            <div
              style={{
                background: "#0D1B26",
                border: "1px solid #1A3A50",
                borderRadius: 6,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "12px 16px",
                  borderBottom: "1px solid #1A3A50",
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#C8E8F0",
                  letterSpacing: 1,
                }}
              >
                PROTOCOL ABUSE ENGINE
              </div>
              <div style={{ padding: "8px 0" }}>
                {protocols.map((p, i) => (
                  <div
                    key={p.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      padding: "10px 16px",
                      borderBottom: i < protocols.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none",
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 12,
                        color: "#C8E8F0",
                        width: 60,
                        flexShrink: 0,
                      }}
                    >
                      {p.name}
                    </span>
                    <div
                      style={{
                        flex: 1,
                        height: 3,
                        background: "rgba(26,58,80,0.3)",
                        borderRadius: 1,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          height: "100%",
                          width: `${p.value}%`,
                          background: barColor(p.value),
                          borderRadius: 1,
                        }}
                      />
                    </div>
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 11,
                        color: barColor(p.value),
                        width: 35,
                        textAlign: "right",
                        flexShrink: 0,
                      }}
                    >
                      {p.value}%
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Col 2 — Segmentation Validator */}
            <div
              style={{
                background: "#0D1B26",
                border: "1px solid #1A3A50",
                borderRadius: 6,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  padding: "12px 16px",
                  borderBottom: "1px solid #1A3A50",
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#C8E8F0",
                  letterSpacing: 1,
                }}
              >
                SEGMENTATION VALIDATOR
              </div>
              <div style={{ padding: "8px 0" }}>
                {zones.map((z, i) => (
                  <div
                    key={z.name}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      padding: "10px 16px",
                      borderBottom: i < zones.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none",
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 12,
                        color: "#C8E8F0",
                        width: 50,
                        flexShrink: 0,
                      }}
                    >
                      {z.name}
                    </span>
                    <div
                      style={{
                        flex: 1,
                        height: 3,
                        background: "rgba(26,58,80,0.3)",
                        borderRadius: 1,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          height: "100%",
                          width: `${z.score}%`,
                          background: barColor(z.score),
                          borderRadius: 1,
                        }}
                      />
                    </div>
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 11,
                        color: barColor(z.score),
                        width: 35,
                        textAlign: "right",
                        flexShrink: 0,
                      }}
                    >
                      {z.score}%
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Col 3 — Evidence Confidence */}
            <div
              style={{
                background: "#0D1B26",
                border: "1px solid #1A3A50",
                borderRadius: 6,
                overflow: "hidden",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div
                style={{
                  padding: "12px 16px",
                  borderBottom: "1px solid #1A3A50",
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#C8E8F0",
                  letterSpacing: 1,
                }}
              >
                EVIDENCE CONFIDENCE
              </div>
              <div
                style={{
                  flex: 1,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  padding: "20px",
                  gap: 4,
                }}
              >
                <span
                  style={{
                    fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
                    fontSize: 48,
                    fontWeight: 700,
                    color: "#00D4FF",
                    lineHeight: 1,
                  }}
                >
                  87%
                </span>
                <span
                  style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 10,
                    color: "#3D7A94",
                    letterSpacing: 2,
                    marginTop: 4,
                  }}
                >
                  AVG CONFIDENCE
                </span>
              </div>
              <div style={{ padding: "12px 16px", borderTop: "1px solid #1A3A50" }}>
                {evidenceBreakdown.map((e) => (
                  <div
                    key={e.label}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "4px 0",
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 10,
                        color: "#3D7A94",
                      }}
                    >
                      {e.label}
                    </span>
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 11,
                        color: barColor(e.value),
                      }}
                    >
                      {e.value}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </main>

        {/* ─── Bottom Status Bar ─── */}
        <footer
          style={{
            height: 32,
            borderTop: "1px solid #1A3A50",
            background: "#0D1B26",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 20px",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
              ENGINE <span style={{ color: "#00FF88" }}>●</span> NOMINAL
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
              API <span style={{ color: "#00FF88" }}>●</span> ONLINE
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
              DB <span style={{ color: "#00FF88" }}>●</span> CONNECTED
            </span>
          </div>

          <div
            style={{
              fontFamily: "'Share Tech Mono', monospace",
              fontSize: 10,
              color: "#3D7A94",
              textAlign: "center",
              flex: 1,
              overflow: "hidden",
            }}
          >
            <span className="animate-blink">{tickerMessages[tickerIndex]}</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
              {utcTime}
            </span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
              ADVERSA v0.9.1
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
