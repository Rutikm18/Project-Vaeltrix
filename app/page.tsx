"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import {
  Network, Activity, Shield, Cpu, ArrowRight,
  ChevronRight, Clock, BarChart2, Zap,
} from "lucide-react";
import { PageShell } from "../components/PageShell";
import { DashboardCharts } from "../components/DashboardCharts";
import { useMouseGradient } from "../hooks/useMouseGradient";

/* ─── Data ─── */
type Severity   = "CRITICAL" | "HIGH" | "MEDIUM";
type PathStatus = "VALIDATED" | "SIMULATING" | "PENDING";
type AgentStatus= "ACTIVE" | "THINKING" | "IDLE";

interface AttackPath { id: string; origin: string; target: string; severity: Severity; confidence: number; status: PathStatus; }
interface Agent      { name: string; status: AgentStatus; activity: string; }

const ATTACK_PATHS: AttackPath[] = [
  { id: "AP-001", origin: "WS-042",   target: "DC01",         severity: "CRITICAL", confidence: 97, status: "VALIDATED"  },
  { id: "AP-002", origin: "SVC-SQL",  target: "DOMAIN ADMIN", severity: "CRITICAL", confidence: 94, status: "VALIDATED"  },
  { id: "AP-003", origin: "VLAN30",   target: "VLAN10",       severity: "HIGH",     confidence: 88, status: "SIMULATING" },
  { id: "AP-004", origin: "WS-042",   target: "10.10.10.0/24",severity: "HIGH",     confidence: 82, status: "SIMULATING" },
  { id: "AP-005", origin: "INT-SEG",  target: "NTLM-RELAY",   severity: "MEDIUM",   confidence: 71, status: "PENDING"    },
];

const AGENTS: Agent[] = [
  { name: "Recon Agent",       status: "ACTIVE",   activity: "Enumerating 10.10.10.0/24"   },
  { name: "Exploit Agent",     status: "THINKING", activity: "Validating Kerberoast path…"  },
  { name: "Lateral Agent",     status: "IDLE",     activity: "Standby"                     },
  { name: "AD Trust Analyzer", status: "ACTIVE",   activity: "Mapping corp.local trusts"   },
  { name: "Stealth Agent",     status: "ACTIVE",   activity: "Profiling EDR baseline"      },
];

const SLA_FINDINGS = [
  { id: "VAPT-CRIT-001", title: "Unconstrained Kerberos Delegation on DC01",      severity: "CRITICAL" as const, status: "OPEN",           deadline: "2026-05-11T09:32:00Z", hoursTotal: 24  },
  { id: "VAPT-CRIT-002", title: "Kerberoastable svc_backup → Domain Admin",       severity: "CRITICAL" as const, status: "IN_REVIEW",      deadline: "2026-05-11T10:14:00Z", hoursTotal: 24  },
  { id: "VAPT-HIGH-001", title: "LLMNR/NBT-NS Poisoning — NTLM Credential Relay", severity: "HIGH"     as const, status: "IN_REMEDIATION", deadline: "2026-05-13T11:05:00Z", hoursTotal: 72  },
  { id: "VAPT-HIGH-002", title: "Lateral Movement via WMI — WS-042 to CORP",      severity: "HIGH"     as const, status: "OPEN",           deadline: "2026-05-13T14:22:00Z", hoursTotal: 72  },
  { id: "VAPT-MED-001",  title: "Network Segmentation Bypass — VLAN30 to VLAN10", severity: "MEDIUM"   as const, status: "VERIFIED",       deadline: "2026-05-18T09:15:00Z", hoursTotal: 168 },
];

const PROTOCOLS = [
  { name: "LDAP",     value: 91 },
  { name: "SMB",      value: 78 },
  { name: "Kerberos", value: 65 },
  { name: "RPC",      value: 43 },
];

const ZONES = [
  { name: "MGMT", score: 96 },
  { name: "DMZ",  score: 94 },
  { name: "OT",   score: 88 },
  { name: "CORP", score: 71 },
];

/* ─── Helpers ─── */
function getSla(deadline: string, hoursTotal: number) {
  const due = new Date(deadline).getTime(), now = Date.now();
  const pct = Math.max(0, Math.min(100, ((due - now) / (hoursTotal * 3_600_000)) * 100));
  const hrs = Math.max(0, (due - now) / 3_600_000);
  const breached = now > due;
  const color = breached || pct < 10 ? "var(--sev-critical-color)"
    : pct < 25 ? "var(--sev-high-color)"
    : pct < 50 ? "var(--sev-medium-color)"
    : "var(--accent)";
  const label = breached ? "BREACHED" : hrs < 24 ? `${Math.round(hrs)}h` : `${Math.round(hrs / 24)}d`;
  return { pct, breached, color, label };
}

function riskColor(v: number) {
  return v >= 85 ? "var(--sev-critical-color)" : v >= 65 ? "var(--sev-high-color)" : v >= 45 ? "var(--sev-medium-color)" : "var(--accent)";
}

const PATH_STATUS: Record<PathStatus, { color: string; bg: string }> = {
  VALIDATED:  { color: "var(--accent)",           bg: "var(--accent-ghost)"    },
  SIMULATING: { color: "var(--sev-high-color)",   bg: "var(--sev-high-bg)"     },
  PENDING:    { color: "var(--text-muted)",       bg: "var(--bg-hover)"        },
};

const SEV_LABEL: Record<Severity, { color: string; bg: string }> = {
  CRITICAL: { color: "var(--sev-critical-color)", bg: "var(--sev-critical-bg)" },
  HIGH:     { color: "var(--sev-high-color)",     bg: "var(--sev-high-bg)"     },
  MEDIUM:   { color: "var(--sev-medium-color)",   bg: "var(--sev-medium-bg)"   },
};

const AGENT_STATUS: Record<AgentStatus, { color: string; glow: string; pulse: boolean }> = {
  ACTIVE:   { color: "var(--accent)",           glow: "var(--accent-glow)",         pulse: true  },
  THINKING: { color: "var(--sev-high-color)",   glow: "var(--sev-high-glow)",       pulse: true  },
  IDLE:     { color: "var(--text-muted)",       glow: "transparent",                pulse: false },
};

/* ─── Sub-components ─── */
function SectionHeader({ icon, title, action, delay = 0 }: { icon: React.ReactNode; title: string; action?: React.ReactNode; delay?: number }) {
  return (
    <div className="stagger-item" style={{ animationDelay: `${delay}ms`, display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div style={{ color: "var(--accent)", display: "flex", transition: "transform 0.2s var(--ease-spring)" }}
          onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.transform = "scale(1.2) rotate(-5deg)"; }}
          onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = "scale(1) rotate(0deg)"; }}
        >
          {icon}
        </div>
        <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
          {title}
        </span>
      </div>
      {action}
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const color = value >= 90 ? "var(--sev-critical-color)" : value >= 75 ? "var(--sev-high-color)" : "var(--sev-medium-color)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div className="progress-track" style={{ width: 60, height: 4 }}>
        <div className="progress-fill" style={{ width: `${value}%`, background: color }} />
      </div>
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color, minWidth: 32 }}>
        {value}%
      </span>
    </div>
  );
}

/* ─── Animated card wrapper with mouse glow ─── */
function GlowCard({ children, delay = 0, style }: { children: React.ReactNode; delay?: number; style?: React.CSSProperties }) {
  const { ref, onMouseMove, onMouseLeave } = useMouseGradient<HTMLDivElement>();
  const [hovered, setHovered] = useState(false);

  return (
    <div
      ref={ref}
      onMouseMove={onMouseMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { onMouseLeave(); setHovered(false); }}
      className="stagger-item"
      style={{
        animationDelay: `${delay}ms`,
        background: "var(--bg-panel)",
        border: `0.5px solid ${hovered ? "var(--border-strong)" : "var(--border-subtle)"}`,
        borderRadius: 14,
        overflow: "hidden",
        position: "relative",
        transition: "border-color 0.18s ease, transform 0.18s var(--ease-out), box-shadow 0.2s ease",
        transform: hovered ? "translateY(-2px)" : "translateY(0)",
        boxShadow: hovered ? "var(--shadow-md)" : "none",
        ...style,
      }}
    >
      {/* Mouse-follow glow overlay */}
      <div style={{
        position: "absolute", inset: 0, borderRadius: "inherit",
        pointerEvents: "none", zIndex: 0,
        opacity: hovered ? 1 : 0,
        transition: "opacity 0.2s ease",
        background: "radial-gradient(circle at var(--glow-x, 50%) var(--glow-y, 50%), var(--accent-glow) 0%, transparent 65%)",
      } as React.CSSProperties} />
      <div style={{ position: "relative", zIndex: 1, height: "100%" }}>
        {children}
      </div>
    </div>
  );
}

/* ─── Dashboard ─── */
export default function Dashboard() {
  const [agentsOnline, setAgentsOnline] = useState(3);
  const breachedCount = SLA_FINDINGS.filter((f) => getSla(f.deadline, f.hoursTotal).breached).length;

  useEffect(() => {
    const id = setInterval(() => {
      setAgentsOnline((p) => Math.max(1, Math.min(5, p + (Math.random() > 0.7 ? (Math.random() > 0.5 ? 1 : -1) : 0))));
    }, 8000);
    return () => clearInterval(id);
  }, []);

  return (
    <PageShell
      title="Dashboard"
      subtitle="Security Overview"
      statusItems={[
        { label: "AGENTS",  value: `${agentsOnline}/5`,          color: "var(--accent)"             },
        { label: "SLA",     value: breachedCount > 0 ? `${breachedCount} BREACHED` : "ON TRACK", color: breachedCount > 0 ? "var(--sev-critical-color)" : "var(--accent)" },
        { label: "OPS",     value: "3 ACTIVE",                   color: "var(--sev-high-color)"     },
      ]}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 28 }}>

        {/* KPIs + Charts */}
        <DashboardCharts />

        {/* Separator */}
        <div style={{ height: "0.5px", background: "var(--border-subtle)" }} />

        {/* ── Attack Paths + Agent Monitor ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 16 }}>

          {/* Attack Paths */}
          <div>
            <SectionHeader delay={200} icon={<Network size={15} />} title="Attack Paths"
              action={
                <a href="/attack-graph" style={{ display: "flex", alignItems: "center", gap: 4, fontFamily: "'Inter', sans-serif", fontSize: 12, fontWeight: 500, color: "var(--accent)", textDecoration: "none", transition: "opacity 0.15s ease" }}
                  onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.7")}
                  onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
                >
                  View graph <ChevronRight size={13} />
                </a>
              }
            />
            <GlowCard delay={240}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--bg-sidebar)" }}>
                    {["Path", "Route", "Severity", "Confidence", "Status"].map((h) => (
                      <th key={h} style={{
                        padding: "9px 20px", textAlign: "left",
                        fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
                        color: "var(--text-muted)", letterSpacing: 0.3,
                        borderBottom: "0.5px solid var(--border-subtle)", whiteSpace: "nowrap",
                      }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {ATTACK_PATHS.map((p, i) => {
                    const ss  = PATH_STATUS[p.status];
                    const sev = SEV_LABEL[p.severity];
                    return (
                      <tr key={p.id} className="table-row-hover stagger-item" style={{
                        animationDelay: `${280 + i * 40}ms`,
                        borderBottom: i < ATTACK_PATHS.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                        cursor: "pointer",
                      }}>
                        <td style={{ padding: "11px 20px" }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 600, color: "var(--accent)" }}>
                            {p.id}
                          </span>
                        </td>
                        <td style={{ padding: "11px 20px", whiteSpace: "nowrap" }}>
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--text-secondary)" }}>{p.origin}</span>
                          <ArrowRight size={11} style={{ margin: "0 6px", color: "var(--text-muted)", verticalAlign: "middle" }} />
                          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--text-primary)", fontWeight: 600 }}>{p.target}</span>
                        </td>
                        <td style={{ padding: "11px 20px" }}>
                          <span style={{
                            fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
                            color: sev.color, background: sev.bg, borderRadius: 5, padding: "2px 8px",
                            textTransform: "uppercase",
                          }}>
                            {p.severity}
                          </span>
                        </td>
                        <td style={{ padding: "11px 20px" }}>
                          <ConfidenceBar value={p.confidence} />
                        </td>
                        <td style={{ padding: "11px 20px" }}>
                          <span style={{
                            fontFamily: "'Inter', sans-serif", fontSize: 11, fontWeight: 600,
                            color: ss.color, background: ss.bg, borderRadius: 6, padding: "3px 9px",
                          }}>
                            {p.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </GlowCard>
          </div>

          {/* Agent Monitor */}
          <div>
            <SectionHeader delay={220} icon={<Cpu size={15} />} title="Agent Monitor" />
            <GlowCard delay={260} style={{ height: "auto" }}>
              {AGENTS.map((agent, i) => {
                const as_ = AGENT_STATUS[agent.status];
                const [rowHovered, setRowHovered] = useState(false);
                return (
                  <div key={agent.name} className="stagger-item"
                    style={{
                      animationDelay: `${300 + i * 40}ms`,
                      display: "flex", alignItems: "center", gap: 12,
                      padding: "13px 20px",
                      borderBottom: i < AGENTS.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                      transition: "background 0.12s ease",
                      background: rowHovered ? "var(--bg-surface)" : "transparent",
                      cursor: "default",
                    }}
                    onMouseEnter={() => setRowHovered(true)}
                    onMouseLeave={() => setRowHovered(false)}
                  >
                    {/* Status dot with ring */}
                    <div className="status-dot">
                      {as_.pulse && (
                        <span className="status-dot-ring" style={{
                          background: as_.glow,
                          opacity: rowHovered ? 1 : 0.6,
                          transition: "opacity 0.2s ease",
                        }} />
                      )}
                      <span className={`status-dot-core ${as_.pulse ? "animate-pulse-dot" : ""}`}
                        style={{ background: as_.color, width: 7, height: 7 }} />
                    </div>

                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 500, color: "var(--text-primary)", marginBottom: 2 }}>
                        {agent.name}
                      </div>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {agent.activity}
                      </div>
                    </div>

                    <span style={{
                      fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700,
                      color: as_.color,
                      background: as_.pulse ? `color-mix(in srgb, ${as_.color} 12%, transparent)` : "var(--bg-hover)",
                      borderRadius: 5, padding: "2px 7px", flexShrink: 0,
                      transition: "transform 0.18s var(--ease-spring)",
                      transform: rowHovered ? "scale(1.06)" : "scale(1)",
                    }}>
                      {agent.status}
                    </span>
                  </div>
                );
              })}
            </GlowCard>
          </div>
        </div>

        {/* ── SLA + Protocol + Zone ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 240px 240px", gap: 16 }}>

          {/* SLA Tracker */}
          <div>
            <SectionHeader delay={360} icon={<Clock size={15} />} title="SLA Status" />
            <GlowCard delay={400}>
              {/* Summary strip */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", borderBottom: "0.5px solid var(--border-subtle)" }}>
                {[
                  { label: "Breached",  value: breachedCount, color: "var(--sev-critical-color)" },
                  { label: "At risk",   value: SLA_FINDINGS.filter((f) => { const s = getSla(f.deadline, f.hoursTotal); return !s.breached && s.pct < 25; }).length, color: "var(--sev-high-color)" },
                  { label: "Due <48h",  value: SLA_FINDINGS.filter((f) => { const s = getSla(f.deadline, f.hoursTotal); return !s.breached && s.pct < 50 && s.pct >= 25; }).length, color: "var(--sev-medium-color)" },
                  { label: "On track",  value: SLA_FINDINGS.filter((f) => { const s = getSla(f.deadline, f.hoursTotal); return !s.breached && s.pct >= 50; }).length, color: "var(--accent)" },
                ].map((m, i) => {
                  const [cellHovered, setCellHovered] = useState(false);
                  return (
                    <div key={m.label}
                      style={{
                        padding: "14px 16px", textAlign: "center", cursor: "default",
                        borderRight: i < 3 ? "0.5px solid var(--border-subtle)" : "none",
                        background: cellHovered ? "var(--bg-surface)" : "transparent",
                        transition: "background 0.12s ease",
                      }}
                      onMouseEnter={() => setCellHovered(true)}
                      onMouseLeave={() => setCellHovered(false)}
                    >
                      <div style={{
                        fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: m.color, lineHeight: 1, marginBottom: 4,
                        transition: "transform 0.18s var(--ease-spring)",
                        transform: cellHovered ? "scale(1.08)" : "scale(1)",
                      }}>
                        {m.value}
                      </div>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 10, color: "var(--text-muted)", fontWeight: 500 }}>
                        {m.label}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* SLA rows */}
              {SLA_FINDINGS.map((f, i) => {
                const s = getSla(f.deadline, f.hoursTotal);
                const [rowHovered, setRowHovered] = useState(false);
                return (
                  <div key={f.id} className="stagger-item"
                    style={{
                      animationDelay: `${440 + i * 40}ms`,
                      display: "flex", alignItems: "center", gap: 12, padding: "10px 20px",
                      borderBottom: i < SLA_FINDINGS.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                      transition: "background 0.12s ease",
                      background: rowHovered ? "var(--bg-surface)" : "transparent",
                      cursor: "default",
                    }}
                    onMouseEnter={() => setRowHovered(true)}
                    onMouseLeave={() => setRowHovered(false)}
                  >
                    <span style={{
                      fontFamily: "'Inter', sans-serif", fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
                      color: { CRITICAL: "var(--sev-critical-color)", HIGH: "var(--sev-high-color)", MEDIUM: "var(--sev-medium-color)" }[f.severity],
                      background: { CRITICAL: "var(--sev-critical-bg)", HIGH: "var(--sev-high-bg)", MEDIUM: "var(--sev-medium-bg)" }[f.severity],
                      borderRadius: 5, padding: "2px 7px", flexShrink: 0, textTransform: "uppercase" as const,
                    }}>
                      {f.severity}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", marginBottom: 5 }}>
                        {f.title}
                      </div>
                      <div className="progress-track" style={{ height: 3 }}>
                        <div className={`progress-fill ${s.breached ? "sla-pulse" : ""}`}
                          style={{ width: `${s.pct}%`, background: s.color }} />
                      </div>
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700, color: s.color, flexShrink: 0, minWidth: 56, textAlign: "right" }}>
                      {s.label}
                    </span>
                  </div>
                );
              })}
            </GlowCard>
          </div>

          {/* Protocol Risk */}
          <div>
            <SectionHeader delay={380} icon={<Activity size={15} />} title="Protocol Risk" />
            <GlowCard delay={420}>
              {PROTOCOLS.map((p, i) => {
                const [rowHovered, setRowHovered] = useState(false);
                return (
                  <div key={p.name} className="stagger-item"
                    style={{
                      animationDelay: `${460 + i * 40}ms`,
                      padding: "13px 20px", display: "flex", flexDirection: "column", gap: 8,
                      borderBottom: i < PROTOCOLS.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                      transition: "background 0.12s ease",
                      background: rowHovered ? "var(--bg-surface)" : "transparent",
                      cursor: "default",
                    }}
                    onMouseEnter={() => setRowHovered(true)}
                    onMouseLeave={() => setRowHovered(false)}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{p.name}</span>
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700,
                        color: riskColor(p.value),
                        transition: "transform 0.18s var(--ease-spring)",
                        transform: rowHovered ? "scale(1.1)" : "scale(1)",
                        display: "inline-block",
                      }}>
                        {p.value}%
                      </span>
                    </div>
                    <div className="progress-track" style={{ height: 5 }}>
                      <div className="progress-fill" style={{ width: `${p.value}%`, background: riskColor(p.value) }} />
                    </div>
                  </div>
                );
              })}
            </GlowCard>
          </div>

          {/* Zone Health */}
          <div>
            <SectionHeader delay={400} icon={<Shield size={15} />} title="Zone Health" />
            <GlowCard delay={440}>
              {ZONES.map((z, i) => {
                const health = z.score >= 90 ? "var(--accent)" : z.score >= 75 ? "var(--sev-medium-color)" : "var(--sev-critical-color)";
                const [rowHovered, setRowHovered] = useState(false);
                return (
                  <div key={z.name} className="stagger-item"
                    style={{
                      animationDelay: `${480 + i * 40}ms`,
                      padding: "13px 20px", display: "flex", alignItems: "center", gap: 12,
                      borderBottom: i < ZONES.length - 1 ? "0.5px solid var(--border-subtle)" : "none",
                      transition: "background 0.12s ease",
                      background: rowHovered ? "var(--bg-surface)" : "transparent",
                      cursor: "default",
                    }}
                    onMouseEnter={() => setRowHovered(true)}
                    onMouseLeave={() => setRowHovered(false)}
                  >
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: "var(--text-primary)", width: 42, flexShrink: 0 }}>
                      {z.name}
                    </span>
                    <div className="progress-track" style={{ flex: 1, height: 5 }}>
                      <div className="progress-fill" style={{ width: `${z.score}%`, background: health }} />
                    </div>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700,
                      color: health, minWidth: 32, textAlign: "right",
                      transition: "transform 0.18s var(--ease-spring)",
                      transform: rowHovered ? "scale(1.1)" : "scale(1)",
                      display: "inline-block",
                    }}>
                      {z.score}
                    </span>
                  </div>
                );
              })}
              <div style={{
                padding: "12px 20px",
                borderTop: "0.5px solid var(--border-subtle)",
                display: "flex", alignItems: "center", justifyContent: "space-between",
              }}>
                <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--text-muted)" }}>Avg confidence</span>
                <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: "var(--accent)", lineHeight: 1 }}>87%</span>
              </div>
            </GlowCard>
          </div>
        </div>

      </div>
    </PageShell>
  );
}
