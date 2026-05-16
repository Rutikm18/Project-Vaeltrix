"use client";

import React, { useState } from "react";
import { Menu, Grid, AlertTriangle } from "lucide-react";
import { Sidebar } from "../../components/Sidebar";

/* ─── Types ─── */
interface Zone {
  id: string;
  name: string;
  cidr: string;
  systems: number;
  score: number;
  status: "SECURE" | "VULNERABLE" | "MISCONFIGURED";
  controls: string[];
}

interface AclRule {
  id: string;
  sourceZone: string;
  destZone: string;
  protocol: string;
  port: string;
  action: "ALLOW" | "DENY";
  expectedAction: "ALLOW" | "DENY";
  finding: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

interface TrafficFlow {
  src: string;
  dst: string;
  protocol: string;
  observed: boolean;
  allowed: boolean;
  blocked: boolean;
  anomaly: string | null;
}

interface SegmentationFinding {
  id: string;
  title: string;
  sourceZone: string;
  destZone: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  evidence: string;
  remediation: string;
}

/* ─── Data ─── */
const zones: Zone[] = [
  {
    id: "dmz",
    name: "DMZ",
    cidr: "10.10.0.0/24",
    systems: 8,
    score: 94,
    status: "SECURE",
    controls: ["WAF", "IDS/IPS", "FW-RULE-SET-A"],
  },
  {
    id: "corp",
    name: "CORP",
    cidr: "10.10.10.0/24",
    systems: 241,
    score: 61,
    status: "MISCONFIGURED",
    controls: ["Internal FW", "NAC", "EDR"],
  },
  {
    id: "ot",
    name: "OT / ICS",
    cidr: "192.168.100.0/24",
    systems: 34,
    score: 78,
    status: "VULNERABLE",
    controls: ["Partial FW", "VLAN isolation (bypassed)"],
  },
  {
    id: "mgmt",
    name: "MGMT",
    cidr: "172.16.1.0/24",
    systems: 12,
    score: 88,
    status: "SECURE",
    controls: ["Jump host", "MFA required", "Full FW rules"],
  },
  {
    id: "dev",
    name: "DEV / TEST",
    cidr: "10.20.0.0/24",
    systems: 22,
    score: 54,
    status: "VULNERABLE",
    controls: ["Minimal segmentation", "No NAC"],
  },
];

const aclRules: AclRule[] = [
  { id: "ACL-001", sourceZone: "CORP",    destZone: "DMZ",  protocol: "TCP", port: "443",  action: "ALLOW",  expectedAction: "ALLOW",  finding: "Compliant",                    severity: "LOW"      },
  { id: "ACL-002", sourceZone: "CORP",    destZone: "MGMT", protocol: "TCP", port: "ANY",  action: "ALLOW",  expectedAction: "DENY",   finding: "VLAN CORP→MGMT unrestricted",  severity: "CRITICAL" },
  { id: "ACL-003", sourceZone: "DMZ",     destZone: "CORP", protocol: "TCP", port: "445",  action: "ALLOW",  expectedAction: "DENY",   finding: "SMB allowed from DMZ to CORP", severity: "CRITICAL" },
  { id: "ACL-004", sourceZone: "OT",      destZone: "CORP", protocol: "ANY", port: "ANY",  action: "DENY",   expectedAction: "DENY",   finding: "Compliant",                    severity: "LOW"      },
  { id: "ACL-005", sourceZone: "DEV",     destZone: "CORP", protocol: "TCP", port: "3389", action: "ALLOW",  expectedAction: "DENY",   finding: "RDP from DEV to CORP allowed", severity: "HIGH"     },
  { id: "ACL-006", sourceZone: "CORP",    destZone: "OT",   protocol: "TCP", port: "102",  action: "ALLOW",  expectedAction: "DENY",   finding: "S7comm (port 102) to OT zone", severity: "HIGH"     },
  { id: "ACL-007", sourceZone: "MGMT",    destZone: "ALL",  protocol: "TCP", port: "22",   action: "ALLOW",  expectedAction: "ALLOW",  finding: "Compliant — jump host only",  severity: "LOW"      },
];

const trafficFlows: TrafficFlow[] = [
  { src: "WS-042 (CORP)",        dst: "DC01 (CORP)",          protocol: "SMB/445",    observed: true,  allowed: true,  blocked: false, anomaly: null },
  { src: "WS-042 (CORP)",        dst: "10.10.0.0/24 (DMZ)",   protocol: "ICMP",       observed: true,  allowed: true,  blocked: false, anomaly: "Unexpected lateral recon" },
  { src: "WEB-01 (DMZ)",         dst: "SVC-SQL (CORP)",       protocol: "TCP/1433",   observed: true,  allowed: false, blocked: false, anomaly: "SQL from DMZ — rule bypass" },
  { src: "MGMT-SRV (MGMT)",      dst: "ALL CORP",             protocol: "RDP/3389",   observed: true,  allowed: true,  blocked: false, anomaly: null },
  { src: "WS-128 (CORP)",        dst: "MGMT-SRV (MGMT)",      protocol: "SMB/445",    observed: true,  allowed: false, blocked: false, anomaly: "CORP→MGMT via SMB — pivot path" },
  { src: "OT-PLC-01 (OT)",       dst: "CORP-APP (CORP)",      protocol: "TCP/102",    observed: false, allowed: false, blocked: true,  anomaly: null },
];

const findings: SegmentationFinding[] = [
  {
    id: "SEG-001",
    title: "CORP to MGMT — Unrestricted Access (VLAN Bypass)",
    sourceZone: "CORP",
    destZone: "MGMT",
    severity: "CRITICAL",
    evidence: "ACL rule ACL-002 permits TCP ANY from CORP VLAN to MGMT VLAN. Validated via: Test-NetConnection -ComputerName MGMT-SRV -Port 3389 → TcpTestSucceeded: True",
    remediation: "Apply explicit DENY rules on MGMT VLAN ingress ACL for all CORP sources except jump host IP (172.16.1.5). Enforce MFA on all MGMT access.",
  },
  {
    id: "SEG-002",
    title: "SMB/445 Permitted from DMZ to CORP",
    sourceZone: "DMZ",
    destZone: "CORP",
    severity: "CRITICAL",
    evidence: "ACL-003: Allows TCP/445 inbound from DMZ (10.10.0.0/24) to CORP (10.10.10.0/24). Enables SMB relay from compromised DMZ host. Validated: Responder + Impacket ntlmrelayx successful relay.",
    remediation: "Block TCP/445, TCP/139, UDP/137-138 from DMZ to CORP at perimeter FW. Enable SMB signing on all CORP hosts.",
  },
  {
    id: "SEG-003",
    title: "RDP (3389) from DEV to CORP — Lateral Movement Vector",
    sourceZone: "DEV",
    destZone: "CORP",
    severity: "HIGH",
    evidence: "ACL-005: DEV VLAN (10.20.0.0/24) can reach CORP on TCP/3389. Exploitable for direct lateral movement from DEV systems without jump host. Evidence: xfreerdp successful from 10.20.0.15 to 10.10.10.42.",
    remediation: "Block all direct RDP from DEV to CORP. Enforce access via MFA-gated jump host only (172.16.1.5). Apply network segmentation via firewall VLAN policies.",
  },
];

/* ─── Helpers ─── */
function scoreColor(s: number) {
  if (s >= 85) return "#00FF88";
  if (s >= 70) return "#00D4FF";
  if (s >= 55) return "#FF9900";
  return "#FF4444";
}

function sevColor(s: string) {
  if (s === "CRITICAL") return "#FF4444";
  if (s === "HIGH")     return "#FF9900";
  if (s === "MEDIUM")   return "#FFD500";
  return "#00FF88";
}

function statusIndicator(s: Zone["status"]) {
  if (s === "SECURE")        return { color: "#00FF88", label: "SECURE" };
  if (s === "MISCONFIGURED") return { color: "#FF4444", label: "MISCONFIGURED" };
  return { color: "#FF9900", label: "VULNERABLE" };
}

/* ─── Main Page ─── */
export default function SegmentationPage() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab]     = useState(0);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);

  const tabs = ["Zone Map", "ACL Analysis", "Traffic Flows", "Findings"];

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
      {sidebarOpen && (
        <div
          className="md:hidden"
          onClick={() => setSidebarOpen(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(5,10,14,0.75)", zIndex: 40 }}
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Header */}
        <header style={{ height: 52, borderBottom: "1px solid #1A3A50", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 20px", flexShrink: 0, background: "#050A0E" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button className="md:hidden" onClick={() => setSidebarOpen(true)} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
              <Menu size={20} color="#00D4FF" />
            </button>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 18, color: "#00D4FF", letterSpacing: 3 }}>ADVERSA</span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>SEGMENTATION v0.9.1</span>
            <Grid size={14} color="#00D4FF" style={{ marginLeft: 4 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF4444" }}>
              {aclRules.filter((r) => r.action !== r.expectedAction && r.severity === "CRITICAL").length} CRITICAL ACL GAPS
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900" }}>
              {zones.filter((z) => z.status !== "SECURE").length}/{zones.length} ZONES AT RISK
            </span>
          </div>
        </header>

        {/* Tabs */}
        <div style={{ display: "flex", borderBottom: "1px solid #1A3A50", flexShrink: 0 }}>
          {tabs.map((tab, i) => (
            <button key={tab} onClick={() => setActiveTab(i)} style={{ padding: "10px 20px", background: activeTab === i ? "rgba(0,212,255,0.04)" : "transparent", border: "none", borderBottom: activeTab === i ? "2px solid #00D4FF" : "2px solid transparent", color: activeTab === i ? "#C8E8F0" : "#3D7A94", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, cursor: "pointer", whiteSpace: "nowrap" }}>
              {tab}
            </button>
          ))}
        </div>

        {/* Content */}
        <main style={{ flex: 1, overflowY: "auto", padding: 20 }}>
          {/* ── Tab 0: Zone Map ── */}
          {activeTab === 0 && (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
                {zones.map((zone) => {
                  const si = statusIndicator(zone.status);
                  return (
                    <div
                      key={zone.id}
                      style={{
                        background: "#0D1B26",
                        border: `1px solid ${zone.status === "MISCONFIGURED" ? "#FF444440" : zone.status === "VULNERABLE" ? "#FF990040" : "#1A3A50"}`,
                        borderRadius: 6,
                        padding: "16px",
                        position: "relative",
                        overflow: "hidden",
                      }}
                    >
                      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: si.color }} />
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                        <div>
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 14, color: "#C8E8F0", letterSpacing: 1 }}>{zone.name}</div>
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginTop: 2 }}>{zone.cidr}</div>
                        </div>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: si.color, padding: "2px 8px", border: `1px solid ${si.color}40`, borderRadius: 3 }}>{si.label}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                        <div style={{ flex: 1, height: 4, background: "rgba(26,58,80,0.5)", borderRadius: 2, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${zone.score}%`, background: scoreColor(zone.score) }} />
                        </div>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: scoreColor(zone.score), width: 36 }}>{zone.score}%</span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>Systems</span>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0" }}>{zone.systems}</span>
                      </div>
                      <div>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginBottom: 6 }}>CONTROLS</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {zone.controls.map((c) => (
                            <span key={c} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8.5, color: "#3D7A94", padding: "2px 6px", border: "1px solid #1A3A50", borderRadius: 3 }}>{c}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Zone-to-zone matrix */}
              <div style={{ marginTop: 20, background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                  ZONE COMMUNICATION MATRIX
                </div>
                <div style={{ padding: 16, overflowX: "auto" }}>
                  <table style={{ borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        <th style={{ width: 80, fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>FROM \ TO</th>
                        {zones.map((z) => (
                          <th key={z.id} style={{ padding: "4px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", textAlign: "center" }}>{z.name}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {zones.map((srcZone) => (
                        <tr key={srcZone.id}>
                          <td style={{ padding: "8px 0", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>{srcZone.name}</td>
                          {zones.map((dstZone) => {
                            if (srcZone.id === dstZone.id) return (
                              <td key={dstZone.id} style={{ padding: "8px 12px", textAlign: "center" }}>
                                <span style={{ color: "#1A3A50", fontSize: 10 }}>—</span>
                              </td>
                            );
                            const rule = aclRules.find(
                              (r) =>
                                r.sourceZone.toUpperCase() === srcZone.name.toUpperCase() &&
                                r.destZone.toUpperCase() === dstZone.name.toUpperCase()
                            );
                            const isMismatch = rule && rule.action !== rule.expectedAction;
                            return (
                              <td key={dstZone.id} style={{ padding: "8px 12px", textAlign: "center" }}>
                                <span
                                  style={{
                                    fontFamily: "'Share Tech Mono', monospace",
                                    fontSize: 9,
                                    padding: "2px 6px",
                                    borderRadius: 3,
                                    background: !rule ? "rgba(61,122,148,0.15)" : isMismatch ? "#FF444425" : rule.action === "ALLOW" ? "#00D4FF15" : "#1A3A50",
                                    color: !rule ? "#3D7A94" : isMismatch ? "#FF4444" : rule.action === "ALLOW" ? "#00D4FF" : "#3D7A94",
                                  }}
                                >
                                  {!rule ? "–" : isMismatch ? "GAP" : rule.action}
                                </span>
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ── Tab 1: ACL Analysis ── */}
          {activeTab === 1 && (
            <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                FIREWALL ACL RULE AUDIT
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["RULE ID", "SRC ZONE", "DST ZONE", "PROTO", "PORT", "ACTUAL", "EXPECTED", "STATUS", "FINDING"].map((h) => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {aclRules.map((rule, i) => {
                      const mismatch = rule.action !== rule.expectedAction;
                      return (
                        <tr key={rule.id} style={{ background: mismatch ? "rgba(255,68,68,0.02)" : "transparent" }}>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00D4FF", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.id}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.sourceZone}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.destZone}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.protocol}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.port}</td>
                          <td style={{ padding: "10px 12px", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: rule.action === "ALLOW" ? "#00D4FF" : "#3D7A94", padding: "1px 5px", border: "1px solid currentColor", borderRadius: 3 }}>{rule.action}</span>
                          </td>
                          <td style={{ padding: "10px 12px", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", padding: "1px 5px", border: "1px solid #1A3A50", borderRadius: 3 }}>{rule.expectedAction}</span>
                          </td>
                          <td style={{ padding: "10px 12px", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            {mismatch ? (
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: sevColor(rule.severity), padding: "1px 5px", background: `${sevColor(rule.severity)}20`, borderRadius: 3 }}>MISMATCH</span>
                            ) : (
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00FF88" }}>OK</span>
                            )}
                          </td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: mismatch ? sevColor(rule.severity) : "#3D7A94", borderBottom: i < aclRules.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.finding}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Tab 2: Traffic Flows ── */}
          {activeTab === 2 && (
            <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                OBSERVED TRAFFIC FLOWS
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["SOURCE", "DESTINATION", "PROTOCOL", "OBSERVED", "ALLOWED", "ANOMALY"].map((h) => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", letterSpacing: 1 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {trafficFlows.map((flow, i) => (
                      <tr key={i} style={{ background: flow.anomaly ? "rgba(255,153,0,0.02)" : "transparent" }}>
                        <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < trafficFlows.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{flow.src}</td>
                        <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < trafficFlows.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{flow.dst}</td>
                        <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < trafficFlows.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{flow.protocol}</td>
                        <td style={{ padding: "10px 12px", borderBottom: i < trafficFlows.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: flow.observed ? "#00FF88" : "#3D7A94" }}>{flow.observed ? "YES" : "NO"}</span>
                        </td>
                        <td style={{ padding: "10px 12px", borderBottom: i < trafficFlows.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: flow.allowed ? "#00D4FF" : flow.blocked ? "#00FF88" : "#FF4444" }}>
                            {flow.blocked ? "BLOCKED" : flow.allowed ? "ALLOWED" : "BYPASS"}
                          </span>
                        </td>
                        <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: flow.anomaly ? "#FF9900" : "#3D7A94", borderBottom: i < trafficFlows.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          {flow.anomaly ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Tab 3: Findings ── */}
          {activeTab === 3 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {findings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    background: "#0D1B26",
                    border: `1px solid ${selectedFinding === f.id ? sevColor(f.severity) + "60" : "#1A3A50"}`,
                    borderLeft: `3px solid ${sevColor(f.severity)}`,
                    borderRadius: 6,
                    overflow: "hidden",
                    cursor: "pointer",
                    transition: "border-color 0.15s",
                  }}
                  onClick={() => setSelectedFinding(selectedFinding === f.id ? null : f.id)}
                >
                  <div style={{ padding: "12px 16px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00D4FF" }}>{f.id}</span>
                      <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 14, fontWeight: 500, color: "#C8E8F0" }}>{f.title}</span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>{f.sourceZone} → {f.destZone}</span>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: sevColor(f.severity), padding: "2px 6px", background: `${sevColor(f.severity)}20`, borderRadius: 3 }}>{f.severity}</span>
                    </div>
                  </div>
                  {selectedFinding === f.id && (
                    <div style={{ padding: "0 16px 16px 16px", borderTop: "1px solid #1A3A50" }}>
                      <div style={{ paddingTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
                        <div>
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginBottom: 4, letterSpacing: 1 }}>EVIDENCE</div>
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0", lineHeight: 1.6, background: "#050A0E", padding: "8px 12px", borderRadius: 4, border: "1px solid #1A3A50" }}>
                            {f.evidence}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginBottom: 4, letterSpacing: 1 }}>REMEDIATION</div>
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00D4FF", lineHeight: 1.6, background: "#050A0E", padding: "8px 12px", borderRadius: 4, border: "1px solid #1A3A50" }}>
                            {f.remediation}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </main>

        {/* Footer */}
        <footer style={{ height: 32, borderTop: "1px solid #1A3A50", background: "#0D1B26", display: "flex", alignItems: "center", padding: "0 20px", gap: 16, flexShrink: 0 }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>ZONES: <span style={{ color: "#C8E8F0" }}>{zones.length}</span></span>
          <span style={{ color: "#1A3A50" }}>|</span>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>ACL GAPS: <span style={{ color: "#FF4444" }}>{aclRules.filter((r) => r.action !== r.expectedAction).length}</span></span>
          <span style={{ color: "#1A3A50" }}>|</span>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>ANOMALOUS FLOWS: <span style={{ color: "#FF9900" }}>{trafficFlows.filter((f) => f.anomaly).length}</span></span>
        </footer>
      </div>
    </div>
  );
}
