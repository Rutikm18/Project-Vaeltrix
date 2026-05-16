"use client";

import React, { useState } from "react";
import { Menu, Eye, Shield } from "lucide-react";
import { Sidebar } from "../../components/Sidebar";

/* ─── Types ─── */
interface DetectionTool {
  name: string;
  type: string;
  vendor: string;
  coverage: number;
  status: "ACTIVE" | "PARTIAL" | "INACTIVE";
}

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  detected: "FULL" | "PARTIAL" | "GAP" | "N/A";
  tool: string;
  ruleId: string;
  findingRef: string | null;
  recommendation: string;
}

interface DetectionGap {
  id: string;
  technique: string;
  ttpId: string;
  tactic: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
  recommendation: string;
  logSource: string;
}

interface AlertTuning {
  ruleName: string;
  tool: string;
  falsePositiveRate: string;
  status: "NOISY" | "GOOD" | "TUNING_NEEDED";
  suggestion: string;
}

/* ─── Data ─── */
const detectionStack: DetectionTool[] = [
  { name: "CrowdStrike Falcon",   type: "EDR",          vendor: "CrowdStrike",  coverage: 72, status: "ACTIVE"   },
  { name: "Splunk SIEM",          type: "SIEM",         vendor: "Splunk",       coverage: 58, status: "ACTIVE"   },
  { name: "Palo Alto NGFW",       type: "NDR/FW",       vendor: "Palo Alto",    coverage: 81, status: "ACTIVE"   },
  { name: "Tenable.io",           type: "VM Scanner",   vendor: "Tenable",      coverage: 94, status: "ACTIVE"   },
  { name: "Darktrace",            type: "AI-NDR",       vendor: "Darktrace",    coverage: 44, status: "PARTIAL"  },
  { name: "Microsoft Sentinel",   type: "SIEM/SOAR",    vendor: "Microsoft",    coverage: 0,  status: "INACTIVE" },
];

const mitreTechniques: MitreTechnique[] = [
  { id: "T1557.001", name: "LLMNR/NBT-NS Poisoning",          tactic: "Credential Access",  detected: "GAP",     tool: "—",              ruleId: "—",              findingRef: "VAPT-HIGH-001", recommendation: "Zeek/Suricata LLMNR response anomaly + Splunk ES alert on LDAP traffic from non-DC hosts" },
  { id: "T1558.003", name: "Kerberoasting",                   tactic: "Credential Access",  detected: "PARTIAL", tool: "Splunk",          ruleId: "KRBTGT-TGS-001", findingRef: "VAPT-CRIT-002", recommendation: "Tune Splunk rule to alert on >5 TGS-REQ per hour from single non-DC source (Event 4769)" },
  { id: "T1134.001", name: "Token Impersonation",             tactic: "Privilege Escalation",detected: "GAP",     tool: "—",              ruleId: "—",              findingRef: "VAPT-CRIT-001", recommendation: "CrowdStrike custom IOA: detect CreateToken / DuplicateTokenEx calls outside approved processes" },
  { id: "T1003.006", name: "DCSync",                          tactic: "Credential Access",  detected: "FULL",    tool: "CrowdStrike",     ruleId: "CS-DCSYNC-001",  findingRef: null,            recommendation: "Already detected — confirm SIEM correlation rule exists for backup coverage" },
  { id: "T1047",     name: "Windows Management Instrumentation",tactic: "Execution",         detected: "PARTIAL", tool: "CrowdStrike",     ruleId: "CS-WMI-EXEC",    findingRef: "VAPT-HIGH-002", recommendation: "Add Splunk alert for WMI process creation from remote IPs; tune CS sensor policy for wmic.exe /node" },
  { id: "T1021.002", name: "SMB/Admin Shares",                tactic: "Lateral Movement",   detected: "PARTIAL", tool: "Splunk",          ruleId: "SMB-ADMIN-001",  findingRef: null,            recommendation: "Alert on ADMIN$ access from non-admin subnets; track IPC$ connections (Event 5145)" },
  { id: "T1021.003", name: "DCOM Remote Execution",           tactic: "Lateral Movement",   detected: "GAP",     tool: "—",              ruleId: "—",              findingRef: "VAPT-HIGH-002", recommendation: "Zeek network detection on DCOM port 135+dynamic RPC; CS behavior detection on mmc.exe spawning child processes" },
  { id: "T1550.002", name: "Pass the Hash",                   tactic: "Lateral Movement",   detected: "PARTIAL", tool: "CrowdStrike",     ruleId: "CS-PTH-DETECT",  findingRef: null,            recommendation: "Enable Splunk ES Pass-the-Hash alert (correlate 4624 LogonType 3 with unknown NTLMv1 sources)" },
  { id: "T1055",     name: "Process Injection",               tactic: "Defense Evasion",    detected: "FULL",    tool: "CrowdStrike",     ruleId: "CS-INJECT-001",  findingRef: null,            recommendation: "Good coverage — verify Splunk SIEM receives CS telemetry" },
  { id: "T1190",     name: "Exploit Public-Facing Application",tactic: "Initial Access",    detected: "PARTIAL", tool: "Palo Alto NGFW",  ruleId: "PA-CVE-BLOCK",   findingRef: null,            recommendation: "Ensure WAF rules are updated for latest CVEs; tune Palo Alto App-ID for internal web apps" },
  { id: "T1078.002", name: "Valid Accounts — Domain",         tactic: "Initial Access",     detected: "PARTIAL", tool: "Splunk",          ruleId: "AD-LOGON-001",   findingRef: null,            recommendation: "Add impossible travel detection; correlate VPN logon times with AD auth (Event 4624/4625)" },
  { id: "T1110.002", name: "Password Cracking",               tactic: "Credential Access",  detected: "GAP",     tool: "—",              ruleId: "—",              findingRef: "VAPT-CRIT-002", recommendation: "Offline cracking is undetectable by network tools — mitigate via AES256 enforcement + gMSA" },
  { id: "T1599.001", name: "Network Boundary Bridging",       tactic: "Defense Evasion",    detected: "GAP",     tool: "—",              ruleId: "—",              findingRef: "VAPT-MED-001",  recommendation: "Palo Alto/Zeek: alert on cross-VLAN flows that violate zone policy; SIEM correlation on ACL denies + bypasses" },
  { id: "T1484.002", name: "Domain Trust Modification",       tactic: "Privilege Escalation",detected: "PARTIAL", tool: "Splunk",         ruleId: "AD-TRUST-001",   findingRef: null,            recommendation: "Alert on netdom /trust and DS replication changes (Event 4706); monitor for new trust creation" },
];

const detectionGaps: DetectionGap[] = [
  {
    id: "GAP-001",
    technique: "LLMNR/NBT-NS Poisoning & NTLM Relay",
    ttpId: "T1557.001",
    tactic: "Credential Access",
    severity: "CRITICAL",
    description: "No network-level detection rule exists for LLMNR broadcast responses from non-authoritative hosts. Responder ran for 3 hours during the assessment without triggering a single alert.",
    recommendation: "Deploy Zeek network monitoring with LLMNR anomaly script; create Splunk rule: source=zeek AND proto=LLMNR AND NOT src_ip IN (authorized_dns_servers)",
    logSource: "Network flow (Zeek/NDR) — NOT present in current SIEM",
  },
  {
    id: "GAP-002",
    technique: "Token Impersonation via Unconstrained Delegation",
    ttpId: "T1134.001",
    tactic: "Privilege Escalation",
    severity: "CRITICAL",
    description: "CrowdStrike did not alert on Mimikatz sekurlsa::tickets or lsadump::dcsync during the engagement. The ASEP rule set appears misconfigured or out-of-date.",
    recommendation: "Update CS sensor policy to enable 'LSASS Memory Access' detection. Verify current policy version against CS recommended settings. Re-run baseline.",
    logSource: "CrowdStrike EDR — policy gap",
  },
  {
    id: "GAP-003",
    technique: "DCOM-based Lateral Movement",
    ttpId: "T1021.003",
    tactic: "Lateral Movement",
    severity: "HIGH",
    description: "WMI/DCOM remote execution was not detected by either CrowdStrike or Splunk during 18-host lateral movement exercise. No Process Creation events logged due to disabled audit policy.",
    recommendation: "Enable Advanced Audit Policy: Process Creation (Success). Deploy 'Advanced Audit Policy Configuration' via GPO. Enable CrowdStrike ProcessCreation telemetry forwarding to Splunk.",
    logSource: "Windows Event Log (4688) — audit policy disabled on 73% of CORP endpoints",
  },
  {
    id: "GAP-004",
    technique: "Offline Password Hash Cracking (Kerberoasting)",
    ttpId: "T1110.002",
    tactic: "Credential Access",
    severity: "HIGH",
    description: "Offline cracking of Kerberos tickets (RC4-HMAC) is fundamentally undetectable once the hash is obtained. The TGS request itself (Event 4769) is logged but not alerted.",
    recommendation: "Preventive control: enforce AES256 for all service accounts; implement gMSA. Detective control: alert on Event 4769 with Ticket Options 0x40810010 from unusual source IPs.",
    logSource: "Windows Security Event 4769 — logged but not alerted in Splunk",
  },
];

const alertTuning: AlertTuning[] = [
  { ruleName: "AD-LOGON-FAILURE-THRESHOLD", tool: "Splunk", falsePositiveRate: "HIGH (78%)", status: "NOISY",         suggestion: "Reduce scope to privileged accounts only; add time-based correlation (>10 failures in 5min from same source)" },
  { ruleName: "PROCESS-CREATION-ADMIN",     tool: "CrowdStrike", falsePositiveRate: "LOW (4%)", status: "GOOD",     suggestion: "Coverage is adequate; ensure telemetry feeds Splunk for correlation" },
  { ruleName: "SMB-ADMIN-SHARE-ACCESS",     tool: "Splunk", falsePositiveRate: "MEDIUM (41%)", status: "TUNING_NEEDED", suggestion: "Baseline normal admin share activity; whitelist IT subnets; alert only on non-business-hours or unusual users" },
  { ruleName: "LATERAL-MOVEMENT-WMI",       tool: "CrowdStrike", falsePositiveRate: "LOW (2%)", status: "TUNING_NEEDED", suggestion: "Rule exists but doesn't cover /node: parameter — update IOA query to include remote WMI invocations" },
  { ruleName: "KERBEROAST-TGS-REQUEST",     tool: "Splunk", falsePositiveRate: "MEDIUM (35%)", status: "TUNING_NEEDED", suggestion: "Add filter: TicketEncryptionType = 0x17 (RC4); alert on >3 service account TGS requests per user per hour" },
];

/* ─── Helpers ─── */
function covColor(n: number) {
  if (n >= 80) return "#00FF88";
  if (n >= 60) return "#00D4FF";
  if (n >= 40) return "#FF9900";
  if (n > 0)   return "#FF4444";
  return "#3D7A94";
}

function detColor(d: MitreTechnique["detected"]) {
  if (d === "FULL")    return "#00FF88";
  if (d === "PARTIAL") return "#FF9900";
  if (d === "GAP")     return "#FF4444";
  return "#3D7A94";
}

function sevColor(s: string) {
  if (s === "CRITICAL") return "#FF4444";
  if (s === "HIGH")     return "#FF9900";
  return "#FFD500";
}

/* ─── Main Page ─── */
export default function DetectionPage() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab]     = useState(0);
  const [tacticFilter, setTacticFilter] = useState("ALL");

  const tabs = ["Coverage Matrix", "Detection Gaps", "Alert Tuning", "Stack Status"];

  const tactics = ["ALL", "Initial Access", "Execution", "Credential Access", "Lateral Movement", "Privilege Escalation", "Defense Evasion"];

  const filteredTech = mitreTechniques.filter(
    (t) => tacticFilter === "ALL" || t.tactic === tacticFilter
  );

  const fullCoverage    = mitreTechniques.filter((t) => t.detected === "FULL").length;
  const partialCoverage = mitreTechniques.filter((t) => t.detected === "PARTIAL").length;
  const gapCount        = mitreTechniques.filter((t) => t.detected === "GAP").length;
  const overallPct      = Math.round(((fullCoverage + partialCoverage * 0.5) / mitreTechniques.length) * 100);

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
        <div className="md:hidden" onClick={() => setSidebarOpen(false)} style={{ position: "fixed", inset: 0, background: "rgba(5,10,14,0.75)", zIndex: 40 }} />
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
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>DETECTION GAPS v0.9.1</span>
            <Eye size={14} color="#00D4FF" style={{ marginLeft: 4 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00FF88" }}>FULL: {fullCoverage}</span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900" }}>PARTIAL: {partialCoverage}</span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF4444" }}>GAPS: {gapCount}</span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00D4FF" }}>COVERAGE: {overallPct}%</span>
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
          {/* ── Tab 0: Coverage Matrix ── */}
          {activeTab === 0 && (
            <div>
              {/* Summary stats */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
                {[
                  { label: "OVERALL COVERAGE",  value: `${overallPct}%`,   color: overallPct >= 70 ? "#00D4FF" : "#FF9900" },
                  { label: "FULL COVERAGE",      value: fullCoverage,       color: "#00FF88" },
                  { label: "PARTIAL COVERAGE",   value: partialCoverage,    color: "#FF9900" },
                  { label: "DETECTION GAPS",     value: gapCount,           color: "#FF4444" },
                  { label: "TECHNIQUES ASSESSED",value: mitreTechniques.length, color: "#C8E8F0" },
                ].map((s) => (
                  <div key={s.label} style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, padding: "14px 16px" }}>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginBottom: 6, letterSpacing: 1 }}>{s.label}</div>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 26, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</div>
                  </div>
                ))}
              </div>

              {/* Tactic filter */}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 14 }}>
                {tactics.map((t) => (
                  <button key={t} onClick={() => setTacticFilter(t)} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, padding: "3px 10px", borderRadius: 4, border: "1px solid", borderColor: tacticFilter === t ? "#00D4FF" : "#1A3A50", background: tacticFilter === t ? "rgba(0,212,255,0.08)" : "transparent", color: tacticFilter === t ? "#00D4FF" : "#3D7A94", cursor: "pointer" }}>
                    {t}
                  </button>
                ))}
              </div>

              {/* Matrix table */}
              <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["TECHNIQUE ID", "NAME", "TACTIC", "DETECTION", "TOOL", "RULE ID", "FINDING", "RECOMMENDATION"].map((h) => (
                          <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredTech.map((tech, i) => (
                        <tr key={tech.id} style={{ background: tech.detected === "GAP" ? "rgba(255,68,68,0.02)" : "transparent" }}>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF9900", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none", whiteSpace: "nowrap" }}>{tech.id}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none" }}>{tech.name}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none", whiteSpace: "nowrap" }}>{tech.tactic}</td>
                          <td style={{ padding: "10px 12px", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: detColor(tech.detected), padding: "2px 6px", background: `${detColor(tech.detected)}20`, borderRadius: 3 }}>{tech.detected}</span>
                          </td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none" }}>{tech.tool}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none", whiteSpace: "nowrap" }}>{tech.ruleId}</td>
                          <td style={{ padding: "10px 12px", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none" }}>
                            {tech.findingRef ? (
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#FF4444", padding: "1px 5px", border: "1px solid #FF444440", borderRadius: 3 }}>{tech.findingRef}</span>
                            ) : (
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>—</span>
                            )}
                          </td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: i < filteredTech.length - 1 ? "1px solid rgba(26,58,80,0.2)" : "none", maxWidth: 300, whiteSpace: "normal", lineHeight: 1.4 }}>{tech.recommendation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ── Tab 1: Detection Gaps ── */}
          {activeTab === 1 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {detectionGaps.map((gap) => (
                <div key={gap.id} style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderLeft: `3px solid ${sevColor(gap.severity)}`, borderRadius: 6, padding: "14px 16px" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#00D4FF" }}>{gap.id}</span>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF9900" }}>{gap.ttpId}</span>
                      <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 14, fontWeight: 600, color: "#C8E8F0" }}>{gap.technique}</span>
                    </div>
                    <div style={{ display: "flex", gap: 8 }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>{gap.tactic}</span>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: sevColor(gap.severity), padding: "1px 6px", background: `${sevColor(gap.severity)}20`, borderRadius: 3 }}>{gap.severity}</span>
                    </div>
                  </div>
                  <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 13, color: "#C8E8F0", lineHeight: 1.5, marginBottom: 10 }}>{gap.description}</div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    <div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginBottom: 4 }}>LOG SOURCE GAP</div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF4444", lineHeight: 1.5 }}>{gap.logSource}</div>
                    </div>
                    <div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00FF88", marginBottom: 4 }}>RECOMMENDATION</div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", lineHeight: 1.5 }}>{gap.recommendation}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Tab 2: Alert Tuning ── */}
          {activeTab === 2 && (
            <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                ALERT TUNING RECOMMENDATIONS
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["RULE NAME", "TOOL", "FALSE POSITIVE RATE", "STATUS", "SUGGESTION"].map((h) => (
                        <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {alertTuning.map((rule, i) => {
                      const statusColor = rule.status === "NOISY" ? "#FF4444" : rule.status === "GOOD" ? "#00FF88" : "#FF9900";
                      return (
                        <tr key={rule.ruleName}>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < alertTuning.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.ruleName}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < alertTuning.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.tool}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: rule.falsePositiveRate.includes("HIGH") ? "#FF4444" : rule.falsePositiveRate.includes("MEDIUM") ? "#FF9900" : "#00FF88", borderBottom: i < alertTuning.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{rule.falsePositiveRate}</td>
                          <td style={{ padding: "10px 12px", borderBottom: i < alertTuning.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: statusColor, padding: "2px 6px", background: `${statusColor}20`, borderRadius: 3 }}>{rule.status.replace("_", " ")}</span>
                          </td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < alertTuning.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none", lineHeight: 1.5 }}>{rule.suggestion}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Tab 3: Stack Status ── */}
          {activeTab === 3 && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 12 }}>
              {detectionStack.map((tool) => (
                <div key={tool.name} style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, padding: "16px", position: "relative", overflow: "hidden" }}>
                  <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: covColor(tool.coverage) }} />
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                    <div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 13, color: "#C8E8F0", marginBottom: 2 }}>{tool.name}</div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>{tool.vendor} · {tool.type}</div>
                    </div>
                    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: tool.status === "ACTIVE" ? "#00FF88" : tool.status === "PARTIAL" ? "#FF9900" : "#FF4444", padding: "2px 8px", border: `1px solid currentColor`, borderRadius: 3 }}>{tool.status}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ flex: 1, height: 6, background: "rgba(26,58,80,0.5)", borderRadius: 3, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${tool.coverage}%`, background: covColor(tool.coverage), transition: "width 0.6s ease" }} />
                    </div>
                    <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 14, fontWeight: 700, color: covColor(tool.coverage), width: 40 }}>
                      {tool.coverage > 0 ? `${tool.coverage}%` : "—"}
                    </span>
                  </div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginTop: 6 }}>TECHNIQUE COVERAGE</div>
                </div>
              ))}
            </div>
          )}
        </main>

        {/* Footer */}
        <footer style={{ height: 32, borderTop: "1px solid #1A3A50", background: "#0D1B26", display: "flex", alignItems: "center", padding: "0 20px", gap: 16, flexShrink: 0 }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>COVERAGE: <span style={{ color: "#00D4FF" }}>{overallPct}%</span></span>
          <span style={{ color: "#1A3A50" }}>|</span>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>GAPS: <span style={{ color: "#FF4444" }}>{gapCount}</span></span>
          <span style={{ color: "#1A3A50" }}>|</span>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>TOOLS ACTIVE: <span style={{ color: "#00FF88" }}>{detectionStack.filter((t) => t.status === "ACTIVE").length}/{detectionStack.length}</span></span>
        </footer>
      </div>
    </div>
  );
}
