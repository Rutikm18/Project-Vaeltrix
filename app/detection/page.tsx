"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Eye, Shield, AlertTriangle, Play, Copy, Check,
  ChevronDown, ChevronRight, RefreshCw, Settings,
  CheckCircle2, XCircle, MinusCircle,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type TabKey = "matrix" | "correlation" | "gaps" | "sigma" | "stack" | "siem-config";
type DetectionOutcome = "detected" | "prevented" | "missed";

interface AttackAction {
  id: string; mitreId: string; mitreTechnique: string;
  tactic: string; targetIp: string; timestamp: string; actionDetail: string;
}

interface SIEMAlert {
  id: string; source: string; timestamp: string;
  targetIp: string; mitreId: string; ruleName: string; severity: string;
  splQuery?: string; kqlQuery?: string;
}

interface EDRDetection {
  id: string; source: string; timestamp: string;
  targetIp: string; mitreId: string; alertName: string;
  prevented: boolean; confidence: number;
}

interface DetectionResult {
  attackActionId: string; mitreId: string; mitreTechnique: string;
  tactic: string; targetIp: string; timestamp: string;
  outcome: DetectionOutcome;
  matchedSiemAlerts: SIEMAlert[];
  matchedEdrDetections: EDRDetection[];
}

interface CoverageStats {
  totalTechniques: number; detected: number; prevented: number;
  missed: number; coveragePct: number;
}

interface SigmaRule {
  mitreId: string; technique: string; yaml: string;
  logSource: string; status: "stable" | "experimental";
}

interface Gap { result: DetectionResult; sigmaRule: SigmaRule; }

/* ─── Static matrix data (existing coverage matrix) ─── */
const MITRE_MATRIX = [
  { id: "T1557.001", name: "LLMNR/NBT-NS Poisoning",          tactic: "Credential Access",    detected: "GAP",     tool: "—",             ruleId: "—",              findingRef: "VAPT-HIGH-001", recommendation: "Zeek LLMNR anomaly + Splunk ES on LDAP traffic from non-DC hosts" },
  { id: "T1558.003", name: "Kerberoasting",                   tactic: "Credential Access",    detected: "PARTIAL", tool: "Splunk",         ruleId: "KRBTGT-TGS-001", findingRef: "VAPT-CRIT-002", recommendation: "Tune Splunk: alert >5 TGS-REQ/hr from single non-DC source (Event 4769)" },
  { id: "T1134.001", name: "Token Impersonation",             tactic: "Privilege Escalation", detected: "GAP",     tool: "—",             ruleId: "—",              findingRef: "VAPT-CRIT-001", recommendation: "CrowdStrike custom IOA: detect CreateToken/DuplicateTokenEx outside approved processes" },
  { id: "T1003.006", name: "DCSync",                          tactic: "Credential Access",    detected: "FULL",    tool: "CrowdStrike",    ruleId: "CS-DCSYNC-001",  findingRef: null,            recommendation: "Detected — confirm SIEM correlation backup rule exists" },
  { id: "T1047",     name: "Windows Management Instrumentation",tactic:"Execution",           detected: "PARTIAL", tool: "CrowdStrike",    ruleId: "CS-WMI-EXEC",    findingRef: "VAPT-HIGH-002", recommendation: "Add Splunk alert for WMI process creation from remote IPs" },
  { id: "T1021.002", name: "SMB/Admin Shares",                tactic: "Lateral Movement",    detected: "PARTIAL", tool: "Splunk",         ruleId: "SMB-ADMIN-001",  findingRef: null,            recommendation: "Alert on ADMIN$ from non-admin subnets; track IPC$ (Event 5145)" },
  { id: "T1021.003", name: "DCOM Remote Execution",           tactic: "Lateral Movement",    detected: "GAP",     tool: "—",             ruleId: "—",              findingRef: "VAPT-HIGH-002", recommendation: "Zeek on DCOM port 135; CS behavior on mmc.exe spawning children" },
  { id: "T1550.002", name: "Pass the Hash",                   tactic: "Lateral Movement",    detected: "PARTIAL", tool: "CrowdStrike",    ruleId: "CS-PTH-DETECT",  findingRef: null,            recommendation: "Enable Splunk ES PTH alert (4624 LogonType 3 + unknown NTLMv1 sources)" },
  { id: "T1055",     name: "Process Injection",               tactic: "Defense Evasion",     detected: "FULL",    tool: "CrowdStrike",    ruleId: "CS-INJECT-001",  findingRef: null,            recommendation: "Good — verify CS telemetry reaches Splunk" },
  { id: "T1190",     name: "Exploit Public-Facing Application",tactic:"Initial Access",      detected: "PARTIAL", tool: "Palo Alto NGFW", ruleId: "PA-CVE-BLOCK",   findingRef: null,            recommendation: "Ensure WAF rules updated for latest CVEs; tune Palo Alto App-ID" },
  { id: "T1078.002", name: "Valid Accounts — Domain",         tactic: "Initial Access",      detected: "PARTIAL", tool: "Splunk",         ruleId: "AD-LOGON-001",   findingRef: null,            recommendation: "Add impossible travel; correlate VPN logon with AD auth (4624/4625)" },
  { id: "T1110.002", name: "Password Cracking",               tactic: "Credential Access",   detected: "GAP",     tool: "—",             ruleId: "—",              findingRef: "VAPT-CRIT-002", recommendation: "Offline cracking undetectable — mitigate via AES256 + gMSA" },
  { id: "T1599.001", name: "Network Boundary Bridging",       tactic: "Defense Evasion",     detected: "GAP",     tool: "—",             ruleId: "—",              findingRef: "VAPT-MED-001",  recommendation: "Palo Alto: alert cross-VLAN flows violating zone policy" },
  { id: "T1484.002", name: "Domain Trust Modification",       tactic: "Privilege Escalation",detected: "PARTIAL", tool: "Splunk",         ruleId: "AD-TRUST-001",   findingRef: null,            recommendation: "Alert on netdom /trust and DS replication changes (Event 4706)" },
];

const DETECTION_STACK = [
  { name: "CrowdStrike Falcon", type: "EDR",        vendor: "CrowdStrike", coverage: 72, status: "ACTIVE"   },
  { name: "Splunk SIEM",        type: "SIEM",       vendor: "Splunk",      coverage: 58, status: "ACTIVE"   },
  { name: "Palo Alto NGFW",     type: "NDR/FW",     vendor: "Palo Alto",   coverage: 81, status: "ACTIVE"   },
  { name: "Tenable.io",         type: "VM Scanner", vendor: "Tenable",     coverage: 94, status: "ACTIVE"   },
  { name: "Darktrace",          type: "AI-NDR",     vendor: "Darktrace",   coverage: 44, status: "PARTIAL"  },
  { name: "Microsoft Sentinel", type: "SIEM/SOAR",  vendor: "Microsoft",   coverage: 0,  status: "INACTIVE" },
];

/* ─── Helpers ─── */
function sevColor(s: string) {
  if (s === "CRITICAL" || s === "critical") return "#FF1744";
  if (s === "HIGH"     || s === "high")     return "#FF6D00";
  if (s === "MEDIUM"   || s === "medium")   return "#FFD600";
  return "#00E676";
}

function detColor(d: string) {
  if (d === "FULL")    return "#00E676";
  if (d === "PARTIAL") return "#FF6D00";
  if (d === "GAP")     return "#FF1744";
  return "#64748B";
}

function outcomeColor(o: DetectionOutcome) {
  if (o === "prevented") return "#00E676";
  if (o === "detected")  return "#FFD600";
  return "#FF1744";
}

function outcomeIcon(o: DetectionOutcome) {
  if (o === "prevented") return <CheckCircle2 size={14} color="#00E676" />;
  if (o === "detected")  return <MinusCircle  size={14} color="#FFD600" />;
  return <XCircle size={14} color="#FF1744" />;
}

function covColor(n: number) {
  return n >= 80 ? "#00E676" : n >= 60 ? "var(--adv-accent)" : n >= 40 ? "#FF6D00" : n > 0 ? "#FF1744" : "#64748B";
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#00E676" : "#64748B", padding: "2px 4px" }}>
      {copied ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

/* ─── Main Page ─── */
const ENG_ID = "ENG-001";

export default function DetectionPage() {
  const { success, error: toastError, info } = useToast();

  const [activeTab,    setActiveTab]    = useState<TabKey>("matrix");
  const [tacticFilter, setTacticFilter] = useState("ALL");

  const [results,   setResults]   = useState<DetectionResult[]>([]);
  const [coverage,  setCoverage]  = useState<CoverageStats | null>(null);
  const [gaps,      setGaps]      = useState<Gap[]>([]);
  const [timeline,  setTimeline]  = useState<AttackAction[]>([]);
  const [siemAlerts, setSiemAlerts]  = useState<SIEMAlert[]>([]);
  const [edrDets,   setEdrDets]   = useState<EDRDetection[]>([]);
  const [running,   setRunning]   = useState(false);
  const [loaded,    setLoaded]    = useState(false);

  const [expandedResult, setExpandedResult] = useState<string | null>(null);
  const [expandedGap,    setExpandedGap]    = useState<string | null>(null);

  // SIEM config form
  const [siemType,  setSiemType]  = useState<"Splunk" | "Sentinel" | "Elastic">("Splunk");
  const [siemHost,  setSiemHost]  = useState("");
  const [siemToken, setSiemToken] = useState("");
  const [siemIndex, setSiemIndex] = useState("");
  const [savingCfg, setSavingCfg] = useState(false);

  const loadResults = useCallback(() => {
    fetch(`/api/engagements/${ENG_ID}/detection-validation/results`)
      .then((r) => r.json())
      .then((d) => {
        setResults(d.results ?? []);
        setTimeline(d.timeline ?? []);
        setSiemAlerts(d.siemAlerts ?? []);
        setEdrDets(d.edrDetections ?? []);
        setLoaded(true);
      })
      .catch(() => toastError("Load Error", "Failed to load correlation results."));

    fetch(`/api/engagements/${ENG_ID}/detection-validation/coverage`)
      .then((r) => r.json())
      .then((d) => setCoverage(d.coverage))
      .catch(() => null);

    fetch(`/api/engagements/${ENG_ID}/detection-validation/gaps`)
      .then((r) => r.json())
      .then((d) => setGaps(d.gaps ?? []))
      .catch(() => null);
  }, [toastError]);

  useEffect(() => { loadResults(); }, [loadResults]);

  const runCorrelation = useCallback(async () => {
    setRunning(true);
    info("Running", "Correlating attack timeline with SIEM/EDR data…");
    try {
      await fetch(`/api/engagements/${ENG_ID}/detection-validation/run`, { method: "POST" });
      loadResults();
      success("Done", "Correlation complete.");
    } catch {
      toastError("Error", "Correlation job failed.");
    } finally {
      setRunning(false);
    }
  }, [info, success, toastError, loadResults]);

  const saveSiemConfig = useCallback(async () => {
    if (!siemHost || !siemToken) { toastError("Validation", "Host and token are required."); return; }
    setSavingCfg(true);
    try {
      await fetch(`/api/engagements/${ENG_ID}/detection-validation/siem-config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: siemType, host: siemHost, token: siemToken, index: siemIndex }),
      });
      success("Saved", `${siemType} configuration saved.`);
      setSiemHost(""); setSiemToken(""); setSiemIndex("");
    } catch {
      toastError("Error", "Failed to save SIEM config.");
    } finally {
      setSavingCfg(false);
    }
  }, [siemType, siemHost, siemToken, siemIndex, success, toastError]);

  const fullCount    = MITRE_MATRIX.filter((t) => t.detected === "FULL").length;
  const partialCount = MITRE_MATRIX.filter((t) => t.detected === "PARTIAL").length;
  const gapCount     = MITRE_MATRIX.filter((t) => t.detected === "GAP").length;
  const overallPct   = Math.round(((fullCount + partialCount * 0.5) / MITRE_MATRIX.length) * 100);
  const tactics      = ["ALL", ...Array.from(new Set(MITRE_MATRIX.map((t) => t.tactic)))];
  const filteredMatrix = MITRE_MATRIX.filter((t) => tacticFilter === "ALL" || t.tactic === tacticFilter);

  const tabs: { key: TabKey; label: string; icon: React.ReactNode }[] = [
    { key: "matrix",      label: "COVERAGE MATRIX",  icon: <Shield size={12} /> },
    { key: "correlation", label: `CORRELATION (${results.length})`, icon: <Eye size={12} /> },
    { key: "gaps",        label: `GAPS & SIGMA (${gaps.length})`,  icon: <AlertTriangle size={12} /> },
    { key: "sigma",       label: "SIGMA RULES",       icon: <Copy size={12} /> },
    { key: "stack",       label: "STACK STATUS",      icon: <CheckCircle2 size={12} /> },
    { key: "siem-config", label: "SIEM CONFIG",       icon: <Settings size={12} /> },
  ];

  return (
    <PageShell
      title="DETECTION VALIDATION"
      subtitle="ATTACK LOGGER · SIEM QUERY · EDR CORRELATOR · SIGMA GENERATOR"
      statusItems={[
        { label: "COVERAGE", value: `${coverage?.coveragePct ?? overallPct}%`, color: "var(--adv-accent)" },
        { label: "MISSED",   value: String(coverage?.missed ?? gapCount),       color: "#FF1744" },
        { label: "TOOLS",    value: `${DETECTION_STACK.filter((t) => t.status === "ACTIVE").length}/${DETECTION_STACK.length}`, color: "#00E676" },
      ]}
    >
      {/* Run correlation bar */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 0 12px", borderBottom: "1px solid var(--adv-border)", marginBottom: 0, flexShrink: 0 }}>
        <button onClick={runCorrelation} disabled={running}
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 16px", borderRadius: 5, border: "1px solid rgba(0,230,118,0.3)", background: "rgba(0,230,118,0.08)", color: "#00E676", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, cursor: running ? "not-allowed" : "pointer" }}>
          {running ? <RefreshCw size={11} style={{ animation: "spin 1s linear infinite" }} /> : <Play size={11} />}
          {running ? "CORRELATING…" : "RUN CORRELATION"}
        </button>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>
          Correlates attack timeline against mocked Splunk · Sentinel · CrowdStrike · Defender within ±5 min window per technique
        </span>

        {/* Tab bar right-aligned */}
        <div style={{ marginLeft: "auto", display: "flex" }}>
          {tabs.map(({ key, label, icon }) => (
            <button key={key} onClick={() => setActiveTab(key)}
              style={{
                padding: "6px 12px", border: "none", background: "none", cursor: "pointer",
                borderBottom: `2px solid ${activeTab === key ? "var(--adv-accent)" : "transparent"}`,
                display: "flex", alignItems: "center", gap: 5,
                fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                color: activeTab === key ? "var(--adv-accent)" : "var(--adv-text-muted)",
                whiteSpace: "nowrap",
              }}>
              {icon}{label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", paddingTop: 12 }}>

        {/* ── COVERAGE MATRIX ─────────────────────────────────── */}
        {activeTab === "matrix" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
              {[
                { label: "COVERAGE",   value: `${overallPct}%`, color: overallPct >= 70 ? "var(--adv-accent)" : "#FF6D00" },
                { label: "FULL",       value: fullCount,         color: "#00E676" },
                { label: "PARTIAL",    value: partialCount,      color: "#FF6D00" },
                { label: "GAPS",       value: gapCount,          color: "#FF1744" },
                { label: "TECHNIQUES", value: MITRE_MATRIX.length, color: "var(--adv-text)" },
              ].map((s) => (
                <div key={s.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "12px 14px" }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>{s.label}</div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {tactics.map((t) => (
                <button key={t} onClick={() => setTacticFilter(t)}
                  style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, padding: "3px 10px", borderRadius: 4, cursor: "pointer",
                    border: `1px solid ${tacticFilter === t ? "var(--adv-accent)" : "var(--adv-border)"}`,
                    background: tacticFilter === t ? "rgba(37,99,235,0.08)" : "transparent",
                    color: tacticFilter === t ? "var(--adv-accent)" : "var(--adv-text-muted)" }}>
                  {t}
                </button>
              ))}
            </div>
            <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["TTP ID", "TECHNIQUE", "TACTIC", "STATUS", "TOOL", "RULE", "FINDING", "RECOMMENDATION"].map((h) => (
                      <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredMatrix.map((t, i) => (
                    <tr key={t.id} style={{ background: t.detected === "GAP" ? "rgba(255,23,68,0.02)" : "transparent" }}>
                      <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF6D00", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{t.id}</td>
                      <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text)", borderBottom: "1px solid var(--adv-border)" }}>{t.name}</td>
                      <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{t.tactic}</td>
                      <td style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: detColor(t.detected), background: `${detColor(t.detected)}15`, borderRadius: 3, padding: "1px 6px" }}>{t.detected}</span>
                      </td>
                      <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{t.tool}</td>
                      <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", whiteSpace: "nowrap" }}>{t.ruleId}</td>
                      <td style={{ padding: "9px 12px", borderBottom: "1px solid var(--adv-border)" }}>
                        {t.findingRef
                          ? <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF1744", border: "1px solid rgba(255,23,68,0.3)", borderRadius: 3, padding: "1px 5px" }}>{t.findingRef}</span>
                          : <span style={{ color: "var(--adv-text-muted)", fontSize: 9 }}>—</span>}
                      </td>
                      <td style={{ padding: "9px 12px", fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)", lineHeight: 1.4, maxWidth: 260 }}>{t.recommendation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── CORRELATION ─────────────────────────────────────── */}
        {activeTab === "correlation" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {coverage && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
                {[
                  { label: "COVERAGE",  value: `${coverage.coveragePct}%`, color: coverage.coveragePct >= 60 ? "var(--adv-accent)" : "#FF1744" },
                  { label: "DETECTED",  value: coverage.detected,           color: "#FFD600" },
                  { label: "PREVENTED", value: coverage.prevented,          color: "#00E676" },
                  { label: "MISSED",    value: coverage.missed,             color: "#FF1744" },
                ].map((s) => (
                  <div key={s.label} style={{ background: "var(--adv-panel)", border: `1px solid ${s.color}25`, borderRadius: 6, padding: "12px 14px" }}>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 5 }}>{s.label}</div>
                    <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Attack timeline + correlation */}
            <div style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>
                ATTACK TIMELINE × SIEM/EDR CORRELATION  <span style={{ fontSize: 9, color: "var(--adv-text-muted)" }}>· ±5 min window · same target host</span>
              </div>
              {(!loaded || results.length === 0) ? (
                <div style={{ padding: "40px 0", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>
                  Click RUN CORRELATION to correlate the attack timeline
                </div>
              ) : results.map((r) => (
                <div key={r.attackActionId} style={{ borderBottom: "1px solid var(--adv-border)" }}>
                  <div onClick={() => setExpandedResult(expandedResult === r.attackActionId ? null : r.attackActionId)}
                    style={{ padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
                    {outcomeIcon(r.outcome)}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF6D00" }}>{r.mitreId}</span>
                        <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", fontWeight: 600 }}>{r.mitreTechnique}</span>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{r.tactic}</span>
                      </div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>
                        {r.targetIp} · {new Date(r.timestamp).toLocaleTimeString()} · SIEM: {r.matchedSiemAlerts.length} alert{r.matchedSiemAlerts.length !== 1 ? "s" : ""} · EDR: {r.matchedEdrDetections.length} detection{r.matchedEdrDetections.length !== 1 ? "s" : ""}
                      </div>
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: outcomeColor(r.outcome), background: `${outcomeColor(r.outcome)}15`, borderRadius: 3, padding: "1px 7px", flexShrink: 0 }}>
                      {r.outcome.toUpperCase()}
                    </span>
                    {expandedResult === r.attackActionId ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
                  </div>
                  {expandedResult === r.attackActionId && (
                    <div style={{ padding: "10px 14px 14px", borderTop: "1px solid var(--adv-border)", display: "flex", flexDirection: "column", gap: 10 }}>
                      {/* Timeline action detail */}
                      {timeline.find((a) => a.id === r.attackActionId) && (
                        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "8px 12px" }}>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>ATTACK ACTION DETAIL</div>
                          <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text)", lineHeight: 1.5 }}>
                            {timeline.find((a) => a.id === r.attackActionId)?.actionDetail}
                          </div>
                        </div>
                      )}
                      {/* SIEM matches */}
                      {r.matchedSiemAlerts.length > 0 && (
                        <div>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>SIEM ALERTS MATCHED</div>
                          {r.matchedSiemAlerts.map((a) => (
                            <div key={a.id} style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.15)", borderRadius: 4, padding: "8px 10px", marginBottom: 5 }}>
                              <div style={{ display: "flex", justifyContent: "space-between" }}>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF" }}>{a.source} · {a.ruleName}</span>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{new Date(a.timestamp).toLocaleTimeString()}</span>
                              </div>
                              {(a.splQuery || a.kqlQuery) && (
                                <div style={{ marginTop: 5, display: "flex", alignItems: "center", gap: 4 }}>
                                  <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#64748B", flex: 1 }}>{a.splQuery ?? a.kqlQuery}</code>
                                  <CopyBtn text={a.splQuery ?? a.kqlQuery ?? ""} />
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                      {/* EDR matches */}
                      {r.matchedEdrDetections.length > 0 && (
                        <div>
                          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>EDR DETECTIONS MATCHED</div>
                          {r.matchedEdrDetections.map((d) => (
                            <div key={d.id} style={{ background: d.prevented ? "rgba(0,230,118,0.04)" : "rgba(255,214,0,0.04)", border: `1px solid ${d.prevented ? "rgba(0,230,118,0.2)" : "rgba(255,214,0,0.2)"}`, borderRadius: 4, padding: "8px 10px", marginBottom: 5 }}>
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: d.prevented ? "#00E676" : "#FFD600" }}>{d.source} · {d.alertName}</span>
                                <div style={{ display: "flex", gap: 8 }}>
                                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: d.prevented ? "#00E676" : "#FFD600" }}>{d.prevented ? "PREVENTED" : "DETECTED"}</span>
                                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{d.confidence}% confidence</span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                      {r.outcome === "missed" && (
                        <div style={{ background: "rgba(255,23,68,0.04)", border: "1px solid rgba(255,23,68,0.2)", borderRadius: 4, padding: "8px 10px", fontFamily: "'Inter', sans-serif", fontSize: 12, color: "#FF1744" }}>
                          No SIEM alert or EDR detection matched within ±5 min on {r.targetIp}. A Sigma rule has been auto-generated in the GAPS tab.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── GAPS & SIGMA ─────────────────────────────────────── */}
        {activeTab === "gaps" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", marginBottom: 4 }}>
              {gaps.length} missed technique{gaps.length !== 1 ? "s" : ""} — each includes a generated Sigma rule for deployment to your SIEM.
            </div>
            {gaps.map((g) => (
              <div key={g.result.attackActionId} style={{ background: "var(--adv-bg)", border: "1px solid rgba(255,23,68,0.25)", borderLeft: "3px solid #FF1744", borderRadius: 6, overflow: "hidden" }}>
                <div onClick={() => setExpandedGap(expandedGap === g.result.attackActionId ? null : g.result.attackActionId)}
                  style={{ padding: "12px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10 }}>
                  <XCircle size={14} color="#FF1744" />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF6D00" }}>{g.result.mitreId}</span>
                      <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", fontWeight: 600 }}>{g.result.mitreTechnique}</span>
                    </div>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>
                      {g.result.tactic} · {g.result.targetIp} · Sigma: <span style={{ color: g.sigmaRule.status === "stable" ? "#00E676" : "#FFD600" }}>{g.sigmaRule.status}</span> · Log: {g.sigmaRule.logSource}
                    </div>
                  </div>
                  {expandedGap === g.result.attackActionId ? <ChevronDown size={13} color="#64748B" /> : <ChevronRight size={13} color="#64748B" />}
                </div>
                {expandedGap === g.result.attackActionId && (
                  <div style={{ borderTop: "1px solid var(--adv-border)", padding: "12px 14px" }}>
                    <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>GENERATED SIGMA RULE</div>
                    <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, overflow: "hidden" }}>
                      <div style={{ padding: "5px 10px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>SIGMA YAML · {g.sigmaRule.logSource}</span>
                        <CopyBtn text={g.sigmaRule.yaml} />
                      </div>
                      <pre style={{ margin: 0, padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.7, overflowX: "auto", maxHeight: 320 }}>
                        {g.sigmaRule.yaml}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── ALL SIGMA RULES ──────────────────────────────────── */}
        {activeTab === "sigma" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", marginBottom: 4 }}>
              All generated Sigma rules — deploy these to Splunk, Sentinel, or Elastic to close detection gaps.
            </div>
            {gaps.map((g) => (
              <div key={g.sigmaRule.mitreId} style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF6D00" }}>{g.sigmaRule.mitreId}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>{g.sigmaRule.technique}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: g.sigmaRule.status === "stable" ? "#00E676" : "#FFD600", background: g.sigmaRule.status === "stable" ? "rgba(0,230,118,0.1)" : "rgba(255,214,0,0.1)", borderRadius: 3, padding: "0 5px" }}>{g.sigmaRule.status}</span>
                  </div>
                  <CopyBtn text={g.sigmaRule.yaml} />
                </div>
                <pre style={{ margin: 0, padding: "10px 14px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.7, overflowX: "auto", maxHeight: 300 }}>
                  {g.sigmaRule.yaml}
                </pre>
              </div>
            ))}
            {gaps.length === 0 && (
              <div style={{ padding: "60px 0", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "var(--adv-text-muted)" }}>
                Run correlation first to generate Sigma rules for missed techniques.
              </div>
            )}
          </div>
        )}

        {/* ── STACK STATUS ─────────────────────────────────────── */}
        {activeTab === "stack" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
            {DETECTION_STACK.map((tool) => {
              const sc = tool.status === "ACTIVE" ? "#00E676" : tool.status === "PARTIAL" ? "#FF6D00" : "#FF1744";
              return (
                <div key={tool.name} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 16, position: "relative", overflow: "hidden" }}>
                  <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: covColor(tool.coverage) }} />
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                    <div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text)", marginBottom: 2 }}>{tool.name}</div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{tool.vendor} · {tool.type}</div>
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sc, border: `1px solid ${sc}`, borderRadius: 3, padding: "1px 6px" }}>{tool.status}</span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ flex: 1, height: 6, background: "var(--adv-bg)", borderRadius: 3, overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${tool.coverage}%`, background: covColor(tool.coverage), borderRadius: 3 }} />
                    </div>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 700, color: covColor(tool.coverage), width: 38 }}>
                      {tool.coverage > 0 ? `${tool.coverage}%` : "—"}
                    </span>
                  </div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 5 }}>TECHNIQUE COVERAGE</div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── SIEM CONFIG ──────────────────────────────────────── */}
        {activeTab === "siem-config" && (
          <div style={{ maxWidth: 520 }}>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text-muted)", marginBottom: 16 }}>
              Configure SIEM/EDR connections for live correlation. Credentials are stored in memory for this session only.
            </div>
            <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 20, display: "flex", flexDirection: "column", gap: 14 }}>
              {[
                { label: "SIEM TYPE", node: (
                  <div style={{ display: "flex", gap: 6 }}>
                    {(["Splunk", "Sentinel", "Elastic"] as const).map((t) => (
                      <button key={t} onClick={() => setSiemType(t)}
                        style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "5px 14px", borderRadius: 4, cursor: "pointer",
                          border: `1px solid ${siemType === t ? "var(--adv-accent)" : "var(--adv-border)"}`,
                          background: siemType === t ? "rgba(37,99,235,0.1)" : "transparent",
                          color: siemType === t ? "var(--adv-accent)" : "var(--adv-text-muted)" }}>
                        {t}
                      </button>
                    ))}
                  </div>
                )},
                { label: "HOST / URL", node: (
                  <input value={siemHost} onChange={(e) => setSiemHost(e.target.value)}
                    placeholder={siemType === "Splunk" ? "https://splunk.corp.local:8089" : siemType === "Sentinel" ? "https://management.azure.com/..." : "https://elastic.corp.local:9200"}
                    style={{ width: "100%", boxSizing: "border-box", background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "7px 10px", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, outline: "none" }} />
                )},
                { label: siemType === "Splunk" ? "API TOKEN" : siemType === "Sentinel" ? "BEARER TOKEN" : "API KEY", node: (
                  <input value={siemToken} onChange={(e) => setSiemToken(e.target.value)} type="password"
                    placeholder="••••••••••••••••"
                    style={{ width: "100%", boxSizing: "border-box", background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "7px 10px", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, outline: "none" }} />
                )},
                { label: siemType === "Splunk" ? "INDEX" : siemType === "Sentinel" ? "WORKSPACE ID" : "INDEX PATTERN", node: (
                  <input value={siemIndex} onChange={(e) => setSiemIndex(e.target.value)}
                    placeholder={siemType === "Splunk" ? "wineventlog" : siemType === "Sentinel" ? "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" : "logs-*"}
                    style={{ width: "100%", boxSizing: "border-box", background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "7px 10px", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, outline: "none" }} />
                )},
              ].map(({ label, node }) => (
                <div key={label}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 6 }}>{label}</div>
                  {node}
                </div>
              ))}
              <button onClick={saveSiemConfig} disabled={savingCfg}
                style={{ padding: "8px 20px", borderRadius: 5, border: "1px solid rgba(37,99,235,0.3)", background: "rgba(37,99,235,0.1)", color: "var(--adv-accent)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, cursor: "pointer", display: "flex", alignItems: "center", gap: 6, alignSelf: "flex-start" }}>
                {savingCfg ? <RefreshCw size={12} style={{ animation: "spin 1s linear infinite" }} /> : <Settings size={12} />}
                SAVE & TEST CONNECTION
              </button>
            </div>

            <div style={{ marginTop: 16, background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 16 }}>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 10 }}>
                {siemType === "Splunk" ? "SPLUNK SPL EXAMPLE" : siemType === "Sentinel" ? "SENTINEL KQL EXAMPLE" : "ELASTIC EQL EXAMPLE"}
              </div>
              <div style={{ position: "relative" }}>
                <div style={{ position: "absolute", top: 2, right: 4 }}>
                  <CopyBtn text={
                    siemType === "Splunk"
                      ? 'index=wineventlog EventCode=4769 TicketEncryptionType=0x17 | stats count by src_ip'
                      : siemType === "Sentinel"
                      ? 'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | summarize count() by IpAddress'
                      : 'sequence by host.ip [process where process.name == "wmic.exe" and process.args : "/node*"]'
                  } />
                </div>
                <pre style={{ margin: 0, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#00D4FF", lineHeight: 1.6, overflowX: "auto" }}>
                  {siemType === "Splunk"
                    ? 'index=wineventlog EventCode=4769 TicketEncryptionType=0x17\n| stats count by src_ip\n| where count > 5'
                    : siemType === "Sentinel"
                    ? 'SecurityEvent\n| where EventID == 4769\n| where TicketEncryptionType == "0x17"\n| summarize count() by IpAddress\n| where count_ > 5'
                    : 'sequence by host.ip\n  [process where process.name == "wmic.exe"\n   and process.args : "/node*"]\n  [network where destination.port == 135]'}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </PageShell>
  );
}
