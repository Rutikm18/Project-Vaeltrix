"use client";

import React, { useState, useMemo, useCallback } from "react";
import {
  AlertTriangle, ChevronDown, ChevronRight, Copy, Check,
  Search, Filter, CheckCircle, XCircle, Clock, Shield,
  ExternalLink, ArrowUpDown, BarChart2, FileText,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type FindingStatus = "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED" | "ACCEPTED" | "FALSE_POSITIVE";

interface RemStep { step: number; title: string; command?: string; description: string; estimatedHours: number; verification?: string; completed: boolean; completedBy?: string; }
interface ComplianceRef { framework: string; refs: string[]; }
interface Finding {
  id: string; title: string; severity: Severity; cvss: string; cvssVector: string;
  category: string; status: FindingStatus; affectedHost: string; discoveredAt: string;
  description: string; technicalDetails: string; attackPath: string;
  evidence: { label: string; content: string }[];
  impact: string; businessImpact?: string;
  exploitability?: "EASY" | "MODERATE" | "DIFFICULT";
  remediation: (string | RemStep)[];
  compliance: ComplianceRef[];
  mitre: { id: string; name: string }[];
  riskScore?: number;
}

/* ─── Color Maps ─── */
const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676", INFO: "#0284C7",
};

const STATUS_COLOR: Record<FindingStatus, string> = {
  OPEN:          "#FF1744",
  IN_REVIEW:     "#FF9900",
  IN_REMEDIATION:"#2563EB",
  VERIFIED:      "#059669",
  CLOSED:        "#64748B",
  ACCEPTED:      "#9C27B0",
  FALSE_POSITIVE:"#64748B",
};

const STATUS_LABEL: Record<FindingStatus, string> = {
  OPEN: "OPEN", IN_REVIEW: "IN REVIEW", IN_REMEDIATION: "REMEDIATING",
  VERIFIED: "VERIFIED", CLOSED: "CLOSED", ACCEPTED: "ACCEPTED", FALSE_POSITIVE: "FALSE POS.",
};

/* ─── SLA helpers ─── */
const SLA_HOURS: Partial<Record<Severity, number>> = { CRITICAL: 24, HIGH: 72, MEDIUM: 168, LOW: 720 };

function getSlaColor(discoveredAt: string, severity: Severity): { color: string; label: string; pct: number } {
  const slaH = SLA_HOURS[severity];
  if (!slaH) return { color: "var(--adv-text-muted)", label: "N/A", pct: 100 };
  const due = new Date(discoveredAt).getTime() + slaH * 3_600_000;
  const now = Date.now();
  const leftMs = due - now;
  const pct = Math.max(0, Math.min(100, (leftMs / (slaH * 3_600_000)) * 100));
  if (now > due) return { color: "#FF1744", label: "BREACHED", pct: 0 };
  const h = Math.round(leftMs / 3_600_000);
  const label = h < 24 ? `${h}h` : `${Math.round(h / 24)}d`;
  const color = pct < 10 ? "#FF1744" : pct < 25 ? "#FF6D00" : pct < 50 ? "#FFD600" : "#00E676";
  return { color, label, pct };
}

/* ─── Static data ─── */
const FINDINGS: Finding[] = [
  {
    id: "VAPT-CRIT-001",
    title: "Unconstrained Kerberos Delegation on DC01",
    severity: "CRITICAL", cvss: "9.8",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    category: "Active Directory", status: "OPEN",
    affectedHost: "DC01.corp.local",
    discoveredAt: "2026-05-10T09:32:00Z",
    businessImpact: "Complete domain takeover — all 842 user accounts, file shares, and business-critical systems compromised.",
    exploitability: "EASY",
    riskScore: 98,
    description: "DC01 is configured with Unconstrained Kerberos Delegation (TrustedForDelegation=TRUE). Any user authenticating to a service on DC01 has their TGT cached in LSASS, extractable by any local admin — enabling full domain compromise via ticket replay.",
    technicalDetails: "The attribute TrustedForDelegation is TRUE on DC01. Combined with SpoolSS coercion, an attacker captures the DC01 machine TGT and performs DCSync to extract all domain hashes.",
    attackPath: "WS-042 → SpoolSS Coerce → DC01 TGT → mimikatz lsadump::dcsync → All NTLM hashes → Domain Admin",
    evidence: [
      { label: "AD Attribute Query", content: "PS> Get-ADComputer DC01 -Properties TrustedForDelegation\nTrustedForDelegation : True  ← VULNERABILITY" },
      { label: "DCSync Attack", content: "mimikatz # lsadump::dcsync /domain:corp.local /all /csv\n...842 accounts extracted" },
    ],
    impact: "Complete domain compromise. Golden Ticket persistence, full credential harvest of 842 accounts.",
    remediation: [
      { step: 1, title: "Disable unconstrained delegation", command: "Set-ADComputer DC01 -TrustedForDelegation $false", description: "Remove TrustedForDelegation from DC01 computer object.", estimatedHours: 0.5, verification: "Get-ADComputer DC01 -Properties TrustedForDelegation | Select TrustedForDelegation", completed: false },
      { step: 2, title: "Enroll DC01 in Protected Users", command: "Add-ADGroupMember 'Protected Users' -Members DC01$", description: "Prevents Kerberos delegation for the computer account.", estimatedHours: 0.5, completed: false },
      { step: 3, title: "Disable SpoolSS on DCs", command: "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled", description: "Eliminates the coercion vector.", estimatedHours: 1, verification: "Get-Service Spooler | Select Status", completed: false },
      { step: 4, title: "Deploy Credential Guard", description: "Enable Credential Guard via GPO to protect LSASS on all DCs.", estimatedHours: 4, completed: false },
      { step: 5, title: "Alert on Event ID 4768 from non-DCs", description: "SIEM rule: TGT requests originating from non-DC machines.", estimatedHours: 2, completed: false },
    ],
    compliance: [
      { framework: "NIST SP 800-53 Rev 5", refs: ["AC-6 (Least Privilege)", "IA-5 (Authenticator Management)"] },
      { framework: "CIS Controls v8", refs: ["Control 5.4 — Restrict Administrator Privileges"] },
    ],
    mitre: [{ id: "T1558.003", name: "Kerberoasting" }, { id: "T1134.001", name: "Token Impersonation" }, { id: "T1003.006", name: "DCSync" }],
  },
  {
    id: "VAPT-CRIT-002",
    title: "Kerberoastable Service Account: svc_backup → Domain Admin Path",
    severity: "CRITICAL", cvss: "9.1",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    category: "Active Directory", status: "IN_REVIEW",
    affectedHost: "corp.local (svc_backup)",
    discoveredAt: "2026-05-10T10:14:00Z",
    businessImpact: "Domain Admin via offline credential cracking. Any domain user can initiate the attack.",
    exploitability: "EASY",
    riskScore: 95,
    description: "svc_backup has an SPN registered and uses RC4-HMAC encryption. Password cracked in 4h using Hashcat. The account is a Domain Admin member.",
    technicalDetails: "RC4-HMAC (etype 23) TGS tickets are optimized for offline cracking. Password set 14 months ago, no rotation policy.",
    attackPath: "Any user → Request TGS for svc_backup SPN → Export RC4 hash → Hashcat crack → Domain Admin",
    evidence: [
      { label: "Kerberoasting", content: "PS> Invoke-Kerberoast -OutputFormat Hashcat\n$krb5tgs$23$*svc_backup$CORP.LOCAL...[RC4 hash]" },
      { label: "Password Cracked", content: "hashcat -m 13100: Backup@Corp2024! ← RECOVERED in 4h 7m" },
    ],
    impact: "Full domain compromise via service account credential recovery.",
    remediation: [
      { step: 1, title: "Remove svc_backup from Domain Admins", command: "Remove-ADGroupMember 'Domain Admins' -Members svc_backup", description: "Principle of least privilege — service accounts must not be DAs.", estimatedHours: 0.5, verification: "Get-ADUser svc_backup -Properties MemberOf | Select -Expand MemberOf", completed: false },
      { step: 2, title: "Force AES256 encryption", command: "Set-ADUser svc_backup -KerberosEncryptionType AES256", description: "Eliminates RC4 crack path — AES256 is computationally infeasible to crack.", estimatedHours: 0.5, verification: "Get-ADUser svc_backup -Properties msDS-SupportedEncryptionTypes", completed: false },
      { step: 3, title: "Reset password (25+ chars)", command: "Set-ADAccountPassword svc_backup -Reset -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)", description: "Immediately invalidate the cracked credential.", estimatedHours: 0.5, completed: false },
      { step: 4, title: "Migrate to Group Managed Service Account (gMSA)", description: "gMSA eliminates manual password management — auto-rotates every 30 days.", estimatedHours: 8, completed: false },
    ],
    compliance: [
      { framework: "NIST SP 800-53 Rev 5", refs: ["AC-6 (Least Privilege)", "IA-5 (Authenticator Management)"] },
      { framework: "PCI DSS v4.0", refs: ["Req 8.3.1 — Strong authentication for all accounts"] },
    ],
    mitre: [{ id: "T1558.003", name: "Kerberoasting" }, { id: "T1110.002", name: "Password Cracking" }],
  },
  {
    id: "VAPT-HIGH-001",
    title: "LLMNR/NBT-NS Poisoning — NTLM Credential Relay",
    severity: "HIGH", cvss: "8.1",
    cvssVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    category: "Protocol Abuse", status: "IN_REMEDIATION",
    affectedHost: "10.10.10.0/24 CORP VLAN",
    discoveredAt: "2026-05-10T11:05:00Z",
    businessImpact: "Any workstation credential can be captured and replayed for lateral movement. 67% of CORP hosts have SMB signing disabled.",
    exploitability: "EASY",
    riskScore: 82,
    description: "LLMNR and NBT-NS are enabled on all CORP workstations. An attacker in the broadcast domain can intercept queries, capture NTLMv2 hashes, and relay them to hosts with SMB signing disabled.",
    technicalDetails: "Responder + ntlmrelayx successfully relayed credentials to SVC-SQL, granting local admin shell without cracking any password.",
    attackPath: "CORP VLAN → LLMNR poison (Responder) → NTLMv2 capture → Relay to SVC-SQL → Local admin shell",
    evidence: [
      { label: "LLMNR Capture", content: "[SMB] NTLMv2 Client: 10.10.10.42 | User: CORP\\john.doe | Hash captured" },
      { label: "Relay Success", content: "ntlmrelayx: Authenticating as CORP/john.doe against smb://10.10.10.50 SUCCEED\nStarted interactive SMB shell on SVC-SQL" },
    ],
    impact: "Lateral movement without password cracking on 67% of CORP hosts.",
    remediation: [
      { step: 1, title: "Disable LLMNR via GPO", command: "Computer Configuration → Admin Templates → Network → DNS Client → Turn off multicast name resolution = Enabled", description: "Prevent LLMNR queries from being broadcast.", estimatedHours: 1, completed: true, completedBy: "Priya Sharma" },
      { step: 2, title: "Disable NBT-NS", command: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_*' -Name NetbiosOptions -Value 2", description: "Disable NetBIOS over TCP/IP on all interfaces.", estimatedHours: 1, completed: false },
      { step: 3, title: "Enforce SMB signing on all CORP hosts", command: "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force", description: "Prevents relay attacks even if hash is captured.", estimatedHours: 2, completed: false },
    ],
    compliance: [
      { framework: "NIST SP 800-53 Rev 5", refs: ["SC-7 (Boundary Protection)", "SC-8 (Transmission Integrity)"] },
    ],
    mitre: [{ id: "T1557.001", name: "LLMNR/NBT-NS Poisoning" }, { id: "T1550.002", name: "Pass the Hash" }],
  },
  {
    id: "VAPT-HIGH-002",
    title: "Lateral Movement via WMI — WS-042 to CORP",
    severity: "HIGH", cvss: "7.5",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
    category: "Lateral Movement", status: "OPEN",
    affectedHost: "WS-042, 10.10.10.0/24",
    discoveredAt: "2026-05-10T14:22:00Z",
    exploitability: "MODERATE",
    riskScore: 75,
    description: "WMI remote execution accessible across CORP VLAN without network restrictions. 18 of 241 hosts vulnerable using captured credentials.",
    technicalDetails: "No Process Creation auditing (Event ID 4688 disabled). CrowdStrike detection bypassed during engagement window.",
    attackPath: "WS-042 → wmic /node:TARGET process call create → Remote cmd.exe → Persistence via WMI subscription",
    evidence: [
      { label: "WMI Remote Exec", content: "Invoke-WmiMethod: ProcessId=4824, ReturnValue=0 ← SUCCESS on WS-128\n18/241 CORP hosts vulnerable" },
    ],
    impact: "Horizontal spread across CORP VLAN — 18+ footholds without triggering alerts.",
    remediation: [
      { step: 1, title: "Block WMI remote access via Windows Firewall", command: "netsh advfirewall firewall add rule name='Block WMI Remote' protocol=TCP dir=in localport=135 action=block", description: "Restrict WMI DCOM port at host level.", estimatedHours: 2, completed: false },
      { step: 2, title: "Deploy LAPS", description: "Local Administrator Password Solution — unique local admin password per host eliminates relay reuse.", estimatedHours: 8, completed: false },
      { step: 3, title: "Enable Process Creation auditing", command: "GPO: Audit Process Creation = Success, Failure (Event ID 4688 with command line)", description: "Required for WMI execution visibility.", estimatedHours: 1, completed: false },
    ],
    compliance: [
      { framework: "NIST SP 800-53 Rev 5", refs: ["AC-17 (Remote Access)", "AU-12 (Audit Record Generation)"] },
    ],
    mitre: [{ id: "T1047", name: "Windows Management Instrumentation" }],
  },
  {
    id: "VAPT-MED-001",
    title: "Network Segmentation Bypass — VLAN30 to VLAN10",
    severity: "MEDIUM", cvss: "6.4",
    cvssVector: "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
    category: "Segmentation", status: "VERIFIED",
    affectedHost: "VLAN30 → VLAN10 inter-VLAN routing",
    discoveredAt: "2026-05-11T09:15:00Z",
    exploitability: "DIFFICULT",
    riskScore: 55,
    description: "CORP (VLAN30) can directly reach MGMT (VLAN10) on TCP/445. Jump host enforcement applied at application layer only.",
    technicalDetails: "Core switch ACL has broad PERMIT from CORP to MGMT. Windows Firewall on MGMT-SRV bypassable via SMB share.",
    attackPath: "WS-042 → Direct TCP/445 to 172.16.1.10 → SMB share access → Credential files on MGMT share",
    evidence: [
      { label: "Connectivity Proof", content: "Test-NetConnection 172.16.1.10 -Port 445: TcpTestSucceeded = True ← CORP can reach MGMT on SMB" },
    ],
    impact: "CORP compromise → MGMT zone access without MFA jump host enforcement.",
    remediation: [
      { step: 1, title: "Apply DENY ACL at MGMT VLAN ingress", description: "Block all CORP sources except jump host (172.16.1.5/32).", estimatedHours: 2, completed: true, completedBy: "Marcus Lee" },
      { step: 2, title: "Block SMB from CORP to MGMT at firewall", description: "Explicit deny for TCP/445, TCP/139, UDP/137-138.", estimatedHours: 1, completed: true, completedBy: "Marcus Lee" },
    ],
    compliance: [
      { framework: "NIST SP 800-53 Rev 5", refs: ["SC-7 (Boundary Protection)"] },
      { framework: "PCI DSS v4.0", refs: ["Req 1.3.2 — Restrict inbound traffic"] },
    ],
    mitre: [{ id: "T1599", name: "Network Boundary Bridging" }],
  },
];

/* ─── Copy Button ─── */
function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#059669" : "#64748B", padding: "2px 4px" }}>
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

/* ─── Severity Badge ─── */
function SevBadge({ s }: { s: Severity }) {
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "2px 8px", borderRadius: 4,
      background: `${SEV_COLOR[s]}15`, color: SEV_COLOR[s], border: `1px solid ${SEV_COLOR[s]}30`,
    }}>{s}</span>
  );
}

/* ─── Status Badge ─── */
function StatusBadge({ s, onClick }: { s: FindingStatus; onClick?: () => void }) {
  return (
    <span
      onClick={onClick}
      style={{
        fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "2px 8px", borderRadius: 4,
        background: `${STATUS_COLOR[s]}12`, color: STATUS_COLOR[s], border: `1px solid ${STATUS_COLOR[s]}30`,
        cursor: onClick ? "pointer" : "default",
      }}
    >
      {STATUS_LABEL[s]}
    </span>
  );
}

/* ─── Remediation Checklist ─── */
function RemediationChecklist({ steps, findingId }: { steps: (string | RemStep)[]; findingId: string }) {
  const [checks, setChecks] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    steps.forEach((s, i) => { if (typeof s !== "string") init[`${findingId}-${i}`] = s.completed; });
    return init;
  });

  const toggle = (key: string) => setChecks((p) => ({ ...p, [key]: !p[key] }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {steps.map((s, i) => {
        if (typeof s === "string") {
          const key = `${findingId}-${i}`;
          return (
            <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <div
                onClick={() => toggle(key)}
                style={{
                  width: 16, height: 16, borderRadius: 4, flexShrink: 0, marginTop: 2, cursor: "pointer",
                  background: checks[key] ? "rgba(5,150,105,0.2)" : "transparent",
                  border: `1.5px solid ${checks[key] ? "#059669" : "#E2E8F0"}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}
              >
                {checks[key] && <Check size={10} color="#059669" />}
              </div>
              <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: checks[key] ? "#64748B" : "#0F172A", textDecoration: checks[key] ? "line-through" : "none", lineHeight: 1.5 }}>{s}</span>
            </div>
          );
        }

        /* Enhanced step */
        const key = `${findingId}-${i}`;
        const done = checks[key] ?? s.completed;
        return (
          <div key={i} style={{ background: "var(--adv-bg)", border: `1px solid ${done ? "rgba(5,150,105,0.2)" : "#E2E8F0"}`, borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: s.command ? 8 : 0 }}>
              <div
                onClick={() => toggle(key)}
                style={{
                  width: 16, height: 16, borderRadius: 4, flexShrink: 0, marginTop: 2, cursor: "pointer",
                  background: done ? "rgba(5,150,105,0.2)" : "transparent",
                  border: `1.5px solid ${done ? "#059669" : "#E2E8F0"}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}
              >
                {done && <Check size={10} color="#059669" />}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: done ? "#64748B" : "#0F172A", textDecoration: done ? "line-through" : "none" }}>
                    Step {s.step}: {s.title}
                  </span>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>~{s.estimatedHours}h</span>
                </div>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)", marginTop: 2 }}>{s.description}</div>
              </div>
            </div>
            {s.command && (
              <div style={{ background: "var(--adv-panel)", borderRadius: 4, padding: "6px 10px", display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 4 }}>
                <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)", flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{s.command}</code>
                <CopyBtn text={s.command} />
              </div>
            )}
            {s.verification && (
              <div style={{ marginTop: 4, display: "flex", gap: 6, alignItems: "center" }}>
                <CheckCircle size={10} color="#059669" />
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>Verify: </span>
                <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#059669" }}>{s.verification}</code>
              </div>
            )}
            {s.completedBy && (
              <div style={{ marginTop: 4, fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#059669" }}>
                ✓ Completed by {s.completedBy}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ─── Finding Detail ─── */
function FindingDetail({ f, onStatusChange }: { f: Finding; onStatusChange: (id: string, s: FindingStatus) => void }) {
  const [tab, setTab] = useState<"overview" | "evidence" | "remediation" | "compliance">("overview");
  const sla = getSlaColor(f.discoveredAt, f.severity);

  const WORKFLOW: { status: FindingStatus; label: string; color: string; desc: string }[] = [
    { status: "IN_REVIEW",      label: "Mark In Review",    color: "#FF9900", desc: "Begin active analysis" },
    { status: "IN_REMEDIATION", label: "Start Remediation", color: "var(--adv-accent)", desc: "Remediation in progress" },
    { status: "VERIFIED",       label: "Mark Verified",     color: "#059669", desc: "Fix confirmed working" },
    { status: "ACCEPTED",       label: "Accept Risk",       color: "#9C27B0", desc: "Documented risk acceptance" },
    { status: "FALSE_POSITIVE", label: "False Positive",    color: "var(--adv-text-muted)", desc: "Finding is invalid" },
  ];

  return (
    <div className="animate-scale-in" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 8, overflow: "hidden" }}>
      {/* Detail Header */}
      <div style={{ padding: "16px 20px", borderBottom: "1px solid var(--adv-border)", background: "var(--adv-bg)" }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
          <SevBadge s={f.severity} />
          <StatusBadge s={f.status} />
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", background: "rgba(100,116,139,0.1)", border: "1px solid var(--adv-border)", borderRadius: 4, padding: "2px 8px" }}>
            CVSS {f.cvss}
          </span>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: sla.color,
            background: `${sla.color}10`, border: `1px solid ${sla.color}30`, borderRadius: 4, padding: "2px 8px",
          }}>
            SLA: {sla.label}
          </span>
          {f.exploitability && (
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: f.exploitability === "EASY" ? "#FF1744" : f.exploitability === "MODERATE" ? "#FFD600" : "#00E676", background: "rgba(0,0,0,0.2)", border: "1px solid var(--adv-border)", borderRadius: 4, padding: "2px 8px" }}>
              EXPLOIT: {f.exploitability}
            </span>
          )}
        </div>
        <h2 style={{ fontFamily: "'Inter', sans-serif", fontSize: 18, fontWeight: 700, color: "var(--adv-text)", margin: 0, lineHeight: 1.3 }}>{f.title}</h2>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginTop: 6 }}>
          {f.id} · {f.category} · {f.affectedHost}
        </div>
        {f.businessImpact && (
          <div style={{ marginTop: 10, padding: "8px 12px", background: `${SEV_COLOR[f.severity]}08`, border: `1px solid ${SEV_COLOR[f.severity]}20`, borderRadius: 5 }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: SEV_COLOR[f.severity] }}>BUSINESS IMPACT</span>
            <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", marginTop: 4 }}>{f.businessImpact}</div>
          </div>
        )}
      </div>

      {/* Workflow buttons */}
      <div style={{ padding: "10px 20px", borderBottom: "1px solid var(--adv-border)", display: "flex", gap: 6, flexWrap: "wrap" }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", alignSelf: "center" }}>ADVANCE:</span>
        {WORKFLOW.map((w) => (
          <button
            key={w.status}
            onClick={() => onStatusChange(f.id, w.status)}
            disabled={f.status === w.status}
            style={{
              padding: "4px 10px", borderRadius: 4, cursor: f.status === w.status ? "default" : "pointer",
              border: `1px solid ${f.status === w.status ? "#E2E8F0" : `${w.color}50`}`,
              background: f.status === w.status ? "transparent" : `${w.color}10`,
              color: f.status === w.status ? "#64748B" : w.color,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
              opacity: f.status === w.status ? 0.5 : 1,
            }}
          >
            {w.label}
          </button>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--adv-border)" }}>
        {(["overview", "evidence", "remediation", "compliance"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: "9px 16px", background: tab === t ? "rgba(37,99,235,0.04)" : "transparent",
            border: "none", borderBottom: tab === t ? "2px solid #2563EB" : "2px solid transparent",
            color: tab === t ? "#0F172A" : "#64748B", fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10, letterSpacing: 1, cursor: "pointer", textTransform: "uppercase",
          }}>
            {t === "remediation" ? `Remediation (${Array.isArray(f.remediation) ? f.remediation.length : 0})` : t}
          </button>
        ))}
      </div>

      <div style={{ padding: "16px 20px" }}>
        {tab === "overview" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 6 }}>DESCRIPTION</div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 14, color: "var(--adv-text)", lineHeight: 1.6 }}>{f.description}</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginTop: 12, marginBottom: 6 }}>ATTACK PATH</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FF9900", lineHeight: 1.8 }}>{f.attackPath}</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginTop: 12, marginBottom: 6 }}>IMPACT</div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.5 }}>{f.impact}</div>
            </div>
            <div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 6 }}>TECHNICAL DETAILS</div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.6 }}>{f.technicalDetails}</div>
              <div style={{ marginTop: 12 }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 6 }}>MITRE ATT&CK</div>
                {f.mitre.map((m) => (
                  <div key={m.id} style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)" }}>{m.id}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text-muted)" }}>{m.name}</span>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 12 }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)", marginBottom: 6 }}>CVSS VECTOR</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text)", background: "var(--adv-bg)", padding: "6px 10px", borderRadius: 4, wordBreak: "break-all" }}>
                  {f.cvssVector}
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === "evidence" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {f.evidence.map((e, i) => (
              <div key={i} style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "8px 12px", borderBottom: "1px solid var(--adv-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>{e.label}</span>
                  <CopyBtn text={e.content} />
                </div>
                <pre style={{ margin: 0, padding: "12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6, maxHeight: 250, overflow: "auto" }}>
                  {e.content}
                </pre>
              </div>
            ))}
          </div>
        )}

        {tab === "remediation" && (
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-text-muted)" }}>
                {Array.isArray(f.remediation) ? f.remediation.filter((s) => typeof s !== "string" && s.completed).length : 0} / {f.remediation.length} steps completed
              </span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#FFD600" }}>
                ~{Array.isArray(f.remediation) ? f.remediation.reduce((a, s) => a + (typeof s !== "string" ? s.estimatedHours : 1), 0) : 0}h estimated
              </span>
            </div>
            <RemediationChecklist steps={f.remediation} findingId={f.id} />
          </div>
        )}

        {tab === "compliance" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {f.compliance.map((c, i) => (
              <div key={i} style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 14px" }}>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-accent)", marginBottom: 8 }}>{c.framework}</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {c.refs.map((r, j) => (
                    <div key={j} style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, color: "var(--adv-text)", lineHeight: 1.4 }}>· {r}</div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Main Page ─── */
export default function FindingsPage() {
  const { success, info } = useToast();
  const [findings, setFindings] = useState<Finding[]>(FINDINGS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [filterSev, setFilterSev] = useState<Severity | "ALL">("ALL");
  const [filterStatus, setFilterStatus] = useState<FindingStatus | "ALL">("ALL");
  const [filterCat, setFilterCat] = useState<string>("ALL");
  const [sortBy, setSortBy] = useState<"cvss" | "date" | "status">("cvss");

  const categories = useMemo(() => ["ALL", ...Array.from(new Set(findings.map((f) => f.category)))], [findings]);

  const filtered = useMemo(() => {
    let list = [...findings];
    if (filterSev !== "ALL") list = list.filter((f) => f.severity === filterSev);
    if (filterStatus !== "ALL") list = list.filter((f) => f.status === filterStatus);
    if (filterCat !== "ALL") list = list.filter((f) => f.category === filterCat);
    if (search) list = list.filter((f) => f.title.toLowerCase().includes(search.toLowerCase()) || f.id.includes(search) || f.affectedHost.toLowerCase().includes(search.toLowerCase()));
    list.sort((a, b) => {
      if (sortBy === "cvss") return Number(b.cvss) - Number(a.cvss);
      if (sortBy === "date") return new Date(b.discoveredAt).getTime() - new Date(a.discoveredAt).getTime();
      return a.status.localeCompare(b.status);
    });
    return list;
  }, [findings, filterSev, filterStatus, filterCat, search, sortBy]);

  const stats = useMemo(() => ({
    critical: findings.filter((f) => f.severity === "CRITICAL" && f.status === "OPEN").length,
    high:     findings.filter((f) => f.severity === "HIGH" && f.status === "OPEN").length,
    open:     findings.filter((f) => f.status === "OPEN" || f.status === "IN_REVIEW").length,
    verified: findings.filter((f) => f.status === "VERIFIED" || f.status === "CLOSED").length,
  }), [findings]);

  const handleStatusChange = useCallback((id: string, newStatus: FindingStatus) => {
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status: newStatus } : f));
    success("Status updated", `${id} → ${STATUS_LABEL[newStatus]}`);
  }, [success]);

  const selected = findings.find((f) => f.id === selectedId) ?? null;

  return (
    <PageShell
      title="FINDINGS"
      subtitle="VAPT · TRIAGE · VALIDATION · REMEDIATION"
      statusItems={[
        { label: "CRITICAL OPEN", value: String(stats.critical), color: "#FF1744" },
        { label: "HIGH OPEN",     value: String(stats.high),     color: "#FF6D00" },
        { label: "REMEDIATED",    value: String(stats.verified),  color: "#059669" },
      ]}
    >
      <div style={{ display: "grid", gridTemplateColumns: selectedId ? "360px 1fr" : "1fr", gap: 16 }}>

        {/* ── Left: List ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>

          {/* Stats row */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
            {[
              { label: "CRITICAL",   value: findings.filter((f) => f.severity === "CRITICAL").length, color: "#FF1744" },
              { label: "HIGH",       value: findings.filter((f) => f.severity === "HIGH").length,     color: "#FF6D00" },
              { label: "OPEN",       value: stats.open,     color: "#FF9900" },
              { label: "VERIFIED",   value: stats.verified, color: "#059669" },
            ].map((m) => (
              <div key={m.label} className="animate-fade-up" style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 12px", textAlign: "center" }}>
                <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 22, fontWeight: 700, color: m.color }}>{m.value}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginTop: 2 }}>{m.label}</div>
              </div>
            ))}
          </div>

          {/* Filters */}
          <div style={{ background: "linear-gradient(160deg, rgba(37,99,235,0.05) 0%, #FFFFFF 55%)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "10px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 4, padding: "5px 10px" }}>
              <Search size={11} color="#64748B" />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search findings..."
                style={{ background: "none", border: "none", outline: "none", color: "var(--adv-text)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, width: "100%" }}
              />
            </div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
                <button key={s} onClick={() => setFilterSev(s)} style={{
                  padding: "3px 8px", borderRadius: 3, cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                  border: `1px solid ${filterSev === s ? (s === "ALL" ? "#2563EB" : SEV_COLOR[s as Severity]) : "#E2E8F0"}`,
                  background: filterSev === s ? (s === "ALL" ? "rgba(37,99,235,0.1)" : `${SEV_COLOR[s as Severity]}15`) : "transparent",
                  color: filterSev === s ? (s === "ALL" ? "#2563EB" : SEV_COLOR[s as Severity]) : "#64748B",
                }}>{s}</button>
              ))}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 6, alignItems: "center" }}>
              <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value as FindingStatus | "ALL")}
                style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 4, color: "var(--adv-text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "3px 6px", outline: "none" }}>
                {["ALL", "OPEN", "IN_REVIEW", "IN_REMEDIATION", "VERIFIED", "CLOSED", "ACCEPTED", "FALSE_POSITIVE"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={filterCat} onChange={(e) => setFilterCat(e.target.value)}
                style={{ background: "var(--adv-bg)", border: "1px solid var(--adv-border)", borderRadius: 4, color: "var(--adv-text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, padding: "3px 6px", outline: "none" }}>
                {categories.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              <button onClick={() => setSortBy(sortBy === "cvss" ? "date" : sortBy === "date" ? "status" : "cvss")}
                style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 8px", background: "transparent", border: "1px solid var(--adv-border)", borderRadius: 4, color: "var(--adv-text-muted)", cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", fontSize: 9 }}>
                <ArrowUpDown size={10} /> {sortBy.toUpperCase()}
              </button>
            </div>
          </div>

          {/* Finding list */}
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {filtered.map((f) => {
              const sla = getSlaColor(f.discoveredAt, f.severity);
              const isSelected = selectedId === f.id;
              return (
                <div
                  key={f.id}
                  className="card-hover stagger-item"
                  onClick={() => setSelectedId(isSelected ? null : f.id)}
                  style={{
                    background: isSelected ? "rgba(37,99,235,0.04)" : "#FFFFFF",
                    border: `1px solid ${isSelected ? "#2563EB" : "#E2E8F0"}`,
                    borderLeft: `3px solid ${SEV_COLOR[f.severity]}`,
                    borderRadius: 6, padding: "10px 12px", cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", flex: 1 }}>
                      <SevBadge s={f.severity} />
                      <StatusBadge s={f.status} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{f.id}</span>
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: sla.color }}>{sla.label}</span>
                  </div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--adv-text)", lineHeight: 1.3, marginBottom: 4 }}>
                    {f.title}
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{f.affectedHost}</span>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "#FF6D00" }}>CVSS {f.cvss}</span>
                  </div>
                  {/* SLA mini-bar */}
                  <div style={{ height: 2, background: "#E2E8F0", borderRadius: 1, marginTop: 6, overflow: "hidden" }}>
                    <div className="progress-bar-fill" style={{ height: "100%", width: `${sla.pct}%`, background: sla.color, borderRadius: 1 }} />
                  </div>
                </div>
              );
            })}

            {filtered.length === 0 && (
              <div style={{ textAlign: "center", padding: 32, color: "var(--adv-text-muted)", fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
                No findings match the current filters.
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Detail ── */}
        {selected && (
          <div style={{ minWidth: 0 }}>
            <FindingDetail f={selected} onStatusChange={handleStatusChange} />
          </div>
        )}
      </div>
    </PageShell>
  );
}
