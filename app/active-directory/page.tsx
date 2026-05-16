"use client";

import React, { useState } from "react";
import { Menu, Users, AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import { Sidebar } from "../../components/Sidebar";

/* ─── Types ─── */
interface KerberoastAccount {
  samAccountName: string;
  spn: string;
  passwordLastSet: string;
  hashType: string;
  crackable: boolean;
  groups: string[];
}

interface DelegationEntry {
  accountName: string;
  accountType: "user" | "computer";
  delegationType: "Unconstrained" | "Constrained" | "Resource-Based";
  allowedTo: string;
  risk: "CRITICAL" | "HIGH" | "MEDIUM";
}

interface PrivilegedGroup {
  name: string;
  memberCount: number;
  members: string[];
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

interface AsrepAccount {
  samAccountName: string;
  dn: string;
  hashObtained: boolean;
  cracked: boolean;
}

interface TrustRelationship {
  domain: string;
  direction: "Inbound" | "Outbound" | "Bidirectional";
  type: "Forest" | "External" | "Realm";
  sid_filtering: boolean;
  risk: "HIGH" | "MEDIUM" | "LOW";
}

/* ─── Data ─── */
const domainInfo = {
  name: "corp.local",
  netbios: "CORP",
  dcs: ["DC01.corp.local (PDC)", "DC02.corp.local"],
  functionalLevel: "Windows Server 2016",
  totalUsers: 842,
  totalComputers: 317,
  totalGroups: 94,
  domainAdmins: 7,
  discoveredAt: "2026-05-10T09:32:00Z",
};

const passwordPolicy = [
  { attribute: "Min Password Length",   value: "8 chars",     status: "FAIL",   note: "Below 12 char recommendation" },
  { attribute: "Password History",       value: "10 passwords", status: "PASS",   note: "Meets baseline" },
  { attribute: "Max Password Age",       value: "90 days",     status: "PASS",   note: "Acceptable" },
  { attribute: "Complexity Requirement", value: "Enabled",     status: "PASS",   note: "" },
  { attribute: "Account Lockout",        value: "5 attempts",  status: "PASS",   note: "Meets baseline" },
  { attribute: "Fine-Grained PSO",       value: "None found",  status: "WARN",   note: "No PSO for privileged accounts" },
  { attribute: "Reversible Encryption",  value: "Disabled",    status: "PASS",   note: "" },
  { attribute: "Kerberos Encryption",    value: "RC4 + AES",   status: "WARN",   note: "RC4 still allowed (CVE-2022-37967)" },
];

const kerberoastAccounts: KerberoastAccount[] = [
  {
    samAccountName: "svc_backup",
    spn: "MSSQLSvc/SQL01.corp.local:1433",
    passwordLastSet: "2024-01-15",
    hashType: "RC4-HMAC (Etype 23)",
    crackable: true,
    groups: ["Domain Users", "Backup Operators"],
  },
  {
    samAccountName: "svc_iis",
    spn: "HTTP/web01.corp.local",
    passwordLastSet: "2024-03-20",
    hashType: "RC4-HMAC (Etype 23)",
    crackable: true,
    groups: ["Domain Users"],
  },
  {
    samAccountName: "svc_monitoring",
    spn: "WSMAN/mon01.corp.local",
    passwordLastSet: "2025-06-10",
    hashType: "AES256-CTS-HMAC-SHA1",
    crackable: false,
    groups: ["Domain Users"],
  },
];

const delegationEntries: DelegationEntry[] = [
  {
    accountName: "DC01$",
    accountType: "computer",
    delegationType: "Unconstrained",
    allowedTo: "ANY (TrustedForDelegation = TRUE)",
    risk: "CRITICAL",
  },
  {
    accountName: "svc_iis",
    accountType: "user",
    delegationType: "Constrained",
    allowedTo: "HTTP/web01.corp.local",
    risk: "MEDIUM",
  },
  {
    accountName: "WS-042$",
    accountType: "computer",
    delegationType: "Unconstrained",
    allowedTo: "ANY (TrustedForDelegation = TRUE)",
    risk: "CRITICAL",
  },
];

const privilegedGroups: PrivilegedGroup[] = [
  { name: "Domain Admins",     memberCount: 7,  members: ["Administrator", "john.admin", "svc_backup", "jane.doe", "backup_svc", "sqlsa", "deploy_svc"], risk: "CRITICAL" },
  { name: "Enterprise Admins", memberCount: 2,  members: ["Administrator", "john.admin"], risk: "CRITICAL" },
  { name: "Backup Operators",  memberCount: 4,  members: ["svc_backup", "BKUP01$", "waldo.hicks", "net_admin"], risk: "HIGH" },
  { name: "Server Operators",  memberCount: 3,  members: ["svc_deploy", "net_admin", "WS-042$"], risk: "HIGH" },
  { name: "Account Operators", memberCount: 5,  members: ["helpdesk1", "helpdesk2", "helpdesk3", "svc_hr", "admin_temp"], risk: "MEDIUM" },
];

const asrepAccounts: AsrepAccount[] = [
  { samAccountName: "testuser01", dn: "CN=testuser01,OU=TestAccounts,DC=corp,DC=local", hashObtained: true, cracked: true },
  { samAccountName: "svc_legacy", dn: "CN=svc_legacy,OU=ServiceAccounts,DC=corp,DC=local", hashObtained: true, cracked: false },
];

const trustRelationships: TrustRelationship[] = [
  { domain: "dev.corp.local",   direction: "Bidirectional", type: "Forest",   sid_filtering: false, risk: "HIGH" },
  { domain: "partner.ext",      direction: "Inbound",       type: "External", sid_filtering: true,  risk: "LOW"  },
  { domain: "legacy.corp",      direction: "Bidirectional", type: "External", sid_filtering: false, risk: "HIGH" },
];

/* ─── Helpers ─── */
function riskColor(r: string) {
  if (r === "CRITICAL") return "#FF4444";
  if (r === "HIGH")     return "#FF9900";
  if (r === "MEDIUM")   return "#FFD500";
  return "#00FF88";
}

function statusColor(s: string) {
  if (s === "FAIL") return "#FF4444";
  if (s === "WARN") return "#FF9900";
  return "#00FF88";
}

/* ─── Main Page ─── */
export default function ActiveDirectoryPage() {
  const [sidebarOpen, setSidebarOpen]   = useState(false);
  const [expandedGroup, setExpandedGroup] = useState<string | null>("Domain Admins");
  const [activeTab, setActiveTab]       = useState(0);

  const tabs = ["Domain Overview", "Kerberos Attacks", "Delegation", "Privileged Groups", "Trusts"];

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
            <button className="md:hidden" onClick={() => setSidebarOpen(true)} style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}>
              <Menu size={20} color="#00D4FF" />
            </button>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 18, color: "#00D4FF", letterSpacing: 3 }}>ADVERSA</span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>ACTIVE DIRECTORY v0.9.1</span>
            <Users size={14} color="#00D4FF" style={{ marginLeft: 4 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF4444" }}>
              {kerberoastAccounts.filter((a) => a.crackable).length} KERBEROASTABLE
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900" }}>
              {delegationEntries.filter((d) => d.risk === "CRITICAL").length} UNCONSTRAINED DELEG.
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900" }}>
              DOMAIN: <span style={{ color: "#00D4FF" }}>{domainInfo.name}</span>
            </span>
          </div>
        </header>

        {/* Tab Bar */}
        <div style={{ display: "flex", borderBottom: "1px solid #1A3A50", flexShrink: 0, background: "#050A0E" }}>
          {tabs.map((tab, i) => (
            <button
              key={tab}
              onClick={() => setActiveTab(i)}
              style={{
                padding: "10px 20px",
                background: activeTab === i ? "rgba(0,212,255,0.04)" : "transparent",
                border: "none",
                borderBottom: activeTab === i ? "2px solid #00D4FF" : "2px solid transparent",
                color: activeTab === i ? "#C8E8F0" : "#3D7A94",
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 11,
                letterSpacing: 0.5,
                cursor: "pointer",
                whiteSpace: "nowrap",
              }}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Content */}
        <main style={{ flex: 1, overflowY: "auto", padding: 20 }}>
          {/* ── Tab 0: Domain Overview ── */}
          {activeTab === 0 && (
            <div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: 12,
                  marginBottom: 20,
                }}
              >
                {[
                  { label: "TOTAL USERS",     value: domainInfo.totalUsers,     color: "#00D4FF" },
                  { label: "TOTAL COMPUTERS", value: domainInfo.totalComputers,  color: "#00D4FF" },
                  { label: "TOTAL GROUPS",    value: domainInfo.totalGroups,     color: "#00D4FF" },
                  { label: "DOMAIN ADMINS",   value: domainInfo.domainAdmins,    color: "#FF4444" },
                  { label: "DCS",             value: domainInfo.dcs.length,      color: "#FF9900" },
                ].map((m) => (
                  <div
                    key={m.label}
                    style={{
                      background: "#0D1B26",
                      border: "1px solid #1A3A50",
                      borderRadius: 6,
                      padding: "14px 16px",
                    }}
                  >
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginBottom: 8, letterSpacing: 1 }}>
                      {m.label}
                    </div>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 28, fontWeight: 700, color: m.color, lineHeight: 1 }}>
                      {m.value}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                {/* Domain Topology */}
                <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                    DOMAIN TOPOLOGY
                  </div>
                  <div style={{ padding: 16 }}>
                    {[
                      { label: "Domain Name",      value: domainInfo.name },
                      { label: "NetBIOS",           value: domainInfo.netbios },
                      { label: "Forest Function",   value: domainInfo.functionalLevel },
                      { label: "Domain Controllers", value: domainInfo.dcs.join(", ") },
                      { label: "Enumerated At",     value: new Date(domainInfo.discoveredAt).toLocaleString() },
                    ].map((row) => (
                      <div key={row.label} style={{ display: "flex", padding: "6px 0", borderBottom: "1px solid rgba(26,58,80,0.3)" }}>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94", width: 180, flexShrink: 0 }}>{row.label}</span>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>{row.value}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Password Policy */}
                <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                  <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                    PASSWORD POLICY AUDIT
                  </div>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr>
                          {["ATTRIBUTE", "VALUE", "STATUS", "NOTE"].map((h) => (
                            <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {passwordPolicy.map((row, i) => (
                          <tr key={row.attribute}>
                            <td style={{ padding: "8px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < passwordPolicy.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{row.attribute}</td>
                            <td style={{ padding: "8px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#00D4FF", borderBottom: i < passwordPolicy.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{row.value}</td>
                            <td style={{ padding: "8px 12px", borderBottom: i < passwordPolicy.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: statusColor(row.status), padding: "1px 6px", borderRadius: 3, background: `${statusColor(row.status)}15` }}>{row.status}</span>
                            </td>
                            <td style={{ padding: "8px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: i < passwordPolicy.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{row.note}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── Tab 1: Kerberos Attacks ── */}
          {activeTab === 1 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Kerberoastable */}
              <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>KERBEROASTABLE SERVICE ACCOUNTS</span>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF4444", padding: "2px 8px", border: "1px solid #FF444440", borderRadius: 4 }}>MITRE T1558.003</span>
                </div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["ACCOUNT", "SPN", "HASH TYPE", "LAST PW SET", "CRACKABLE", "MEMBER OF"].map((h) => (
                          <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {kerberoastAccounts.map((acct, i) => (
                        <tr key={acct.samAccountName}>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF4444", borderBottom: i < kerberoastAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.samAccountName}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0", borderBottom: i < kerberoastAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.spn}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: acct.hashType.includes("RC4") ? "#FF9900" : "#00FF88", borderBottom: i < kerberoastAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.hashType}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < kerberoastAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.passwordLastSet}</td>
                          <td style={{ padding: "10px 12px", borderBottom: i < kerberoastAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: acct.crackable ? "#FF4444" : "#00FF88", padding: "2px 6px", borderRadius: 3, background: acct.crackable ? "#FF444420" : "#00FF8820" }}>{acct.crackable ? "YES" : "NO"}</span>
                          </td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: i < kerberoastAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.groups.join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* AS-REP Roasting */}
              <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>AS-REP ROASTABLE ACCOUNTS</span>
                  <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF9900", padding: "2px 8px", border: "1px solid #FF990040", borderRadius: 4 }}>MITRE T1558.004</span>
                </div>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        {["ACCOUNT", "DISTINGUISHED NAME", "HASH OBTAINED", "CRACKED"].map((h) => (
                          <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {asrepAccounts.map((acct, i) => (
                        <tr key={acct.samAccountName}>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900", borderBottom: i < asrepAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.samAccountName}</td>
                          <td style={{ padding: "10px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < asrepAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{acct.dn}</td>
                          <td style={{ padding: "10px 12px", borderBottom: i < asrepAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: acct.hashObtained ? "#FF4444" : "#3D7A94", padding: "2px 6px", borderRadius: 3, background: acct.hashObtained ? "#FF444420" : "transparent" }}>{acct.hashObtained ? "YES" : "NO"}</span>
                          </td>
                          <td style={{ padding: "10px 12px", borderBottom: i < asrepAccounts.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: acct.cracked ? "#FF4444" : "#00D4FF", padding: "2px 6px", borderRadius: 3, background: acct.cracked ? "#FF444420" : "#00D4FF20" }}>{acct.cracked ? "CRACKED" : "PENDING"}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ── Tab 2: Delegation ── */}
          {activeTab === 2 && (
            <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>KERBEROS DELEGATION ANALYSIS</span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF4444", padding: "2px 8px", border: "1px solid #FF444440", borderRadius: 4 }}>MITRE T1134.001</span>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["ACCOUNT", "TYPE", "DELEGATION", "ALLOWED TO DELEGATE", "RISK"].map((h) => (
                        <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", whiteSpace: "nowrap", letterSpacing: 1 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {delegationEntries.map((entry, i) => (
                      <tr key={entry.accountName}>
                        <td style={{ padding: "12px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: entry.risk === "CRITICAL" ? "#FF4444" : "#C8E8F0", borderBottom: i < delegationEntries.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{entry.accountName}</td>
                        <td style={{ padding: "12px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < delegationEntries.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{entry.accountType.toUpperCase()}</td>
                        <td style={{ padding: "12px 14px", borderBottom: i < delegationEntries.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: entry.delegationType === "Unconstrained" ? "#FF4444" : "#FF9900", padding: "2px 6px", borderRadius: 3, background: entry.delegationType === "Unconstrained" ? "#FF444420" : "#FF990020" }}>{entry.delegationType}</span>
                        </td>
                        <td style={{ padding: "12px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: entry.delegationType === "Unconstrained" ? "#FF4444" : "#C8E8F0", borderBottom: i < delegationEntries.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{entry.allowedTo}</td>
                        <td style={{ padding: "12px 14px", borderBottom: i < delegationEntries.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: riskColor(entry.risk), padding: "2px 6px", borderRadius: 3, background: `${riskColor(entry.risk)}20` }}>{entry.risk}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{ padding: "12px 16px", borderTop: "1px solid #1A3A50", background: "#050A0E" }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#FF4444" }}>
                  ⚠ CRITICAL: Unconstrained Delegation on DC01$ allows any compromised host to capture TGTs for all authenticating principals including Domain Admins.
                </div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginTop: 4 }}>
                  Remediation: Set-ADComputer DC01 -TrustedForDelegation $false | Enable Protected Users group for DA accounts
                </div>
              </div>
            </div>
          )}

          {/* ── Tab 3: Privileged Groups ── */}
          {activeTab === 3 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {privilegedGroups.map((group) => {
                const isExpanded = expandedGroup === group.name;
                return (
                  <div key={group.name} style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
                    <div
                      onClick={() => setExpandedGroup(isExpanded ? null : group.name)}
                      style={{
                        padding: "12px 16px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        cursor: "pointer",
                        borderBottom: isExpanded ? "1px solid #1A3A50" : "none",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        {isExpanded ? <ChevronDown size={14} color="#00D4FF" /> : <ChevronRight size={14} color="#3D7A94" />}
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0" }}>{group.name}</span>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>{group.memberCount} members</span>
                      </div>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: riskColor(group.risk), padding: "2px 6px", borderRadius: 3, background: `${riskColor(group.risk)}20` }}>{group.risk}</span>
                    </div>
                    {isExpanded && (
                      <div style={{ padding: "10px 16px", display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {group.members.map((member) => (
                          <span
                            key={member}
                            style={{
                              fontFamily: "'Share Tech Mono', monospace",
                              fontSize: 10,
                              color: member.includes("svc_") || member.includes("admin") ? "#FF9900" : "#C8E8F0",
                              padding: "3px 8px",
                              border: "1px solid #1A3A50",
                              borderRadius: 4,
                              background: "#050A0E",
                            }}
                          >
                            {member}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* ── Tab 4: Trusts ── */}
          {activeTab === 4 && (
            <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A3A50", fontFamily: "'Share Tech Mono', monospace", fontSize: 12, color: "#C8E8F0", letterSpacing: 1 }}>
                DOMAIN TRUST RELATIONSHIPS
              </div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["TRUSTED DOMAIN", "DIRECTION", "TYPE", "SID FILTERING", "RISK"].map((h) => (
                        <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", borderBottom: "1px solid #1A3A50", letterSpacing: 1 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {trustRelationships.map((trust, i) => (
                      <tr key={trust.domain}>
                        <td style={{ padding: "12px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0", borderBottom: i < trustRelationships.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{trust.domain}</td>
                        <td style={{ padding: "12px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#00D4FF", borderBottom: i < trustRelationships.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{trust.direction}</td>
                        <td style={{ padding: "12px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", borderBottom: i < trustRelationships.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>{trust.type}</td>
                        <td style={{ padding: "12px 14px", borderBottom: i < trustRelationships.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: trust.sid_filtering ? "#00FF88" : "#FF4444", padding: "2px 6px", borderRadius: 3, background: trust.sid_filtering ? "#00FF8820" : "#FF444420" }}>
                            {trust.sid_filtering ? "ENABLED" : "DISABLED"}
                          </span>
                        </td>
                        <td style={{ padding: "12px 14px", borderBottom: i < trustRelationships.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: riskColor(trust.risk), padding: "2px 6px", borderRadius: 3, background: `${riskColor(trust.risk)}20` }}>{trust.risk}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </main>

        {/* Footer */}
        <footer style={{ height: 32, borderTop: "1px solid #1A3A50", background: "#0D1B26", display: "flex", alignItems: "center", padding: "0 20px", gap: 16, flexShrink: 0 }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
            DOMAIN: <span style={{ color: "#00D4FF" }}>{domainInfo.name}</span>
          </span>
          <span style={{ color: "#1A3A50" }}>|</span>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
            KERBEROASTABLE: <span style={{ color: "#FF4444" }}>{kerberoastAccounts.filter((a) => a.crackable).length}</span>
          </span>
          <span style={{ color: "#1A3A50" }}>|</span>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
            UNCONSTRAINED DELEG: <span style={{ color: "#FF4444" }}>{delegationEntries.filter((d) => d.delegationType === "Unconstrained").length}</span>
          </span>
        </footer>
      </div>
    </div>
  );
}
