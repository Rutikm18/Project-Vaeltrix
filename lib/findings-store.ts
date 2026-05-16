import fs from "fs";
import path from "path";

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingStatus = "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED" | "ACCEPTED" | "FALSE_POSITIVE";

export interface RemediationStep {
  step: number;
  title: string;
  command?: string;
  description: string;
  estimatedHours: number;
  verification?: string;
  completed: boolean;
  completedBy?: string;
  completedAt?: string;
}

export interface ComplianceRef {
  framework: string;
  refs: string[];
}

export interface MitreTechnique {
  id: string;
  name: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  cvss: string;
  cvssVector: string;
  category: string;
  status: FindingStatus;
  affectedHost: string;
  discoveredAt: string;
  updatedAt: string;
  assignee?: string;
  caseId?: string;
  slaDeadline: string;
  description: string;
  technicalDetails: string;
  attackPath: string;
  evidence: { label: string; content: string }[];
  impact: string;
  businessImpact?: string;
  exploitability?: "EASY" | "MODERATE" | "DIFFICULT";
  remediation: RemediationStep[];
  compliance: ComplianceRef[];
  mitre: MitreTechnique[];
  riskScore?: number;
  validatedBy?: string;
  validatedAt?: string;
  falsePositiveReason?: string;
}

const DATA_FILE = path.join(process.cwd(), "data", "findings.json");

const SLA_HOURS: Partial<Record<FindingSeverity, number>> = {
  CRITICAL: 24,
  HIGH: 72,
  MEDIUM: 168,
  LOW: 720,
};

function slaDeadline(discoveredAt: string, severity: FindingSeverity): string {
  const h = SLA_HOURS[severity];
  if (!h) return discoveredAt;
  return new Date(new Date(discoveredAt).getTime() + h * 3_600_000).toISOString();
}

const SEED_FINDINGS: Finding[] = [
  {
    id: "VAPT-CRIT-001",
    title: "Unconstrained Kerberos Delegation on DC01",
    severity: "CRITICAL",
    cvss: "9.8",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    category: "Active Directory",
    status: "OPEN",
    affectedHost: "DC01.corp.local",
    discoveredAt: "2026-05-10T09:32:00Z",
    updatedAt: "2026-05-10T09:32:00Z",
    slaDeadline: slaDeadline("2026-05-10T09:32:00Z", "CRITICAL"),
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
    severity: "CRITICAL",
    cvss: "9.1",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    category: "Active Directory",
    status: "IN_REVIEW",
    affectedHost: "corp.local (svc_backup)",
    discoveredAt: "2026-05-10T10:14:00Z",
    updatedAt: "2026-05-10T14:00:00Z",
    slaDeadline: slaDeadline("2026-05-10T10:14:00Z", "CRITICAL"),
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
      { step: 2, title: "Force AES256 encryption", command: "Set-ADUser svc_backup -KerberosEncryptionType AES256", description: "Eliminates RC4 crack path.", estimatedHours: 0.5, verification: "Get-ADUser svc_backup -Properties msDS-SupportedEncryptionTypes", completed: false },
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
    severity: "HIGH",
    cvss: "8.1",
    cvssVector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    category: "Protocol Abuse",
    status: "IN_REMEDIATION",
    affectedHost: "10.10.10.0/24 CORP VLAN",
    discoveredAt: "2026-05-10T11:05:00Z",
    updatedAt: "2026-05-11T09:00:00Z",
    slaDeadline: slaDeadline("2026-05-10T11:05:00Z", "HIGH"),
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
    severity: "HIGH",
    cvss: "7.5",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
    category: "Lateral Movement",
    status: "OPEN",
    affectedHost: "WS-042, 10.10.10.0/24",
    discoveredAt: "2026-05-10T14:22:00Z",
    updatedAt: "2026-05-10T14:22:00Z",
    slaDeadline: slaDeadline("2026-05-10T14:22:00Z", "HIGH"),
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
    severity: "MEDIUM",
    cvss: "6.4",
    cvssVector: "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
    category: "Segmentation",
    status: "VERIFIED",
    affectedHost: "VLAN30 → VLAN10 inter-VLAN routing",
    discoveredAt: "2026-05-11T09:15:00Z",
    updatedAt: "2026-05-13T11:00:00Z",
    slaDeadline: slaDeadline("2026-05-11T09:15:00Z", "MEDIUM"),
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

function ensureDataDir() {
  const dir = path.join(process.cwd(), "data");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export function readFindings(): Finding[] {
  ensureDataDir();
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(SEED_FINDINGS, null, 2));
    return SEED_FINDINGS;
  }
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8")) as Finding[];
  } catch {
    return SEED_FINDINGS;
  }
}

export function writeFindings(findings: Finding[]) {
  ensureDataDir();
  fs.writeFileSync(DATA_FILE, JSON.stringify(findings, null, 2));
}

export function getFindingById(id: string): Finding | undefined {
  return readFindings().find((f) => f.id === id);
}

export function createFinding(data: Omit<Finding, "id" | "discoveredAt" | "updatedAt" | "slaDeadline">): Finding {
  const findings = readFindings();
  const seq = findings.length + 1;
  const sev = data.severity;
  const id = `VAPT-${sev.slice(0, 4)}-${String(seq).padStart(3, "0")}`;
  const now = new Date().toISOString();
  const newFinding: Finding = {
    ...data,
    id,
    discoveredAt: now,
    updatedAt: now,
    slaDeadline: slaDeadline(now, sev),
  };
  writeFindings([...findings, newFinding]);
  return newFinding;
}

export function updateFinding(id: string, patch: Partial<Finding>): Finding | null {
  const findings = readFindings();
  const idx = findings.findIndex((f) => f.id === id);
  if (idx === -1) return null;
  const updated: Finding = { ...findings[idx], ...patch, updatedAt: new Date().toISOString() };
  findings[idx] = updated;
  writeFindings(findings);
  return updated;
}

export function deleteFinding(id: string): boolean {
  const findings = readFindings();
  const next = findings.filter((f) => f.id !== id);
  if (next.length === findings.length) return false;
  writeFindings(next);
  return true;
}

export function getSlaInfo(f: Finding): {
  hoursLeft: number;
  pctLeft: number;
  breached: boolean;
  color: string;
  label: string;
} {
  const slaH = SLA_HOURS[f.severity];
  if (!slaH) return { hoursLeft: 0, pctLeft: 100, breached: false, color: "#3D7A94", label: "N/A" };

  const due = new Date(f.slaDeadline).getTime();
  const created = new Date(f.discoveredAt).getTime();
  const now = Date.now();
  const totalMs = due - created;
  const leftMs = due - now;
  const hoursLeft = Math.max(0, leftMs / 3_600_000);
  const pctLeft = Math.max(0, Math.min(100, (leftMs / totalMs) * 100));
  const breached = now > due;

  let color = "#00E676";
  if (breached || pctLeft < 10) color = "#FF1744";
  else if (pctLeft < 25) color = "#FF6D00";
  else if (pctLeft < 50) color = "#FFD600";

  const label = breached ? "BREACHED" : hoursLeft < 24 ? `${Math.round(hoursLeft)}h` : `${Math.round(hoursLeft / 24)}d`;

  return { hoursLeft, pctLeft, breached, color, label };
}
