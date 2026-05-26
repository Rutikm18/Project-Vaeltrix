# ADVERSA — Scanning Engine: Full Tool Integration
## Task 1: Network Vulnerability Discovery Pipeline

**Classification:** Internal / Engineering Reference  
**Version:** 1.0  
**Scope:** Integrate 8 security tools into a chained, findings-producing scan pipeline

---

## Pipeline Overview

Tools execute in a fixed dependency chain. Each stage feeds the next:

```
Target(s) Input
     │
     ▼
[1] Naabu ──────── Port Discovery (fast, broad)
     │ open ports
     ▼
[2] Nmap ─────────  Service Enumeration (targeted on Naabu ports)
     │ service/version/OS map
     ├──────────────────────────────────────────────────────┐
     ▼                                                       ▼
[3] Nuclei ──────── Template Vuln Scan          [7] testssl.sh ── TLS/SSL Analysis
     │                                                       │
     ▼                                                       │
[4] OpenVAS ─────── Deep CVE Scan                           │
     │                                                       │
     ├──────┬────────────────────────────────────────────────┘
     ▼      ▼
[5] NetExec  [6] Impacket ── Protocol Validation (SMB/LDAP/Kerberos)
     │              │
     └──────┬───────┘
            ▼
     [8] EyeWitness ── Screenshot Evidence (web services)
            │
            ▼
     ┌──────────────┐
     │  Findings DB │  ← All tool results auto-parsed into Finding objects
     └──────────────┘
```

---

## Current State

| Tool       | Agent (`agent.py`)         | API Route                      | UI          |
|------------|----------------------------|-------------------------------|-------------|
| Nmap       | `execute_discovery()` ✅   | `app/api/scan/nmap/route.ts` ✅ | scan page ✅ |
| Nuclei     | `execute_vuln_scan()` ⚠️   | None                          | None        |
| Naabu      | None                       | None                          | None        |
| OpenVAS    | None                       | None                          | None        |
| NetExec    | None                       | None                          | None        |
| Impacket   | `execute_ad_enum()` ⚠️     | None                          | None        |
| testssl.sh | None                       | None                          | None        |
| EyeWitness | None                       | None                          | None        |

⚠️ = stub exists, not production-ready

---

## Task 1.1 — Naabu: Port Discovery

**Purpose:** Fast async port scanner. Runs first to identify all open ports before Nmap's slower service scan.

**Why before Nmap:** Naabu scans all 65535 ports in seconds using SYN probes. Nmap then runs targeted `-p <naabu-ports>` instead of `-p-`, cutting Nmap time by 80%.

### Files to create/modify

| File | Action |
|------|--------|
| `app/api/scan/naabu/route.ts` | Create — HTTP POST handler |
| `infrastructure/agent/agent.py` | Add `execute_naabu()` |
| `app/scan/page.tsx` | Add Naabu as Step 1 in pipeline UI |

### API Route: `POST /api/scan/naabu`

**Request body:**
```typescript
{
  targets: string[];      // IPs, CIDRs, or hostnames
  ports?: string;         // "1-65535" | "top-1000" | "top-100" (default: top-1000)
  rate?: number;          // packets/sec, default 1000, max 5000
  excludePorts?: string;  // comma-separated ports to exclude
  timeout?: number;       // per-host timeout ms, default 5000
}
```

**Response:**
```typescript
{
  scanId: string;
  startTime: string;
  endTime: string;
  elapsed: string;
  hosts: {
    ip: string;
    openPorts: number[];
    portCount: number;
  }[];
  totalHosts: number;
  totalOpenPorts: number;
  command: string;        // exact naabu command run
}
```

### Agent executor: `execute_naabu()`

```python
# Key naabu flags:
# -host <targets>         target IPs/CIDRs
# -p <ports>              port range (default: top-1000)
# -rate <n>               packets/sec
# -json                   JSON output per host
# -o /tmp/naabu_out.json  output file
# -silent                 suppress banner
# -exclude-ports <ports>  skip specific ports

naabu_cmd = [
    "naabu",
    "-list", "/tmp/naabu_targets.txt",
    "-p", port_spec,
    "-rate", str(rate),
    "-json",
    "-o", "/tmp/naabu_out.json",
    "-silent",
]
```

**Output parsing:** Naabu writes one JSON object per line:
```json
{"ip": "10.0.0.1", "port": 22, "protocol": "tcp"}
{"ip": "10.0.0.1", "port": 80, "protocol": "tcp"}
```
Group by IP to produce the port list passed to Nmap.

### Nmap handoff

After Naabu completes, extract the port list per host:
```python
# Build per-host port string for Nmap: "-p 22,80,443,8080"
nmap_ports = ",".join(str(p) for p in sorted(open_ports))
```

---

## Task 1.2 — Nmap: Service Enumeration (Enhancement)

**Current state:** Basic XML parser exists in `app/api/scan/nmap/route.ts`. Agent executor in `execute_discovery()` uses hardcoded flags. Nmap runs independently, not aware of Naabu results.

**Changes needed:**

### 1. Accept Naabu port list as input

Modify `POST /api/scan/nmap` to accept `ports?: string` parameter. When provided, replace `-p-` or top-port flags with `-p <naabu_ports>`.

**Updated request body:**
```typescript
{
  target: string;
  scanType: "quick" | "service" | "full" | "os" | "vuln" | "stealth" | "targeted";
  ports?: string;       // NEW: port list from Naabu, e.g. "22,80,443,8080"
  scripts?: string[];   // NEW: specific NSE scripts to run
}
```

### 2. New scan profile: `targeted`

```typescript
targeted: (ports: string) => ["-sV", "-sC", "-A", "--version-intensity", "7", "-p", ports]
```

### 3. Enhanced XML parsing

Extend `parseNmapXml()` to extract:

```typescript
interface ScanPort {
  // existing fields ...
  scripts: {                  // NEW: NSE script output
    id: string;               // script name e.g. "http-title"
    output: string;           // raw script output
  }[];
  banner?: string;            // NEW: extracted service banner
  vulnerabilities?: {         // NEW: from vuln scripts
    id: string;               // CVE-YYYY-NNNNN
    state: string;            // "VULNERABLE" | "LIKELY_VULNERABLE"
    description: string;
    refs: string[];
  }[];
}
```

NSE script output lives in `<script id="..." output="...">` inside the `<port>` element.

### 4. Auto-generate findings from vuln scan

When `scanType === "vuln"`, parse NSE vuln script output and call `POST /api/findings` for each confirmed vulnerability found. Use this mapping:

| NSE Script | Finding Category | Default Severity |
|------------|-----------------|-----------------|
| `vuln-*` CVE confirmed | Network Service | Based on CVSS |
| `http-shellshock` | RCE | CRITICAL |
| `ms17-010` | RCE (EternalBlue) | CRITICAL |
| `ssl-heartbleed` | Cryptographic | CRITICAL |
| `smb-vuln-ms08-067` | RCE | CRITICAL |
| `http-slowloris-check` | DoS | HIGH |
| `mysql-empty-password` | Authentication | HIGH |
| `ftp-anon` | Authentication | MEDIUM |
| `smtp-open-relay` | Misconfiguration | MEDIUM |

### 5. Agent enhancement

Update `execute_discovery()` in `agent.py` to:
- Accept `ports` parameter from job payload
- Use Naabu port list when available
- Parse full nmap XML with python-nmap (`import nmap`)
- Return structured data including services and banners

---

## Task 1.3 — Nuclei: Main Vulnerability Scanning

**Purpose:** Template-based scanner covering CVEs, misconfigs, exposed panels, default creds, TLS issues.

**Current state:** `execute_vuln_scan()` in `agent.py` runs nuclei with basic tags. No API route. No output parsing. No findings creation.

### Files to create/modify

| File | Action |
|------|--------|
| `app/api/scan/nuclei/route.ts` | Create |
| `lib/nuclei-parser.ts` | Create — parse JSONL output → Finding[] |
| `infrastructure/agent/agent.py` | Rewrite `execute_vuln_scan()` |

### API Route: `POST /api/scan/nuclei`

**Request body:**
```typescript
{
  targets: string[];              // IPs, hostnames, URLs
  templates?: string[];           // specific template paths (optional)
  tags?: string[];                // template tags: "cves", "misconfigs", "ssl", etc.
  severity?: ("critical"|"high"|"medium"|"low"|"info")[];  // filter by severity
  rateLimit?: number;             // requests/sec, default 50
  concurrency?: number;           // parallel templates, default 25
  retries?: number;               // default 1
  timeout?: number;               // per-request ms, default 5000
  createFindings?: boolean;       // auto-create findings for confirmed vulns
}
```

**Response:**
```typescript
{
  scanId: string;
  elapsed: string;
  totalTemplates: number;
  matches: NucleiMatch[];
  findingsCreated: string[];      // Finding IDs created (if createFindings=true)
  stats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

interface NucleiMatch {
  templateId: string;             // e.g. "CVE-2021-44228"
  templateName: string;
  severity: string;
  host: string;
  ip: string;
  port: string;
  matchedAt: string;              // URL or IP:port
  type: string;                   // "http" | "tcp" | "ssl" | "dns"
  extractedResults?: string[];    // data extracted by the template
  curl?: string;                  // curl command that confirmed the vuln
  timestamp: string;
  cvss?: string;
  cve?: string;
  reference?: string[];
  tags: string[];
}
```

### Nuclei output format (JSONL)

Each match is a single JSON line:
```json
{
  "template-id": "CVE-2021-44228",
  "info": {"name": "Log4j RCE", "severity": "critical", "tags": ["cve","log4j"]},
  "host": "http://10.0.0.5:8080",
  "ip": "10.0.0.5",
  "port": "8080",
  "matched-at": "http://10.0.0.5:8080/login",
  "extracted-results": ["jndi:ldap://..."],
  "curl-command": "curl -X POST ...",
  "timestamp": "2026-05-21T10:00:00Z"
}
```

### Nuclei → Finding mapping: `lib/nuclei-parser.ts`

```typescript
function nucleiMatchToFinding(match: NucleiMatch, engagementId: string): Omit<Finding, "id"> {
  const severityMap: Record<string, FindingSeverity> = {
    critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO"
  };

  return {
    title: match.templateName,
    severity: severityMap[match.severity] ?? "INFO",
    cvss: match.cvss ?? deriveCvss(match.severity),
    cvssVector: "",
    category: deriveCategory(match.tags),     // "CVE" | "Misconfiguration" | "Exposed Panel" etc.
    status: "OPEN",
    affectedHost: match.ip,
    discoveredAt: match.timestamp,
    updatedAt: match.timestamp,
    slaDeadline: computeSlaDeadline(severityMap[match.severity]),
    description: `${match.templateName} detected on ${match.matchedAt}`,
    technicalDetails: match.curlCommand ?? `Template: ${match.templateId}\nMatched at: ${match.matchedAt}`,
    attackPath: `External → ${match.ip}:${match.port} → ${match.templateId}`,
    evidence: [
      { label: "Nuclei Match", content: JSON.stringify(match, null, 2) },
      ...(match.curlCommand ? [{ label: "Reproduction Command", content: match.curlCommand }] : []),
    ],
    impact: deriveImpact(match),
    businessImpact: "",
    exploitability: match.severity === "critical" ? "EASY" : "MODERATE",
    remediation: deriveRemediation(match),
    compliance: [],
    mitre: [],
    riskScore: computeRiskScore(match.severity),
  };
}
```

### Template tag strategy
            for line in f:
                try:
                    matches.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass

    # Report results back for findings creation
    await report_progress(100)
    return {
        "scanner": "nuclei",
        "matches": matches,
        "stats": count_by_severity(matches),
    }
```

---

## Task 1.4 — OpenVAS: Deep CVE Scanning

**Purpose:** Authenticated CVE scanner. Runs after Nuclei for deep authenticated scanning. Uses GVM (Greenbone Vulnerability Manager) API.

**Why after Nuclei:** OpenVAS is slow (10–40min per target). Run Nuclei first for fast wins; OpenVAS validates and deepens.

### Files to create/modify

| File | Action |
|------|--------|
| `app/api/scan/openvas/route.ts` | Create |
| `lib/openvas-client.ts` | Create — GVM XML protocol wrapper |
| `infrastructure/agent/agent.py` | Add `execute_openvas_scan()` |

### OpenVAS API flow

OpenVAS exposes a GMP (Greenbone Management Protocol) XML-over-TLS API. Use the `python-gvm` library in the agent.

```python
# agent.py: execute_openvas_scan()
from gvm.connections import TLSConnection
from gvm.protocols import Gmp
from gvm.transforms import EtreeTransform

async def execute_openvas_scan(job: ScanJob, creds: dict, report_progress) -> dict:
    gvm_host     = creds.get("openvas_host", "openvas")
    gvm_port     = int(creds.get("openvas_port", "9390"))
    gvm_user     = creds.get("openvas_user", "admin")
    gvm_password = creds.get("openvas_password", "")

    with TLSConnection(hostname=gvm_host, port=gvm_port) as conn:
        with Gmp(conn, transform=EtreeTransform()) as gmp:
            gmp.authenticate(gvm_user, gvm_password)
            
            # Create target
            target_resp = gmp.create_target(
                name=f"adversa-{job.id}",
                hosts=",".join(job.target_cidrs),
                port_list_id=GMP_FULL_PORT_LIST_ID,
            )
            target_id = target_resp.get("id")
            
            # Create task with "Full and Fast" scan config
            task_resp = gmp.create_task(
                name=f"adversa-task-{job.id}",
                config_id=GMP_FULL_FAST_CONFIG_ID,
                target_id=target_id,
                scanner_id=GMP_OPENVAS_SCANNER_ID,
            )
            task_id = task_resp.get("id")
            
            # Start task
            gmp.start_task(task_id)
            await report_progress(15)
            
            # Poll until complete
            while True:
                await asyncio.sleep(30)
                report = gmp.get_task(task_id)
                status = report.find("task/status").text
                progress = int(report.find("task/progress").text or 0)
                await report_progress(15 + int(progress * 0.75))
                if status in ("Done", "Stopped"):
                    break
            
            # Fetch results
            report_id = report.find("task/last_report/report").get("id")
            results = gmp.get_results(
                task_id=task_id,
                filter_string="levels=hmlg rows=-1",
            )
            
            # Parse into structured findings
            findings = parse_openvas_results(results)
            
            # Cleanup
            gmp.delete_task(task_id, ultimate=True)
            gmp.delete_target(target_id, ultimate=True)
            
            await report_progress(100)
            return {"scanner": "openvas", "findings": findings, "stats": count_by_severity(findings)}
```

### OpenVAS → Finding mapping

```python
def parse_openvas_results(results_xml) -> list[dict]:
    findings = []
    for result in results_xml.findall(".//result"):
        severity = float(result.findtext("severity") or "0")
        if severity < 0.1:
            continue

        nvt = result.find("nvt")
        cve_refs = [ref.get("id") for ref in nvt.findall("refs/ref[@type='cve']")]
        
        findings.append({
            "title":           result.findtext("name"),
            "severity":        cvss_to_severity(severity),
            "cvss":            str(severity),
            "cves":            cve_refs,
            "affectedHost":    result.findtext("host/hostname") or result.findtext("host"),
            "port":            result.findtext("port"),
            "description":     result.findtext("description"),
            "solution":        nvt.findtext("solution"),
            "insight":         nvt.findtext("insight"),
            "detection":       nvt.findtext("detection"),
            "nvtOid":          nvt.get("oid"),
            "qod":             result.findtext("qod/value"),     # quality of detection %
        })
    return findings
```

### API Route: `POST /api/scan/openvas`

```typescript
// Request
{
  targets: string[];
  scanConfig?: "full-fast" | "full-fast-ultimate" | "empty" | "system-discovery";
  // OpenVAS connection (or read from env)
  gvmHost?: string;
  gvmPort?: number;
  gvmUser?: string;
  createFindings?: boolean;
}

// Response
{
  taskId: string;
  status: "queued" | "running" | "done" | "error";
  progress: number;        // 0-100
  findings: OpenVAsFinding[];
  findingsCreated: string[];
}
```

**Important:** OpenVAS scans are long-running. The API route should start the task and return `taskId`. Poll `GET /api/scan/openvas/[taskId]` for status.

### Environment variables to add to `.env.local`

```env
OPENVAS_HOST=openvas
OPENVAS_PORT=9390
OPENVAS_USER=admin
OPENVAS_PASSWORD=
# GVM constant IDs (get via gmp.get_configs() / get_targets() on first run)
OPENVAS_FULL_FAST_CONFIG_ID=
OPENVAS_FULL_PORT_LIST_ID=
OPENVAS_SCANNER_ID=
```

---

## Task 1.5 — NetExec: SMB Validation

**Purpose:** Validate SMB vulnerabilities, enumerate shares, check password policies, test null sessions and relay opportunities.

### Files to create/modify

| File | Action |
|------|--------|
| `app/api/scan/netexec/route.ts` | Create |
| `infrastructure/agent/agent.py` | Add `execute_smb_validation()` |

### NetExec capabilities to implement

| Check | Command | Finding |
|-------|---------|---------|
| SMB signing disabled | `nxc smb <target> --gen-relay-list` | HIGH — relay attack possible |
| Null session | `nxc smb <target> -u '' -p ''` | HIGH — unauthenticated access |
| Guest login | `nxc smb <target> -u 'guest' -p ''` | HIGH — guest access enabled |
| Share enumeration | `nxc smb <target> -u <user> -p <pass> --shares` | INFO / HIGH based on sensitive shares |
| Password policy | `nxc smb <target> -u <user> -p <pass> --pass-pol` | Depends on policy weakness |
| Active sessions | `nxc smb <target> -u <user> -p <pass> --sessions` | INFO |
| SMB versions | `nxc smb <target>` | CRITICAL if SMBv1 enabled |

### Agent executor

```python
async def execute_smb_validation(job: ScanJob, creds: dict, report_progress) -> dict:
    domain   = creds.get("domain", "")
    username = creds.get("username", "")
    password = creds.get("password", "")
    
    results = {}
    findings = []

    for cidr in job.target_cidrs:
        # 1. Base SMB scan — detect SMBv1, signing, OS
        proc = await asyncio.create_subprocess_exec(
            "nxc", "smb", cidr,
            "--json", "-o", "/tmp/nxc_base.json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        base_results = load_nxc_json("/tmp/nxc_base.json")
        
        # Flag SMBv1 hosts
        for host in base_results:
            if host.get("smbv1"):
                findings.append(make_finding(
                    title=f"SMBv1 Enabled — {host['host']}",
                    severity="CRITICAL",
                    host=host["host"],
                    description="SMBv1 is enabled. Vulnerable to EternalBlue (MS17-010) and other SMBv1 exploits.",
                    mitre=[{"id": "T1210", "name": "Exploitation of Remote Services"}],
                ))
            if not host.get("signing"):
                findings.append(make_finding(
                    title=f"SMB Signing Disabled — {host['host']}",
                    severity="HIGH",
                    host=host["host"],
                    description="SMB signing is not enforced. Vulnerable to NTLM relay attacks.",
                    mitre=[{"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning and SMB Relay"}],
                ))

        await report_progress(30)

        # 2. Null session check
        proc = await asyncio.create_subprocess_exec(
            "nxc", "smb", cidr, "-u", "", "-p", "", "--shares",
            "--json", "-o", "/tmp/nxc_null.json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        # Parse for successful null sessions and readable shares

        await report_progress(60)

        # 3. Authenticated checks (if creds provided)
        if username and password:
            proc = await asyncio.create_subprocess_exec(
                "nxc", "smb", cidr,
                "-u", username, "-p", password,
                "-d", domain,
                "--shares", "--pass-pol", "--sessions",
                "--json", "-o", "/tmp/nxc_auth.json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

    await report_progress(100)
    return {"scanner": "netexec", "findings": findings, "rawResults": results}
```

### API Route: `POST /api/scan/netexec`

```typescript
// Request
{
  targets: string[];
  domain?: string;
  username?: string;
  password?: string;
  checks?: ("smb" | "null-session" | "shares" | "password-policy" | "relay-list")[];
  createFindings?: boolean;
}

// Response
{
  hosts: {
    ip: string;
    hostname: string;
    os: string;
    domain: string;
    smbv1: boolean;
    signing: boolean;
    shares?: { name: string; access: "READ" | "WRITE" | "NO ACCESS" }[];
    passwordPolicy?: { minLength: number; lockoutThreshold: number; complexityEnabled: boolean };
    nullSession: boolean;
  }[];
  findings: NxcFinding[];
  findingsCreated: string[];
}
```

---

## Task 1.6 — Impacket: Protocol Validation

**Purpose:** Validate Kerberos, LDAP, DCOM, and WMI protocol weaknesses. Uses Impacket scripts from the Impacket suite.

**Note:** All Impacket checks are **read-only enumeration**. No exploitation, no password spraying, no lateral movement. Explicit engagement authorization required (checked against `job.profile !== "safe-check"`).

### Files to modify

| File | Action |
|------|--------|
| `infrastructure/agent/agent.py` | Rewrite `execute_ad_enum()` fully |

### Impacket checks to implement

| Check | Script | Purpose | Finding |
|-------|--------|---------|---------|
| Kerberoastable accounts | `GetUserSPNs.py` | List SPNs — high-privilege SPN = kerberoast target | HIGH |
| AS-REP Roastable | `GetNPUsers.py` | No pre-auth required accounts | HIGH |
| Password policy | `GetADUsers.py` | Enumerate domain policy | INFO |
| Domain admins | `GetADUsers.py -all` | List DA/EA group members | INFO |
| LDAP anonymous | `ldapsearch` via ldap3 | Anonymous LDAP bind allowed | HIGH |
| DCSync rights | `secretsdump.py --just-dc-meta` | Accounts with DCSync permissions | CRITICAL |

### Enhanced agent executor

```python
async def execute_ad_enum(job: ScanJob, creds: dict, report_progress) -> dict:
    dc_ip    = creds.get("dc_ip", "")
    domain   = creds.get("domain", "")
    username = creds.get("username", "")
    password = creds.get("password", "")
    
    if not all([dc_ip, domain, username, password]):
        return {"error": "AD credentials required in Vault", "scanner": "impacket"}

    findings = []
    target   = f"{domain}/{username}:{password}"

    # 1. Kerberoastable accounts (read-only — just lists SPNs, no hash capture)
    proc = await asyncio.create_subprocess_exec(
        "GetUserSPNs.py", target, "-dc-ip", dc_ip,
        "-no-pass", "-request",  # request=True to test if hash is capturable
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    spn_output = stdout.decode()
    
    spns = parse_spn_output(spn_output)
    if spns:
        findings.append({
            "title": f"Kerberoastable Service Accounts ({len(spns)} found)",
            "severity": "HIGH",
            "description": f"{len(spns)} service accounts with SPNs are kerberoastable.",
            "technicalDetails": spn_output[:2000],
            "mitre": [{"id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}],
        })

    await report_progress(30)

    # 2. AS-REP Roastable
    proc = await asyncio.create_subprocess_exec(
        "GetNPUsers.py", domain + "/",
        "-dc-ip", dc_ip, "-no-pass", "-usersfile", "/tmp/domain_users.txt",
        "-format", "hashcat",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    asrep_hashes = [l for l in stdout.decode().splitlines() if l.startswith("$krb5asrep")]
    
    if asrep_hashes:
        findings.append({
            "title": f"AS-REP Roasting — {len(asrep_hashes)} Account(s) Vulnerable",
            "severity": "HIGH",
            "description": "Accounts do not require Kerberos preauthentication.",
            "mitre": [{"id": "T1558.004", "name": "AS-REP Roasting"}],
        })

    await report_progress(60)

    # 3. LDAP anonymous bind check
    import ldap3
    try:
        conn = ldap3.Connection(dc_ip, auto_bind=ldap3.AUTO_BIND_NO_TLS)
        if conn.bind():
            findings.append({
                "title": "LDAP Anonymous Bind Enabled",
                "severity": "HIGH",
                "description": "Domain controller allows anonymous LDAP bind. Unauthenticated enumeration is possible.",
                "mitre": [{"id": "T1087.002", "name": "Account Discovery: Domain Account"}],
            })
    except Exception:
        pass

    await report_progress(100)
    return {"scanner": "impacket", "findings": findings, "spns": spns}
```

---

## Task 1.7 — testssl.sh: TLS Validation

**Purpose:** Comprehensive TLS/SSL analysis. Checks cipher suites, protocol versions, certificate validity, HSTS, HPKP, and 40+ security headers.

### Files to create/modify

| File | Action |
|------|--------|
| `app/api/scan/testssl/route.ts` | Create |
| `lib/testssl-parser.ts` | Create — parse JSON output → Finding[] |
| `infrastructure/agent/agent.py` | Add `execute_tls_scan()` |

### API Route: `POST /api/scan/testssl`

**Request body:**
```typescript
{
  targets: string[];           // hostnames or host:port (default port 443)
  checks?: (
    | "protocols"              // TLS versions: SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3
    | "ciphers"                // cipher suite analysis
    | "certificate"            // cert validity, chain, hostname
    | "headers"                // HTTP security headers
    | "heartbleed"             // CVE-2014-0160
    | "ccs"                    // CVE-2014-0224
    | "ticketbleed"            // CVE-2016-9244
    | "robot"                  // ROBOT attack
    | "drown"                  // DROWN (CVE-2016-0800)
    | "logjam"                 // Logjam DH
    | "beast"                  // BEAST attack
    | "lucky13"                // Lucky Thirteen
    | "sweet32"                // SWEET32
    | "poodle"                 // POODLE (SSLv3)
  )[];
  createFindings?: boolean;
}
```

### testssl.sh command

```bash
testssl.sh \
  --jsonfile /tmp/testssl_out.json \
  --severity LOW \           # report findings from LOW and above
  --parallel \               # test multiple hosts in parallel
  --fast \                   # skip lengthy cipher suite tests in favor of speed
  --color 0 \               # no ANSI in output
  $TARGET
```

### testssl.sh JSON output structure

```json
{
  "scanTime": "...",
  "serverDefaults": {...},
  "findings": [
    {
      "id": "SSLv3",
      "ip": "10.0.0.1/443",
      "port": "443",
      "severity": "CRITICAL",
      "finding": "offered",
      "cve": "CVE-2014-3566",
      "cwe": "CWE-310"
    },
    {
      "id": "cipher_order_TLSv1_2",
      "severity": "LOW",
      "finding": "server does not have a cipher preference"
    }
  ]
}
```

### testssl finding → ADVERSA finding mapping: `lib/testssl-parser.ts`

```typescript
const TESTSSL_FINDING_MAP: Record<string, { title: string; severity: FindingSeverity; mitre: string }> = {
  "SSLv2":       { title: "SSLv2 Enabled",       severity: "CRITICAL", mitre: "T1040" },
  "SSLv3":       { title: "SSLv3 Enabled (POODLE)", severity: "CRITICAL", mitre: "T1040" },
  "TLS1":        { title: "TLS 1.0 Enabled",     severity: "HIGH",     mitre: "T1040" },
  "TLS1_1":      { title: "TLS 1.1 Enabled",     severity: "MEDIUM",   mitre: "T1040" },
  "heartbleed":  { title: "Heartbleed (CVE-2014-0160)", severity: "CRITICAL", mitre: "T1040" },
  "CCS":         { title: "CCS Injection (CVE-2014-0224)", severity: "HIGH", mitre: "T1040" },
  "ROBOT":       { title: "ROBOT Attack",        severity: "HIGH",     mitre: "T1040" },
  "DROWN":       { title: "DROWN Attack",        severity: "CRITICAL", mitre: "T1040" },
  "LOGJAM-common": { title: "Logjam DH Downgrade", severity: "HIGH",  mitre: "T1040" },
  "SWEET32":     { title: "SWEET32 Attack",      severity: "MEDIUM",   mitre: "T1040" },
  "cert_expired": { title: "Certificate Expired", severity: "HIGH",    mitre: "" },
  "cert_notYetValid": { title: "Certificate Not Yet Valid", severity: "HIGH", mitre: "" },
  "cert_hostnameMismatch": { title: "Hostname Mismatch", severity: "HIGH", mitre: "T1040" },
  "HSTS_not_offered": { title: "HSTS Not Configured", severity: "MEDIUM", mitre: "" },
};

export function parseTestsslOutput(json: TestsslOutput, host: string): Omit<Finding, "id">[] {
  return json.findings
    .filter(f => f.severity !== "OK" && f.severity !== "INFO")
    .map(f => {
      const meta = TESTSSL_FINDING_MAP[f.id] ?? {
        title: `TLS Issue: ${f.id}`,
        severity: mapTestsslSeverity(f.severity),
        mitre: "",
      };
      return {
        title: `${meta.title} — ${host}`,
        severity: meta.severity,
        category: "Cryptographic / TLS",
        affectedHost: host,
        cvss: deriveCvssFromSeverity(meta.severity),
        description: f.finding,
        evidence: [{ label: "testssl.sh Output", content: JSON.stringify(f, null, 2) }],
        mitre: meta.mitre ? [{ id: meta.mitre, name: "Network Sniffing" }] : [],
        // ... remaining Finding fields
      };
    });
}
```

---

## Task 1.8 — EyeWitness: Evidence Collection

**Purpose:** Screenshot every web service discovered by Nmap. Provides visual evidence for findings and detects login panels, admin interfaces, default pages.

**Trigger condition:** Run against all hosts where Nmap found HTTP/HTTPS services (ports 80, 443, 8080, 8443, etc.)

### Files to create/modify

| File | Action |
|------|--------|
| `infrastructure/agent/agent.py` | Add `execute_eyewitness()` |
| `app/api/scan/eyewitness/route.ts` | Create — retrieve screenshots |
| `lib/findings-store.ts` | Add `attachScreenshot()` helper |

### Agent executor

```python
async def execute_eyewitness(job: ScanJob, creds: dict, report_progress) -> dict:
    # Build URL list from Nmap results stored in job context
    urls = []
    if os.path.exists("/tmp/nmap_out.xml"):
        urls = extract_web_urls_from_nmap("/tmp/nmap_out.xml")
    
    if not urls:
        return {"scanner": "eyewitness", "screenshots": [], "message": "No web services found"}

    url_file = "/tmp/eyewitness_urls.txt"
    with open(url_file, "w") as f:
        f.write("\n".join(urls))

    output_dir = f"/tmp/eyewitness-{job.id}"

    cmd = [
        "eyewitness",
        "-f", url_file,
        "-d", output_dir,
        "--no-prompt",
        "--timeout", "15",
        "--threads", "5",
        "--web",                   # web mode (selenium)
        "--prepend-https",         # try HTTPS if HTTP fails
        "--compress",              # compress screenshots
    ]

    await report_progress(20)
    proc = await asyncio.create_subprocess_exec(*cmd, ...)
    await proc.communicate()
    await report_progress(90)

    # Collect screenshots and categorize
    screenshots = []
    categories  = {"login": [], "admin": [], "default": [], "error": [], "other": []}

    for img_file in glob.glob(f"{output_dir}/*.png"):
        url = derive_url_from_filename(img_file)
        category = categorize_screenshot(img_file)   # simple filename/content heuristics
        screenshots.append({
            "url": url,
            "file": img_file,
            "category": category,
            "fileSize": os.path.getsize(img_file),
        })
        categories[category].append(url)

    # Flag admin panels and login pages as findings
    admin_findings = []
    for url in categories["admin"] + categories["login"]:
        admin_findings.append({
            "title": f"Exposed Admin/Login Interface — {url}",
            "severity": "MEDIUM",
            "description": f"Web interface accessible at {url}. Verify authentication requirements.",
            "evidence": [{"label": "Screenshot", "content": f"[See EyeWitness output: {output_dir}]"}],
            "mitre": [{"id": "T1133", "name": "External Remote Services"}],
        })

    await report_progress(100)
    return {
        "scanner": "eyewitness",
        "screenshots": screenshots,
        "categories": categories,
        "outputDir": output_dir,
        "adminFindings": admin_findings,
    }


def extract_web_urls_from_nmap(xml_path: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from nmap XML output."""
    WEB_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https",
                 8000: "http", 8888: "http", 3000: "http", 5000: "http", 9090: "http"}
    urls = []
    # Parse XML and extract open web ports
    import xml.etree.ElementTree as ET
    tree = ET.parse(xml_path)
    for host in tree.findall(".//host"):
        ip = host.find(".//address[@addrtype='ipv4']")
        if ip is None:
            continue
        ip_addr = ip.get("addr")
        for port in host.findall(".//port"):
            if port.find("state").get("state") != "open":
                continue
            portid = int(port.get("portid"))
            scheme = WEB_PORTS.get(portid)
            if scheme:
                urls.append(f"{scheme}://{ip_addr}:{portid}")
    return urls
```

---

## Task 1.9 — Scan Pipeline Orchestration

**Purpose:** Single API endpoint that runs all 8 tools in the correct order, tracks progress per stage, and aggregates all findings.

### Files to create

| File | Action |
|------|--------|
| `app/api/scan/pipeline/route.ts` | Create — SSE streaming orchestrator |
| `app/api/scan/pipeline/[scanId]/route.ts` | Create — GET status endpoint |
| `lib/scan-pipeline.ts` | Create — pipeline state machine |

### API Route: `POST /api/scan/pipeline`

Returns Server-Sent Events stream with per-stage progress.

**Request body:**
```typescript
{
  targets: string[];
  profile: "fast" | "standard" | "deep";   // controls which tools run + depth
  tools?: ScanTool[];                        // override tool selection
  credentials?: {
    domain?: string;
    username?: string;
    password?: string;
    dcIp?: string;
  };
  createFindings: boolean;   // auto-create findings in findings store
  engagementId?: string;     // associate findings with engagement
}

type ScanTool = "naabu" | "nmap" | "nuclei" | "openvas" | "netexec" | "impacket" | "testssl" | "eyewitness";
```

**Tool selection by profile:**

| Profile | Tools | Estimated Time |
|---------|-------|---------------|
| `fast` | naabu → nmap → nuclei → testssl | 5–15 min |
| `standard` | naabu → nmap → nuclei → netexec → testssl → eyewitness | 20–45 min |
| `deep` | All 8 tools | 60–180 min |

**SSE event stream:**

```typescript
// Each event is a JSON object:
{ type: "stage_start",    stage: "naabu",   timestamp: "..." }
{ type: "stage_progress", stage: "naabu",   progress: 45, message: "Scanning 10.0.0.0/24..." }
{ type: "stage_complete", stage: "naabu",   result: { openPorts: 142, hosts: 8 } }
{ type: "stage_error",    stage: "naabu",   error: "naabu not found", skipped: true }
{ type: "finding",        finding: Finding, source: "nuclei" }  // real-time as found
{ type: "pipeline_complete", stats: {...}, totalFindings: 23, scanId: "..." }
```

### Pipeline state machine: `lib/scan-pipeline.ts`

```typescript
interface PipelineStage {
  tool: ScanTool;
  label: string;
  depends: ScanTool[];          // must complete before this runs
  outputKey: string;             // key in context passed to next stage
  run: (ctx: PipelineContext) => Promise<StageResult>;
}

interface PipelineContext {
  targets: string[];
  profile: "fast" | "standard" | "deep";
  credentials: Credentials;
  // outputs accumulated from each stage:
  naabuPorts?: Record<string, number[]>;    // ip → open ports
  nmapHosts?: ScanHost[];
  nucleiMatches?: NucleiMatch[];
  testsslFindings?: TlsFinding[];
  nxcResults?: NxcResult[];
  eyewitnessScreenshots?: Screenshot[];
}

const PIPELINE_STAGES: PipelineStage[] = [
  {
    tool: "naabu",
    label: "Port Discovery",
    depends: [],
    outputKey: "naabuPorts",
    run: runNaabu,
  },
  {
    tool: "nmap",
    label: "Service Enumeration",
    depends: ["naabu"],
    outputKey: "nmapHosts",
    run: (ctx) => runNmap({ ...ctx, ports: flattenNaabuPorts(ctx.naabuPorts) }),
  },
  {
    tool: "nuclei",
    label: "Vulnerability Scan",
    depends: ["nmap"],
    outputKey: "nucleiMatches",
    run: runNuclei,
  },
  {
    tool: "testssl",
    label: "TLS Analysis",
    depends: ["nmap"],          // parallel with nuclei (both depend on nmap)
    outputKey: "testsslFindings",
    run: runTestssl,
  },
  // ...etc
];
```

### Progress aggregation

Overall pipeline progress = weighted sum of stage progresses:

| Stage | Weight |
|-------|--------|
| naabu | 5% |
| nmap | 20% |
| nuclei | 25% |
| openvas | 20% |
| netexec | 10% |
| impacket | 10% |
| testssl | 5% |
| eyewitness | 5% |

---

## Task 1.10 — Scan Page UI Overhaul

**Purpose:** Replace the current single-tool Nmap scanner with a full pipeline scan UI.

**File:** `app/scan/page.tsx`

### Layout redesign

```
┌─────────────────────────────────────────────────────────────────┐
│ SCAN ENGINE                                              [New Scan]│
├─────────────────────────────────────────────────────────────────┤
│ Target(s)  [ 10.0.0.0/24, 10.0.0.5          ] [+Add]          │
│ Profile    [ fast ▾ ] [ standard ▾ ] [● deep ]                 │
│ Tools      [✓ naabu] [✓ nmap] [✓ nuclei] [⚪ openvas] ...     │
│            [Scan Credentials (optional) ▾]                      │
│                                               [▶ Start Pipeline] │
├─────────────────────────────────────────────────────────────────┤
│ PIPELINE PROGRESS                                               │
│ ●── Naabu      [████████████████████] 100%  8 hosts, 142 ports │
│ ●── Nmap       [████████████░░░░░░░░]  60%  Scanning...        │
│ ○── Nuclei     [░░░░░░░░░░░░░░░░░░░░]   0%  Waiting            │
│ ○── testssl    [░░░░░░░░░░░░░░░░░░░░]   0%  Waiting            │
│ ○── EyeWitness [░░░░░░░░░░░░░░░░░░░░]   0%  Waiting            │
│                                      Overall: 34% ⠸ 8 min left │
├─────────────────────────────────────────────────────────────────┤
│ LIVE FINDINGS  ┌─────────────────┐  ┌────────────────────────┐ │
│ [3 critical]   │ CRITICAL (3)    │  │ VAPT-CRIT-018          │ │
│ [7 high]       │ ▶ EternalBlue   │  │ MS17-010 SMB RCE       │ │
│ [12 medium]    │ ▶ Log4Shell     │  │ 10.0.0.4:445           │ │
│                │ ▶ SSLv3 POODLE  │  │ [Push to Findings]     │ │
│                │ HIGH (7)        │  │ [View Details]         │ │
│                │ ▶ ...           │  └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Key UI components to build

| Component | Purpose |
|-----------|---------|
| `PipelineProgress` | Visual stage-by-stage progress with animated bars |
| `LiveFindingsFeed` | Real-time finding cards as SSE events arrive |
| `ToolStatusBadge` | Per-tool status: waiting / running / done / error |
| `FindingPreviewCard` | Compact finding with Push-to-Findings action |
| `ScanCredentialsPanel` | Collapsible credentials input (never stored in URL/logs) |
| `TargetInputList` | Multi-target input with CIDR validation |

### State management

```typescript
interface ScanPageState {
  targets: string[];
  profile: "fast" | "standard" | "deep";
  selectedTools: ScanTool[];
  credentials: {
    domain: string;
    username: string;
    password: string;   // memory only, never persisted
    dcIp: string;
  };
  scan: {
    id: string | null;
    status: "idle" | "running" | "complete" | "error";
    stages: Record<ScanTool, StageState>;
    overallProgress: number;
    startedAt: string | null;
    completedAt: string | null;
  };
  findings: FindingPreview[];    // accumulated from SSE
}
```

### SSE consumer

```typescript
function startPipelineScan(targets: string[], profile: string, tools: string[]) {
  const eventSource = new EventSource("/api/scan/pipeline/stream");
  // POST body sent as query params or via ReadableStream body

  eventSource.onmessage = (e) => {
    const event = JSON.parse(e.data);
    switch (event.type) {
      case "stage_progress":
        updateStageProgress(event.stage, event.progress);
        break;
      case "stage_complete":
        markStageComplete(event.stage, event.result);
        break;
      case "finding":
        addLiveFinding(event.finding, event.source);
        break;
      case "pipeline_complete":
        finalizeScan(event.stats);
        break;
    }
  };
}
```

---

## Task 1.11 — Findings Auto-Creation & Deduplication

**Purpose:** All tool outputs must produce structured `Finding` objects. Prevent duplicate findings when multiple tools confirm the same vulnerability.

### Deduplication logic: `lib/findings-store.ts`

Add `upsertFinding()`:

```typescript
async function upsertFinding(candidate: Omit<Finding, "id">): Promise<{ id: string; created: boolean }> {
  const existing = await findDuplicate(candidate);
  if (existing) {
    // Merge evidence and update
    await mergeFindingEvidence(existing.id, candidate.evidence);
    return { id: existing.id, created: false };
  }
  const id = await createFinding(candidate);
  return { id, created: true };
}

function findDuplicate(candidate: Omit<Finding, "id">): Finding | null {
  // Deduplicate on: same affectedHost + same CVE/template ID or same title (normalized)
  return findings.find(f =>
    f.affectedHost === candidate.affectedHost &&
    (
      titlesMatch(f.title, candidate.title) ||
      sharesCve(f, candidate)
    )
  ) ?? null;
}
```

### Finding source tagging

Add `source` field to Finding:

```typescript
interface Finding {
  // ... existing fields
  source: "nmap" | "nuclei" | "openvas" | "netexec" | "impacket" | "testssl" | "eyewitness" | "manual";
  confirmedBy?: string[];    // additional tools that confirmed the same finding
}
```

---

## Task 1.12 — Agent Infrastructure Updates

### New job types in `agent.py`

Add to `JobType` enum:
```python
class JobType(str, Enum):
    DISCOVERY        = "discovery"
    PORT_DISCOVERY   = "port_discovery"    # Naabu
    VULN_SCAN        = "vuln_scan"         # Nuclei (enhanced)
    DEEP_VULN_SCAN   = "deep_vuln_scan"    # OpenVAS
    SMB_VALIDATION   = "smb_validation"    # NetExec
    AD_ENUM          = "ad_enum"           # Impacket
    TLS_SCAN         = "tls_scan"          # testssl.sh
    EVIDENCE_COLLECT = "evidence_collect"  # EyeWitness
    LATERAL_MOVEMENT = "lateral_movement"
    CLOUD_SCAN       = "cloud_scan"
    PIPELINE         = "pipeline"          # Full orchestrated scan
```

### Tool availability check on startup

```python
async def check_tool_availability() -> dict[str, bool]:
    tools = {
        "naabu":     ["naabu", "-version"],
        "nmap":      ["nmap", "--version"],
        "nuclei":    ["nuclei", "-version"],
        "netexec":   ["nxc", "--version"],
        "testssl":   ["testssl.sh", "--version"],
        "eyewitness": ["eyewitness", "--version"],
    }
    availability = {}
    for name, cmd in tools.items():
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=PIPE, stderr=PIPE)
            await proc.communicate()
            availability[name] = proc.returncode == 0
        except FileNotFoundError:
            availability[name] = False
    
    log.info("Tool availability: %s", availability)
    return availability
```

### requirements.txt additions

```
# existing
aiohttp>=3.9.0
hvac>=2.0.0

# new
python-gvm>=24.0.0      # OpenVAS GMP
ldap3>=2.9.1            # LDAP enumeration
impacket>=0.12.0        # AD/protocol validation
python-nmap>=0.7.1      # nmap XML parsing
```

### Dockerfile additions

```dockerfile
# Install scanning tools
RUN apt-get update && apt-get install -y \
    nmap \
    testssl.sh \
    eyewitness \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN nuclei -update-templates   # pre-pull templates at build time

# Install NetExec
RUN pip install netexec

# Install Impacket
RUN pip install impacket
```

---

## New API Routes Summary

| Method | Route | Tool | Purpose |
|--------|-------|------|---------|
| POST | `/api/scan/naabu` | Naabu | Port discovery |
| POST | `/api/scan/nmap` | Nmap | Service enumeration (enhanced) |
| POST | `/api/scan/nuclei` | Nuclei | Vulnerability scan |
| POST | `/api/scan/openvas` | OpenVAS | Deep CVE scan |
| GET | `/api/scan/openvas/[taskId]` | OpenVAS | Poll task status |
| POST | `/api/scan/netexec` | NetExec | SMB validation |
| POST | `/api/scan/testssl` | testssl.sh | TLS analysis |
| POST | `/api/scan/eyewitness` | EyeWitness | Screenshot evidence |
| POST | `/api/scan/pipeline` | All | Orchestrated full scan |
| GET | `/api/scan/pipeline/[scanId]` | All | Pipeline status |

---

## New Environment Variables

```env
# OpenVAS / GVM
OPENVAS_HOST=openvas
OPENVAS_PORT=9390
OPENVAS_USER=admin
OPENVAS_PASSWORD=

# Scan Engine Limits
SCAN_MAX_RATE=1000                  # naabu packets/sec
SCAN_NUCLEI_CONCURRENCY=25          # nuclei parallel templates
SCAN_NUCLEI_RATE_LIMIT=50           # nuclei requests/sec
SCAN_PIPELINE_TIMEOUT=7200          # max pipeline runtime in seconds (2h)

# EyeWitness
EYEWITNESS_OUTPUT_DIR=/var/adversa/screenshots
EYEWITNESS_THREADS=5
EYEWITNESS_TIMEOUT=15
```

---

## Execution Order

Implement tasks in this order to build on working pieces:

1. **Task 1.1** — Naabu API route + basic parsing
2. **Task 1.2** — Nmap enhancement (port input + enhanced XML parser)
3. **Task 1.7** — testssl.sh (independent, fast to implement)
4. **Task 1.3** — Nuclei API route + findings creation
5. **Task 1.8** — EyeWitness (builds on Nmap web URL extraction)
6. **Task 1.5** — NetExec SMB validation
7. **Task 1.6** — Impacket AD enum rewrite
8. **Task 1.4** — OpenVAS (most complex, long-running, save for last)
9. **Task 1.9** — Pipeline orchestration (requires all tools working)
10. **Task 1.10** — Scan page UI overhaul (requires pipeline SSE working)
11. **Task 1.11** — Deduplication + source tagging
12. **Task 1.12** — Agent infrastructure (Dockerfile, new job types)
