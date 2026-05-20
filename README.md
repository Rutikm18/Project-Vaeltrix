# ADVERSA — AI-Powered Network VAPT Platform

**ADVERSA** is an autonomous, AI-driven Vulnerability Assessment and Penetration Testing (VAPT) operations platform built for enterprise network security engagements.aa It combines a multi-agent AI offensive reasoning engine with structured findings management, network segmentation validation, Active Directory attack surface analysis, detection gap mapping, and compliance-mapped reporting.

> **Classification:** For authorized security testing, internal use, and controlled lab environments only.

---

## Platform Overview

| Module | Description |
|---|---|
| **Dashboard** | Real-time SOC overview — attack paths, agent status, metrics |
| **AI Brain** | Claude-powered offensive reasoning chatbot — models attack chains, TTPs, threat scenarios |
| **Attack Graph** | Interactive SVG attack path visualization with MITRE ATT&CK annotations |
| **Active Directory** | AD attack surface — Kerberoasting, delegation, privileged groups, domain trusts |
| **Segmentation** | Network zone validation — ACL audit, traffic flow analysis, VLAN bypass detection |
| **Findings** | Full VAPT findings with evidence, CVSS scoring, compliance mapping, remediation |
| **Detection** | MITRE ATT&CK coverage matrix, detection gaps, alert tuning recommendations |
| **Reports** | Executive summary, technical findings, compliance mapping, evidence statistics |

---

## Quick Start

### Prerequisites

- Node.js 18+ 
- npm / pnpm / yarn / bun
- Anthropic API key (for AI Brain module)

### Installation

```bash
git clone <repo-url>
cd adversa
npm install
```

### Environment Variables

Create `.env.local` in the project root:

```env
NEXT_PUBLIC_ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxx
```

> **Note:** The Anthropic API key is used client-side for the AI Brain module. For production deployments, proxy all Claude API calls through a backend route to keep the key server-side.

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

### Production Build

```bash
npm run build
npm run start
```

---

## Module Details

### AI Brain (`/aibrain`)

The AI Brain integrates Claude claude-sonnet-4-20250514 as an elite offensive reasoning engine. It models:

- Attack chain analysis from initial access to domain compromise
- Active Directory attack paths (Kerberoasting, DCSync, delegation abuse)
- Protocol-level abuse scenarios (LLMNR/SMB relay, Kerberos ticket attacks)
- Lateral movement modelling across segmented networks
- EDR/SIEM bypass reasoning

**Quick Prompts available:**
- Kerberoasting chain from standard user to DA
- Lateral movement past NGFW
- Ransomware blast radius from SMB foothold
- Credential relay in flat enterprise networks

### Attack Graph (`/attack-graph`)

SVG-based interactive attack path visualization:

- Node types: Workstations, Servers, Domain Controllers, Firewalls, Targets
- Edge coloring by severity (Critical/High/Medium) and validation status
- MITRE ATT&CK TTP annotations per edge
- Click-to-select attack path highlighting
- Zone filter (PERIMETER / DMZ / CORP / MGMT)

### Active Directory (`/active-directory`)

AD attack surface analysis across 5 tabs:

1. **Domain Overview** — topology, password policy audit
2. **Kerberos Attacks** — Kerberoastable accounts (T1558.003), AS-REP Roastable accounts
3. **Delegation** — Unconstrained/Constrained delegation analysis (T1134.001)
4. **Privileged Groups** — Expandable member lists with risk classification
5. **Trusts** — Domain trust relationships with SID filtering status

### Segmentation (`/segmentation`)

Network zone validation across 4 tabs:

1. **Zone Map** — Security scoring per zone, control inventory, zone-to-zone communication matrix
2. **ACL Analysis** — Firewall rule audit table with expected vs actual action comparison
3. **Traffic Flows** — Observed traffic with anomaly annotation
4. **Findings** — Segmentation-specific findings with clickable evidence detail

### Findings (`/findings`)

Full VAPT findings database with per-finding detail view:

- **CVSS v3.1** scoring with vector string
- **Evidence artifacts** — terminal output blocks with one-click copy
- **Attack path** narrative
- **Business impact** assessment
- **Remediation steps** — numbered, actionable, technology-specific
- **Compliance mapping** — NIST SP 800-115, NIST SP 800-53 Rev 5, ISO 27001:2022, PCI DSS v4.0, CIS Controls v8
- **MITRE ATT&CK** technique tagging

### Detection (`/detection`)

Detection coverage analysis across 4 tabs:

1. **Coverage Matrix** — MITRE ATT&CK technique table with FULL / PARTIAL / GAP status per tool
2. **Detection Gaps** — Detailed gap analysis with log source identification and recommendations
3. **Alert Tuning** — False positive rate analysis and rule tuning guidance
4. **Stack Status** — Coverage percentage per tool in the detection stack

### Reports (`/reports`)

Enterprise-grade reporting across 4 report types:

#### Executive Summary
C-suite overview with risk posture statement, key metrics, and top-5 critical findings with immediate action recommendations.

#### Technical Findings
Index of all findings with CVSS scores and direct links to the Findings module for full evidence detail.

#### Compliance Report
Expandable compliance control mapping across **4 frameworks and 35+ controls**:

| Framework | Version | Controls Assessed |
|---|---|---|
| NIST SP 800-115 | Technical Guide to IS Testing | 8 |
| NIST SP 800-53 Rev 5 | Security and Privacy Controls | 10 |
| ISO/IEC 27001:2022 | Annex A Controls | 9 |
| PCI DSS v4.0 | March 2022 | 10 |
| CIS Controls v8 | May 2021 | 8 |

Each control entry includes:
- **Control ID** with exact document reference
- **Full requirement text** verbatim from the standard
- **Status** — COMPLIANT / PARTIAL / GAP / NOT APPLICABLE
- **Assessment Evidence** — what was observed during the engagement
- **Finding References** — linked to specific VAPT finding IDs
- **Remediation Priority** — CRITICAL / HIGH / MEDIUM / LOW

#### Evidence Summary
Statistical overview of all evidence artifacts collected during the engagement.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 15 (App Router) |
| Language | TypeScript |
| Styling | Tailwind CSS v4 + Inline styles |
| Icons | Lucide React |
| AI API | Anthropic Claude claude-sonnet-4-20250514 |
| Fonts | Rajdhani (body), Share Tech Mono (labels) |
| Visualization | SVG (custom Attack Graph) |

---

## Project Structure

```
adversa/
├── app/
│   ├── page.tsx                 # Dashboard
│   ├── layout.tsx               # Root layout (fonts, metadata)
│   ├── globals.css              # Global styles, animations, theme vars
│   ├── aibrain/
│   │   └── page.tsx             # AI Offensive Brain chat
│   ├── attack-graph/
│   │   └── page.tsx             # Attack path visualization
│   ├── active-directory/
│   │   └── page.tsx             # AD attack surface analysis
│   ├── segmentation/
│   │   └── page.tsx             # Network segmentation validation
│   ├── findings/
│   │   └── page.tsx             # VAPT findings + evidence
│   ├── detection/
│   │   └── page.tsx             # Detection gap analysis
│   └── reports/
│       └── page.tsx             # Compliance reports
├── components/
│   └── Sidebar.tsx              # Shared navigation sidebar
├── public/                      # Static assets
├── package.json
├── tsconfig.json
├── next.config.mjs
└── ARCHITECTURE.md
```

---

## Security Notice

This platform is designed for **authorized security testing only**. All findings, attack paths, and techniques documented within are for defensive and educational purposes:

- Only use against systems you own or have explicit written authorization to test
- The AI Brain provides offensive reasoning to help defenders understand attacker perspective
- Never deploy with a client-side API key in production — proxy AI calls server-side
- Rotate API keys regularly; never commit `.env.local` to version control

---

## License

Internal use — ADVERSA Security Platform. All rights reserved.
# Project-Vaeltrix
