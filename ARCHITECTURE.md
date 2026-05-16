# ADVERSA Platform — Architecture Reference

**Version:** v0.9.1  
**Last Updated:** 2026-05-12  
**Classification:** Internal / Technical Reference

---

## 1. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ADVERSA Platform                                 │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                     Next.js Frontend (App Router)                │   │
│  │                                                                   │   │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │Dashboard │  │ AI Brain │  │ Attack Graph│  │Active Dir.  │  │   │
│  │  │/         │  │/aibrain  │  │/attack-graph│  │/active-dir. │  │   │
│  │  └──────────┘  └────┬─────┘  └─────────────┘  └─────────────┘  │   │
│  │                     │                                             │   │
│  │  ┌──────────┐  ┌────▼─────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │Segmentat.│  │ Findings │  │  Detection  │  │   Reports   │  │   │
│  │  │/segment. │  │/findings │  │ /detection  │  │  /reports   │  │   │
│  │  └──────────┘  └──────────┘  └─────────────┘  └─────────────┘  │   │
│  │                                                                   │   │
│  │  Shared: components/Sidebar.tsx, app/globals.css                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                              │                                           │
│                    API Calls (client-side)                               │
│                              │                                           │
│                    ┌─────────▼──────────┐                               │
│                    │  Anthropic Claude  │                               │
│                    │  claude-sonnet-4-20250514 │                               │
│                    │  (AI Brain only)   │                               │
│                    └────────────────────┘                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Module Architecture

### 2.1 Application Layer (Next.js 15 App Router)

Each route is a self-contained Next.js page component with `"use client"` directive. All state is local to each page — no global state management library is used.

```
app/
├── layout.tsx          RootLayout — HTML shell, font imports, metadata
├── globals.css         Theme variables, animations, scrollbar styles
├── page.tsx            Dashboard — metrics, attack paths, agent status
├── aibrain/page.tsx    AI Brain — Claude chat interface
├── attack-graph/page.tsx   SVG-based attack path graph
├── active-directory/page.tsx  AD enumeration analysis
├── segmentation/page.tsx      Network zone validation
├── findings/page.tsx          Finding detail with evidence
├── detection/page.tsx         Detection coverage matrix
└── reports/page.tsx           Compliance-mapped reports
```

### 2.2 Shared Component Layer

```
components/
└── Sidebar.tsx
    ├── Uses: usePathname() hook for active route detection
    ├── Uses: Next.js Link for client-side navigation
    ├── Props: open: boolean, onClose: () => void
    └── Renders: Navigation items, logo, system status
```

The Sidebar is a **controlled component** — parent pages own the `open` state and pass it as props. Mobile state management:
- `position: fixed` on mobile, `md:static` on desktop
- `transform: translateX(-100%)` when closed on mobile
- `transform: translateX(0)` when open
- Mobile overlay backdrop rendered by parent pages

### 2.3 Data Layer

All data is currently static (hardcoded TypeScript objects in each page file). Data types are defined per page. This architecture is designed to be upgraded to backend API calls with minimal refactoring — each data object maps directly to a REST endpoint or WebSocket stream.

**Future integration points:**

| Page | Data Source (Future) |
|---|---|
| Dashboard | `/api/dashboard/metrics` WebSocket |
| Attack Graph | `/api/graph/nodes` + `/api/graph/edges` |
| Active Directory | BloodHound CE API / LDAP enumeration results |
| Segmentation | Firewall API / PCAP analysis results |
| Findings | Findings database (PostgreSQL / SQLite) |
| Detection | SIEM API (Splunk REST / Sentinel) |
| Reports | Report generation service |

---

## 3. AI Brain Architecture

### 3.1 Request Flow

```
User Input
    │
    ▼
sendMessage() [aibrain/page.tsx:262]
    │
    ├─► Add user message to state
    ├─► activateAgents() — keyword-based agent simulation
    │
    ▼
fetch("https://api.anthropic.com/v1/messages")
    │
    Headers:
    ├─ x-api-key: NEXT_PUBLIC_ANTHROPIC_API_KEY
    ├─ anthropic-version: 2023-06-01
    └─ Content-Type: application/json
    │
    Body:
    ├─ model: claude-sonnet-4-20250514
    ├─ max_tokens: 1000
    ├─ system: [Offensive Brain persona prompt]
    └─ messages: [full conversation history]
    │
    ▼
Claude API Response
    │
    ▼
Animated typewriter rendering [AnimatedMessage component]
    │
    ▼
Message appended to conversation state
```

### 3.2 System Prompt Design

The AI Brain uses a structured persona prompt that constrains responses to:

```
[THREAT ASSESSMENT]  — brief scenario analysis
[ATTACK REASONING]   — step-by-step red team logic
[RECOMMENDED ATTACK VECTORS] — numbered specific vectors
[CONFIDENCE SCORE]   — percentage + risk statement
```

This forces structured, actionable output and maintains consistent formatting across all responses.

### 3.3 Agent Simulation

The multi-agent framework is a UX simulation — agents change status based on keyword detection in user queries:

| Keyword Pattern | Agent Activated |
|---|---|
| `exploit`, `cve`, `payload` | Exploit Agent |
| `lateral`, `pivot`, `wmi` | Lateral Agent |
| `ad`, `domain`, `kerberos` | AD Trust Analyzer |
| `recon`, `scan`, `enumerate` | Recon Agent |
| `stealth`, `evade`, `edr` | Stealth Agent |

---

## 4. Findings Data Model

Each finding in the system follows this TypeScript interface:

```typescript
interface Finding {
  id: string;                    // e.g. "VAPT-CRIT-001"
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss: string;                  // e.g. "9.8"
  cvssVector: string;            // Full CVSS v3.1 vector
  category: string;              // e.g. "Active Directory"
  status: "OPEN" | "IN_PROGRESS" | "REMEDIATED" | "ACCEPTED";
  affectedHost: string;
  discoveredAt: string;          // ISO 8601
  description: string;
  technicalDetails: string;
  attackPath: string;
  evidence: { label: string; content: string }[];  // Terminal output blocks
  impact: string;
  remediation: string[];         // Ordered remediation steps
  compliance: {
    framework: string;
    refs: string[];              // Exact control IDs with names
  }[];
  mitre: { id: string; name: string }[];  // ATT&CK technique IDs
}
```

### Finding ID Convention

```
VAPT-{SEVERITY}-{SEQUENCE}
     ├─ CRIT  → Critical (CVSS 9.0+)
     ├─ HIGH  → High (CVSS 7.0–8.9)
     ├─ MED   → Medium (CVSS 4.0–6.9)
     └─ LOW   → Low (CVSS < 4.0)
```

---

## 5. Compliance Mapping Architecture

The Reports module implements a structured compliance mapping data model:

```typescript
interface ComplianceControl {
  controlId: string;        // e.g. "NIST-800-115 §5.2", "AC-6", "A.8.8", "Req 11.3.2", "CIS 7.5"
  controlName: string;
  requirement: string;      // Verbatim text from standard document
  findingRefs: string[];    // Links to VAPT-XXXX-NNN finding IDs
  status: "GAP" | "PARTIAL" | "COMPLIANT" | "NOT_APPLICABLE";
  evidenceSummary: string;  // What was observed/tested
  remediationPriority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}
```

### Supported Frameworks

| ID | Framework | Document Reference |
|---|---|---|
| `NIST_800_115` | NIST SP 800-115 | Technical Guide to Information Security Testing (Sep 2008) |
| `NIST_800_53` | NIST SP 800-53 Rev 5 | Security and Privacy Controls (Sep 2020) |
| `ISO_27001` | ISO/IEC 27001:2022 | Annex A Information Security Controls |
| `PCI_DSS` | PCI DSS v4.0 | Payment Card Industry DSS (March 2022) |
| `CIS_V8` | CIS Controls v8 | Center for Internet Security Controls (May 2021) |

### Compliance Score Calculation

```
compliance_score = (compliant + partial × 0.5) / total_controls × 100

Where:
  compliant = controls fully met
  partial   = controls partially addressed (weighted 0.5)
  total     = all in-scope controls for the framework
```

---

## 6. Visualization Architecture

### Attack Graph SVG

The attack graph uses inline SVG with fixed ViewBox (`0 0 880 420`):

```
Node placement (x, y coordinates in SVG units):
  FW-EXT        (60, 200)   — Entry point
  WEB-01/02     (170, 140/280) — DMZ hosts
  FW-INT        (290, 200)  — Internal firewall
  WS-042/128    (410, 130/270) — CORP workstations
  SVC-SQL/MGMT  (540, 130/270) — Servers
  DC01          (670, 130)  — Domain Controller
  DOMAIN ADMIN  (790, 130)  — Target

Edge rendering:
  - Lines with SVG <marker> arrowheads per severity
  - Validated edges: solid stroke; unvalidated: dashed
  - Active path edges: stroke-width 2.5, opacity 1.0
  - Inactive edges: opacity 0.35

Node rendering:
  - <circle> with fill/stroke per type
  - Compromised nodes: SVG filter#glow-red
  - Active path nodes: filter#glow-cyan + pulse animation
  - Hover tooltip: absolute SVG <g> with <rect> + <text>

Zone backgrounds:
  - <rect> elements per zone band (PERIMETER/DMZ/CORP/MGMT)
  - Vertical <line> zone separators (dashed)
```

---

## 7. Routing Structure

All routes are Next.js App Router pages with full client-side navigation via `<Link>` components in the shared Sidebar.

```
/                    → Dashboard (app/page.tsx)
/aibrain             → AI Brain (app/aibrain/page.tsx)
/attack-graph        → Attack Graph (app/attack-graph/page.tsx)
/active-directory    → Active Directory (app/active-directory/page.tsx)
/segmentation        → Segmentation (app/segmentation/page.tsx)
/findings            → Findings (app/findings/page.tsx)
/detection           → Detection (app/detection/page.tsx)
/reports             → Reports (app/reports/page.tsx)
```

Active route detection uses Next.js `usePathname()` hook in the Sidebar component for accurate highlighting without manual state.

---

## 8. Styling Architecture

### Design System

| Variable | Value | Usage |
|---|---|---|
| `--color-bg` | `#050A0E` | Page backgrounds |
| `--color-panel` | `#0D1B26` | Card / panel backgrounds |
| `--color-border` | `#1A3A50` | All borders |
| `--color-cyan` | `#00D4FF` | Primary accent, links, active states |
| `--color-green` | `#00FF88` | Success, VALIDATED, COMPLIANT |
| `--color-red` | `#FF4444` | Critical severity, errors, OPEN |
| `--color-orange` | `#FF9900` | High severity, warnings, PARTIAL |
| `--color-yellow` | `#FFD500` | Medium severity |
| `--color-text` | `#C8E8F0` | Primary text |
| `--color-muted` | `#3D7A94` | Secondary labels, metadata |

### Typography

| Use Case | Font | Size |
|---|---|---|
| Module titles / large numbers | Rajdhani Bold | 14–28px |
| Labels, IDs, monospace data | Share Tech Mono | 9–13px |
| Body text, descriptions | Rajdhani Regular | 13–16px |

### Animation Classes (globals.css)

| Class | Effect | Usage |
|---|---|---|
| `.animate-pulse-dot` | Opacity 1→0.4→1 (2s loop) | Active status dots, live indicators |
| `.animate-blink` | Opacity 1→0 (1s step) | Ticker messages |
| `.animate-slide-in` | translateX(-6px → 0) | Component entrance |

---

## 9. End-to-End User Workflow

### Typical Engagement Workflow

```
1. SCOPE SETUP
   └─ Configure engagement details (client, scope, dates) in Reports module

2. RECON & ENUMERATION
   └─ Attack Graph: load network topology
   └─ Active Directory: review AD enumeration results
   └─ Segmentation: validate zone boundaries

3. VULNERABILITY ANALYSIS
   └─ Findings: review all identified vulnerabilities
   └─ Attack Graph: trace attack paths per finding
   └─ AI Brain: query for additional attack chains
   │    Example: "Kerberoasting chain from standard user to DA in corp.local"

4. EXPLOITATION & VALIDATION
   └─ Findings: add evidence artifacts per finding
   └─ Attack Graph: mark paths as VALIDATED / SIMULATING
   └─ Detection: verify which techniques triggered alerts

5. POST-EXPLOITATION
   └─ Active Directory: map privilege escalation paths
   └─ Segmentation: document lateral movement across zones

6. DETECTION ASSESSMENT
   └─ Detection: review coverage matrix per MITRE ATT&CK
   └─ Detection: identify gaps in EDR/SIEM coverage
   └─ Detection: document alert tuning recommendations

7. REPORTING
   └─ Reports → Executive Summary: C-suite overview
   └─ Reports → Technical Findings: full detail index
   └─ Reports → Compliance Mapping: framework controls assessment
   └─ Reports → Evidence Summary: artifact statistics
   └─ Export PDF for client delivery
```

### Mobile Workflow

On mobile viewports (`< 768px`):
- Sidebar is hidden by default (off-screen left)
- Menu icon in top-left header opens sidebar via overlay
- Sidebar overlay backdrop dismisses on tap
- All tables are horizontally scrollable
- Grid layouts collapse to single column

---

## 10. Future Architecture Considerations

### Backend Integration (Phase 2)

```
┌─────────────┐    REST/WS    ┌─────────────────┐
│  Frontend   │ ◄──────────► │   API Gateway   │
│  (Next.js)  │               │   (FastAPI)     │
└─────────────┘               └────────┬────────┘
                                        │
                          ┌─────────────▼──────────────┐
                          │                            │
                   ┌──────▼──────┐          ┌─────────▼───────┐
                   │  Findings   │          │  Scan Engine    │
                   │  Database   │          │  (Nmap, Nessus) │
                   │ (PostgreSQL)│          │                 │
                   └─────────────┘          └─────────────────┘
```

### AI Brain — Server-Side Proxy (Phase 2)

Replace direct browser-to-Anthropic calls with a Next.js API route to keep the key server-side:

```
app/api/brain/route.ts
    └─ POST handler: receives user messages
    └─ Calls Anthropic API server-side (ANTHROPIC_API_KEY env var)
    └─ Streams response back to client
    └─ Implements rate limiting and auth middleware
```

### Real-Time Updates (Phase 3)

```
WebSocket connection per active engagement
    └─ Live agent status updates
    └─ Real-time finding ingestion from scan tools
    └─ Alert feed from SIEM integration
    └─ Attack path confidence updates
```
