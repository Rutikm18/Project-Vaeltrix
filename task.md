# ADVERSA Platform — Master Task Tracker

**Project:** ADVERSA — AI-Powered Network VAPT Platform  
**Version:** v1.0 (Enterprise Build)  
**Last Updated:** 2026-05-16 (all tasks complete)  
**Classification:** Internal / Engineering Reference

---

## Vision

Transform ADVERSA from a static UI demo into a **production-grade, end-to-end security engineering platform** that covers the full VAPT lifecycle:

```
Scan → Findings → Triage → Validation → Case Management → SLA Tracking
    → Prioritization → Remediation Guidance → 3rd-Party Integration → Reporting
```

---

## Design System

### Color Palette (Psychology-Driven)

| Token           | Hex       | Psychology / Usage                                      |
|---|---|---|
| Critical        | `#FF1744` | Maximum urgency — stops engineer in their tracks        |
| High            | `#FF6D00` | Serious concern — demands same-day attention            |
| Medium          | `#FFD600` | Caution — schedule for this sprint                      |
| Low             | `#00E676` | Minor — backlog ok                                      |
| Accent / Info   | `#00D4FF` | Technology trust — active states, links                 |
| Success         | `#00FF88` | Completion reward — satisfying resolution               |
| Background      | `#050A0E` | Deep focus — reduces eye strain in long sessions        |
| Panel           | `#0D1B26` | Hierarchy separator                                     |
| Border          | `#1A3A50` | Subtle structure                                        |
| Text Primary    | `#C8E8F0` | High legibility on dark background                      |
| Text Muted      | `#3D7A94` | Secondary / metadata                                    |

### SLA Color Progression (Time Pressure Psychology)

| Remaining Time  | Color     | Behavior                    |
|---|---|---|
| > 50%           | `#00E676` | Calm green — no urgency      |
| 25–50%          | `#FFD600` | Yellow alert — plan action   |
| 10–25%          | `#FF6D00` | Orange — act now             |
| < 10%           | `#FF1744` | Red pulse — breach imminent  |
| Breached        | `#FF1744` | Red + pulse animation        |

### Animations (ReactBits-Inspired)

- **Counter roll-up**: Numbers animate from 0 → target on mount
- **Skeleton shimmer**: Loading placeholders with shimmer sweep
- **Toast notifications**: Slide in from top-right with auto-dismiss
- **SLA pulse**: Critical SLA breach indicator pulses
- **Card hover lift**: translateY(-2px) + shadow on hover
- **Tab transitions**: Smooth opacity/slide between tab content
- **Progress bar fill**: Animated fill on mount
- **Modal scale-in**: scale(0.97) → scale(1) + fade
- **Status badge glow**: Colored box-shadow on active states
- **Stagger lists**: List items fade in with 50ms delay offsets

---

## Task List

| # | Task | Status | Priority | Module |
|---|---|---|---|---|
| 01 | ~~Server-side AI proxy~~ | ✅ DONE | P0 | AI Brain |
| 02 | Write task.md | ✅ DONE | P0 | Docs |
| 03 | ~~Fix Sidebar desktop CSS bug~~ | ✅ DONE | P0 | Global |
| 04 | ~~Design system: globals.css upgrade~~ | ✅ DONE | P0 | Global |
| 05 | ~~Toast notification component~~ | ✅ DONE | P0 | Global |
| 06 | ~~Shared layout: PageShell component~~ | ✅ DONE | P0 | Global |
| 07 | ~~Enhanced Findings page — filters, CRUD, SLA badges, workflow~~ | ✅ DONE | P1 | Findings |
| 08 | ~~Case Management page (/cases) — Kanban, SLA, detail modal~~ | ✅ DONE | P1 | Cases |
| 09 | ~~SLA Tracking — dashboard metrics + breach alerts~~ | ✅ DONE | P1 | Dashboard |
| 10 | ~~Remediation Guidance — step tracker, verification commands~~ | ✅ DONE | P1 | Findings |
| 11 | ~~Integrations Settings page (/settings)~~ | ✅ DONE | P2 | Settings |
| 12 | ~~API: Email notification route~~ | ✅ DONE | P2 | API |
| 13 | ~~API: Slack webhook route~~ | ✅ DONE | P2 | API |
| 14 | ~~API: Jira ticket creation route~~ | ✅ DONE | P2 | API |
| 15 | ~~Nmap Scanner page (/scan) with live output~~ | ✅ DONE | P2 | Scanner |
| 16 | ~~Reports PDF export (print CSS)~~ | ✅ DONE | P2 | Reports |
| 17 | ~~MITRE ATT&CK live data integration~~ | ✅ DONE | P3 | Detection |

---

## Task Details

### Task 03 — Fix Sidebar Desktop CSS Bug

**Problem:** Inline `style.transform` overrides Tailwind `md:translate-x-0` on desktop,
causing the sidebar to be hidden when `open=false`.

**Fix:** Remove inline transform. Use conditional `className` for mobile toggle,
let `md:translate-x-0` handle desktop visibility.

**Files:** `components/Sidebar.tsx`

---

### Task 04 — Design System: globals.css Upgrade

Add to globals.css:
- CSS custom properties for all color tokens
- `.animate-counter` — number roll-up keyframes
- `.shimmer` — skeleton shimmer keyframes
- `.card-hover` — lift effect
- `.animate-scale-in` — modal entrance
- `.animate-slide-in-right` — toast entrance
- `.animate-slide-out-right` — toast exit
- `.sla-pulse` — breach pulse with glow
- `.stagger-item` — list stagger base class
- Print media query skeleton for PDF export

---

### Task 05 — Toast Notification Component

**File:** `components/Toast.tsx`  
**Provider:** `components/ToastProvider.tsx`  
**Hook:** `hooks/useToast.ts`

Toast types: `success | error | warning | info`
Features: auto-dismiss (4s), manual dismiss, stacking (max 3), icon per type

---

### Task 06 — PageShell Component

**File:** `components/PageShell.tsx`

Replaces the repeated header+sidebar boilerplate across all 8 pages.
Props: `title`, `subtitle`, `children`, `headerActions?`

---

### Task 07 — Enhanced Findings Page

**File:** `app/findings/page.tsx`  
**Data:** `data/findings.json` + `app/api/findings/route.ts`

Features:
- Filter bar: severity, status, category, MITRE tactic, search
- Sort: by CVSS, date, status, SLA
- Bulk operations: assign, change status, export
- Finding cards with SLA countdown badge
- Validation workflow buttons: `Validate` | `Accept Risk` | `False Positive`
- Status flow: `OPEN → IN_REVIEW → IN_REMEDIATION → VERIFIED → CLOSED`
- Evidence panel: paste terminal output, copy-to-clipboard
- Remediation checklist with step completion tracking
- Compliance mapping toggle view
- Link to Case

---

### Task 08 — Case Management Page

**File:** `app/cases/page.tsx`  
**Data:** `data/cases.json` + `app/api/cases/route.ts`

Columns: `OPEN | IN_REVIEW | IN_REMEDIATION | VERIFIED | CLOSED`

Card fields:
- Case ID + Finding ID
- Severity badge (color coded)
- Title (truncated)
- Assignee avatar/initials
- SLA countdown (color changes by remaining %)
- MITRE tactic tag

Detail Modal:
- Full finding detail
- Activity log / audit trail (who changed what, when)
- Comment thread
- Integration panel: Send Email / Create Jira / Notify Slack
- Attachment list

---

### Task 09 — SLA Tracking Dashboard

**File:** `app/page.tsx` (Dashboard)

Add SLA section:
- Total SLA breaches today
- Breach-risk items (< 10% time left)
- Average time-to-remediation
- SLA performance by severity
- Upcoming SLA deadlines (next 48h)

---

### Task 10 — Remediation Guidance Engine

**File:** `app/findings/page.tsx`

Enhanced remediation panel:
- Step-by-step checklist (each step checkable)
- Commands with copy button
- Before/after configuration snippets
- Verification command that proves remediation worked
- Link to relevant KB/documentation
- Estimated effort (hours)

---

### Task 11 — Integrations Settings Page

**File:** `app/settings/page.tsx`

Sections:
- Email: SMTP host, port, from, to, credentials
- Slack: Webhook URL, channel, notify on (severity levels)
- Jira: URL, API token, project key, issue type mapping
- Notification rules: triggers (on new critical, on SLA breach, on case close)
- Engagement metadata: client, scope, assessor, dates

---

### Task 12 — Email Notification API

**File:** `app/api/integrations/email/route.ts`

POST body: `{ to, subject, findingId, type: 'new_finding' | 'sla_breach' | 'case_update' }`
Uses: `process.env.SMTP_*` env vars
Fallback: formatted JSON preview if SMTP not configured

---

### Task 13 — Slack Webhook API

**File:** `app/api/integrations/slack/route.ts`

POST body: `{ findingId, caseId?, message?, type }`
Uses: `process.env.SLACK_WEBHOOK_URL`
Payload: Rich block kit message with severity color, fields, action buttons

---

### Task 14 — Jira Integration API

**File:** `app/api/integrations/jira/route.ts`

POST body: `{ findingId, summary, description, priority, labels }`
Uses: `process.env.JIRA_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`
Returns: Jira issue key + URL

---

### Task 15 — Nmap Scanner Page

**File:** `app/scan/page.tsx`, `app/api/scan/nmap/route.ts`

Features:
- Target input (IP, hostname, CIDR) with validation
- Scan type: Quick | Full | Service Detection | OS Detection | Vulnerability
- Real-time output stream (Server-Sent Events)
- Results: host table with open ports, service versions, OS guess
- Export discovered hosts to Attack Graph
- Export vulnerable services to Findings

---

### Task 16 — Reports PDF Export

**File:** `app/reports/page.tsx`, `app/globals.css`

Print CSS:
- Hide sidebar, header, buttons on print
- ADVERSA logo + client/engagement header
- Proper page breaks (avoid splitting finding cards)
- Table borders print correctly
- Severity colors that work in print (use darker shades)

---

### Task 17 — MITRE ATT&CK Live Data

**File:** `app/api/mitre/route.ts`, `app/detection/page.tsx`

- Fetch from MITRE GitHub (enterprise-attack.json)
- Cache in memory for 1 hour
- Expose: technique name, description, tactic, mitigation IDs
- Update detection matrix with real technique metadata

---

## Data Models

### Finding (Enhanced)

```typescript
interface Finding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss: string;
  cvssVector: string;
  category: string;
  status: "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED" | "ACCEPTED" | "FALSE_POSITIVE";
  affectedHost: string;
  discoveredAt: string;
  updatedAt: string;
  assignee?: string;
  caseId?: string;
  slaDeadline: string;         // ISO 8601
  description: string;
  technicalDetails: string;
  attackPath: string;
  evidence: { label: string; content: string }[];
  impact: string;
  businessImpact: string;      // NEW: business-layer impact
  exploitability: "EASY" | "MODERATE" | "DIFFICULT";  // NEW
  remediation: RemediationStep[];  // ENHANCED
  compliance: ComplianceRef[];
  mitre: MitreTechnique[];
  riskScore: number;           // composite 0-100
  validatedBy?: string;
  validatedAt?: string;
  falsePositiveReason?: string;
}

interface RemediationStep {
  step: number;
  title: string;
  command?: string;
  description: string;
  estimatedHours: number;
  verification?: string;       // command to prove it's fixed
  completed: boolean;
  completedBy?: string;
  completedAt?: string;
}
```

### Case

```typescript
interface Case {
  id: string;             // CASE-001
  findingId: string;
  title: string;
  severity: Severity;
  status: "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED";
  assignee: string;
  createdAt: string;
  updatedAt: string;
  dueDate: string;        // SLA deadline
  slaHours: number;       // total SLA window
  comments: CaseComment[];
  activities: CaseActivity[];
  integrations: {
    jiraKey?: string;
    jiraUrl?: string;
    slackNotified?: boolean;
    slackTs?: string;
    emailSent?: boolean;
    emailSentAt?: string;
  };
}

interface CaseComment {
  id: string;
  author: string;
  content: string;
  timestamp: string;
}

interface CaseActivity {
  id: string;
  action: string;
  actor: string;
  timestamp: string;
  field?: string;
  oldValue?: string;
  newValue?: string;
}
```

---

## SLA Policy

| Severity | SLA Window | Escalation at     |
|---|---|---|
| CRITICAL  | 24 hours   | 12 hours remaining |
| HIGH      | 72 hours   | 24 hours remaining |
| MEDIUM    | 7 days     | 2 days remaining   |
| LOW       | 30 days    | 7 days remaining   |

---

## API Routes

| Method | Route                          | Description                    |
|---|---|---|
| POST   | `/api/brain`                   | AI chat proxy (✅ DONE)        |
| GET    | `/api/findings`                | List all findings               |
| POST   | `/api/findings`                | Create finding                  |
| GET    | `/api/findings/[id]`           | Get finding by ID               |
| PUT    | `/api/findings/[id]`           | Update finding                  |
| DELETE | `/api/findings/[id]`           | Delete finding                  |
| GET    | `/api/cases`                   | List all cases                  |
| POST   | `/api/cases`                   | Create case                     |
| GET    | `/api/cases/[id]`              | Get case by ID                  |
| PUT    | `/api/cases/[id]`              | Update case                     |
| POST   | `/api/cases/[id]/comment`      | Add comment to case             |
| POST   | `/api/integrations/email`      | Send email notification         |
| POST   | `/api/integrations/slack`      | Send Slack notification         |
| POST   | `/api/integrations/jira`       | Create Jira ticket              |
| POST   | `/api/scan/nmap`               | Run Nmap scan                   |
| GET    | `/api/mitre`                   | MITRE ATT&CK technique data     |

---

## Environment Variables

```env
# AI Brain (server-side)
ANTHROPIC_API_KEY=

# Email
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=

# Slack
SLACK_WEBHOOK_URL=

# Jira
JIRA_URL=
JIRA_EMAIL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=

# App
NEXT_TELEMETRY_DISABLED=1
PORT=3000
```

---

## File Structure (Target)

```
adversa/
├── app/
│   ├── api/
│   │   ├── brain/route.ts          ✅ DONE
│   │   ├── findings/
│   │   │   ├── route.ts
│   │   │   └── [id]/route.ts
│   │   ├── cases/
│   │   │   ├── route.ts
│   │   │   └── [id]/
│   │   │       ├── route.ts
│   │   │       └── comment/route.ts
│   │   ├── integrations/
│   │   │   ├── email/route.ts
│   │   │   ├── slack/route.ts
│   │   │   └── jira/route.ts
│   │   ├── scan/nmap/route.ts
│   │   └── mitre/route.ts
│   ├── cases/page.tsx              (new)
│   ├── scan/page.tsx               (new)
│   ├── settings/page.tsx           (new)
│   ├── findings/page.tsx           (enhanced)
│   ├── detection/page.tsx          (enhanced)
│   ├── reports/page.tsx            (enhanced)
│   └── page.tsx                    (enhanced dashboard)
├── components/
│   ├── Sidebar.tsx                 (fixed)
│   ├── PageShell.tsx               (new)
│   ├── Toast.tsx                   (new)
│   └── ToastProvider.tsx           (new)
├── hooks/
│   └── useToast.ts                 (new)
├── lib/
│   ├── findings-store.ts           (new)
│   └── cases-store.ts              (new)
└── data/
    ├── findings.json               (new)
    └── cases.json                  (new)
```
