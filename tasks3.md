Let me read your full project doc first to make precise, file-specific prompts.Here is every task with its exact prompt. Copy each one directly into a new Claude conversation when you're ready for that task.

---

## Phase 1 — Foundation types

---

**Task 1.1 — `lib/engine/types.ts`**

```
I'm building ADVERSA, a network VAPT platform in Next.js + TypeScript.
I need to create lib/engine/types.ts — the shared type contract used by
the CLI, web pipeline API, and Python agent.

Create this file with exactly these types:

1. Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
2. ScanProfile = 'fast' | 'standard' | 'deep'
3. ScanOptions {
   targets: string[]
   profile: ScanProfile
   stealth: number (1-9)
   tools: ('naabu'|'nmap'|'nuclei'|'testssl')[]
   save: boolean
   engagementId?: string
   scanId?: string
}
4. DiscoveredHost {
   ip: string
   ports: number[]
   services: { port: number; proto: string; name?: string; version?: string }[]
   os?: string
   hostnames?: string[]
}
5. Evidence {
   label: string
   content: string
   timestamp: string
}
6. LiveFinding {
   id: string
   title: string
   severity: Severity
   cvss?: string
   cvssVector?: string
   host: string
   port?: number
   protocol?: string
   service?: string
   serviceVersion?: string
   evidence: Evidence[]
   source: 'nmap'|'nuclei'|'testssl'|'naabu'|'openvas'|'manual'
   cveIds?: string[]
   mitre?: { id: string; name: string }[]
   compliance?: { framework: string; refs: string[] }[]
   attackPath?: string
   remediation?: string
   timestamp: string
   engagementId?: string
   status: 'OPEN'|'IN_REVIEW'|'IN_REMEDIATION'|'VERIFIED'|'CLOSED'
   slaDeadline?: string
   falsePositive?: boolean
   falsePositiveReason?: string
}
7. ScanCallbacks {
   onStageStart: (stage: string) => void
   onStageComplete: (stage: string, summary: string) => void
   onHostDiscovered: (host: DiscoveredHost) => void
   onFinding: (finding: LiveFinding) => void
   onProgress: (pct: number, message: string) => void
   onError: (stage: string, error: string) => void
   onComplete: (summary: ScanSummary) => void
}
8. ScanSummary {
   scanId: string
   startTime: string
   endTime: string
   duration: number
   hostsScanned: number
   portsFound: number
   totalFindings: number
   bySeverity: Record<Severity, number>
   savedCount: number
   engagementId?: string
}
9. AgentJob {
   id: string
   type: 'scan'|'exploit'|'verify'
   scanId: string
   targets: string[]
   profile?: ScanProfile
   stealth?: number
   tools?: string[]
   scopeToken: string
   exploitCommand?: string
   createdAt: string
}
10. AgentJobResult {
    jobId: string
    agentId: string
    status: 'COMPLETE'|'FAILED'|'PARTIAL'
    findings: LiveFinding[]
    error?: string
    duration: number
}

Export all types. No default export. Pure types file — no logic.
```

---

**Task 1.2 — Finding ID generator**

```
I'm building ADVERSA VAPT platform. I need a small utility in
lib/finding-id.ts that generates and tracks finding IDs.

Requirements:
- IDs follow format: VAPT-CRIT-001, VAPT-HIGH-003, VAPT-MED-012, VAPT-LOW-004, VAPT-INFO-001
- Severity mapping: CRITICAL→CRIT, HIGH→HIGH, MEDIUM→MED, LOW→LOW, INFO→INFO
- Counter persists within a process (module-level Map)
- resetCounters() function for tests
- generateFindingId(severity: Severity): string
- Must be safe to call from multiple places — no duplicate IDs in one session

Import Severity from './engine/types'.
Export generateFindingId and resetCounters.
No external dependencies.
```

---

**Task 1.3 — Target validator**

```
I'm building ADVERSA VAPT platform. I need lib/target-parser.ts.

This file must export one function:
  parseTargets(input: string | string[]): string[]

Rules:
- Accepts: single IP (10.0.0.1), CIDR (192.168.1.0/24),
  hostname (example.com), range (10.0.0.1-10.0.0.50),
  or a mixed array of any of these
- Strips blank lines, comments (lines starting with #)
- Throws a clear error if any target is obviously invalid
  (e.g. 999.999.999.999, empty string after trim)
- Does NOT expand CIDRs to individual IPs — just validates and returns cleaned array
- Returns deduplicated list

Also export:
  isValidTarget(target: string): boolean
  isPrivateRange(target: string): boolean  — returns true for RFC1918

No external dependencies. Use only built-in Node.js.
TypeScript, strict mode.
```

---

## Phase 2 — Parsers

---

**Task 2.1 — nmap XML parser**

```
I'm building ADVERSA VAPT platform. I need lib/nmap-parser.ts.

This file parses nmap XML output (from nmap -oX -) into structured objects.

Install dependency: npm install fast-xml-parser

Export these types and functions:

type NmapService = {
  port: number
  proto: 'tcp' | 'udp'
  state: 'open' | 'closed' | 'filtered'
  name?: string
  product?: string
  version?: string
  extrainfo?: string
}

type NmapScriptResult = {
  id: string
  output: string
}

type NmapHost = {
  ip: string
  hostnames: string[]
  os?: string
  status: 'up' | 'down'
  services: NmapService[]
  scripts: NmapScriptResult[]
}

function parseNmapXml(xml: string): NmapHost[]

Rules:
- Handle nmap XML structure: nmaprun → host → ports → port
- Extract hostnames from host/hostnames/hostname[@type=PTR or A]
- Extract OS from osmatch[0].name if present
- Extract NSE script output from port/script and host/script elements
- Skip hosts with status=down
- If XML is empty or malformed, return []
- No throwing — always return array

Import nothing from other project files.
TypeScript strict mode.
```

---

**Task 2.2 — nuclei JSONL parser**

```
I'm building ADVERSA VAPT platform. I need lib/nuclei-parser.ts.

nuclei outputs one JSON object per line (JSONL) when run with -json flag.
Each line looks like:
{
  "template-id": "CVE-2021-44228",
  "info": {
    "name": "Log4j RCE",
    "severity": "critical",
    "description": "Apache Log4j2 RCE",
    "classification": { "cve-id": ["CVE-2021-44228"] }
  },
  "host": "http://10.0.0.1:8080",
  "matched-at": "http://10.0.0.1:8080/api/login",
  "extracted-results": ["..."],
  "timestamp": "2024-01-01T00:00:00Z"
}

Export:

type NucleiMatch = {
  templateId: string
  name: string
  severity: 'critical'|'high'|'medium'|'low'|'info'|'unknown'
  description?: string
  host: string
  ip?: string
  port?: number
  matchedAt: string
  cveIds: string[]
  extractedResults: string[]
  timestamp: string
}

function parseNucleiLine(jsonl: string): NucleiMatch | null
  — parses one line, returns null if invalid/empty

function nucleiSeverityToSeverity(s: string): Severity
  — maps nuclei lowercase → ADVERSA uppercase Severity

Import Severity from './engine/types'.
No external dependencies beyond built-in JSON.parse.
Return null on any parse error — never throw.
TypeScript strict mode.
```

---

**Task 2.3 — testssl parser**

```
I'm building ADVERSA VAPT platform. I need lib/testssl-parser.ts.

testssl.sh outputs a JSON file (via --jsonfile flag) with this structure:
{
  "id": "SSLv2",
  "severity": "CRITICAL",
  "finding": "offered (NOT ok)",
  "cve": "CVE-2015-3197",
  "cwe": "CWE-326"
}

Export:

type TestsslIssue = {
  id: string
  severity: string
  finding: string
  cve?: string
  cwe?: string
}

function parseTestsslJson(
  jsonContent: string,
  host: string,
  port: number
): LiveFinding[]

Rules:
- Parse the JSON array of TestsslIssue objects
- Skip entries where severity is 'OK', 'INFO', or 'DEBUG'
- Map testssl severity to ADVERSA Severity:
    CRITICAL → CRITICAL
    HIGH, WARN → HIGH
    MEDIUM → MEDIUM
    LOW → LOW
    everything else → INFO
- Build a LiveFinding per issue:
    title = issue.id + ': ' + first 60 chars of finding
    source = 'testssl'
    evidence = [{ label: 'testssl output', content: finding }]
    cveIds = [cve] if present
    host, port from params
- Return [] on any parse error

Import LiveFinding, Severity from './engine/types'.
Import generateFindingId from './finding-id'.
TypeScript strict mode.
```

---

**Task 2.4 — naabu output parser**

```
I'm building ADVERSA VAPT platform. I need lib/naabu-parser.ts.

naabu outputs JSONL when run with -json flag. Each line:
{ "ip": "10.0.0.1", "port": 80, "protocol": "tcp" }

Export:

type NaabuResult = {
  ip: string
  port: number
  protocol: 'tcp' | 'udp'
}

function parseNaabuLine(jsonl: string): NaabuResult | null
  — parses one line, returns null if invalid

function groupNaabuResults(results: NaabuResult[]): DiscoveredHost[]
  — groups by IP into DiscoveredHost objects
  — sets ports array, services array with proto only (no name/version yet)

Import DiscoveredHost from './engine/types'.
No external deps. Return null on parse errors.
TypeScript strict mode.
```

---

**Task 2.5 — Parser unit tests**

```
I'm building ADVERSA VAPT platform. I need tests for all four parsers.
Create tests/parsers.test.ts using Node.js built-in test runner (node:test).

Write tests for:

1. nmap-parser.ts:
   - parseNmapXml with a realistic nmap XML string (include 2 hosts,
     3 open ports, 1 NSE script result)
   - Returns correct ip, ports, services
   - Skips down hosts
   - Returns [] for empty string

2. nuclei-parser.ts:
   - parseNucleiLine with a valid JSONL line including CVE
   - Returns null for empty string
   - Returns null for malformed JSON
   - nucleiSeverityToSeverity maps 'critical' → 'CRITICAL'

3. testssl-parser.ts:
   - parseTestsslJson skips OK severity entries
   - Maps WARN → HIGH correctly
   - Returns [] for invalid JSON

4. naabu-parser.ts:
   - parseNaabuLine returns correct NaabuResult
   - groupNaabuResults groups two results for same IP correctly
   - Returns null for invalid line

Use realistic sample data as inline strings.
No external test libraries — only node:test and node:assert.
```

---

## Phase 3 — Core scan engine

---

**Task 3.1 — Tool runners**

```
I'm building ADVERSA VAPT platform. I need lib/engine/tool-runners.ts.

This file contains four async functions that spawn scanning tools
as child processes and stream output line by line via callbacks.
It must work on Linux, macOS, and Windows.

Import: DiscoveredHost, ScanOptions, ScanCallbacks from './types'
Import: parseNmapXml from '../nmap-parser'
Import: parseNucleiLine from '../nuclei-parser'
Import: parseTestsslJson from '../testssl-parser'
Import: parseNaabuLine, groupNaabuResults from '../naabu-parser'

The stealth → rate/timing mapping:
const NAABU_RATE = [0,50,100,300,500,1000,2000,3000,5000]  // index = stealth
const NMAP_TIMING = [0,1,1,2,2,3,3,4,4,5]

Export these four functions:

1. runNaabu(targets: string[], stealth: number, cb: ScanCallbacks): Promise<DiscoveredHost[]>
   - spawns: naabu -host <targets> -rate <rate> -s c -json -silent
   - parses each stdout line with parseNaabuLine
   - calls cb.onHostDiscovered for each new host discovered
   - returns grouped DiscoveredHost[]

2. runNmap(hosts: DiscoveredHost[], stealth: number, cb: ScanCallbacks): Promise<void>
   - spawns: nmap -sT -sV -T<timing> -p <ports> --script banner,ssl-cert,http-title -oX - <ips>
   - collects all stdout into buffer
   - on close: parses with parseNmapXml, enriches hosts.services in place
   - calls cb.onHostDiscovered with enriched host for each

3. runNuclei(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]>
   - builds URL targets: http://<ip>:<port> for each open port
   - spawns: nuclei -t /opt/nuclei-templates -json -silent -no-color -u <targets>
   - parses each stdout line with parseNucleiLine
   - converts to LiveFinding, calls cb.onFinding immediately per match
   - returns all findings

4. runTestssl(hosts: DiscoveredHost[], cb: ScanCallbacks): Promise<LiveFinding[]>
   - filters hosts with port 443 or 8443 only
   - for each: spawns testssl.sh --fast --jsonfile /tmp/testssl-<ip>.json <ip>:<port>
   - reads json file after process exits, parses with parseTestsslJson
   - calls cb.onFinding per finding
   - cleans up temp files

Cross-OS rules:
- Use process.platform to detect windows: spawn with shell:true on windows
- Add creationflags for no window flash on windows (via spawnOptions)
- Binary names: 'nmap.exe'/'nmap', 'naabu.exe'/'naabu' based on platform
- Always set encoding:'utf8' on stdio

On any spawn error: call cb.onError(stage, error.message), return empty result.
Never throw — always resolve.
TypeScript strict mode.
```

---

**Task 3.2 — Pipeline orchestrator**

```
I'm building ADVERSA VAPT platform. I need lib/engine/scanner.ts.

This is the core engine — the single runScan() function used by BOTH
the web SSE API and the CLI. It orchestrates the tool runners in order.

Import:
- ScanOptions, ScanCallbacks, ScanSummary, LiveFinding from './types'
- runNaabu, runNmap, runNuclei, runTestssl from './tool-runners'
- parseTargets from '../target-parser'
- generateFindingId from '../finding-id'

Export ONE function:
  async function runScan(opts: ScanOptions, cb: ScanCallbacks): Promise<void>

Pipeline order:
  Stage 1: naabu    (sequential — feeds port list to nmap)
  Stage 2: nmap     (sequential — after naabu)
  Stage 3+4: nuclei + testssl  (parallel with Promise.all)
  Stage 5: AI triage (only if ANTHROPIC_API_KEY exists in env)
             — dynamically import('../ai-engine').then(m => m.triageFindings)
             — if import fails or key missing: skip silently
  Stage 6: save to findings-store if opts.save === true
             — dynamically import('../findings-store').then(...)

Between each stage: call cb.onProgress with realistic percentage.

Build ScanSummary at the end: count bySeverity from allFindings array.
Call cb.onComplete with summary.

Rules:
- Wrap entire function in try/catch — call cb.onError on any uncaught error
- Never let one stage failure crash the whole scan — if nuclei fails,
  still run testssl
- Skip tools not in opts.tools array
- opts.scanId defaults to 'SCAN-' + Date.now() if not provided

TypeScript strict mode. No external dependencies beyond the imports above.
```

---

**Task 3.3 — `lib/findings-store.ts`**

```
I'm building ADVERSA VAPT platform. I need lib/findings-store.ts.

This file manages reading and writing findings to data/findings.json.
Both the CLI and web dashboard share this file as storage.

Import: LiveFinding, Severity from './engine/types'

Export these functions:

1. function getAllFindings(): LiveFinding[]
   - reads data/findings.json, returns parsed array
   - returns [] if file doesn't exist or is invalid JSON
   - creates data/ directory if missing

2. function saveFindings(findings: LiveFinding[], engagementId?: string): number
   - reads existing findings
   - for each new finding: check for duplicate (same host + same cveIds overlap
     OR same host + same title)
   - if duplicate: merge evidence arrays, update timestamp — don't add new entry
   - if new: add with slaDeadline calculated from severity:
       CRITICAL: +24h, HIGH: +72h, MEDIUM: +168h, LOW: +720h, INFO: no deadline
   - write back to data/findings.json with 2-space indent
   - return count of NEW findings added (not duplicates)

3. function getFindingById(id: string): LiveFinding | undefined

4. function updateFindingStatus(id: string, status: LiveFinding['status']): boolean
   - returns true if found and updated

5. function getFindingsByEngagement(engagementId: string): LiveFinding[]

6. function getFindingStats(): { total: number; bySeverity: Record<Severity, number>; byStatus: Record<string, number> }

Use synchronous fs (readFileSync/writeFileSync) — this is a local JSON store.
Ensure data/ directory exists before any write.
TypeScript strict mode.
```

---

**Task 3.4 — Dedup logic test**

```
I'm building ADVERSA VAPT platform.
I need to test the deduplication logic in lib/findings-store.ts.

Create tests/findings-store.test.ts using node:test.

Test cases:
1. saveFindings with 2 findings, same host + same CVE ID → only 1 saved, evidence merged
2. saveFindings with 2 findings, same host + different CVEs → 2 saved
3. saveFindings with same host + same title but no CVE → deduped as 1
4. SLA deadline for CRITICAL = within 25 hours from now
5. SLA deadline for INFO = undefined
6. getFindingStats returns correct bySeverity count
7. updateFindingStatus changes status correctly
8. getAllFindings returns [] for missing file (don't create a real file — mock the fs calls or use a temp path)

Use a temp directory (os.tmpdir()) for the data file in tests.
Override DATA_PATH by passing it as parameter OR by setting an env var
DATA_PATH before importing — pick whichever approach makes the module
cleanly testable without monkey-patching.

node:test + node:assert only.
```

---

**Task 3.5 — CLI scan command**

```
I'm building ADVERSA VAPT platform.
I need to wire up cli/commands/scan.ts to use the shared scan engine.

The CLI already has a Commander setup in cli/index.ts.
I need scan.ts to:

Import:
- runScan from '../../lib/engine/scanner'
- ScanOptions from '../../lib/engine/types'
- renderBanner, renderStageStart, renderStageComplete,
  renderHost, renderFinding, renderComplete, renderError
  from '../ui/output' (create stubs if output.ts doesn't exist yet)

Export default function:
  async function scanCommand(targets: string[], options: Record<string, string>): Promise<void>

Logic:
1. Parse targets: if --file flag, read file line by line; else use positional args
2. Build ScanOptions from commander options
3. Print banner
4. Call runScan with callbacks that render ANSI output:
   - onStageStart → console.log with stage name styled
   - onFinding → print severity badge + title + host:port
   - onHostDiscovered → print ip + ports
   - onComplete → print summary table
5. process.exit(0) on complete, process.exit(1) on error

Also create cli/ui/output.ts with these ANSI render functions:
- renderBanner(): void  — prints ADVERSA ascii + version
- renderStageStart(stage: string): void
- renderStageComplete(stage: string, summary: string): void
- renderHost(host: DiscoveredHost): void
- renderFinding(finding: LiveFinding): void
   — color coded: CRITICAL=red, HIGH=yellow, MEDIUM=cyan, LOW=white, INFO=gray
- renderComplete(summary: ScanSummary): void
   — prints table: hosts, findings, duration

Use process.stdout.write for ANSI. Colors via escape codes only, no chalk dependency.
TypeScript strict mode.
```

---

## Phase 4 — Manager server APIs

---

**Task 4.1 — Agent register API**

```
I'm building ADVERSA VAPT platform (Next.js App Router).
I need app/api/agents/register/route.ts.

This endpoint is called by the Python CLI agent on startup to register itself.

POST /api/agents/register
Body: {
  sessionId: string
  hostname: string
  os: 'Windows'|'Linux'|'Darwin'
  osVersion: string
  arch: string
  agentVersion: string
  capabilities: string[]         // ['nmap','nuclei','naabu','testssl']
  networkInterfaces: {
    name: string
    ip: string
    cidr: string
  }[]
}
Auth: Bearer token in Authorization header

Logic:
1. Validate Bearer token against AGENT_SECRET env var
2. Upsert agent record into lib/agents-store.ts
3. Return { agentId: string, registeredAt: string }

In lib/agents-store.ts add/update:
  type Agent = {
    id: string           // generated: AGT-<random 6 chars uppercase>
    sessionId: string
    hostname: string
    os: string
    osVersion: string
    arch: string
    agentVersion: string
    capabilities: string[]
    networkInterfaces: { name: string; ip: string; cidr: string }[]
    status: 'ONLINE'|'OFFLINE'|'BUSY'|'ERROR'
    registeredAt: string
    lastSeen: string
  }

  function registerAgent(data: Omit<Agent, 'id'|'registeredAt'|'lastSeen'|'status'>): Agent
  function updateAgentLastSeen(agentId: string): void
  function getAllAgents(): Agent[]
  function getAgent(agentId: string): Agent | undefined

Store in data/agents.json (same pattern as findings-store.ts).
Return 401 for missing/invalid token.
Return 200 with agentId on success.
TypeScript strict mode.
```

---

**Task 4.2 — Job long-poll API**

```
I'm building ADVERSA VAPT platform (Next.js App Router).
I need app/api/agents/jobs/next/route.ts.

This is the long-poll endpoint. The Python agent calls this in a loop.
The server holds the connection for up to 28 seconds waiting for a job.
If a job is ready, return it immediately. If timeout, return 204.

GET /api/agents/jobs/next
Auth: Bearer agentId token

Logic:
1. Extract agentId from token (token IS the agentId for simplicity — validate it exists)
2. Update agent lastSeen
3. Poll job queue every 500ms for up to 28 seconds:
   - Check lib/job-store.ts for a pending job matching this agent's capabilities
   - If found: mark as DISPATCHED, return 200 with the job JSON
   - If not found after 28s: return 204 No Content

Create lib/job-store.ts:
  type Job = {
    id: string              // JOB-<timestamp>-<random>
    type: 'scan'|'exploit'|'verify'
    agentId?: string        // which agent to dispatch to (null = any capable agent)
    status: 'PENDING'|'DISPATCHED'|'RUNNING'|'COMPLETE'|'FAILED'
    payload: Record<string, unknown>
    scopeToken: string      // signed JWT
    createdAt: string
    dispatchedAt?: string
    completedAt?: string
  }

  function createJob(type: Job['type'], payload: object, scopeToken: string, agentId?: string): Job
  function getNextJobForAgent(agentId: string, capabilities: string[]): Job | undefined
  function markDispatched(jobId: string, agentId: string): void
  function updateJobStatus(jobId: string, status: Job['status']): void
  function getAllJobs(): Job[]

Store in data/jobs.json.
Use async sleep loop (setInterval + Promise) for the poll — not a blocking loop.
TypeScript strict mode.
```

---

**Task 4.3 — Findings ingest API**

```
I'm building ADVERSA VAPT platform (Next.js App Router).
I need app/api/findings/ingest/route.ts.

The Python agent POSTs findings here as they are discovered during scanning.
This happens in real time — one finding per POST or a small batch.

POST /api/findings/ingest
Auth: Bearer agentId
Body: {
  scanId: string
  agentId: string
  findings: LiveFinding[]    // 1 to 50 findings per call
}

Logic:
1. Validate agentId token (agent must exist in agents-store)
2. Validate body — findings must be non-empty array
3. Call saveFindings(findings, engagementId) from findings-store.ts
4. Broadcast each finding to any SSE listeners for this scanId
   (use a module-level Map<scanId, Set<ReadableStreamController>>
   that the SSE endpoint also uses — create lib/scan-events.ts for this)
5. Return { saved: number, duplicates: number }

Return 401 for bad token.
Return 400 for invalid body.
Return 200 with result.

Also create lib/scan-events.ts:
  - module-level Map: scanListeners: Map<string, Set<(data: string) => void>>
  - function subscribeScan(scanId: string, callback: (data: string) => void): () => void
     returns an unsubscribe function
  - function broadcastToScan(scanId: string, event: string, data: object): void
     formats as SSE: "event: <event>\ndata: <JSON>\n\n"
     calls all callbacks for that scanId

TypeScript strict mode.
```

---

**Task 4.4 — SSE scan stream**

```
I'm building ADVERSA VAPT platform (Next.js App Router).
I need app/api/scan/stream/[scanId]/route.ts.

This SSE endpoint is what the browser connects to when watching a scan.
It receives live findings pushed by the findings ingest endpoint.

GET /api/scan/stream/[scanId]
No auth needed (dashboard is internal operator tool)

Logic:
1. Extract scanId from route params
2. Set up SSE response with correct headers:
   Content-Type: text/event-stream
   Cache-Control: no-cache
   Connection: keep-alive
3. Send initial heartbeat event immediately
4. Subscribe to scan events via subscribeScan(scanId, callback) from lib/scan-events.ts
5. Keep connection alive with a heartbeat ping every 15 seconds
6. On client disconnect: call unsubscribe()
7. Stream any events that come in via broadcastToScan

SSE event format:
  event: finding
  data: { ...LiveFinding }

  event: stage_start
  data: { stage: string }

  event: heartbeat
  data: { ts: string }

  event: complete
  data: { ...ScanSummary }

Use NextRequest and a ReadableStream with a controller.
Unsubscribe and close the stream cleanly on disconnect.
TypeScript strict mode.
```

---

**Task 4.5 — Scan trigger + job status APIs**

```
I'm building ADVERSA VAPT platform (Next.js App Router).
I need two small API routes:

1. app/api/scans/start/route.ts
POST /api/scans/start
Body: {
  targets: string[]
  profile: 'fast'|'standard'|'deep'
  stealth: number
  tools: string[]
  engagementId?: string
  agentId?: string     // which agent to use; null = auto-assign
}

Logic:
- Validate targets with parseTargets from lib/target-parser.ts
- Generate a scope token (for now: simple JWT signed with SCOPE_SECRET env var)
  Payload: { scanId, targets, notBefore: now, notAfter: now+24h }
  Use jsonwebtoken package: npm install jsonwebtoken @types/jsonwebtoken
- Create a job via createJob() from lib/job-store.ts
- Return { scanId, jobId, scopeToken }

2. app/api/scans/[scanId]/status/route.ts
GET /api/scans/[scanId]/status

Logic:
- Look up job by scanId from job-store
- Get findings for this scanId from findings-store
- Return {
    scanId,
    status: job.status,
    findingCount: findings.length,
    bySeverity: { CRITICAL: N, ... },
    agentId: job.agentId,
    startedAt: job.dispatchedAt,
  }
- Return 404 if scanId not found

TypeScript strict mode.
```

---

## Phase 5 — Python CLI agent

---

**Task 5.1 — Agent project structure + bootstrap**

```
I'm building ADVERSA VAPT platform.
I need to create the Python CLI agent as a separate package.

Create this directory structure inside the repo:
agent/
  __init__.py
  main.py           ← entry point
  config.py         ← reads env vars / CLI args
  requirements.txt

requirements.txt must include:
  requests==2.31.0
  PyJWT==2.8.0
  click==8.1.7

config.py must read these (from env vars with CLI flag overrides):
  ADVERSA_MANAGER_URL   (required, e.g. https://app.adversa.io)
  ADVERSA_AGENT_TOKEN   (required, the Bearer token)
  ADVERSA_LOG_LEVEL     (optional, default INFO)

Export a Config dataclass with those three fields + a load() classmethod
that reads from environment and validates both required fields are present,
raising a clear error if missing.

main.py entry point:
  - Uses click for CLI: adversa-agent --token X --manager Y
  - CLI flags override env vars
  - Calls Config.load(), then AdversaAgent(config).start()
  - Catches KeyboardInterrupt cleanly (prints "Agent stopped")

Keep it minimal — just bootstrap and wiring.
Python 3.10+. Type hints throughout.
```

---

**Task 5.2 — Tool adapter (cross-platform)**

```
I'm building ADVERSA VAPT platform — Python CLI agent.
I need agent/tool_adapter.py.

This class abstracts tool execution so the same code works on
Windows, Linux, and macOS.

class ToolAdapter:

  TOOLS = {
    'nmap': { 'windows': 'nmap.exe', 'linux': 'nmap', 'darwin': 'nmap' },
    'naabu': { 'windows': 'naabu.exe', 'linux': 'naabu', 'darwin': 'naabu' },
    'nuclei': { 'windows': 'nuclei.exe', 'linux': 'nuclei', 'darwin': 'nuclei' },
    'testssl': { 'windows': 'testssl.sh', 'linux': 'testssl.sh', 'darwin': 'testssl.sh' }
  }

  def check_all(self) -> dict[str, bool]
    — returns { 'nmap': True, 'naabu': False, ... }
    — uses shutil.which() to check each binary

  def is_available(self, tool: str) -> bool

  def run(
    self,
    tool: str,
    args: list[str],
    on_line: Callable[[str], None],
    timeout: int = 300
  ) -> int
    — resolves correct binary name for current OS (platform.system())
    — on Windows: adds CREATE_NO_WINDOW flag + shell=True
    — on Linux/macOS: shell=False
    — streams stdout line by line, calls on_line for each non-empty line
    — returns process exit code
    — raises ToolNotAvailableError if binary not found
    — kills process if timeout exceeded

  def get_platform_key(self) -> str
    — returns 'windows' | 'linux' | 'darwin'

class ToolNotAvailableError(Exception): pass

Python 3.10+. Use subprocess, shutil, platform.
Type hints throughout. No external dependencies.
```

---

**Task 5.3 — Result buffer**

```
I'm building ADVERSA VAPT platform — Python CLI agent.
I need agent/result_buffer.py.

This class writes findings locally first (so nothing is lost if
network drops), then immediately tries to ship to the manager server.
On reconnect, it flushes anything that failed.

class ResultBuffer:
  def __init__(self, scan_id: str, manager_url: str, token: str)
    - creates local buffer file at:
      Windows: %TEMP%/adversa/<scan_id>.jsonl
      Linux/macOS: /tmp/adversa/<scan_id>.jsonl
    - creates parent directory if missing

  def write(self, finding: dict) -> None
    - appends JSON line to local file (always succeeds locally)
    - calls _try_ship(finding) — catches all exceptions silently

  def write_batch(self, findings: list[dict]) -> None
    - writes all, then ships as one batch POST

  def _try_ship(self, finding: dict) -> bool
    - POST to {manager_url}/api/findings/ingest
    - headers: Authorization: Bearer {token}
    - body: { scanId: self.scan_id, findings: [finding] }
    - timeout: 5 seconds
    - returns True if 200, False otherwise (never raises)

  def flush_pending(self) -> int
    - reads local file line by line
    - for each line not yet shipped: calls _try_ship
    - returns count of successfully flushed items
    - cleans up file if all flushed successfully

  def cleanup(self) -> None
    - deletes the local buffer file

Python 3.10+. Use pathlib, json, requests.
Type hints throughout.
```

---

**Task 5.4 — Agent poll loop**

```
I'm building ADVERSA VAPT platform — Python CLI agent.
I need agent/poll_loop.py.

This module handles registration and the main job polling loop.
The agent never receives inbound connections — it only polls outbound.

class AgentPoller:
  def __init__(self, config: Config, tool_adapter: ToolAdapter)

  def register(self) -> str
    — POST {manager_url}/api/agents/register
    — body: {
        sessionId: str (uuid4),
        hostname: socket.gethostname(),
        os: platform.system(),
        osVersion: platform.version(),
        arch: platform.machine(),
        agentVersion: '0.1.0',
        capabilities: list of available tools from tool_adapter.check_all(),
        networkInterfaces: list of { name, ip, cidr } from self._get_interfaces()
      }
    — headers: Authorization: Bearer {token}
    — returns agentId from response
    — raises RuntimeError if registration fails

  def _get_interfaces(self) -> list[dict]
    — uses socket module to get local IPs
    — returns [{ name: 'eth0', ip: '192.168.1.5', cidr: '192.168.1.0/24' }]
    — best-effort: return [] on any error

  def poll_once(self) -> dict | None
    — GET {manager_url}/api/agents/jobs/next
    — headers: Authorization: Bearer {agentId}
    — timeout: 35 seconds (longer than server's 28s hold)
    — returns job dict if 200, None if 204, raises on other errors

  def run_forever(self, job_handler: Callable[[dict], None]) -> None
    — infinite loop:
        try:
          job = self.poll_once()
          if job:
            job_handler(job)
        except KeyboardInterrupt:
          raise
        except Exception as e:
          log error, sleep 5 seconds
    — on KeyboardInterrupt: return cleanly

  def update_status(self, job_id: str, status: str, stage: str = '') -> None
    — POST {manager_url}/api/agents/jobs/{job_id}/status
    — body: { status, stage }

Python 3.10+. Use requests, socket, platform, uuid.
Type hints throughout.
```

---

**Task 5.5 — Scope verifier**

```
I'm building ADVERSA VAPT platform — Python CLI agent.
I need agent/scope_verifier.py.

This is a critical safety component. Before the agent runs ANY
tool or command, it must verify the signed scope token.

class ScopeVerifier:
  def __init__(self, public_key_or_secret: str)
    — stores the key used to verify JWT signatures
    — (same key as SCOPE_SECRET on the server, shared as env var)

  def verify(self, scope_token: str, target: str) -> bool
    — decodes JWT using PyJWT
    — checks:
        1. Token is not expired (exp claim)
        2. Current time >= notBefore claim
        3. target IP/hostname is within allowed_targets list
           (check exact match OR CIDR containment using ipaddress module)
    — returns True only if ALL checks pass
    — returns False (never raises) if token invalid, expired, or target out of scope
    — logs reason for rejection

  def _is_in_scope(self, target: str, allowed: list[str]) -> bool
    — handles: exact IP match, CIDR containment, hostname match
    — uses ipaddress.ip_network and ipaddress.ip_address for CIDR check

class ScopeViolationError(Exception): pass

Python 3.10+. Use PyJWT, ipaddress (stdlib), logging.
Type hints throughout.
Write 5 inline doctest examples showing pass/fail cases.
```

---

**Task 5.6 — Scan executor**

```
I'm building ADVERSA VAPT platform — Python CLI agent.
I need agent/scan_executor.py.

This ties everything together on the agent side.
It receives a scan job, runs the tools in pipeline order,
and streams results back via ResultBuffer.

class ScanExecutor:
  def __init__(
    self,
    tool_adapter: ToolAdapter,
    result_buffer: ResultBuffer,
    scope_verifier: ScopeVerifier,
    poller: AgentPoller
  )

  def execute(self, job: dict) -> None
    — entry point called by the poll loop

    Steps:
    1. Verify scope: scope_verifier.verify(job['scopeToken'], each target)
       — if fails: report job FAILED with reason, return
    2. Report status RUNNING/port_scan
    3. Run naabu → get open_ports: list of { ip, port, proto }
    4. Report status RUNNING/service_probe
    5. Run nmap on discovered hosts → enrich with service names
    6. Report status RUNNING/cve_scan
    7. Run nuclei in parallel with testssl using threading.Thread
    8. Report status COMPLETE

    For each finding discovered: call result_buffer.write(finding_dict)

    Each tool run:
    - calls tool_adapter.run(tool, args, on_line=self._parse_and_buffer)
    - builds args based on profile and stealth from job payload
    - uses the same stealth→rate/timing mappings as the TypeScript engine:
        NAABU_RATES = [0,50,100,300,500,1000,2000,3000,5000]
        NMAP_TIMING = [0,1,1,2,2,3,3,4,4,5]

  def _build_finding(
    self, source: str, host: str, port: int,
    severity: str, title: str, evidence: str,
    cve_ids: list[str] | None = None
  ) -> dict
    — builds a finding dict matching LiveFinding shape expected by the server

  def _parse_naabu_line(self, line: str) -> dict | None
  def _parse_nuclei_line(self, line: str) -> dict | None

Python 3.10+. Use threading for parallel nuclei+testssl.
Type hints throughout. Catch all subprocess errors per tool.
```

---

## Phase 6 — AI integration

---

**Task 6.1 — Triage prompt constant**

```
I'm building ADVERSA VAPT platform.
I need lib/prompts/triage.ts.

This file exports ONE string constant: TRIAGE_SYSTEM_PROMPT.

The prompt must instruct Claude to:
- Act as a senior penetration tester analyzing raw scan findings
- Remove false positives (explain why in false_positive_reason field)
- Map findings to real CVE IDs (only ones it's confident about)
- Assign CVSS 3.1 scores and severity
- Assign exploit priority 1-10 (1=highest)
- Identify attack chains: which findings chain together
- Return ONLY valid JSON matching this exact schema (no markdown, no preamble):

{
  "scan_id": string,
  "triage_summary": {
    "total_findings": number,
    "false_positives_removed": number,
    "critical": number, "high": number, "medium": number,
    "low": number, "informational": number
  },
  "findings": [{
    "finding_id": string,
    "host": string, "port": number,
    "service": string,
    "title": string,
    "description": string,
    "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
    "cvss_score": number,
    "cvss_vector": string | null,
    "cve_ids": string[],
    "false_positive": boolean,
    "false_positive_reason": string | null,
    "exploitability": "EASY"|"MODERATE"|"HARD"|"THEORETICAL",
    "exploit_priority": number,
    "remediation_short": string,
    "confidence": "HIGH"|"MEDIUM"|"LOW"
  }],
  "attack_chains": [{
    "description": string,
    "steps": string[],
    "impact": string
  }]
}

Include strict rules in the prompt:
- Never invent CVE IDs — use [] if unsure
- Never fabricate version numbers
- Only include attack chains with 2+ steps

Export as: export const TRIAGE_SYSTEM_PROMPT: string
No logic in this file — just the constant.
TypeScript. Single export.
```

---

**Task 6.2 — `lib/ai-engine.ts`**

```
I'm building ADVERSA VAPT platform.
I need lib/ai-engine.ts — the Claude API wrapper.

Install: npm install @anthropic-ai/sdk

Export these functions:

1. async function triageFindings(findings: LiveFinding[]): Promise<LiveFinding[]>
   - If no ANTHROPIC_API_KEY in env: return findings unchanged
   - If findings is empty: return []
   - Call Claude claude-sonnet-4-6 with TRIAGE_SYSTEM_PROMPT from lib/prompts/triage.ts
   - User message: JSON.stringify({ findings, timestamp: new Date().toISOString() })
   - Parse response: strip any ```json ``` fences, JSON.parse
   - Merge enriched data back onto original findings:
       for each original finding, find matching enriched by host+title
       update: severity, cvss, cvssVector, cveIds, falsePositive, falsePositiveReason
   - On any API error or parse error: log warning, return original findings unchanged
   - max_tokens: 8192

2. async function generateReport(session: ReportSession): Promise<ReportResult>
   - session has: clientName, scope, findings, exploitResults, engagementType
   - Use REPORT_SYSTEM_PROMPT (create lib/prompts/report.ts separately)
   - Return parsed JSON report object
   - On error: throw with message 'Report generation failed: ' + error

3. async function chat(messages: {role:string, content:string}[], systemContext?: string): Promise<string>
   - Used by AI Brain (/aibrain page)
   - system: systemContext ?? 'You are a senior penetration tester assistant...'
   - max_tokens: 2048
   - Returns text content of first block
   - On error: throw

Import: TRIAGE_SYSTEM_PROMPT from './prompts/triage'
Import: LiveFinding from './engine/types'
TypeScript strict mode.
```

---

**Task 6.3 — Report prompt + report API**

```
I'm building ADVERSA VAPT platform.
I need two things:

1. lib/prompts/report.ts
Export REPORT_SYSTEM_PROMPT: string

The prompt instructs Claude to write a pentest report with:
- Executive summary (3-5 sentences, plain English, no jargon)
- Risk scorecard: overall 0-100, plus network/auth/config/patches/web scores
- Per finding: business_impact (plain English) + technical_detail + steps_to_reproduce + remediation_detail + compliance_refs
- Remediation roadmap: priority_1_24h, priority_2_30d, priority_3_90d (lists of finding IDs)
- positive_findings: something the client did right (always include)
- Output ONLY JSON matching this schema — no markdown, no preamble

2. app/api/engagements/[id]/ai-report/route.ts
POST handler:

Logic:
- Get engagement by id from lib/engagements-store.ts
- Get all findings for this engagement from lib/findings-store.ts
- Build session object: { clientName, scope, findings, exploitResults: [], engagementType: 'Black-box network VAPT' }
- Call generateReport(session) from lib/ai-engine.ts
- Store result in engagement record under aiReport field
- Return the report JSON

Handle errors: return 500 with { error: message } if generation fails.
Return 404 if engagement not found.
TypeScript strict mode.
```

---

**Task 6.4 — AI Brain chat API**

```
I'm building ADVERSA VAPT platform (Next.js App Router).
I need app/api/brain/route.ts — the AI Brain chat endpoint.

POST /api/brain
Body: {
  messages: { role: 'user'|'assistant'; content: string }[]
  engagementId?: string    // for context-aware responses
}

Logic:
1. Get recent findings (last 20 by recency) if engagementId provided
   — from lib/findings-store.ts
2. Build system context string:
   "You are a senior penetration tester and red team operator.
   You are working inside ADVERSA, an AI-powered VAPT platform.
   [if findings: Current engagement has N findings: CRITICAL: X, HIGH: Y ...]
   You provide tactical advice on exploitation paths, credential attacks,
   lateral movement, and remediation prioritization.
   Never provide advice outside authorized scope."
3. Call chat(messages, systemContext) from lib/ai-engine.ts
4. Return { content: string }

Handle stream: the existing /aibrain page expects streaming.
Change to use the Anthropic SDK stream API:
  const stream = client.messages.stream({ ... })
  return new Response(stream as any, { headers: { 'Content-Type': 'text/event-stream' }})

Or if simpler: return non-streamed first, note in a comment that streaming can be added.
TypeScript strict mode.
```

---

**Task 6.5 — Exploit command builder**

```
I'm building ADVERSA VAPT platform.
I need lib/prompts/exploit-builder.ts and the exploit dispatch flow.

1. lib/prompts/exploit-builder.ts
Export EXPLOIT_BUILDER_SYSTEM_PROMPT: string

The prompt instructs Claude to:
- Receive a single confirmed vulnerability finding
- Select the right exploit tool (Metasploit module, nuclei template, manual curl)
- Build the EXACT shell command with all parameters filled in
- Return ONLY JSON:
{
  "finding_id": string,
  "exploit_available": boolean,
  "no_exploit_reason": string | null,
  "tool": "metasploit"|"nuclei"|"manual",
  "module_or_template": string,
  "command": string,
  "command_explanation": string,
  "is_verification_only": boolean,
  "expected_success_indicator": string,
  "expected_failure_indicator": string,
  "timeout_seconds": number,
  "risk_level": "LOW"|"MEDIUM"|"HIGH"|"DESTRUCTIVE",
  "requires_human_approval": boolean,
  "human_approval_reason": string | null
}

Strict rules in prompt:
- Only targets in scope token
- Never generate rm/format/wipe/ransom commands
- Prefer verification-only on first attempt
- Set requires_human_approval: true for HIGH or DESTRUCTIVE risk

2. app/api/exploit/build/route.ts
POST /api/exploit/build
Body: { findingId: string; scopeToken: string }

Logic:
- Load finding from findings-store by findingId
- Verify scopeToken is valid JWT (using jsonwebtoken verify)
- Call Claude with EXPLOIT_BUILDER_SYSTEM_PROMPT
  user message: JSON.stringify({ finding, scopeToken })
- Parse response
- Force requires_human_approval = true if risk_level is HIGH or DESTRUCTIVE
  (never trust AI alone on this)
- Store result in lib/exploit-store.ts with status PENDING_APPROVAL
- Return the exploit plan

TypeScript strict mode.
```

---

## How to use these prompts

Each prompt is self-contained. Use them in this order — never skip a phase. When you finish a task, the next prompt will reference the file you just created. If Claude asks clarifying questions on any task, add: `"Keep it simple, match exactly what I described, no extra features."` That keeps scope tight.