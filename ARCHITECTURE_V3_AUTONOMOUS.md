# ADVERSA — Autonomous AI-Native VAPT Architecture (v3)

**Authors:** Architecture working draft
**Status:** Proposed — supersedes v2
**Last Updated:** 2026-06-03

> v2 made the platform a credible event-sourced workflow system. v3 asks
> a different question: **what if the AI is not a triage step but the
> actual operator?** This document designs ADVERSA as an autonomous
> internal-network VAPT system where an AI planner drives the engagement,
> a live attack graph is shared memory, and humans are checkpoint
> approvers rather than pipeline operators.

---

## 0. The thesis (one paragraph)

A pentest is not a pipeline. It is a **loop**: observe → reason → act →
observe. The current generation of VAPT tools encodes the loop in human
heads and the pipeline structure in code. The next generation flips
that: encode the loop in the system, and let humans focus on **scope,
risk tolerance, and approval of high-impact actions**. The AI is not a
plugin — it is the control logic. Everything else (tools, graphs,
sensors, sandboxes) exists to give the AI eyes, hands, and a safe
operating envelope.

---

## 1. The autonomous loop (the heart of the system)

```
                  ┌─────────────────────────────────┐
                  │      ATTACK GRAPH (Neo4j)        │
                  │  hosts · services · creds ·       │
                  │  findings · paths · ATT&CK state  │
                  └────────────────┬────────────────┘
                                   │ query (Cypher)
                                   ▼
   ┌─────────────────────────────────────────────────────┐
   │              PLANNER  (Claude + MCP)                │
   │                                                      │
   │   1. Read current graph state                       │
   │   2. Consult ATT&CK goal tree                       │
   │   3. Choose next ATT&CK technique                   │
   │   4. Choose Skill to execute it                     │
   │   5. Bind Skill to specific targets from graph      │
   │   6. Produce signed action proposal                 │
   └────────────────┬────────────────────────────────────┘
                    │  action proposal (JSON)
                    ▼
   ┌─────────────────────────────────────────────────────┐
   │        SAFETY ENVELOPE  (policy + HSM-signed)        │
   │                                                      │
   │   · Scope check (Cedar policy → graph subgraph)     │
   │   · Risk classification (read-only/active/destruct.)│
   │   · Approval gate (auto/human, per policy)          │
   │   · Symbolic dry-run (does it match intent?)        │
   │   · Sign scope-bound action token (HSM)             │
   └────────────────┬────────────────────────────────────┘
                    │  signed action token
                    ▼
   ┌─────────────────────────────────────────────────────┐
   │        EXECUTOR  (Firecracker + eBPF + MCP server)   │
   │                                                      │
   │   · Spin disposable VM with egress allowlist        │
   │   · Run Skill (naabu/nmap/nuclei/custom)             │
   │   · eBPF kernel-level execution trace               │
   │   · Stream observations to Findings ingest          │
   │   · Hash + timestamp evidence (RFC 3161)            │
   └────────────────┬────────────────────────────────────┘
                    │  observations (events)
                    ▼
   ┌─────────────────────────────────────────────────────┐
   │      OBSERVER  (small-model classifier + LLM)        │
   │                                                      │
   │   · Fast triage with on-box DistilBERT (10ms)        │
   │   · Vector-embed for dedup + similarity              │
   │   · Escalate uncertain cases to Claude               │
   │   · Update graph: new nodes + edges + ATT&CK state   │
   └────────────────┬────────────────────────────────────┘
                    │  graph deltas
                    └────────► back to ATTACK GRAPH ◄─── loop
```

This loop runs continuously for the lifetime of an engagement. The CLI
becomes a **viewer + approver** of the loop, not the driver of it.

---

## 2. What "advanced" actually means here

Concrete picks, each with a defended reason and a research-vs-ship label.

### 2.1 Planner stack — **Claude + Model Context Protocol (MCP)** [SHIP]

The AI planner uses **MCP** (Anthropic's open protocol) to access tools,
graph, and sensor data. Every capability the planner can invoke is an
MCP server.

**Why MCP over hand-rolled function calling:**
- Standard protocol → third-party tools plug in (Burp, Metasploit, custom)
- Resource discovery is built in
- Streaming + session state for long-running activities
- The CLI, web console, and agent all speak the same protocol
- Future-proofed: as the model gets better, the protocol stays stable

**MCP servers we ship:**
| Server                  | Capability                                                  |
|-------------------------|-------------------------------------------------------------|
| `adversa-graph`         | Read/query the attack graph via Cypher                      |
| `adversa-tools`         | Invoke naabu/nmap/nuclei/testssl/custom skills              |
| `adversa-attack`        | ATT&CK technique catalog + applicability check              |
| `adversa-evidence`      | Fetch evidence artifacts (pcap, banners, screenshots)       |
| `adversa-creds`         | Cred vault (read-only, scoped, every access logged)         |
| `adversa-passive`       | Passive sensor feed (ARP, mDNS, DNS, TLS SNI)               |
| `adversa-skills`        | Skill registry — discover + load packaged capabilities       |

### 2.2 Attack graph — **Neo4j** with a strict schema [SHIP]

The graph is the shared memory of the system. Every component reads and
writes it. There is no "scan state" object — there is only the graph.

**Why Neo4j over a property graph in Postgres:**
- Cypher is the right language for path queries ("shortest exploit chain
  from `internet` to `domain_admin`")
- Native graph algorithms (PageRank for asset criticality, betweenness
  for chokepoint identification) replace bespoke code
- Bolt protocol streams subgraph deltas to the UI cheaply

**Node labels:**
```
:Host  :Service  :Cred  :Finding  :CVE  :User  :Group  :Share
:Domain  :Subnet  :Route  :Path  :TacticState  :Evidence
```

**Edge types:**
```
:LISTENS_ON  :RUNS_SERVICE  :HAS_CRED  :EXPLOITS  :PIVOTS_TO
:MEMBER_OF  :OWNS  :TRUSTS  :REACHABLE_FROM  :CHAINED_WITH
:OBSERVED_AT  :MITRE_TACTIC  :MITRE_TECHNIQUE
```

**Sample query — what the planner runs:**
```cypher
MATCH p = shortestPath(
  (start:Host {role:'foothold'})-[*..6]->(target:Host {role:'high_value'})
)
WHERE ALL(
  rel IN relationships(p)
  WHERE type(rel) IN ['EXPLOITS','PIVOTS_TO','HAS_CRED']
)
RETURN p, length(p) AS depth
ORDER BY depth ASC
LIMIT 3
```

The planner receives three candidate exploit chains, scores them on
likelihood × impact ÷ noise, picks one, and asks the executor to
attempt the next step.

### 2.3 Vector store — **Qdrant** for similarity, dedup, fingerprinting [SHIP]

Embedding model: **bge-large-en-v1.5** (open weights, ships on-prem).

**Things we embed:**
- Finding titles + descriptions → finding similarity / dedup
- Service banners → fingerprinting unknown services against a CPE corpus
- CVE descriptions → relevance ranking per service
- Operator chat history → retrieval for the AI Brain

**Why this matters operationally:** today's dedup is `host + cveId`
string match — slightly different titles bypass it. Vector cosine ≥
0.92 catches "Apache 2.4.49 path traversal" === "Apache HTTP 2.4.49
RCE" === "CVE-2021-41773" as one finding.

### 2.4 Skills — **Anthropic Skills format**, signed + versioned [SHIP]

Every capability is a Skill: a directory containing
`SKILL.md` (prompt + instructions for the planner), `tools.json` (MCP
tool definitions), and reference materials.

```
skills/
├── reconnaissance.network/
│   ├── SKILL.md
│   ├── tools.json
│   └── refs/portfingerprints.csv
├── initial-access.smb-relay/
├── credential-access.kerberoast/
├── lateral-movement.psexec/
├── discovery.ad-enumerate/
├── persistence.scheduled-task/   # dangerous — requires human approval
└── exfiltration.dns/             # off by default — opt-in per engagement
```

**Why Skills as a unit of capability:**
- Customers can ship proprietary skills for their internal tools
- The skill registry is the place to enforce policy (this customer's
  policy disables `persistence.*` and `exfiltration.*` entirely)
- Skills are versioned + signed → known good behavior, replayable
- Maps 1:1 to ATT&CK so the planner reasons in standard terminology

### 2.5 ATT&CK as the planner's goal tree [SHIP]

The planner does not invent tactics. It walks the MITRE ATT&CK matrix
as a directed graph of possible next moves, scoring each by:

```
score(technique) = applicability(graph_state)
                 × estimated_success_rate
                 × value_of_information_gained
                 ÷ detection_likelihood
                 ÷ cost_in_time
```

Per-technique success rates are learned from prior engagements
(differentially private — see §2.10).

### 2.6 Safety envelope — **HSM-signed, multi-layer** [SHIP]

The planner produces *proposals*, not actions. Each proposal is
classified:

| Class            | Examples                                | Approval                |
|------------------|-----------------------------------------|-------------------------|
| **READ_ONLY**    | port scan, banner grab, passive sniff   | auto                    |
| **ACTIVE**       | CVE probe, login attempt, NSE script    | auto if in scope        |
| **STATE_CHANGE** | drop file, schedule task, modify config | human approval required |
| **DESTRUCTIVE**  | crash, encrypt, wipe                    | always denied (block)   |

Each approved proposal is wrapped in a **scope-bound action token**
signed by an **HSM-resident private key**. The token contains:

```json
{
  "iss":       "adversa-control-plane",
  "exp":       <60 seconds from now>,
  "tenant":    "...",
  "engagement":"...",
  "skill_id":  "reconnaissance.network@1.4.0",
  "skill_hash":"sha256:...",
  "targets":   ["10.0.0.5", "10.0.0.6"],
  "class":     "ACTIVE",
  "nonce":     "...",
  "approved_by":"alice@acme.com OR auto-policy:scope-bounded-recon"
}
```

The executor refuses any action whose token is invalid, expired, or
out of scope. The HSM key never exists in process memory — even an RCE
in the planner cannot forge a token.

### 2.7 Executor — **Firecracker + eBPF + RFC 3161 evidence** [SHIP-soon]

Each Skill execution gets a fresh Firecracker microVM with:
- Read-only rootfs
- Egress iptables allowlist = exactly the targets in the action token
- eBPF program loaded that records every syscall, network connect, file
  open into a kernel-side ring buffer
- Output stream: structured events back to Findings ingest via mTLS gRPC

When the VM exits:
- The eBPF trace is signed and uploaded to S3 Object Lock
- Every evidence artifact (banner, response body, screenshot) is hashed
- The hash is timestamped via an RFC 3161 Time Stamp Authority
- The result is a **cryptographic chain of custody** — usable in court

**Why this is non-negotiable:** the failure mode "compromised scanner
template exfiltrates customer data" is one CVE away. Firecracker per-
execution gives a separate kernel; eBPF + signed audit gives proof of
exactly what happened.

### 2.8 Confidential AI gateway — **TEE-bound LLM calls** [SHIP-soon]

The AI gateway runs inside a **Trusted Execution Environment**: AWS
Nitro Enclaves, GCP Confidential VMs, or Azure Confidential Computing.

**Properties guaranteed:**
- Cloud provider operator cannot read prompt contents
- ADVERSA operator cannot read customer's prompt contents
- Memory contents are encrypted; attestation proves the running code

**Why for an internal-VAPT product:** customers' prompts contain
**internal network maps, credentials they've harvested, CVEs they
haven't patched**. Calling Claude from outside an enclave makes us a
juicy target for "compromise the AI gateway, get every customer's
attack surface." Confidential computing makes the gateway operator
non-trustworthy by design.

### 2.9 Small-model fast-path — **on-box classifier** [SHIP]

Most findings don't need Claude. A DistilBERT-class classifier (~10ms
inference, runs on CPU) does first-pass:

- Severity (5-way)
- False-positive likelihood
- Whether to escalate to Claude

The model is fine-tuned on the audit log of prior operator decisions
(privacy preserved via DP-SGD, see §2.10). Result: **~95% of findings
get instant classification; ~5% escalate to Claude.** Cost-per-scan
drops by 1-2 orders of magnitude.

### 2.10 Cross-tenant learning — **Differential Privacy** [RESEARCH]

The "small model" in §2.9 wants to learn from all engagements. We
cannot leak any single customer's findings.

**Approach:** train with DP-SGD (TensorFlow Privacy or Opacus),
ε-budget per training round, formal privacy guarantee. Customers opt-in;
their data participates with calibrated noise.

The output: an "industry baseline" — *"organizations like yours had
this finding 14% of the time"* — without ever having shown your data
to anyone else's model query.

**Why marked RESEARCH:** the formal guarantee is solid; the engineering
to make it operationally tractable across tenants of wildly different
sizes is real work. Ship in v2.0 of the product, not v1.

### 2.11 Passive sensor — **eBPF-on-host or SPAN port** [SHIP-soon]

A persistent in-network sensor (deployed once per engagement) that
**never sends a packet** but listens to:

- ARP / NDP → live host inventory
- mDNS / SSDP / NetBIOS → service inventory
- DNS request stream → internal namespace map
- TLS SNI inspection → service mesh map
- ICMP redirect / Router Advertisement → topology

Implemented with eBPF on a Linux host or via SPAN port mirroring.
Output is a continuous stream of `Observation` events into the attack
graph.

**Why this matters for autonomy:** the AI planner can do reconnaissance
**without sending packets** for the first 24h of an engagement. The
attack graph fills in from passive observation. By the time the first
active scan runs, the planner already knows what to target.

### 2.12 Knowledge distillation for on-prem AI [SHIP-later]

Customers who refuse cloud AI need a story. The story is:

1. Cloud Claude is used during development on synthetic data
2. Traces of every Claude decision are logged with the input graph state
3. A student model (e.g. Llama-3.1-8B-Instruct, or future open weights)
   is trained on (state → decision) pairs from those traces
4. The distilled model ships in the on-prem deployment

The cloud LLM is the teacher. The on-prem model is the student. Quality
gap is real (~85-90% of cloud Claude on triage tasks in current public
benchmarks), but the customer chooses: cloud AI with confidentiality
guarantees, or on-prem distilled with quality trade-off.

### 2.13 CRDT-collaborative engagement state — **Yjs** [SHIP-later]

Multiple operators on the same engagement see live shared state without
conflicts. Yjs CRDT under the hood. The attack graph itself is
canonical; CRDTs handle annotations, comments, marked-for-review flags,
and in-progress findings between two analysts on the same target.

### 2.14 WASM-based extensions — **Wasmtime** [SHIP-later]

Customers extend us with their own:
- Detection rules
- Custom parsers (proprietary network appliances)
- Post-processing logic

All run as **WASM modules** in Wasmtime. Cross-platform, sandboxed by
design, deterministic, fast. Customer code cannot touch our process
memory or filesystem.

### 2.15 Reinforcement learning for stealth optimization [RESEARCH]

The stealth-vs-speed dial today is a hand-tuned scalar. A small RL
policy can do better:

- Observation space: target network behavior signals (response times,
  packet loss, rate limits hit)
- Action space: scan rate, source-IP rotation pattern, jitter window
- Reward: completed scan / time / not-detected

The reward signal "not detected" requires customer EDR feedback —
practical only for customers running an ADVERSA integration with their
EDR. Real product feature for a subset of customers; not v1.

### 2.16 SPIFFE + Istio Ambient for service identity [SHIP]

Sidecar-free service mesh. Every service has a SPIFFE SVID. Identity-
aware AuthorizationPolicies driven by Cedar at L7. Zero-trust internal
network without the per-pod sidecar overhead of traditional Istio.

### 2.17 Symbolic execution for destructive-action gating [RESEARCH]

For STATE_CHANGE proposals, before running the action, we run a
symbolic execution pass over a model of the target. If the model
predicts "this exploit will likely crash the target" → escalate to
human approval. If "this exploit will exfiltrate <X>" → block.

Tools: angr or KLEE for binary targets; custom Z3-backed analyzer for
network protocol state machines. Heavy R&D; probably 18-24 months out.

---

## 3. Data architecture (revised)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          OBSERVATIONS                                │
│  (raw events from scanners, sensors, executor)                       │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│       NATS JetStream  ─  ordered, replayable event log              │
└─────────────────────────────────────────────────────────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌────────────────┐     ┌────────────────────┐
│ Postgres OLTP │       │ Neo4j Graph    │     │ Qdrant Vector DB   │
│ (tenants,     │       │ (live attack   │     │ (finding embeds,   │
│  engagements, │       │  graph)        │     │  banner embeds,    │
│  finding      │       │                │     │  CVE embeds)       │
│  current)     │       │                │     │                    │
└───────┬───────┘       └────────┬───────┘     └────────────────────┘
        │                        │
        └────────┬───────────────┘
                 ▼
        ┌────────────────┐
        │ ClickHouse     │       Analytics, trend dashboards
        │ (event log     │       Per-customer compliance reports
        │  + analytics)  │
        └────────────────┘
                 │
                 ▼
        ┌────────────────┐
        │ S3 Object Lock │       Audit log, evidence artifacts,
        │ + RFC 3161 TSA │       hash-chained tamper evidence
        └────────────────┘
```

The graph and the event log are the two sources of truth. Postgres is
a fast lookup cache for current state. ClickHouse is the analytics
plane. S3 is the legal-grade audit trail.

---

## 4. The autonomy ladder

We do not ship "AI does everything" on day one. Operators must trust
the system incrementally. Five rungs:

| Rung | Name                | What the AI decides            | What the operator decides         |
|------|---------------------|--------------------------------|-----------------------------------|
| 0    | Assistant           | Nothing — explains findings    | Every action                      |
| 1    | Co-pilot            | Suggests next action            | Approves every action             |
| 2    | Supervised          | Executes READ_ONLY autonomously| Approves ACTIVE; rejects STATE_CHANGE |
| 3    | Bounded autonomous  | Executes READ_ONLY + ACTIVE     | Approves STATE_CHANGE            |
| 4    | Fully autonomous    | Plans + executes full engagement| Sets scope; reviews end report   |

The product ships at rung 1 (where we are today, basically). Customers
opt in to higher rungs per engagement. Rung 4 is gated on insurance,
SOC reports, and at least 12 months of rung-3 data.

Each rung has its own UI affordances, audit requirements, and policy
defaults. **The rung is a contract between the operator and the
product** — not a feature flag.

---

## 5. End-to-end: an autonomous engagement

A concrete walkthrough of what the system does, top to bottom.

### T+0: Engagement starts
- Operator creates engagement with scope `10.0.0.0/16`, rung 2, kill
  switch active
- Control plane provisions a passive sensor → deployed to a SPAN port
- Control plane provisions a worker pool: 4 Firecracker hosts
- Attack graph is created with `:Engagement` root node + scope subgraph

### T+15min: Passive recon (no packets sent)
- Sensor observes 47 hosts via ARP, 23 services via mDNS, internal
  domain `corp.local` via DNS
- Graph fills: `:Host` and `:Service` nodes with `OBSERVED_AT` edges
- Planner runs first iteration: "I have 47 hosts; I have not actively
  probed any. ATT&CK tactic: Reconnaissance. Next technique: T1595
  Active Scanning."
- Planner proposes `reconnaissance.network@1.4.0` skill on a sample of
  10 hosts at stealth=7

### T+15min+5s: Safety envelope
- Cedar: scope check passes
- Risk: READ_ONLY → auto-approve
- HSM signs action token (60s TTL, 10 specific IPs)
- Token streamed to executor

### T+18min: First active scan
- Firecracker VM spawned with egress allowlist of exactly those 10 IPs
- naabu + nmap run; observations stream back
- eBPF captures every syscall; signed + uploaded
- Findings ingested: 6 services with banners
- Graph updates: `:Service` nodes get version data; new `:Finding`
  nodes for two outdated services
- Small-model classifier triages: 1 INFO, 1 HIGH (Apache 2.4.49 path
  traversal — embeddings flag as CVE-2021-41773)

### T+19min: Planner iteration 2
- Planner queries graph: "any HIGH findings with public exploits?"
- Cypher returns the Apache finding
- Planner consults ATT&CK: T1190 Exploit Public-Facing Application
- Planner proposes `initial-access.cve-2021-41773@1.2.0` against that
  single host
- Class: ACTIVE → auto-approve (in scope, non-destructive)
- HSM signs token; executor runs; gets a `/etc/passwd` readback as evidence

### T+19min: Graph update
- New `:Finding` node: CVE-2021-41773 confirmed, evidence hash recorded
- New `:Cred` placeholder: "filesystem read achieved"
- ATT&CK state updates: `:TacticState{name:'Initial Access'}` → REACHED
- Planner sees Initial Access is reached; next tactic is Execution or
  Discovery

### T+25min: Planner proposes credential dump
- Skill `credential-access.lsass-readonly@2.1.0` on the compromised host
- Class: STATE_CHANGE (probes process memory)
- → **Human approval required**
- Notification sent to operator's CLI + web console
- Operator reviews proposal: target, expected outcome, evidence so far
- Operator approves; HSM signs; executor proceeds

### T+40min: Lateral movement chain proposed
- Planner sees harvested creds; runs Cypher shortest-path query against
  graph; identifies a path: compromised host → file server → backup
  server (high-value)
- Proposes 3 chained actions; presents as one approval to operator
- Operator approves; chain executes; new compromises recorded
- ATT&CK state: Lateral Movement → REACHED

### T+2h: Engagement summary
- Planner notices it has not advanced ATT&CK state in 30 min
- Self-evaluates: "remaining unexplored hosts: 12; estimated value:
  low; time spent: 2h; engagement budget: 4h"
- Decides to stop active probing; switches to verification + reporting
- Triggers report generation
- Report includes: graph snapshot, every action taken with token IDs,
  evidence hashes, ATT&CK tactic coverage, business impact summary

### T+2h05m: Operator reviews
- Web console renders attack graph with severity heatmap
- Every node in the report is clickable → drills into evidence
- Every action has a token ID → audit log trail
- Every LLM decision has a span → reasoning trace
- Operator marks 3 findings as false-positive → small model retrained
  weekly with this signal (DP-protected)

---

## 6. Safety architecture (the non-negotiable part)

Five independent kill switches. Any one stops the engagement.

1. **Scope envelope** — HSM-signed scope token; executor rejects any
   action outside; egress allowlist enforces at network layer
2. **Risk classification** — STATE_CHANGE requires human; DESTRUCTIVE
   is always denied; classification is encoded in the Skill manifest
   and verifiable by hash
3. **Token TTL** — every action token expires in 60 seconds; cannot be
   reused or replayed
4. **Behavior anomaly** — eBPF-observed worker behavior is compared
   against per-Skill baseline; deviation triggers immediate VM
   destruction + alert
5. **Operator kill switch** — physical button in the CLI / web console:
   one keypress halts the engagement, signed revocation propagates in
   <1s to all workers

In addition:
- **Dry-run mode** — every proposal can be inspected before approval;
  shows exactly what would happen
- **Replay protection** — every action token has a single-use nonce
- **Continuous attestation** — workers prove every 5s they are running
  the expected eBPF program and Firecracker config

---

## 7. Observability for an AI-driven system

Standard SLO observability isn't enough when the AI is driving. We
need to observe the **reasoning** as a first-class thing.

**Per-decision trace:**
- Input graph state hash + minimal representation
- Prompt used (with prompt registry version)
- LLM input + output tokens + cost
- Decision rationale (the model's stated reasoning)
- Alternative proposals considered and rejected
- Outcome: action taken, observation received
- Operator override (if any)

**Aggregate metrics:**
- `planner_decisions_total{tactic, technique, outcome}`
- `planner_token_cost_usd{tenant, engagement}`
- `planner_overrides_total{tactic}` — measures how often we disagree
  with the AI; rising trend = either the model regressed or we shifted
  our risk tolerance
- `graph_growth_nodes_per_hour{engagement}` — how fast the engagement
  is finding new state
- `safety_envelope_block_total{class, reason}` — every rejection logged
- `evidence_chain_verifications_total{result}` — every audit hash check

**The eval suite runs continuously** — synthetic engagements against
known-vulnerable lab networks, scored on:
- Coverage (ATT&CK techniques attempted)
- Precision (true findings / total findings)
- Stealth (detections by lab EDR)
- Cost (LLM spend per finding)
- Time-to-first-finding

Regression on any of these blocks deployment.

---

## 8. What the CLI becomes

The current CLI is built for a human operator running scans. In the
autonomous world, the CLI is a **viewer + approver + investigator**:

| Command            | Purpose                                              |
|--------------------|------------------------------------------------------|
| `adversa engage`   | Start an engagement at a chosen autonomy rung        |
| `adversa watch`    | Live graph view, ATT&CK progress, approval queue     |
| `adversa approve`  | Approve / reject pending action proposals            |
| `adversa kill`     | Emergency halt                                       |
| `adversa trace`    | Inspect a single decision: prompt, reasoning, outcome|
| `adversa explain`  | Why was finding X classified as CRITICAL?            |
| `adversa replay`   | Re-run a past engagement against a fresh sandbox     |
| `adversa rung`     | Promote / demote engagement autonomy rung mid-flight |

The interactive wizard from v0.5 stays — it is rung-0 / rung-1 mode.
Rung-2+ adds the "approval queue" UI to the wizard.

---

## 9. Roadmap reality check

The previous v2 doc gave 6-10 months for an event-sourced platform with
extracted workers. Adding the autonomous AI loop adds another 8-12
months of *focused* engineering for a senior team. Total honest
estimate: **~18-24 months to ship rung-3 GA.**

Phasing:

| Phase                          | Months | Major deliverables                                       |
|--------------------------------|--------|----------------------------------------------------------|
| v2 foundation (from v2 doc)    | 0-10   | Postgres, Temporal, workers, AI gateway, multi-tenant    |
| Attack graph + MCP planner     | 10-13  | Neo4j integration, MCP servers, rung-1 planner           |
| Skills registry + ATT&CK       | 13-15  | Skill packaging, ATT&CK goal tree, signed skills         |
| Safety envelope + HSM tokens   | 15-17  | Cloud HSM integration, action token signing, kill switch |
| Firecracker + eBPF executor    | 17-20  | Hard sandboxing, evidence chain, TSA integration         |
| Confidential AI gateway        | 20-22  | TEE deployment, attestation, customer-managed enclaves   |
| Small-model fast-path          | 22-23  | On-box classifier, ~95% Claude bypass                    |
| Passive sensor + rung-2 GA     | 23-24  | Sensor product, pilot customers at rung-2                |

Beyond month 24: rung-3, DP-trained cross-tenant model, on-prem
distillation, WASM extensions, RL stealth optimization, CRDT
collaboration, symbolic execution gating.

---

## 10. The hard truths

1. **This is a 2-year vision, not a quarter plan.** Every month between
   here and rung-3 needs a concrete v2-track deliverable shipping.

2. **The hardest engineering is the safety envelope, not the AI.** The
   LLM is easy; making sure it cannot do something catastrophic is the
   real product.

3. **Autonomy is a contract, not a feature.** Customers will not let
   us run rung-3 on their network until they trust the safety story.
   The trust comes from compliance certifications, insurance, and
   public incident-free track record at rung-2. That takes years of
   real deployments, not engineering effort.

4. **The competitive moat is the evaluation corpus.** Anyone can wire
   Claude into a scanner. The thing nobody else has is a benchmark of
   what good pentest decisions look like across hundreds of engagement
   types — and continuous evals that prevent regressions. Treat the
   eval corpus as the most valuable asset in the company.

5. **The right benchmark is not "AI vs human pentester."** It is "human
   pentester with ADVERSA at rung-3 vs human pentester with current
   tools." We are augmenting humans, not replacing them. The metric is
   findings-per-hour-of-human-time, not findings-per-engagement.

6. **Compliance is feature work.** SOC 2 Type II, ISO 27001, FedRAMP
   Moderate — each is 6-12 months of dedicated effort, each gates
   different customer segments. Plan for them as products, not
   afterthoughts.

7. **The model gets better. Plan for that.** Every architectural
   decision should make the next Claude release easier to adopt, not
   harder. Pin to model capabilities (tool use, MCP, vision, code
   execution) — not model versions.

---

## 11. What I'm not designing here

For completeness:
- Web application security testing (this is **network** VAPT)
- Active Directory enumeration specifics — assumed available as Skills
- Mobile / IoT / OT — different threat models, different products
- Compliance frameworks — covered in a sibling doc when one exists
- Pricing / packaging — these architectural choices imply a per-host or
  per-engagement-hour pricing model, but that conversation lives elsewhere

---

## Appendix A — Tech inventory (quick reference)

| Concern                        | Choice                                    |
|--------------------------------|-------------------------------------------|
| AI planner                     | Claude (Opus 4.7 / Sonnet 4.6) via MCP    |
| Tool protocol                  | Model Context Protocol (MCP)              |
| Attack graph                   | Neo4j (Cypher + GDS)                      |
| Vector store                   | Qdrant (bge-large-en-v1.5 embeddings)     |
| Workflow engine                | Temporal                                  |
| Event bus                      | NATS JetStream                            |
| OLTP                           | PostgreSQL 17 + Drizzle                   |
| Analytics                      | ClickHouse                                |
| Audit                          | S3 Object Lock + RFC 3161 TSA             |
| Cache / sessions               | Redis                                     |
| Sandbox                        | Firecracker microVMs                      |
| Worker observation             | eBPF                                      |
| Service identity               | SPIFFE + SPIRE                            |
| Service mesh                   | Istio Ambient                             |
| Edge                           | Envoy                                     |
| Policy                         | Cedar                                     |
| Secrets                        | HashiCorp Vault                           |
| Confidential compute (AI)      | AWS Nitro Enclaves / GCP Conf. VMs        |
| Token signing                  | Cloud HSM (or YubiHSM2 on-prem)           |
| Image signing                  | Sigstore cosign                           |
| Distributed tracing            | OpenTelemetry → Tempo                     |
| Logs                           | structured JSON → Loki                    |
| Metrics                        | Prometheus → Mimir                        |
| Extensions                     | WebAssembly (Wasmtime)                    |
| Cross-tenant learning          | DP-SGD (Opacus)                           |
| On-prem AI                     | Llama-3.1-70B distilled (vLLM)            |
| CRDT collaboration             | Yjs                                       |
| CLI binary (target)            | Go                                        |
| Agent (target)                 | Go                                        |

That's the system. Build it deliberately and most decisions for the
next two years are already made.
