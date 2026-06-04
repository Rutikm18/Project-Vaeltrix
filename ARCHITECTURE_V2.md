# ADVERSA — Target Architecture (v2)

**Authors:** Architecture working draft
**Status:** Proposed — not yet implemented
**Last Updated:** 2026-06-03

> This document supersedes the conceptual model in `ARCHITECTURE.md` and
> describes what ADVERSA should look like when it is mature: a multi-tenant,
> compliance-grade VAPT platform with first-class AI integration. It is
> deliberately opinionated. Every choice has a stated reason and an
> alternative considered.

---

## 0. Executive thesis

ADVERSA today is a clever **single-binary prototype**: Next.js + JSON
files + an in-process scan engine. It works for one operator on one
laptop. It will collapse the day a real customer asks for any of:

- "I need 10 operators sharing the same engagement."
- "Can you scan our 4,500-host data centre overnight?"
- "Show me which AI prompt influenced the report we sent the client."
- "Prove you didn't scan something out of scope."
- "Deploy this in our isolated network."

The right next step is not to patch the prototype. It is to **commit to a
target architecture**, build the seam between today and tomorrow, and
migrate behind feature flags in vertical slices.

The thesis of this document: **ADVERSA is fundamentally an event-sourced
workflow system with an LLM gateway and a sandboxed tool runtime — not
a CRUD app.** Every architectural choice flows from that framing.

---

## 1. Honest critique of the current state

Numbered so we can score each one against the target.

| #  | Current behaviour                                                                | Why it breaks at scale                                                              |
|----|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| 1  | `data/*.json` flat files                                                          | No concurrent writes, no transactions, no indexes, no audit trail                   |
| 2  | OTP store is `Map<string, …>` in process memory                                  | Restart = every operator logged out; no horizontal scaling                          |
| 3  | `runScan()` runs in the Next.js node process                                     | Long scans block the event loop, crash takes the API down with them                 |
| 4  | Findings overwrite previous state on save                                        | No provenance; "who changed status to CLOSED?" is unanswerable                      |
| 5  | LLM calls are inline `await`                                                      | No retries, no rate limiting, no budget caps, no tracing, no cache                  |
| 6  | Single `.env.local` with all secrets including ANTHROPIC key                      | One leak compromises every layer; no rotation; no separation of duty                |
| 7  | Scope check happens once at API boundary                                          | Defense in single depth — an inner bug bypasses scope                               |
| 8  | Auth token is a plain JWT signed with `AUTH_SECRET`                               | No revocation, no rotation, no mTLS for agents, no audience separation              |
| 9  | Same Node process spawns `naabu`, `nmap`, `nuclei`, `testssl`                      | A compromised template / parser RCE escalates straight to the API server            |
| 10 | Dedup keys on (host + cveId) string match                                        | Slightly different titles bypass dedup; no canonical fingerprinting                 |
| 11 | No queue between scan trigger and execution                                      | Lose a scan if the process dies mid-stage; cannot retry idempotently                |
| 12 | No structured logs, no metrics, no traces                                        | First incident is the first time you wish you had them                              |
| 13 | CLI and server share TypeScript code via file-relative imports                   | CLI cannot evolve independently; can't ship binaries; can't support old clients     |
| 14 | "Dashboard" pages and "API" routes live in one Next.js app                       | A UI bug can DoS the API; cannot scale them independently                           |
| 15 | No tenancy boundary                                                              | First multi-customer deployment is a hard reset                                     |

---

## 2. First principles

Five principles that, if obeyed, make almost every detail decide itself.

### P1. **Events, not state**
Every state change is an immutable, timestamped, signed event. The
"current state" of any aggregate (Scan, Finding, Engagement, User) is a
projection of its event stream. State tables are caches — rebuildable
from the log. This is what makes audit, replay, time-travel debugging,
and bidirectional sync with customer SIEMs trivial later.

### P2. **Workflows are durable, not best-effort**
A scan is a state machine that survives process death. It heartbeats,
retries with backoff, resumes from the last completed stage. The
operator never has to ask "is it still running?" — the workflow engine
knows.

### P3. **The LLM is a subsystem, not a function call**
LLM calls are routed through a gateway that handles: budgeting, caching,
prompt versioning, evals, fallback chains, redaction, and per-call
tracing. We treat token spend like compute spend.

### P4. **Defense in depth on scope**
A scope token is verified at three independent layers: control-plane on
job creation, worker on tool dispatch, and (where possible) at the
network layer via egress allowlist. No single bug bypasses scope.

### P5. **Single tenant is a degenerate case of multi-tenant**
Even when there is one customer, the data model carries `tenant_id`,
the auth context carries `tenant_id`, and every query filters on it.
Multi-tenancy bolted on later always leaks.

---

## 3. Target architecture — block diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                    │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │  adversa CLI │    │  Web console │    │  Scan worker / Py agent  │  │
│  │  (Go binary) │    │ (Next.js SPA)│    │  (gRPC, mTLS)            │  │
│  └──────┬───────┘    └──────┬───────┘    └────────────┬─────────────┘  │
│         │ HTTPS+JWT         │ HTTPS+OIDC              │ mTLS+SPIFFE     │
└─────────┼───────────────────┼─────────────────────────┼─────────────────┘
          │                   │                         │
          ▼                   ▼                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              EDGE                                       │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │   API gateway (Envoy)  ·  rate limit  ·  WAF  ·  mTLS terminate │  │
│   └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌────────────────┐         ┌─────────────────┐         ┌────────────────┐
│  Identity svc  │         │  Engagements    │         │  Findings svc  │
│  OIDC+OTP+JWT  │         │  + Scope/Policy │         │  ingest + read │
│  Cedar policy  │         │  (write side)   │         │   (CQRS)       │
└────────┬───────┘         └────────┬────────┘         └────────┬───────┘
         │                          │                           │
         └──────────────┬───────────┴───────────────────────────┘
                        ▼
                ┌──────────────────────┐
                │   Event bus (NATS    │
                │   JetStream)         │
                └──────────┬───────────┘
                           │ DurableSub
       ┌───────────────────┼───────────────────────────────────┐
       ▼                   ▼                                   ▼
┌──────────────┐    ┌────────────────┐                ┌────────────────┐
│ Workflow svc │    │ AI gateway     │                │ Notification   │
│ (Temporal)   │    │ - budget       │                │ email / slack  │
│ - scan SM    │    │ - cache        │                │ webhook        │
│ - heartbeats │    │ - evals        │                │                │
└──────┬───────┘    └────────┬───────┘                └────────────────┘
       │ dispatches          │ calls
       ▼                     ▼
┌──────────────────┐  ┌─────────────────────┐
│ Scan workers     │  │ Claude / Bedrock /  │
│ (Firecracker μVM)│  │ on-prem inference   │
│  - naabu / nmap  │  └─────────────────────┘
│  - nuclei / tssl │
│  - mTLS to ingest│
└──────┬───────────┘
       │ findings stream (gRPC)
       ▼
┌──────────────────────────────────────────────────────────────────┐
│                          DATA PLANE                              │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌───────────┐ │
│  │ PostgreSQL   │ │ ClickHouse   │ │ S3 (object │ │  Redis    │ │
│  │ (OLTP +      │ │ (findings    │ │ lock for   │ │ rate-lim, │ │
│  │  event log)  │ │  analytics)  │ │ audit log) │ │ cache, BG │ │
│  └──────────────┘ └──────────────┘ └────────────┘ └───────────┘ │
└──────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
              ┌────────────────────────────────────────┐
              │  Observability (OpenTelemetry → Tempo  │
              │  + Loki + Mimir; Grafana for views)    │
              └────────────────────────────────────────┘
```

---

## 4. Components

### 4.1 Edge / API gateway

**Choice:** Envoy + a thin ingress (or AWS ALB + Cloud Map in a managed
deployment).

**Why Envoy:** mature mTLS, native rate-limit filter, WAF integration,
gRPC support out of the box. Kong is simpler but its OSS edition lacks
gRPC quality; NGINX is great until you need observability.

**Responsibilities:**
- TLS termination (1.3 only, ECH where supported)
- mTLS for worker / agent traffic (SPIFFE SVID)
- Rate limits per (tenant, route, identity)
- Request signing verification (for replay protection on sensitive calls)
- OpenTelemetry tracing — generates the root span

### 4.2 Identity service

**Choice:** Custom thin layer on top of an OIDC provider (Ory Hydra
self-hosted, or Auth0/Okta in SaaS). Magic-code email login remains
for low-friction onboarding.

**Why split this out:** every other service trusts the identity service's
JWTs. Concentrating auth here lets you add MFA, SSO (SAML), passkeys,
WebAuthn, device binding without touching scan or findings code.

**Tokens:**
- Access token: 5 minutes, audience-scoped (`adversa.api`, `adversa.agent`)
- Refresh token: 30 days, rotation on use, single-use
- Agent tokens: SPIFFE SVID, 24-hour TTL, automatic rotation

**OTP store:** Redis with TTL keys; rate-limit hash by `(email, ip)`.

### 4.3 Engagements & policy service (write side)

Owns scope, tenants, users, and engagement lifecycle. Source of truth
for "is target X in scope for tenant Y, user Z, engagement E?"

**Policy engine:** Cedar (AWS open-source) for authorization.

**Why Cedar over OPA:**
- Cedar is purpose-built for ABAC (Attribute-Based Access Control)
- Static type checking; can analyze policies offline
- Smaller surface area than Rego for our use case
- AWS Verified Permissions integration if we deploy there

**Policy example:**
```cedar
permit (
  principal,
  action == Action::"scan",
  resource is Target
) when {
  principal.tenant == resource.tenant &&
  resource.address in principal.allowedScopes &&
  resource.address !in resource.tenant.forbiddenScopes
};
```

### 4.4 Findings service (CQRS-split)

**Write side:** accepts `FindingObserved` events from workers via mTLS
gRPC. Idempotent — same (tool, host, port, rule_id, evidence_hash)
inserted twice produces one logical finding.

**Read side:** projected into Postgres tables + ClickHouse for analytics.

**Why CQRS here:** finding writes are firehose (nuclei can produce hundreds
per second under load). Reads are dashboards + reports. Different
schemas, different scaling. Keeping them together creates ugly trade-offs.

**Schema sketch (Postgres):**
```sql
create table finding_events (
  event_id      uuid primary key,
  finding_id    uuid not null,
  tenant_id    uuid not null,
  scan_id       uuid not null,
  engagement_id uuid,
  event_type    text not null, -- 'observed' | 'verified' | 'status_changed' | 'merged'
  payload       jsonb not null,
  occurred_at   timestamptz not null,
  recorded_at   timestamptz not null default now(),
  causation_id  uuid, -- the event that caused this
  correlation_id uuid -- trace_id from the scan
);

create index finding_events_finding_id_idx on finding_events (finding_id, occurred_at);
create index finding_events_tenant_scan_idx on finding_events (tenant_id, scan_id);
```

The `findings_current` table is a **projection**, rebuildable by replaying
events. Status changes don't UPDATE — they APPEND a new event and the
projection re-derives.

### 4.5 Workflow service (Temporal)

**Choice:** Temporal.

**Why Temporal over BullMQ / SQS / homegrown:**
- Scans are state machines, not jobs. They have stages, can pause, can
  branch, can require approvals (think exploit confirmation).
- Determinism guarantees → exactly-once semantics for side effects.
- Built-in heartbeating, retries, exponential backoff with jitter.
- Activity workers run anywhere — including on-prem in customer networks.
- Replay debugging in production is unique to this class of system.

**A scan as a Temporal workflow:**
```typescript
async function scanWorkflow(input: ScanInput): Promise<ScanResult> {
  await activity.verifyScopeAtControlPlane(input);          // 5s timeout
  await activity.emitEvent({ type: 'ScanStarted', ...input });

  const hosts = await activity.runNaabu(input, {
    startToCloseTimeout: '15m',
    heartbeatTimeout:    '30s',
    retry: { maximumAttempts: 2 },
  });

  await activity.runNmap(hosts, { startToCloseTimeout: '30m' });

  // Fan-out
  const [nuclei, testssl] = await Promise.all([
    activity.runNuclei(hosts,  { ... }),
    activity.runTestssl(hosts, { ... }),
  ]);

  const triaged = await activity.aiTriage([...nuclei, ...testssl]);
  await activity.persistFindings(triaged);

  await activity.emitEvent({ type: 'ScanCompleted', ... });
  return summarise(triaged);
}
```

The workflow code is the source of truth for scan behaviour. The
"engine" disappears as a concept — it becomes a set of activities.

### 4.6 Scan workers (Firecracker microVMs)

This is the most security-critical component.

**Hard requirement:** an RCE in a nuclei template or an XML parser
**must not** reach the control plane or another tenant's data.

**Design:**
- One Firecracker microVM per tool execution. Spawned, runs, destroyed.
- Read-only root filesystem; `/tmp` is the only writable mount.
- Egress allowlist enforced by host iptables: only the targets in the
  signed scope token are reachable.
- mTLS gRPC connection back to the control plane is the only outbound
  channel that isn't a scan target.
- Resource caps via cgroups: CPU, memory, PIDs, disk.
- Findings streamed back as they happen — no buffering of state inside
  the VM.

**Alternative considered:** nsjail / Docker user namespaces. Rejected
because shared kernel surface is the dominant CVE class for scanner
sandbox escapes (CVE-2019-5736, CVE-2022-0492, etc.). Firecracker
provides a separate kernel per execution. Cold-start is ~150ms.

### 4.7 AI gateway

The single chokepoint for every LLM call in the system.

**Capabilities:**

1. **Budgeting** — every tenant has a token budget (monthly + per-engagement).
   Calls beyond budget either fall back to cheaper model or fail closed
   based on tenant policy.

2. **Caching** — prompt SHA256 + model + temperature → response.
   Triage prompts are nearly identical across scans; cache hit ratio
   above 30% in steady state is realistic.

3. **Prompt registry** — prompts are versioned artifacts with eval
   coverage. `triage.v3.2` is pinned per engagement and shipped through
   the same release process as code.

4. **Eval harness** — golden inputs run in CI on every prompt change.
   No prompt ships without passing the eval suite (precision/recall on
   finding triage, false-positive rate, hallucination check).

5. **Redaction** — PII / secrets stripped from prompts before send;
   responses scanned for credential leaks before return.

6. **Tracing** — every call gets a span carrying:
   `tenant_id, engagement_id, prompt_id, prompt_version, input_tokens,
   output_tokens, latency_ms, cost_usd, cache_hit, model`.

7. **Fallback chain** — Opus → Sonnet → Haiku → cached canned response.
   Per-tenant policy decides whether budget exhaustion fails closed or
   degrades.

**Provider abstraction:** Anthropic (first-party API, Bedrock, Vertex),
local inference (vLLM) for on-prem. Same gateway interface for all.

**Why this is non-negotiable:** the alternative — every service calling
Anthropic directly — produces an unobservable, uncontrollable spend
surface and makes prompt iteration require a code deploy. The gateway
is the AI equivalent of "every DB query goes through one ORM."

### 4.8 Event bus

**Choice:** NATS JetStream.

**Why over Kafka:** JetStream gives durable, ordered, persistent streams
with at-least-once delivery at a fraction of Kafka's operational
weight. Single binary, no ZooKeeper / KRaft to operate. For our event
volume (thousands of events/sec at peak, not millions), Kafka is
over-provisioned.

**Why over RabbitMQ:** we want ordered, replayable streams (so a new
service can rebuild its projection from genesis). RabbitMQ's classic
queues don't model this naturally.

**Topics:**
- `tenant.{id}.scan.*` — ScanStarted, ScanStageCompleted, ScanCompleted
- `tenant.{id}.finding.*` — FindingObserved, FindingVerified, FindingStatusChanged
- `tenant.{id}.audit.*` — every privileged action
- `tenant.{id}.ai.*` — every LLM call summary (for cost dashboards)

---

## 5. Data plane

### 5.1 PostgreSQL — system of record

- Aurora-compatible deployment in cloud, vanilla PG 17 elsewhere
- Logical replication to read replicas in each AZ
- Synchronous commit to one standby for RPO=0
- pgbouncer in front for connection pooling

**Schema strategy:**
- Multi-tenant via `tenant_id` column on every row + RLS policies
- Row-level security (RLS) enforced — the database refuses cross-tenant
  reads even if the app layer has a bug
- Schema migrations via `drizzle-kit` (preferred over Prisma — smaller,
  more transparent SQL output)

### 5.2 ClickHouse — analytics

- Findings replicated from Postgres via Debezium → Kafka → ClickHouse
- Dashboards, trend analysis, SLA breach reporting
- Customer-facing "compliance" views

**Why this exists:** counting open CRITICAL findings across 500
engagements over 90 days is a 5ms query in ClickHouse and a 5s query
in Postgres. Different read patterns, different stores.

### 5.3 S3 + Object Lock — audit log

- Append-only audit log written in compliance-grade format (CADF or
  custom JSON Lines)
- Object Lock in compliance mode → not deletable for the retention
  period, even by root
- Hash chain across audit entries (each entry includes hash of previous)
  so tampering is detectable even without Object Lock

**What lives here:** every authorization decision, every scope check,
every LLM call summary, every status change to a finding.

### 5.4 Redis

- Rate limit token buckets
- Idempotency cache (24h TTL)
- OTP store
- Session blacklist (for revocation)
- Distributed locks for one-off jobs

**No business state.** Redis is volatile by design here.

---

## 6. Cross-cutting

### 6.1 Authorization model

Three independent layers — any one failing closed protects the system.

**Layer 1: edge.** API gateway checks JWT validity, rate limit, replay
window.

**Layer 2: control plane.** Each service evaluates Cedar policy against
the request (action, principal attrs, resource attrs). Decision logged.

**Layer 3: data plane.** Postgres RLS policies enforce `tenant_id`
isolation. A SQL bug cannot cross tenants.

Workers add a fourth layer for scope: the signed scope token is
re-verified at activity dispatch, and the egress allowlist on the
sandbox enforces it at the network layer.

### 6.2 Observability

**Traces:** OpenTelemetry. Every CLI command opens a root span; it
propagates through API → workflow → activity → worker → LLM call. A
single trace ID lets you see "this scan, all of it, end to end."

**Logs:** Structured JSON, OTel correlation IDs. Loki for storage,
Grafana for query. No `console.log`.

**Metrics:** Prometheus model, Mimir for storage. Golden signals plus
domain metrics:
- `scan_started_total{profile, tenant}`
- `scan_duration_seconds{profile, stage}` (histogram)
- `finding_ingested_total{severity, source, tenant}`
- `llm_tokens_total{model, prompt_id, tenant}`
- `llm_cost_usd_total{model, tenant}`
- `scope_check_total{decision, layer}`
- `otp_attempt_total{result}`

**SLOs:**
| Service           | SLI                                | Target                |
|-------------------|------------------------------------|-----------------------|
| Auth              | p99 latency `/verify`              | < 200ms               |
| Findings ingest   | p99 latency `/ingest`              | < 100ms               |
| Scan dispatch     | time from `start` → first stage    | < 5s                  |
| LLM gateway       | p50, p99                           | < 3s, < 30s           |
| Availability      | successful API requests / total     | 99.9% rolling 30d     |

Error budget burn alerts at 2x and 10x.

### 6.3 Security baseline

- Secrets: HashiCorp Vault (dynamic DB creds, short-TTL API keys, KMS)
- mTLS service-to-service: SPIFFE/SPIRE for SVIDs
- Container images: signed with Sigstore cosign; admission controller
  refuses unsigned images
- SBOM generated per image, scanned for CVEs in CI
- Network policies: default-deny pod-to-pod, explicit allow per service
- Scanner sandbox: Firecracker, read-only rootfs, egress allowlist
- Audit log: S3 Object Lock + hash chain
- Vulnerability disclosure program + bug bounty before GA

### 6.4 Deployment topologies

ADVERSA must support three deployment modes:

1. **SaaS multi-tenant** — our managed service.
2. **Single-tenant cloud** — customer's AWS/GCP, our control plane.
3. **On-prem / air-gapped** — runs entirely in the customer's network,
   no outbound calls, optional manual update channel. AI is replaced
   by local inference (vLLM with a small model) or disabled.

The same code runs in all three; only the deployment artefact (Helm
chart values) differs. This requires the architecture to assume the
network can be hostile and limited from day one.

---

## 7. CLI design (revisited)

The CLI is a **client**, not a code-sharing peer. Today it imports from
`lib/engine`; tomorrow it speaks gRPC.

**Why this matters:** in the target system, the CLI must support old
control-plane versions for at least one major release. Sharing TypeScript
imports makes that impossible.

**Choice for binary:** rewrite the CLI in **Go** once the API stabilises.

**Why Go for CLI:**
- Single static binary; no Node version dance on operator workstations
- Native gRPC, faster startup than tsx
- Built-in cross-compilation for win/linux/mac
- Same language used by the Python agent's replacement (see §8)

Until then, the TypeScript CLI stays — it just stops importing
`lib/engine` directly and talks to the API like any other client.

---

## 8. Python agent (revisited)

Today's `agent/` is a Python long-poller. Fine for v0. The target
agent:

- Rewritten in **Go** for distribution as a single binary
- Communicates via **gRPC bidirectional streams** (not long polling)
- Identity via SPIFFE SVID issued by the control plane at registration
- Runs each tool in a local Firecracker microVM (or nsjail if running
  on a customer VM without nested virt)
- Streams findings as they're produced — no result buffer required
- Self-updates via signed artefact + canary rollout

Long-polling is fine when there are 10 agents. It collapses at 1000.
gRPC streams are the obvious answer.

---

## 9. Migration roadmap

This is honest. No big-bang rewrites; each phase ships behind feature
flags with the legacy path still working until cutover.

### Phase 0 — Stabilise (1–2 weeks)
- Add structured logging (pino) and OpenTelemetry SDK to existing code
- Wrap every API handler in a request span
- Add `tenant_id` column to every JSON file's records (even if it's
  always the same value) — set up the seam for §10 multi-tenancy

### Phase 1 — PostgreSQL foundation (2–3 weeks)
- Stand up Postgres + drizzle + migrations
- Mirror JSON stores into tables; dual-write behind a flag
- Add idempotency keys to every mutation
- Cut reads over; keep dual-writes for one release
- Drop the JSON stores

### Phase 2 — Workflow durability (3–4 weeks)
- Introduce Temporal alongside Next.js
- Move `runScan` into a workflow + activities
- Activities still run in-process for now
- API simply triggers the workflow
- Crash recovery now works end-to-end

### Phase 3 — Workers extracted (4–6 weeks)
- Containerised activity worker
- Tool execution moves into the worker
- mTLS gRPC between worker and API
- Egress allowlist enforced (iptables in container; Firecracker comes later)
- Now the API can't be crashed by scan tools

### Phase 4 — AI gateway (2–3 weeks)
- All Claude calls routed through a new gateway service
- Prompt registry + versioning
- Caching, budgeting, tracing
- Eval harness in CI

### Phase 5 — Decomposition (6–8 weeks)
- Auth → its own service
- Findings ingest → its own service
- NATS JetStream introduced for events
- Each service migrated behind a feature flag

### Phase 6 — Production hardening (4–6 weeks)
- Firecracker sandboxing for tool runs
- SPIFFE/SPIRE for service identity
- Audit log to S3 Object Lock
- ClickHouse for analytics
- SLO dashboards and alerting

### Phase 7 — Multi-tenant GA (4 weeks)
- RLS policies on every table
- Tenant-aware rate limits
- Cedar policy migration
- First customer in pilot

**Total honest estimate:** 6–10 months of focused engineering for a
team of three. Not three weeks. The schedule is the architecture.

---

## 10. Open questions / tradeoffs

These are the calls I deliberately did not make, because they depend on
context I don't have. They are the next conversations to have.

1. **Inference for AI on-prem deployments.** vLLM with Llama-3.1-70B is
   plausible but quality on triage/report tasks needs evaluation. Could
   force the on-prem product into "AI optional" until a smaller model
   matches Claude on the eval suite.

2. **Temporal vs Inngest.** Inngest is a smaller operational burden and
   serverless-friendly; Temporal is the industry standard. Pick Inngest
   if we stay on a managed cloud, Temporal if on-prem matters.

3. **NATS vs Kafka.** I picked NATS for ops simplicity. If the customer
   roadmap involves SIEM exports / stream processing pipelines, Kafka's
   ecosystem (Connect, Streams) wins.

4. **Cedar vs OPA.** Cedar is tighter for ABAC; OPA is more flexible
   and has wider community adoption. If we need policies that aren't
   strictly access decisions (e.g. "compute compliance score"), OPA wins.

5. **Build CLI in Go now vs later.** The TS CLI works today. Rewriting
   it costs 2–3 weeks. Worth it once we have customers running scripts
   against it; not worth it before then.

6. **Multi-region.** Out of scope for v1; document the assumption that
   the system is single-region and pin every contract that would break
   under multi-region (clock skew, eventual consistency, cross-region
   replication of audit log).

7. **Customer-managed encryption keys (CMEK).** Enterprise table stakes
   for SOC2 high. Plan the data model with envelope encryption from
   day one — even if we hardcode the KMS key initially — so CMEK is a
   config change, not a migration.

---

## 11. What this document is not

- It is not a sprint plan. The phases are deliberately coarse.
- It is not a tool inventory. Specific versions belong in a SBOM, not here.
- It is not a hiring plan, though the gap between current and target
  implies one.
- It is not a defence of the current code. The current code is fine for
  what it is — a working prototype. The point is to know what we're
  building toward.

The job of an architect is to make the next decision cheaper. Every
choice here is meant to make the *next* problem easier, not the
current one prettier.
