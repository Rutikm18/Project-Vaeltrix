 ---
  1. Spin up a UAT environment
  
  The fastest path is the full Docker Compose stack:

  cd adversa
  cp infrastructure/.env.example infrastructure/.env
  # Set ANTHROPIC_API_KEY, change all *_PASSWORD values

  docker compose -f infrastructure/docker-compose.full.yml up -d

  # Watch until all services are healthy (~90s)
  docker compose -f infrastructure/docker-compose.full.yml ps

  Expected output — all services should show healthy or running:

  adversa-api       running (healthy)
  adversa-worker    running
  adversa-agent-corp running
  adversa-agent-dmz  running
  adversa-agent-cloud running
  adversa-postgres  running (healthy)
  adversa-redis     running (healthy)
  adversa-neo4j     running (healthy)
  adversa-kafka     running
  adversa-vault     running (healthy)
  adversa-minio     running (healthy)

  ---
  2. Smoke test every module — ordered by dependency
  
  Run these in sequence. Each one validates a distinct Prompt's implementation.

  Module 1 — Platform is up

  curl -sf http://localhost:3000/ && echo "PASS: UI"
  curl -sf http://localhost:3000/api/engagements && echo "PASS: Engagements API"

  Module 2 — Agent registration + heartbeat

  # Register a test agent
  curl -s -X POST http://localhost:3000/api/agents/register \
    -H "Content-Type: application/json" \
    -d '{"agentName":"uat-agent","location":"UAT 
  Lab","capabilities":["discovery","vuln_scan"],"networkSegments":["10.0.0.0/8"]}' \
    | python3 -m json.tool

  # Should return agentId + vaultRoleToken + tlsCert
  # Copy the agentId from the response

  AGENT_ID=<paste_id_here>

  # Send a heartbeat
  curl -s -X POST http://localhost:3000/api/agents/$AGENT_ID/heartbeat \
    | python3 -m json.tool
  # Expect: {"status":"ok","agentStatus":"ONLINE","pendingJobAvailable":false}

  Module 3 — Scan job lifecycle

  # Poll for pending jobs
  curl -s http://localhost:3000/api/agents/AGT-001/jobs | python3 -m json.tool

  # Report progress on JOB-001
  curl -s -X POST http://localhost:3000/api/agents/AGT-001/jobs/JOB-001/progress \
    -H "Content-Type: application/json" \
    -d '{"progress":50}' | python3 -m json.tool

  # Submit result
  curl -s -X POST http://localhost:3000/api/agents/AGT-001/jobs/JOB-001/result \
    -H "Content-Type: application/json" \
    -d '{"result":{"assetsFound":24},"success":true}' | python3 -m json.tool
  # Expect: {"jobId":"JOB-001","status":"COMPLETED"}

  Module 4 — Exploit engine safety gates

  # Should be BLOCKED (out of scope)
  curl -s -X POST http://localhost:3000/api/exploit \
    -H "Content-Type: application/json" \
    -d '{"target":"8.8.8.8","cveId":"CVE-2021-44228","modulePath":"cves/2021/CVE-2021-44228.yaml","payloadType":"dns_callback
  ","blastRadius":5}' \
    | python3 -m json.tool
  # Expect: {"error":"OUT_OF_SCOPE"}

  # Should be BLOCKED (meterpreter is forbidden)
  curl -s -X POST http://localhost:3000/api/exploit \
    -H "Content-Type: application/json" \
    -d '{"target":"10.0.1.10","cveId":"CVE-2021-44228","modulePath":"test","payloadType":"meterpreter","blastRadius":5}' \
    | python3 -m json.tool
  # Expect: {"error":"SAFETY_VIOLATION"}

  # Should SUCCEED (in-scope, safe payload)
  curl -s -X POST http://localhost:3000/api/exploit \
    -H "Content-Type: application/json" \
    -d '{"target":"10.0.1.10","cveId":"CVE-2021-44228","modulePath":"cves/2021/CVE-2021-44228.yaml","payloadType":"dns_callba
  ck","blastRadius":5}' \
    | python3 -m json.tool
  # Expect: {"status":"completed","result":{"success":true|false,...}}

  Module 5 — Attack graph API

  curl -s http://localhost:3000/api/engagements/ENG-001/attack-graph | python3 -m json.tool | head -30
  curl -s http://localhost:3000/api/engagements/ENG-001/attack-paths | python3 -m json.tool
  curl -s http://localhost:3000/api/engagements/ENG-001/chokepoints | python3 -m json.tool
  curl -s http://localhost:3000/api/engagements/ENG-001/blast-radius/ws-042 | python3 -m json.tool

  Module 6 — Detection correlation

  # Run correlation job
  curl -s -X POST http://localhost:3000/api/engagements/ENG-001/detection-validation/run \
    | python3 -m json.tool
  # Expect: {"jobId":"...","status":"completed"}

  # Check coverage
  curl -s http://localhost:3000/api/engagements/ENG-001/detection-validation/coverage \
    | python3 -m json.tool
  # Expect: {"coverage":{"coveragePct":53,"detected":3,"prevented":1,"missed":4}}

  # Get gaps with Sigma rules
  curl -s http://localhost:3000/api/engagements/ENG-001/detection-validation/gaps \
    | python3 -m json.tool | head -40

  Module 7 — AI engine

  # Risk scoring
  curl -s http://localhost:3000/api/engagements/ENG-001/vuln-prioritizer \
    | python3 -m json.tool | head -40
  # Expect: ranked findings with score 0-1000 + SHAP breakdown

  # Generate report (simulated if no API key)
  curl -s -X POST http://localhost:3000/api/engagements/ENG-001/ai-report/generate \
    -H "Content-Type: application/json" \
    -d '{"sections":["executive_summary","remediation"]}' \
    | python3 -m json.tool
  # Expect: {"jobId":"...","status":"completed"}

  # Get draft
  curl -s http://localhost:3000/api/engagements/ENG-001/ai-report/draft \
    | python3 -m json.tool | head -30

  Module 8 — Kafka topics

  curl -s http://localhost:3000/api/kafka/topics | python3 -m json.tool
  # Expect: 5 topics (scan-jobs, scan-results, findings, alerts, audit-events)
  # All lag values should be 0 or near-0

  ---
  3. UI walkthrough checklist

  Open http://localhost:3000 and verify each page manually:

  ┌──────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────┐
  │         Page         │                                         What to check                                          │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ / Dashboard          │ Recharts line chart loads, donut chart shows severity breakdown, activity feed populates,      │
  │                      │ metric cards show correct numbers                                                              │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /engagements         │ Table shows 3 engagements, click NEW ENGAGEMENT → 4-step modal works, all steps validate,      │
  │                      │ submit creates a new row                                                                       │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /engagements/ENG-001 │ All 6 tabs clickable, Overview shows metrics + activity feed                                   │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /scan                │ Enter 10.0.1.0/24, select Standard scan, click RUN → output streams, no JS errors              │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /exploit             │ Enter 10.0.1.50 → scope badge shows IN SCOPE, select Log4Shell, click EXECUTE → job appears in │
  │                      │  EXPLOIT JOBS tab with result                                                                  │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /exploit high-risk   │ Enter 10.0.0.10 (DC) → badge shows DC/HIGH-RISK, SUBMIT FOR APPROVAL → appears in APPROVALS    │
  │                      │ tab → approve → job runs                                                                       │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /active-directory    │ All 6 tabs load, BloodHound tab shows LOAD button, clicking it fetches DA paths                │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /attack-graph        │ SVG graph renders, path selection highlights edges, chokepoints glow, BLAST RADIUS tab: enter  │
  │                      │ ws-042, COMPUTE returns reachable nodes                                                        │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /detection           │ Click RUN CORRELATION → results appear, GAPS & SIGMA tab shows Sigma YAML, SIEM CONFIG form    │
  │                      │ saves                                                                                          │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /ai-report           │ Risk Scoring tab shows 8 findings ranked by score, expand one to see SHAP bars, REPORT         │
  │                      │ GENERATOR: select sections, click GENERATE, DRAFT REVIEW tab shows outputs                     │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /agents              │ 3 agents listed with heartbeat age, expand one to see mTLS command, KAFKA TOPICS tab shows 5   │
  │                      │ topics with lag badges                                                                         │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /findings            │ Filter by CRITICAL, sort by CVSS, expand a finding to see remediation steps                    │
  ├──────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /reports             │ Print page → verify sidebar/buttons are hidden, findings print correctly                       │
  └──────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  4. Key metrics to check

  Reliability

  ┌──────────────────────────┬────────────────────────────────────────────────────────┬──────────────────────────────────┐
  │          Metric          │                     Where to check                     │          Pass threshold          │
  ├──────────────────────────┼────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ All 13 Docker services   │ docker compose ps                                      │ 100% healthy                     │
  │ healthy                  │                                                        │                                  │
  ├──────────────────────────┼────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ API cold start time      │ curl -w "%{time_total}"                                │ < 200ms                          │
  │                          │ http://localhost:3000/api/engagements                  │                                  │
  ├──────────────────────────┼────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Exploit job round-trip   │ Time from POST to completed result                     │ < 3s (includes 0.4–1.9s          │
  │                          │                                                        │ simulated delay)                 │
  ├──────────────────────────┼────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Detection correlation    │ Time for POST /run to return completed                 │ < 500ms                          │
  │ job                      │                                                        │                                  │
  ├──────────────────────────┼────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ AI report generation     │ POST /generate with 3 sections                         │ < 5s (simulated); < 30s (live    │
  │                          │                                                        │ Anthropic)                       │
  ├──────────────────────────┼────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ BloodHound DA path load  │ GET /api/ad/bloodhound                                 │ < 300ms                          │
  └──────────────────────────┴────────────────────────────────────────────────────────┴──────────────────────────────────┘

  Safety gates (must all pass)

  # Run all safety checks in one script
  python3 - <<'EOF'
  import urllib.request, json, sys

  base = "http://localhost:3000"
  checks = [
      ("OUT_OF_SCOPE blocked",     "POST", "/api/exploit",
       {"target":"8.8.8.8","cveId":"X","modulePath":"cves/x.yaml","payloadType":"dns_callback","blastRadius":1},
       lambda r: r.get("error") == "OUT_OF_SCOPE"),
      ("METERPRETER blocked",      "POST", "/api/exploit",
       {"target":"10.0.1.10","cveId":"X","modulePath":"m","payloadType":"meterpreter","blastRadius":1},
       lambda r: r.get("error") == "SAFETY_VIOLATION"),
      ("Blast radius enforced",    "POST", "/api/exploit",
       {"target":"10.0.1.10","cveId":"X","modulePath":"cves/x.yaml","payloadType":"dns_callback","blastRadius":99},
       lambda r: r.get("error") == "BLAST_RADIUS_EXCEEDED"),
      ("Unsafe template blocked",  "POST", "/api/exploit",
       {"target":"10.0.1.10","cveId":"X","modulePath":"exploits/rm-rf.yaml","payloadType":"dns_callback","blastRadius":1},
       lambda r: r.get("error") == "UNSAFE_TEMPLATE"),
  ]

  all_pass = True
  for name, method, path, body, check in checks:
      req = urllib.request.Request(f"{base}{path}",
          data=json.dumps(body).encode(), method=method,
          headers={"Content-Type":"application/json"})
      try:
          resp = urllib.request.urlopen(req)
      except urllib.error.HTTPError as e:
          resp = e
      result = json.loads(resp.read())
      ok = check(result)
      print(f"{'PASS' if ok else 'FAIL'}: {name} → {result.get('error','?')}")
      if not ok: all_pass = False

  sys.exit(0 if all_pass else 1)
  EOF

  Expected output:
  PASS: OUT_OF_SCOPE blocked → OUT_OF_SCOPE
  PASS: METERPRETER blocked → SAFETY_VIOLATION
  PASS: Blast radius enforced → BLAST_RADIUS_EXCEEDED
  PASS: Unsafe template blocked → UNSAFE_TEMPLATE

  Performance under load

  # Install if needed: brew install hey
  # 50 concurrent users, 200 requests on the engagements API
  hey -n 200 -c 50 http://localhost:3000/api/engagements

  # What to look for in the output:
  # Status code distribution: 100% [200]
  # 99th percentile response time: < 500ms
  # Requests/sec: > 100

  # Healthy baselines:
  # adversa-api:     CPU < 10%, MEM < 512MB
  # adversa-postgres: CPU < 5%,  MEM < 256MB
  # adversa-kafka:    CPU < 15%, MEM < 1GB
  # adversa-neo4j:    CPU < 5%,  MEM < 512MB

  ---
  5. What to fix before promoting to production

  These gaps exist because the platform uses in-memory stores (no real DB):

  ┌───────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────┐
  │              Gap              │                                 Production fix                                  │
  ├───────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┤
  │ Data resets on server restart │ Wire lib/*-store.ts to PostgreSQL via Prisma or Drizzle                         │
  ├───────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┤
  │ Agent mTLS is simulated       │ Integrate HashiCorp Vault PKI secrets engine for real cert issuance             │
  ├───────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┤
  │ Kafka is mocked in the API    │ Connect to real Kafka in Docker Compose stack; publish on job create            │
  ├───────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┤
  │ ANTHROPIC_API_KEY not set     │ Add to .env, verify /ai-report Generate button produces live output             │
  ├───────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┤
  │ No auth/session               │ Add NextAuth.js with role-based access (analyst vs. manager for approve/reject) │
  ├───────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────┤
  │ No rate limiting              │ Add next-rate-limit or API Gateway in front                                     │
  └───────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────┘
