Prompt 2 — Network discovery engine
Build a network discovery and fingerprinting engine for an automated VAPT platform.

Tech stack: Python, asyncio, python-nmap, Scapy, Redis (for job state), PostgreSQL.

Build the following:


1. DiscoveryWorker class that:
   - Accepts a ScanJob from a Redis queue (job_id, target_cidrs, excluded_cidrs, scan_profile ENUM[fast,standard,deep])
   - Runs Nmap with appropriate flags per profile:
     - fast: -sn -T4 (ping sweep only)
     - standard: -sV -sC -T3 --top-ports 1000
     - deep: -sV -sC -A -T3 -p- with OS detection
   - Parses Nmap XML output into structured Asset + Service objects
   - Performs banner grabbing on discovered open ports using asyncio socket connections
   - Saves discovered assets and services to PostgreSQL via SQLAlchemy
   - Updates ScanJob status (running → completed/failed) with progress %

2. ServiceIdentifier class that:
   - Takes raw banner strings and port numbers
   - Returns structured dict: {service, version, product, cpe, confidence_score}
   - Handles: HTTP/HTTPS, SSH, SMB, FTP, SMTP, RDP, SNMP, LDAP, Kerberos, MSSQL, MySQL, Redis

3. RateLimiter utility that:
   - Enforces max PPS (packets per second) per target CIDR
   - Enforces time-window restrictions (e.g. business hours only)
   - Reads limits from engagement RoE config

4. Agent registration API (FastAPI):
   - POST /agents/register — agent self-registers with platform, gets JWT
   - POST /agents/heartbeat — agent sends health ping every 30s
   - GET /agents/{id}/jobs — agent polls for pending jobs
   - POST /agents/{id}/jobs/{job_id}/result — agent submits job result

Include: error handling, scan cancellation support, deduplication of assets by IP+hostname, and unit tests for the XML parser and service identifier.

Prompt 3 — Vulnerability scanner integration
Build the vulnerability assessment module for an automated VAPT platform.

Tech stack: Python, FastAPI, Tenable Nessus REST API (or OpenVAS GMP), Nuclei CLI wrapper, PostgreSQL.

Build the following:

1. NessusScanner class:
   - authenticate(url, access_key, secret_key) → stores session
   - create_scan(engagement_id, target_ips, policy_id, credentials) → returns scan_id
   - launch_scan(scan_id) → starts scan
   - poll_status(scan_id) → returns {status, progress_percent}
   - get_results(scan_id) → returns list of raw findings
   - map_finding(raw) → returns Finding schema with CVE IDs, CVSS, description, plugin_id
   - export_nessus_file(scan_id) → download .nessus XML for evidence storage

2. NucleiScanner class:
   - run_scan(targets: list[str], templates: list[str], rate_limit: int) → async subprocess
   - parse_output(jsonl_output) → list of Finding objects
   - template_selector(asset_services) → returns relevant template tags (e.g. ["cves", "misconfigs", "ssl", "default-logins"])

3. VulnEnrichmentService class:
   - enrich(finding: Finding) → enriched Finding
   - fetch_nvd(cve_id) → {cvss_v3, description, references, published_date}
   - fetch_epss(cve_id) → {epss_score, percentile}
   - check_cisa_kev(cve_id) → bool (is it on KEV catalog?)
   - fetch_mitre_techniques(cve_id) → list[str] (ATT&CK technique IDs)
   - compute_composite_risk(finding, asset_criticality) → float (0-1000 scale)
     Formula: (cvss*0.25 + epss*0.20 + kev_bonus*0.20 + exploit_validated*0.15 + asset_crit*0.10 + path_depth*0.05 + lateral_impact*0.05) * 100

4. Background task:
   - After each scan completes, auto-trigger enrichment for all new findings
   - Deduplicate findings by (asset_id, cve_id, plugin_id) hash
   - Send webhook to notification service when critical findings are found

Include unit tests mocking the external API calls.

Prompt 4 — Exploitation engine (safe, non-destructive)
Build a safe exploit validation engine for an automated VAPT platform.

Tech stack: Python, Metasploit RPC API (msfrpcd), asyncio, PostgreSQL.

SAFETY REQUIREMENTS (enforce in code, not just docs):
- All payloads must be non-destructive. Only allowed payload types: cmd/unix/generic, windows/x64/exec with command="whoami", dns callback probes, HTTP callback probes. Never: meterpreter, reverse shells, file encryptors, DoS modules.
- Each exploit job must have a blast_radius_limit (max hosts per job, default 5)
- High-risk targets (domain controllers, critical assets) require human_approval_required=True
- All exploit attempts logged with full audit trail (who triggered, when, payload used, result)
- Scope enforcement: target IP must be in engagement.scope_cidrs and NOT in excluded_cidrs

Build the following:

1. MetasploitRPCClient class:
   - connect(host, port, password) → authenticated session
   - list_modules(module_type) → available exploits/auxiliaries
   - run_module(module_path, options: dict) → job_id
   - get_job_status(job_id) → {status, output}
   - kill_job(job_id)

2. ExploitOrchestrator class:
   - select_exploit(finding: Finding) → returns best Metasploit module path based on CVE/service
   - validate_safety(exploit_path, target) → raises SafetyViolationError if unsafe payload
   - validate_scope(target_ip, engagement) → raises OutOfScopeError if not in scope
   - execute(finding, engagement) → ExploitResult {success, output, evidence_artifact}
   - generate_dns_callback_token(finding_id) → unique FQDN for out-of-band confirmation

3. NucleiExploitRunner class (for CVE PoC templates):
   - run_cve_poc(cve_id, target) → {vulnerable: bool, evidence: str}
   - safe_template_check(template_path) → validates template has no write/delete actions

4. ExploitResult model:
   - finding_id, target_ip, module_used, payload_used, success: bool
   - evidence: {stdout_snippet, dns_callback_received, http_callback_received}
   - executed_by, executed_at, engagement_id
   - Saved to PostgreSQL and S3/MinIO as evidence artifact

5. Human approval workflow:
   - When human_approval_required=True, create ExploitApprovalRequest record
   - POST /exploit-approvals/{id}/approve — manager approves
   - POST /exploit-approvals/{id}/reject — manager rejects with reason
   - Approved requests auto-queue exploit job

Include comprehensive error handling, audit logging for every action, and integration tests against a Metasploitable lab target.

Prompt 5 — Active Directory assessment module
Build the Active Directory assessment module for an automated VAPT platform.

Tech stack: Python, Impacket, ldap3, BloodHound Python collector, PostgreSQL.

Build the following:

1. LDAPEnumerator class:
   - connect(dc_ip, domain, username, password, use_kerberos=False)
   - get_users() → list of ADUser {samaccountname, sid, memberof, spn, no_preauth, admin_count}
   - get_computers() → list of ADComputer {hostname, os, ip, is_dc}
   - get_groups() → list of ADGroup {name, members, is_privileged}
   - check_anonymous_bind(dc_ip) → bool
   - get_aces(object_dn) → list of ACE objects for ACL abuse detection

2. KerberoastChecker class:
   - get_spn_accounts(ldap_conn) → list of {username, spn, password_last_set}
   - request_tgs(username, spn, dc_ip, domain, credentials) → TGS hash (for offline cracking evidence only — do NOT crack, just capture hash as evidence)
   - generate_finding(spn_accounts) → Finding object with severity=Critical if accounts found

3. ASREPRoastChecker class:
   - get_no_preauth_accounts(ldap_conn) → list of usernames
   - request_asrep(username, dc_ip, domain) → AS-REP hash (evidence only)
   - generate_finding(accounts) → Finding object

4. NTLMRelayChecker class:
   - check_smb_signing(ip_list: list[str]) → dict[ip, {signing_enabled, signing_required}]
   - check_ldap_signing(dc_ip, domain) → bool
   - generate_finding(unsigned_hosts) → Finding object with attack_narrative including ntlmrelayx command

5. ADCSChecker class (certificate template analysis):
   - enumerate_templates(ldap_conn) → list of CertTemplate objects
   - check_esc1(template) → bool (ENROLLEE_SUPPLIES_SUBJECT + low privilege enrollment)
   - check_esc4(template) → bool (low privilege write access to template)
   - check_esc8(ca_config) → bool (NTLM relay to AD CS HTTP endpoint)
   - generate_findings(templates) → list[Finding]

6. BloodHoundCollector wrapper:
   - run_collection(dc_ip, domain, credentials, collection_methods=["All"]) → saves JSON files
   - import_to_neo4j(json_files, neo4j_uri, neo4j_user, neo4j_password)
   - query_da_paths() → list of shortest paths to Domain Admins as Finding evidence

All findings must include: MITRE technique, CWE if applicable, step-by-step reproduction, detection opportunity, and remediation recommendation.

Prompt 6 — Attack path analysis engine
Build the attack path analysis engine for an automated VAPT platform.

Tech stack: Python, Neo4j (py2neo or neo4j-python-driver), NetworkX, FastAPI, PostgreSQL.

Build the following:

1. GraphBuilder class:
   - build_asset_graph(engagement_id) → loads assets and findings from PostgreSQL, creates Neo4j nodes and relationships
   - Node types: Asset, Service, Finding, Credential, NetworkSegment
   - Relationship types: HAS_SERVICE, HAS_FINDING, EXPLOITS, CONNECTS_TO, SAME_SEGMENT, CREDENTIAL_REUSE
   - add_exploit_edges(findings) → for each exploited finding, add EXPLOITS edge with weight=exploit_complexity
   - add_network_edges(assets, network_topology) → add CONNECTS_TO edges based on segmentation data

2. PathAnalyzer class:
   - find_paths_to_target(target_asset_id, source_type="internet_exposed") → list of AttackPath
   - Uses Neo4j Cypher shortest path queries:
     MATCH p=shortestPath((src:Asset {internet_exposed:true})-[*..10]->(tgt:Asset {id:$target_id})) RETURN p
   - score_path(path) → float based on: sum of exploit CVSS, count of hops, presence of credential reuse
   - identify_chokepoints(paths) → assets that appear in >50% of all paths to critical targets
   - find_blast_radius(compromised_asset_id) → list of reachable assets from this point

3. AttackPathService (FastAPI router):
   - GET /engagements/{id}/attack-paths → paginated list of paths sorted by risk score
   - GET /engagements/{id}/attack-paths/{path_id} → full path detail with each hop explained
   - GET /engagements/{id}/chokepoints → list of chokepoint assets with remediation priority
   - GET /engagements/{id}/blast-radius/{asset_id} → reachable assets if this asset is compromised
   - GET /engagements/{id}/attack-graph → returns graph data in D3-compatible JSON format for frontend visualization

4. GraphVisualizer data model (for frontend):
   - nodes: [{id, label, type, criticality, compromised, x, y}]
   - edges: [{source, target, technique, weight, exploited}]
   - paths: [{id, hops, risk_score, highlighted}]

Include Cypher query examples, indexing strategy for large graphs (>10k nodes), and a demo dataset generator for testing.

Prompt 7 — Detection validation engine
Build the detection validation engine for an automated VAPT platform.

Tech stack: Python, FastAPI, Splunk REST API, Microsoft Sentinel REST API, CrowdStrike Falcon API, SentinelOne API.

Build the following:

1. AttackLogger class:
   - log_action(engagement_id, finding_id, mitre_technique, target_ip, timestamp, action_detail) → saves to PostgreSQL attack_timeline table
   - Used by all attack modules to record exact timestamp of each attack action

2. SIEMQueryEngine class (abstract + implementations):
   - Abstract: query_alerts(time_start, time_end, host_filter) → list[SIEMAlert]
   - SplunkSIEM: uses Splunk REST API search endpoint with SPL query
   - SentinelSIEM: uses Azure Monitor REST API with KQL query
   - ElasticSIEM: uses Elasticsearch search API with EQL/KQL

3. EDRQueryEngine class (abstract + implementations):
   - Abstract: query_detections(time_start, time_end, host_filter) → list[EDRDetection]
   - CrowdStrikeFalcon: uses Falcon API /incidents/queries/detections endpoint
   - MicrosoftDefender: uses Microsoft Graph Security API /security/alerts_v2
   - SentinelOne: uses SentinelOne REST API /threats endpoint

4. DetectionCorrelator class:
   - correlate(attack_timeline: list[AttackAction], siem_alerts: list[SIEMAlert], edr_detections: list[EDRDetection]) → list[DetectionResult]
   - Match logic: for each attack action, look for alerts/detections within ±5min window on the same target host
   - Result for each action: detected | prevented | missed
   - compute_coverage(results) → {total_techniques, detected, prevented, missed, coverage_pct}
   - generate_gap_report(missed_results) → list[DetectionGap with recommended_sigma_rule]

5. SigmaRuleGenerator class:
   - generate_sigma_for_technique(mitre_technique, missed_evidence) → Sigma rule YAML string
   - Uses a template library of base Sigma rules per MITRE technique
   - Customizes with specific field values observed in the attack evidence

6. DetectionValidationAPI (FastAPI router):
   - POST /engagements/{id}/detection-validation/run → triggers correlation job
   - GET /engagements/{id}/detection-validation/results → full result set
   - GET /engagements/{id}/detection-validation/coverage → ATT&CK coverage matrix data
   - GET /engagements/{id}/detection-validation/gaps → list of missed techniques with Sigma rules
   - POST /engagements/{id}/detection-validation/siem-config → configure SIEM connection

Include mocked SIEM/EDR responses for unit testing and an integration test against a local Splunk instance.

Prompt 8 — AI engine (LLM reporting + risk scoring)
Build the AI engine for an automated VAPT platform.

Tech stack: Python, FastAPI, Anthropic API (claude-sonnet-4-20250514), scikit-learn, XGBoost, PostgreSQL.

Build the following:

1. VulnPrioritizer class (ML-based):
   - train(historical_findings_df) → fits XGBoost model on features: [cvss, epss, kev_flag, exploit_validated, asset_criticality, lateral_reachable_count, days_since_last_patch]
   - predict_priority(finding: Finding, asset: Asset) → float priority score 0-1000
   - explain_prediction(finding) → dict of feature importances for this prediction (SHAP values)
   - Fallback formula if model not trained: weighted formula from Prompt 3

2. LLMReportGenerator class:
   - Uses Anthropic API, model: claude-sonnet-4-20250514, max_tokens: 4096
   - generate_executive_summary(engagement_summary: dict) → 400-600 word plain-language summary for CISO/Board
     Prompt template includes: total findings by severity, top 3 critical risks, attack paths found, detection coverage %, key business risk statement
   - generate_technical_finding(finding: Finding, asset: Asset, exploit_evidence: str) → detailed technical write-up with reproduction steps
   - generate_remediation_steps(finding: Finding) → numbered step-by-step fix guide with commands
   - generate_detection_rule_explanation(sigma_rule: str, technique: str) → plain-language explanation of what the rule detects and why
   - All LLM outputs saved to llm_outputs table with: prompt_hash, model, output, generated_at, reviewed_by, review_status ENUM[pending,approved,rejected]

3. HallucinationGuard class:
   - validate_cve_claims(text: str, actual_cve_ids: list[str]) → flags any CVE IDs in text not in actual list
   - validate_cvss_scores(text: str, actual_scores: dict) → flags any CVSS scores that differ from actual
   - validate_remediation_commands(text: str) → flags commands that look destructive (rm -rf, DROP TABLE, etc.)
   - Returns: {valid: bool, issues: list[str], confidence: float}

4. AIReportAPI (FastAPI router):
   - POST /engagements/{id}/ai-report/generate → async task, returns job_id
   - GET /engagements/{id}/ai-report/status/{job_id} → {status, progress}
   - GET /engagements/{id}/ai-report/draft → returns draft report pending human review
   - POST /engagements/{id}/ai-report/approve → human approves, marks report as final
   - POST /engagements/{id}/ai-report/reject → human rejects with feedback, triggers regeneration

All LLM calls must include: system prompt with explicit instructions to only reference provided data and never invent CVE details, temperature=0.3 for consistency, and retry logic with exponential backoff.

Prompt 9 — Frontend dashboard (React)
Build the React frontend for an automated Network VAPT platform.

Tech stack: React 18, TypeScript, Tailwind CSS, React Query (TanStack Query), React Router v6, Recharts, D3 (for attack graph).

Build the following screens and components:

1. Dashboard screen (/dashboard):
   - 4 metric cards: Total findings (with severity breakdown donut), Active engagements, Assets discovered, Detection coverage %
   - Line chart: findings over time (last 30 days, grouped by severity)
   - Top 5 critical findings table: title, asset, risk score, age, status badge
   - Recent engagement activity feed

2. Engagement management screen (/engagements):
   - Table: name, status badge, asset count, finding count, start date, progress bar
   - Create engagement modal: multi-step form (name+dates → scope CIDRs → credentials → review)
   - Engagement detail page (/engagements/:id): tabs for Overview | Findings | Assets | Attack Paths | Detection | Reports

3. Findings management screen (/findings):
   - Filterable, sortable table: severity badge, title, asset hostname, CVE IDs, risk score, MITRE techniques, status
   - Filters: severity multi-select, status multi-select, asset search, date range, MITRE technique
   - Finding detail drawer (slides in from right): full description, reproduction steps, evidence screenshots, remediation steps, detection status, CVSS breakdown, EPSS score, KEV indicator
   - Bulk actions: change status, assign owner, export selected

4. Attack path visualization screen (/engagements/:id/attack-paths):
   - D3 force-directed graph: nodes colored by asset type, edges colored by technique
   - Node click: shows asset details sidebar
   - Edge click: shows exploit/technique detail
   - Chokepoints highlighted with pulsing ring
   - Filters: show paths to specific target, filter by minimum risk score
   - Legend for node types and edge types

5. Reports screen (/engagements/:id/reports):
   - AI report draft with approve/reject controls (only visible to manager role)
   - Section tabs: Executive Summary | Technical Findings | Compliance Mapping | Detection Gaps
   - Export buttons: PDF, JSON, JIRA bulk import
   - Compliance view: findings mapped to PCI DSS / ISO 27001 / CIS Controls requirements

All components must use React Query for data fetching, include loading skeletons, empty states, and error states. Use TypeScript interfaces matching the backend Pydantic schemas. Include dark mode support via Tailwind dark: variant.

Prompt 10 — Infrastructure, agents & deployment
Build the distributed agent system and deployment infrastructure for an automated Network VAPT platform.

Tech stack: Python, FastAPI (agent side), Docker, Kubernetes (Helm charts), Kafka, HashiCorp Vault, Terraform (AWS).

Build the following:

1. ScanningAgent application (runs on-premise or in cloud):
   - Polls platform API for pending ScanJob every 10 seconds
   - Executes jobs: discovery, vuln_scan, ad_enum, lateral_movement, cloud_scan
   - Reports progress via POST /agents/{id}/jobs/{job_id}/progress
   - Submits results via POST /agents/{id}/jobs/{job_id}/result
   - Heartbeat every 30s to POST /agents/{id}/heartbeat
   - Credentials fetched from HashiCorp Vault (never stored locally)
   - All communication via mTLS (client cert provided at registration)
   - Graceful shutdown: completes current job, then exits

2. Agent registration flow:
   - Agent calls POST /agents/register with {agent_name, location, capabilities[], network_segments[]}
   - Platform issues: agent_id, mTLS client certificate, Vault role token
   - Agent stores cert in secure local keystore

3. Kafka topic design:
   - scan-jobs: ScanJob assignments published by orchestrator, consumed by agents
   - scan-results: Job results published by agents, consumed by enrichment service
   - findings: New/updated findings, consumed by enrichment + notification + risk services
   - alerts: Platform-level alerts for real-time dashboard
   - audit-events: All user/system actions for immutable audit log

4. Docker Compose for local development:
   - Services: api, worker, agent (3 instances), postgres, redis, neo4j, kafka, zookeeper, vault (dev mode), minio
   - Health checks for all services
   - Volume mounts for persistent data
   - Environment variable management via .env file

5. Kubernetes Helm chart (production):
   - Deployments: api (3 replicas), worker (2 replicas), agent-manager
   - ConfigMaps and Secrets (via Vault Agent Injector)
   - Horizontal Pod Autoscaler: api scales on CPU>70%, worker scales on Kafka consumer lag
   - PersistentVolumeClaims for postgres and neo4j
   - Ingress with TLS termination
   - NetworkPolicy: only allow inter-service communication on defined ports

6. Terraform (AWS):
   - VPC with public/private subnets
   - EKS cluster (managed node groups, t3.xlarge)
   - RDS PostgreSQL (db.t3.large, Multi-AZ)
   - ElastiCache Redis
   - MSK Kafka cluster
   - S3 bucket for artifacts with encryption and versioning
   - IAM roles for EKS service accounts (IRSA)
   - Secrets Manager for credentials

Include README with local dev quickstart, agent deployment guide, and production checklist.
