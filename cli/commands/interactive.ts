/**
 * Interactive wizard — the default `adversa` experience.
 * Users pick from menus and fill fields; the product does the rest.
 */
import { Command }                       from 'commander';
import * as readline                     from 'readline';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import path                              from 'path';
import { runScan }                       from '../../lib/engine/scanner';
import { getAllFindings, getFindingById } from '../../lib/findings-store';
import type {
  ScanOptions, ScanCallbacks,
  LiveFinding, DiscoveredHost,
} from '../../lib/engine/types';
import * as out                          from '../ui/output';
import * as llm                          from '../llm';
import {
  requireAuth, loadSession, saveSession,
  apiFetch, serverUrl, clearSession,
}                                        from '../auth';

// ── ANSI shortcuts ──────────────────────────────────────────────────
const A = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[1;31m', green: '\x1b[1;32m', yellow: '\x1b[33m',
  cyan: '\x1b[1;36m', blue: '\x1b[1;34m', gray: '\x1b[90m',
};
const w  = (s: string) => process.stdout.write(s);
const ln = (s = '')   => process.stdout.write(s + '\n');

// ── Prompt helpers ──────────────────────────────────────────────────
function makeRl(): readline.Interface {
  return readline.createInterface({ input: process.stdin, output: process.stdout });
}

function ask(question: string, dflt?: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = makeRl();
    const hint = dflt ? `${A.dim} [${dflt}]${A.reset}` : '';
    rl.question(`  ${A.cyan}?${A.reset} ${question}${hint} `, (answer) => {
      rl.close();
      const trimmed = answer.trim();
      resolve(trimmed === '' ? (dflt ?? '') : trimmed);
    });
  });
}

function askSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = makeRl();
    w(`  ${A.cyan}?${A.reset} ${question} `);
    (process.stdin as NodeJS.ReadStream).setRawMode?.(true);
    let input = '';
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    const handler = (char: string): void => {
      if (char === '\r' || char === '\n') {
        process.stdin.removeListener('data', handler);
        (process.stdin as NodeJS.ReadStream).setRawMode?.(false);
        w('\n');
        rl.close();
        resolve(input);
      } else if (char === '\x7f' || char === '\b') {
        if (input.length > 0) { input = input.slice(0, -1); w('\b \b'); }
      } else if (char === '\x03') {
        process.exit();
      } else {
        input += char;
        w('*');
      }
    };
    process.stdin.on('data', handler);
  });
}

async function confirm(question: string, dflt = true): Promise<boolean> {
  const ans = await ask(`${question} ${dflt ? '(Y/n)' : '(y/N)'}`);
  if (!ans) return dflt;
  return /^y(es)?$/i.test(ans);
}

async function choose<T>(
  question: string,
  options: { label: string; value: T; hint?: string }[],
): Promise<T> {
  ln();
  ln(`  ${A.bold}${question}${A.reset}`);
  options.forEach((o, i) => {
    const hint = o.hint ? `  ${A.dim}${o.hint}${A.reset}` : '';
    ln(`    ${A.cyan}${i + 1}${A.reset}) ${o.label}${hint}`);
  });
  ln();
  while (true) {
    const raw = await ask(`Choose 1–${options.length}`, '1');
    const n = parseInt(raw, 10);
    if (!isNaN(n) && n >= 1 && n <= options.length) return options[n - 1].value;
    ln(`  ${A.red}Invalid choice.${A.reset}`);
  }
}

function banner(): void {
  ln();
  ln(`  ${A.blue}▄▄▄  ██▄  ▄  ██▄ ▄  ██▄ ██▄  ▄▄${A.reset}    ${A.bold}ADVERSA${A.reset}`);
  ln(`  ${A.blue}▀▀▀█  █ █  █  █   ██ █ █  █ █ █${A.reset}    ${A.dim}Network VAPT Platform${A.reset}`);
  ln(`  ${A.blue}▀▀▀▀  ▀▀▀  ▀  ▀▀▀ ▀  ▀▀▀  ▀▀▀${A.reset}     ${A.dim}Interactive mode${A.reset}`);
  ln();
}

function divider(): void {
  ln(`  ${A.gray}${'─'.repeat(68)}${A.reset}`);
}

// ── Auth wizard ─────────────────────────────────────────────────────
async function ensureAuthenticated(): Promise<void> {
  const existing = loadSession();
  if (existing) return;

  ln(`  ${A.yellow}You're not logged in.${A.reset} Let's get you authenticated.`);
  ln();
  const server = serverUrl();
  ln(`  ${A.dim}Server: ${server}${A.reset}`);
  ln();

  const email = await ask('Email');
  if (!email || !email.includes('@')) {
    ln(`  ${A.red}Invalid email.${A.reset}`);
    process.exit(1);
  }

  ln(`  ${A.dim}Requesting magic code…${A.reset}`);
  const reqRes = await fetch(`${server}/api/auth/request`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email }),
  }).catch(() => null);

  if (!reqRes?.ok) {
    ln(`  ${A.red}Could not reach the server.${A.reset}`);
    ln(`  ${A.dim}Is it running? Try: ./run.sh start${A.reset}`);
    process.exit(1);
  }

  const reqData = await reqRes.json() as { dev?: boolean; otp?: string };
  if (reqData.dev && reqData.otp) {
    ln(`  ${A.yellow}[DEV]${A.reset} OTP: ${A.green}${reqData.otp}${A.reset}`);
  } else {
    ln(`  ${A.dim}Check ${email} for a 6-digit code.${A.reset}`);
  }

  const otp = await askSecret('Enter code');
  if (!otp) { ln(`  ${A.red}No code entered.${A.reset}`); process.exit(1); }

  const verRes = await fetch(`${server}/api/auth/verify`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ email, otp }),
  }).catch(() => null);

  const verData = await verRes?.json().catch(() => null) as
    { token?: string; role?: string; error?: string } | null;

  if (!verRes?.ok || !verData?.token) {
    ln(`  ${A.red}${verData?.error ?? 'Authentication failed'}${A.reset}`);
    process.exit(1);
  }

  saveSession({
    email,
    token:   verData.token,
    role:    verData.role ?? 'operator',
    savedAt: new Date().toISOString(),
  });

  ln(`  ${A.green}✓${A.reset} Authenticated as ${A.bold}${email}${A.reset}${verData.role === 'admin' ? ` ${A.cyan}[admin]${A.reset}` : ''}`);
  ln();
}

// ── Wizard: run a scan ──────────────────────────────────────────────
async function wizardScan(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Run a scan${A.reset}`);
  divider();

  // ── Targets
  const targetMode = await choose<'inline' | 'file'>('How will you provide targets?', [
    { label: 'Type them here',         value: 'inline', hint: 'comma-separated IPs / CIDRs / hostnames' },
    { label: 'Read from a file',       value: 'file',   hint: 'one target per line' },
  ]);

  let targets: string[] = [];
  if (targetMode === 'inline') {
    const raw = await ask('Targets', '127.0.0.1');
    targets = raw.split(',').map((t) => t.trim()).filter(Boolean);
  } else {
    const file = await ask('File path', 'targets.txt');
    if (!existsSync(file)) { ln(`  ${A.red}File not found.${A.reset}`); return; }
    targets = readFileSync(file, 'utf-8').split(/[\r\n]+/).map((t) => t.trim()).filter(Boolean);
  }
  if (targets.length === 0) { ln(`  ${A.red}No targets.${A.reset}`); return; }

  // ── Profile
  const profile = await choose<'fast' | 'standard' | 'deep'>('Scan profile', [
    { label: 'Fast',     value: 'fast',     hint: 'naabu + nuclei  ·  ~minutes' },
    { label: 'Standard', value: 'standard', hint: 'naabu + nmap + nuclei  ·  recommended' },
    { label: 'Deep',     value: 'deep',     hint: 'all tools + testssl  ·  thorough' },
  ]);

  // ── Stealth
  const stealthRaw = await ask('Stealth level (1 = quiet, 9 = fast)', '5');
  const stealth = Math.min(9, Math.max(1, parseInt(stealthRaw, 10) || 5));

  // ── Output options
  ln();
  ln(`  ${A.bold}Output options${A.reset}`);
  const save  = await confirm('Persist findings to data/findings.json?', true);
  const useAi = await confirm('Enable AI commentary during scan?',       true);

  // ── Optional engagement
  const tagEng = await confirm('Tag this scan to an engagement?', false);
  let engagementId: string | undefined;
  if (tagEng) {
    engagementId = await pickEngagementId();
  }

  // ── Summary + confirm
  ln();
  ln(`  ${A.bold}Review${A.reset}`);
  ln(`    ${A.dim}Targets:${A.reset}    ${targets.join(', ')}`);
  ln(`    ${A.dim}Profile:${A.reset}    ${profile}`);
  ln(`    ${A.dim}Stealth:${A.reset}    ${stealth}/9`);
  ln(`    ${A.dim}Save:${A.reset}       ${save ? 'yes' : 'no'}`);
  ln(`    ${A.dim}AI:${A.reset}         ${useAi ? 'yes' : 'no'}`);
  if (engagementId) ln(`    ${A.dim}Engagement:${A.reset} ${engagementId}`);
  ln();
  if (!(await confirm('Start scan?', true))) return;

  // ── Run the scan (mirrors cli/commands/scan.ts logic) ────────────
  const PROFILE_TOOLS: Record<string, ScanOptions['tools']> = {
    fast:     ['naabu', 'nuclei'],
    standard: ['naabu', 'nmap', 'nuclei'],
    deep:     ['naabu', 'nmap', 'nuclei', 'testssl'],
  };
  const opts: ScanOptions = {
    targets, profile, stealth,
    tools:  PROFILE_TOOLS[profile],
    save,
    engagementId,
    scanId: `SCAN-${Date.now()}`,
  };

  const session = requireAuth();
  out.banner();
  out.scanHeader(targets, profile, stealth, opts.tools);
  ln(`  ${A.dim}Operator:${A.reset} ${session.email}`);
  ln();

  const discovered: DiscoveredHost[] = [];
  const allFindings: LiveFinding[]   = [];
  const stageFindings = new Map<string, LiveFinding[]>();
  let   currentStage = '';

  const printAiComment = (text: string): void => {
    for (const line of text.split('\n')) {
      ln(`  ${A.dim}${A.cyan}▸${A.reset} ${A.dim}${line}${A.reset}`);
    }
  };

  const callbacks: ScanCallbacks = {
    onStageStart(stage) { currentStage = stage; stageFindings.set(stage, []); out.stageStart(stage); },
    async onStageComplete(stage, summary) {
      out.stageComplete(stage, summary);
      if (useAi) {
        const c = await llm.commentOnStage(stage, summary, discovered, allFindings);
        if (c) printAiComment(c);
        const found = stageFindings.get(stage) ?? [];
        if (found.length > 0) {
          const ctx = await llm.explainFindings(found);
          for (const [id] of ctx) {
            const f = found.find((x) => x.id === id);
            if (f) ln(`    ${A.dim}└─ ${ctx.get(id)}${A.reset}`);
          }
        }
      }
    },
    onHostDiscovered(host) {
      if (!discovered.find((h) => h.ip === host.ip)) discovered.push(host);
      out.hostLine(host);
    },
    onFinding(f) {
      allFindings.push(f);
      stageFindings.get(currentStage)?.push(f);
      out.findingLine(f);
    },
    onProgress(pct, msg) { out.stageProgress(pct, msg); },
    onError(stage, err)   { out.stageError(stage, err); },
    async onComplete(s) {
      out.summary(s);
      if (useAi && allFindings.length > 0) {
        ln(`\n  ${A.cyan}AI Attack Path Analysis${A.reset}`);
        const p = await llm.suggestAttackPath(discovered, allFindings, s);
        if (p) printAiComment(p);
        ln();
      }
      if (save) out.info(`Findings saved to data/findings.json (${allFindings.length} new)`);
    },
  };

  try {
    await runScan(opts, callbacks);
  } catch (e) {
    out.error(`Scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ── Wizard: view findings ──────────────────────────────────────────
async function wizardFindings(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ View findings${A.reset}`);
  divider();

  const view = await choose<'all' | 'filter' | 'detail' | 'stats'>('What do you want to see?', [
    { label: 'All findings (table)',           value: 'all' },
    { label: 'Filter by severity / host',      value: 'filter' },
    { label: 'Full detail of one finding',     value: 'detail' },
    { label: 'Summary stats (counts, SLA)',    value: 'stats' },
  ]);

  let findings = getAllFindings();
  if (findings.length === 0) {
    ln(`  ${A.yellow}No findings yet.${A.reset} Run a scan first (option: ${A.bold}Run a scan${A.reset}).`);
    return;
  }

  if (view === 'filter') {
    const sev = await choose<string>('Severity filter', [
      { label: 'Any',      value: '' },
      { label: 'CRITICAL', value: 'CRITICAL' },
      { label: 'HIGH',     value: 'HIGH' },
      { label: 'MEDIUM',   value: 'MEDIUM' },
      { label: 'LOW',      value: 'LOW' },
      { label: 'INFO',     value: 'INFO' },
    ]);
    if (sev) findings = findings.filter((f) => f.severity === sev);

    const host = await ask('Host substring (blank for any)');
    if (host) findings = findings.filter((f) => f.host.toLowerCase().includes(host.toLowerCase()));
  }

  if (view === 'detail') {
    const id = await ask('Finding ID');
    const f  = getFindingById(id);
    if (!f) { ln(`  ${A.red}Not found.${A.reset}`); return; }
    out.findingDetail(f);
    return;
  }

  if (view === 'stats') {
    const bySev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const byStatus: Record<string, number> = {};
    let breached = 0;
    for (const f of findings) {
      bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
      byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
      if (f.slaDeadline && Date.now() > new Date(f.slaDeadline).getTime() && f.status === 'OPEN') breached++;
    }
    ln();
    ln(`  ${A.bold}FINDINGS SUMMARY${A.reset}  ${A.dim}(${findings.length} total)${A.reset}`);
    for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
      const n = bySev[s] ?? 0;
      if (n === 0) continue;
      ln(`    ${out.sevBadge(s)}  ${String(n).padStart(3)}  ${'█'.repeat(Math.min(n, 40))}`);
    }
    ln();
    for (const [s, n] of Object.entries(byStatus)) ln(`    ${s.padEnd(18)} ${n}`);
    if (breached > 0) ln(`\n  ${A.red}⚠ ${breached} open finding(s) past SLA${A.reset}`);
    ln();
    return;
  }

  out.findingsTable(findings);

  if (await confirm('See full detail of one finding?', false)) {
    const id = await ask('Finding ID');
    const f  = getFindingById(id);
    if (f) out.findingDetail(f);
    else ln(`  ${A.red}Not found.${A.reset}`);
  }
}

// ── Wizard: ask AI ──────────────────────────────────────────────────
async function wizardAsk(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Ask the AI${A.reset}`);
  divider();

  const findings = getAllFindings();
  const hosts: DiscoveredHost[] = [...new Map(
    findings.map((f) => [f.host, { ip: f.host, ports: f.port ? [f.port] : [], services: [] }]),
  ).values()];

  if (findings.length === 0) {
    ln(`  ${A.yellow}No findings loaded — the AI has no scan context.${A.reset}`);
    if (!(await confirm('Continue anyway?', false))) return;
  } else {
    ln(`  ${A.dim}Context: ${findings.length} findings, ${hosts.length} hosts.${A.reset}`);
  }

  ln();
  ln(`  ${A.dim}Type a question and press Enter. Empty line to return to menu.${A.reset}`);
  ln();

  const history: { role: 'user' | 'assistant'; content: string }[] = [];

  while (true) {
    const q = await ask(`${A.cyan}You${A.reset}`);
    if (!q) break;

    w(`  ${A.cyan}AI${A.reset}  `);
    let answer = '';
    await llm.streamAsk(
      q, findings, hosts,
      (chunk) => { w(chunk); answer += chunk; },
      history,
    );
    w('\n\n');
    history.push({ role: 'user', content: q });
    history.push({ role: 'assistant', content: answer });
  }
}

// ── Engagement utilities ────────────────────────────────────────────
interface EngagementRow {
  id: string; name: string; client: string; status: string;
  findingCount: number; assetCount: number; progress: number;
  startDate: string; endDate: string;
  scopeCidrs: string[]; excludedCidrs: string[];
  assessor: string; description?: string;
}

async function fetchEngagements(): Promise<EngagementRow[]> {
  const s = requireAuth();
  const res = await apiFetch(s, '/api/engagements').catch(() => null);
  if (!res?.ok) return [];
  const data = await res.json() as { engagements: EngagementRow[] };
  return data.engagements;
}

async function pickEngagementId(): Promise<string | undefined> {
  const list = await fetchEngagements();
  if (list.length === 0) {
    ln(`  ${A.yellow}No engagements found.${A.reset} Create one from the main menu first.`);
    return undefined;
  }
  const choices = list.map((e) => ({
    label: `${e.id}  ${e.name}`,
    value: e.id,
    hint:  `${e.client} · ${e.status} · ${e.findingCount} findings`,
  }));
  return choose<string>('Pick an engagement', choices);
}

// ── Wizard: engagements ─────────────────────────────────────────────
async function wizardEngagement(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Engagements${A.reset}`);
  divider();

  const action = await choose<'list' | 'show' | 'create'>('What do you want to do?', [
    { label: 'List all engagements',  value: 'list' },
    { label: 'Show one in detail',    value: 'show' },
    { label: 'Create a new one',      value: 'create' },
  ]);

  if (action === 'list' || action === 'show') {
    const list = await fetchEngagements();
    if (list.length === 0) { ln(`  ${A.yellow}None yet.${A.reset}`); return; }

    ln();
    ln(`  ${'ID'.padEnd(10)} ${'STATUS'.padEnd(12)} ${'CLIENT'.padEnd(28)} FINDINGS`);
    ln(`  ${'─'.repeat(70)}`);
    for (const e of list) {
      ln(`  ${e.id.padEnd(10)} ${e.status.padEnd(12)} ${e.client.slice(0, 28).padEnd(28)} ${e.findingCount}`);
    }
    ln();

    if (action === 'show') {
      const id = await pickEngagementId();
      if (!id) return;
      const e = list.find((x) => x.id === id);
      if (!e) return;
      ln(`\n  ${A.bold}${e.name}${A.reset}  ·  ${e.id}`);
      ln(`  ${A.gray}${'─'.repeat(68)}${A.reset}`);
      ln(`  Client      ${e.client}`);
      ln(`  Status      ${e.status}`);
      ln(`  Assessor    ${e.assessor}`);
      ln(`  Window      ${e.startDate} → ${e.endDate}`);
      ln(`  Progress    ${e.progress}%`);
      ln(`  Assets      ${e.assetCount}`);
      ln(`  Findings    ${e.findingCount}`);
      if (e.scopeCidrs.length)    ln(`  Scope       ${e.scopeCidrs.join(', ')}`);
      if (e.excludedCidrs.length) ln(`  Excluded    ${e.excludedCidrs.join(', ')}`);
      if (e.description)          ln(`\n  ${A.dim}${e.description}${A.reset}`);
      ln();
    }
    return;
  }

  // ── create
  const session = requireAuth();
  const name        = await ask('Engagement name');
  const client      = await ask('Client / organization');
  const startDate   = await ask('Start date (YYYY-MM-DD)', new Date().toISOString().slice(0, 10));
  const endDate     = await ask('End date (YYYY-MM-DD)');
  const scopeRaw    = await ask('In-scope CIDRs (comma-separated, blank for none)');
  const excludeRaw  = await ask('Excluded CIDRs (comma-separated, blank for none)');
  const description = await ask('Description (optional)');

  const body = {
    name, client, startDate, endDate,
    scopeCidrs:    scopeRaw.split(',').map((s) => s.trim()).filter(Boolean),
    excludedCidrs: excludeRaw.split(',').map((s) => s.trim()).filter(Boolean),
    description,
    assessor: session.email,
  };

  const res = await apiFetch(session, '/api/engagements', {
    method: 'POST',
    body:   JSON.stringify(body),
  }).catch(() => null);

  if (!res?.ok) {
    const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
    ln(`  ${A.red}${err ?? 'Could not create engagement.'}${A.reset}`);
    return;
  }
  const { engagement } = await res.json() as { engagement: EngagementRow };
  ln(`\n  ${A.green}✓${A.reset} Created ${A.bold}${engagement.id}${A.reset} — ${engagement.name}\n`);
}

// ── Wizard: AI report ───────────────────────────────────────────────
async function wizardReport(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Generate AI report${A.reset}`);
  divider();

  const id = await pickEngagementId();
  if (!id) return;

  const dest = await choose<'terminal' | 'file' | 'both'>('Where do you want the report?', [
    { label: 'Show in terminal',          value: 'terminal' },
    { label: 'Write to a JSON file',      value: 'file' },
    { label: 'Both',                      value: 'both' },
  ]);

  let outFile: string | undefined;
  if (dest === 'file' || dest === 'both') {
    outFile = await ask('Output file', `report-${id}.json`);
  }

  // ── Field selection
  ln();
  ln(`  ${A.bold}Which sections do you want in the terminal view?${A.reset}`);
  const wantSummary    = await confirm('Executive summary?',     true);
  const wantScorecard  = await confirm('Risk scorecard?',        true);
  const wantFindings   = await confirm('Per-finding detail?',    true);
  const wantRoadmap    = await confirm('Remediation roadmap?',   true);
  const wantPositive   = await confirm('Positive findings?',     true);

  const s = requireAuth();
  ln();
  ln(`  ${A.dim}Generating report — this can take 30–60 seconds…${A.reset}`);
  const res = await apiFetch(s, `/api/engagements/${id}/ai-report`, {
    method: 'POST',
  }).catch(() => null);

  if (!res?.ok) {
    const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
    ln(`  ${A.red}${err ?? 'Report generation failed.'}${A.reset}`);
    return;
  }

  type Report = {
    executive_summary?: string;
    risk_scorecard?:    Record<string, number>;
    findings?:          Array<Record<string, unknown>>;
    remediation_roadmap?: { priority_1_24h?: string[]; priority_2_30d?: string[]; priority_3_90d?: string[] };
    positive_findings?: string;
  };
  const report = await res.json() as Report;

  if (outFile) {
    writeFileSync(path.resolve(outFile), JSON.stringify(report, null, 2));
    ln(`  ${A.green}✓${A.reset} Report written to ${outFile}`);
  }

  if (dest === 'file') { ln(); return; }

  // ── Render selected sections
  if (wantSummary && report.executive_summary) {
    ln(`\n  ${A.cyan}═══ EXECUTIVE SUMMARY ═══${A.reset}\n`);
    ln(`  ${report.executive_summary.replace(/\n/g, '\n  ')}`);
  }
  if (wantScorecard && report.risk_scorecard) {
    ln(`\n  ${A.cyan}═══ RISK SCORECARD ═══${A.reset}\n`);
    const sc = report.risk_scorecard;
    ln(`    Overall ${sc.overall ?? '-'}/100   Network ${sc.network ?? '-'}   Auth ${sc.auth ?? '-'}   Config ${sc.config ?? '-'}   Patches ${sc.patches ?? '-'}   Web ${sc.web ?? '-'}`);
  }
  if (wantFindings && report.findings?.length) {
    ln(`\n  ${A.cyan}═══ FINDINGS (${report.findings.length}) ═══${A.reset}\n`);
    for (const f of report.findings as Array<{ severity?: string; finding_id?: string; title?: string; business_impact?: string; remediation_detail?: string }>) {
      ln(`  [${f.severity ?? '?'}] ${f.finding_id ?? ''} — ${f.title ?? ''}`);
      if (f.business_impact)     ln(`    ${A.dim}Impact:${A.reset} ${f.business_impact}`);
      if (f.remediation_detail)  ln(`    ${A.dim}Fix:${A.reset}    ${f.remediation_detail}`);
      ln();
    }
  }
  if (wantRoadmap && report.remediation_roadmap) {
    const r = report.remediation_roadmap;
    ln(`\n  ${A.cyan}═══ REMEDIATION ROADMAP ═══${A.reset}\n`);
    ln(`    ${A.red}24h${A.reset}  ${(r.priority_1_24h ?? []).join(', ') || '(none)'}`);
    ln(`    ${A.yellow}30d${A.reset}  ${(r.priority_2_30d ?? []).join(', ') || '(none)'}`);
    ln(`    ${A.cyan}90d${A.reset}  ${(r.priority_3_90d ?? []).join(', ') || '(none)'}`);
  }
  if (wantPositive && report.positive_findings) {
    ln(`\n  ${A.green}═══ POSITIVE FINDINGS ═══${A.reset}\n`);
    ln(`  ${report.positive_findings.replace(/\n/g, '\n  ')}`);
  }
  ln();
}

// ── Wizard: status ──────────────────────────────────────────────────
async function wizardStatus(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Scan status${A.reset}`);
  divider();

  const s   = requireAuth();
  const res = await apiFetch(s, '/api/scans/list').catch(() => null);
  if (!res?.ok) { ln(`  ${A.red}Could not reach server.${A.reset}`); return; }

  const scans = await res.json() as Array<{
    scanId: string; status: string; targets: string[]; profile: string; createdAt: string;
  }>;
  if (scans.length === 0) { ln(`  ${A.yellow}No scans yet.${A.reset}`); return; }

  ln();
  ln(`  ${'SCAN ID'.padEnd(28)} ${'STATUS'.padEnd(12)} ${'PROFILE'.padEnd(10)} TARGETS`);
  ln(`  ${'─'.repeat(72)}`);
  for (const x of scans) {
    const tgts = (x.targets ?? []).slice(0, 2).join(', ') + ((x.targets?.length ?? 0) > 2 ? '…' : '');
    ln(`  ${x.scanId.padEnd(28)} ${x.status.padEnd(12)} ${(x.profile ?? '').padEnd(10)} ${tgts}`);
  }
  ln();
}

// ── Wizard: admin ───────────────────────────────────────────────────
async function wizardAdmin(): Promise<void> {
  ln();
  ln(`  ${A.cyan}▶ Admin${A.reset}`);
  divider();

  const s = requireAuth();
  if (s.role !== 'admin') {
    ln(`  ${A.yellow}You are not an admin — this menu is read-only.${A.reset}`);
  }

  const action = await choose<'list' | 'add' | 'scope' | 'remove'>('What do you want to do?', [
    { label: 'List users',           value: 'list' },
    { label: 'Add a user',           value: 'add' },
    { label: 'Change a user\'s scope', value: 'scope' },
    { label: 'Remove a user',        value: 'remove' },
  ]);

  if (action === 'list') {
    const res = await apiFetch(s, '/api/admin/users').catch(() => null);
    if (!res?.ok) { ln(`  ${A.red}Failed to list users.${A.reset}`); return; }
    const users = await res.json() as Array<{ email: string; role: string; allowedScopes: string[] }>;
    ln();
    ln(`  ${'EMAIL'.padEnd(34)} ${'ROLE'.padEnd(10)} SCOPES`);
    ln(`  ${'─'.repeat(72)}`);
    for (const u of users) {
      ln(`  ${u.email.padEnd(34)} ${u.role.padEnd(10)} ${u.allowedScopes.join(', ') || '(all)'}`);
    }
    ln();
    return;
  }

  if (action === 'add') {
    const email = await ask('Email');
    const role  = await choose<'operator' | 'admin'>('Role', [
      { label: 'Operator', value: 'operator' },
      { label: 'Admin',    value: 'admin' },
    ]);
    const scopes = (await ask('Allowed CIDRs (comma-separated, blank = none)'))
      .split(',').map((x) => x.trim()).filter(Boolean);

    const res = await apiFetch(s, '/api/admin/users', {
      method: 'POST',
      body:   JSON.stringify({ email, role, allowedScopes: scopes }),
    }).catch(() => null);
    if (!res?.ok) {
      const err = (await res?.json().catch(() => ({})) as { error?: string }).error;
      ln(`  ${A.red}${err ?? 'Could not add user.'}${A.reset}`);
      return;
    }
    ln(`  ${A.green}✓${A.reset} ${email} added as ${role}`);
    return;
  }

  if (action === 'scope') {
    const email = await ask('Email');
    const scopes = (await ask('New CIDR list (comma-separated)'))
      .split(',').map((x) => x.trim()).filter(Boolean);
    const res = await apiFetch(s, `/api/admin/users/${encodeURIComponent(email)}`, {
      method: 'PUT',
      body:   JSON.stringify({ allowedScopes: scopes }),
    }).catch(() => null);
    if (!res?.ok) { ln(`  ${A.red}Failed.${A.reset}`); return; }
    ln(`  ${A.green}✓${A.reset} Updated ${email}`);
    return;
  }

  if (action === 'remove') {
    const email = await ask('Email');
    if (!(await confirm(`Remove ${email}? This cannot be undone.`, false))) return;
    const res = await apiFetch(s, `/api/admin/users/${encodeURIComponent(email)}`, {
      method: 'DELETE',
    }).catch(() => null);
    if (!res?.ok) { ln(`  ${A.red}Failed.${A.reset}`); return; }
    ln(`  ${A.green}✓${A.reset} Removed ${email}`);
  }
}

// ── Main menu loop ──────────────────────────────────────────────────
async function mainMenu(): Promise<void> {
  while (true) {
    const session = loadSession();
    const role    = session?.role === 'admin' ? ` ${A.cyan}[admin]${A.reset}` : '';
    ln();
    ln(`  ${A.bold}Main menu${A.reset}  ${A.dim}— logged in as${A.reset} ${session?.email ?? '?'}${role}`);
    divider();

    type Action = 'scan' | 'findings' | 'ask' | 'report' | 'engagement' | 'status' | 'admin' | 'logout' | 'exit';
    const action = await choose<Action>('Choose an action', [
      { label: 'Run a scan',              value: 'scan',       hint: 'naabu → nmap → nuclei → testssl + AI commentary' },
      { label: 'View findings',           value: 'findings',   hint: 'table, filter, detail, or stats' },
      { label: 'Ask the AI',              value: 'ask',        hint: 'streaming Q&A with scan context' },
      { label: 'Generate AI report',      value: 'report',     hint: 'pick engagement, choose sections' },
      { label: 'Manage engagements',      value: 'engagement', hint: 'list, show, create' },
      { label: 'Scan status',             value: 'status',     hint: 'recent scans + their state' },
      { label: 'Admin — user management', value: 'admin',      hint: 'list / add / scope / remove' },
      { label: 'Log out',                 value: 'logout' },
      { label: 'Exit',                    value: 'exit' },
    ]);

    try {
      switch (action) {
        case 'scan':       await wizardScan();       break;
        case 'findings':   await wizardFindings();   break;
        case 'ask':        await wizardAsk();        break;
        case 'report':     await wizardReport();     break;
        case 'engagement': await wizardEngagement(); break;
        case 'status':     await wizardStatus();     break;
        case 'admin':      await wizardAdmin();      break;
        case 'logout':
          clearSession();
          ln(`  ${A.green}✓${A.reset} Logged out.`);
          await ensureAuthenticated();
          break;
        case 'exit':
          ln(`  ${A.dim}Goodbye.${A.reset}`);
          return;
      }
    } catch (e) {
      ln(`  ${A.red}Error: ${e instanceof Error ? e.message : String(e)}${A.reset}`);
    }

    ln();
    if (!(await confirm('Return to main menu?', true))) return;
  }
}

export function buildInteractiveCommand(): Command {
  return new Command('menu')
    .alias('start')
    .description('Launch interactive mode (the default)')
    .action(async () => {
      banner();
      await ensureAuthenticated();
      await mainMenu();
    });
}

export async function runInteractive(): Promise<void> {
  banner();
  await ensureAuthenticated();
  await mainMenu();
}
