import { spawn, type SpawnOptions } from 'child_process';
import { readFileSync, unlinkSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { DiscoveredHost, ScanCallbacks, LiveFinding } from './types';
import { parseNmapXml }                        from '../nmap-parser';
import { parseNucleiLine, nucleiSeverityToSeverity } from '../nuclei-parser';
import { parseTestsslJson }                    from '../testssl-parser';
import { parseNaabuLine, groupNaabuResults }   from '../naabu-parser';
import { generateFindingId }                   from '../finding-id';
import { diagnoseSpawnError, Errors }          from '../errors';

// ── Stealth mappings (index = stealth level 0–9) ─────────────────
const NAABU_RATE    = [0, 50, 100, 300, 500, 1000, 2000, 3000, 5000];
const NMAP_TIMING   = [0, 1,  1,   2,   2,   3,    3,    4,    4,   5];

// ── Platform helpers ─────────────────────────────────────────────
function isWindows(): boolean {
  return process.platform === 'win32';
}

function binName(tool: string): string {
  const win: Record<string, string> = { nmap: 'nmap.exe', naabu: 'naabu.exe', nuclei: 'nuclei.exe', testssl: 'testssl.sh' };
  const unix: Record<string, string> = { nmap: 'nmap', naabu: 'naabu', nuclei: 'nuclei', testssl: 'testssl.sh' };
  return isWindows() ? (win[tool] ?? tool) : (unix[tool] ?? tool);
}

function spawnOpts(extraEnv?: Record<string, string>): SpawnOptions {
  const base: SpawnOptions = {
    stdio: ['ignore', 'pipe', 'pipe'],
    env:   { ...process.env, ...(extraEnv ?? {}) },
  };
  if (isWindows()) {
    // Prevent console window flash on Windows
    (base as SpawnOptions & { windowsHide: boolean }).windowsHide = true;
    base.shell = true;
  }
  return base;
}

// ── Helper: run a process and stream stdout line by line ─────────
// Captures stderr too so we can produce a useful error when things go wrong.
interface ProcessResult { code: number; stderr: string; }

function streamProcess(
  bin:     string,
  args:    string[],
  onLine:  (line: string) => void,
  opts?:   SpawnOptions,
): Promise<ProcessResult> {
  return new Promise((resolve) => {
    let buf = '';
    let stderr = '';
    let spawnError = '';
    const proc = spawn(bin, args, opts ?? spawnOpts());

    proc.stdout?.on('data', (chunk: Buffer | string) => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const l of lines) if (l.trim()) onLine(l);
    });
    proc.stderr?.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    proc.on('error', (err) => {
      spawnError = err.message;
      resolve({ code: -1, stderr: stderr || spawnError });
    });
    proc.on('close', (code) => {
      if (buf.trim()) onLine(buf);
      resolve({ code: code ?? 0, stderr });
    });
  });
}

function collectProcess(bin: string, args: string[], opts?: SpawnOptions): Promise<{ stdout: string; code: number; stderr: string }> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    const proc = spawn(bin, args, opts ?? spawnOpts());
    proc.stdout?.on('data', (c: Buffer | string) => { stdout += c.toString(); });
    proc.stderr?.on('data', (c: Buffer | string) => { stderr += c.toString(); });
    proc.on('error', (err) => resolve({ stdout, code: -1, stderr: err.message }));
    proc.on('close', (code) => resolve({ stdout, code: code ?? 0, stderr }));
  });
}

// ── runNaabu ─────────────────────────────────────────────────────
export async function runNaabu(
  targets:  string[],
  stealth:  number,
  cb:       ScanCallbacks,
): Promise<DiscoveredHost[]> {
  const rate    = NAABU_RATE[Math.min(stealth, 9)] ?? 1000;
  const results: import('../naabu-parser').NaabuResult[] = [];

  const { code, stderr } = await streamProcess(
    binName('naabu'),
    ['-host', targets.join(','), '-rate', String(rate), '-s', 'c', '-json', '-silent'],
    (line) => {
      const r = parseNaabuLine(line);
      if (r) {
        results.push(r);
        const existing = results.filter((x) => x.ip === r.ip);
        cb.onHostDiscovered({
          ip:       r.ip,
          ports:    existing.map((x) => x.port),
          services: existing.map((x) => ({ port: x.port, proto: x.protocol })),
        });
      }
    },
    spawnOpts(),
  );

  if (code !== 0 && results.length === 0) {
    cb.onError('naabu', diagnoseSpawnError('naabu', code, stderr).render(false));
  }
  return groupNaabuResults(results);
}

// ── runNmap ──────────────────────────────────────────────────────
export async function runNmap(
  hosts:   DiscoveredHost[],
  stealth: number,
  cb:      ScanCallbacks,
): Promise<void> {
  if (hosts.length === 0) return;

  const timing  = NMAP_TIMING[Math.min(stealth, 9)] ?? 3;
  const allPorts = [...new Set(hosts.flatMap((h) => h.ports))].sort((a, b) => a - b);
  const portArg  = allPorts.length > 0 ? allPorts.join(',') : '1-1000';
  const ips      = hosts.map((h) => h.ip);

  const { stdout, code, stderr } = await collectProcess(
    binName('nmap'),
    ['-sT', '-sV', `-T${timing}`, '-p', portArg, '--script', 'banner,ssl-cert,http-title', '-oX', '-', ...ips],
    spawnOpts(),
  );

  if (code !== 0 && !stdout) {
    cb.onError('nmap', diagnoseSpawnError('nmap', code, stderr).render(false));
    return;
  }

  const parsed = parseNmapXml(stdout);
  for (const h of parsed) {
    const open = h.services.filter((s) => s.state === 'open');
    const host = hosts.find((x) => x.ip === h.ip);
    if (!host) continue;

    // Enrich host services in place
    host.services = open.map((s) => ({
      port:    s.port,
      proto:   s.proto,
      name:    s.name,
      version: [s.product, s.version].filter(Boolean).join(' ') || undefined,
    }));
    host.os        = h.os;
    host.hostnames = h.hostnames;

    cb.onHostDiscovered(host);
  }
}

// ── runNuclei ────────────────────────────────────────────────────
export async function runNuclei(
  hosts: DiscoveredHost[],
  cb:    ScanCallbacks,
): Promise<LiveFinding[]> {
  const WEB_PROTO: Record<number, string> = { 80: 'http', 443: 'https', 8080: 'http', 8443: 'https', 8000: 'http', 3000: 'http', 5000: 'http' };
  const urls = hosts.flatMap((h) =>
    h.ports
      .filter((p) => WEB_PROTO[p])
      .map((p) => `${WEB_PROTO[p]}://${h.ip}:${p}`),
  );

  if (urls.length === 0) return [];

  const findings: LiveFinding[] = [];
  const now = new Date().toISOString();

  const templateDir = '/opt/nuclei-templates';
  const args = [
    '-json', '-silent', '-no-color',
    ...(existsSync(templateDir) ? ['-t', templateDir] : []),
    ...urls.flatMap((u) => ['-u', u]),
  ];

  const { code, stderr } = await streamProcess(
    binName('nuclei'),
    args,
    (line) => {
      const match = parseNucleiLine(line);
      if (!match) return;
      const sev = nucleiSeverityToSeverity(match.severity);
      const finding: LiveFinding = {
        id:        generateFindingId(sev),
        title:     match.name,
        severity:  sev,
        host:      match.ip ?? match.host,
        port:      match.port,
        source:    'nuclei',
        cveIds:    match.cveIds,
        evidence:  [{ label: 'nuclei match', content: match.matchedAt, timestamp: now }],
        status:    'OPEN',
        timestamp: now,
      };
      findings.push(finding);
      cb.onFinding(finding);
    },
    spawnOpts({ HOME: '/opt' }),
  );

  if (code !== 0 && findings.length === 0) {
    cb.onError('nuclei', diagnoseSpawnError('nuclei', code, stderr).render(false));
  }
  return findings;
}

// ── runTestssl ───────────────────────────────────────────────────
export async function runTestssl(
  hosts: DiscoveredHost[],
  cb:    ScanCallbacks,
): Promise<LiveFinding[]> {
  const TLS_PORTS = new Set([443, 8443]);
  const targets   = hosts.filter((h) => h.ports.some((p) => TLS_PORTS.has(p)));
  if (targets.length === 0) return [];

  const all: LiveFinding[] = [];

  for (const host of targets) {
    const port    = host.ports.find((p) => TLS_PORTS.has(p)) ?? 443;
    const outFile = join(tmpdir(), `adv-testssl-${host.ip}-${Date.now()}.json`);

    const { code, stderr } = await collectProcess(
      binName('testssl'),
      ['--fast', '--jsonfile', outFile, '--color', '0', '--quiet', `${host.ip}:${port}`],
      spawnOpts(),
    );

    if (code !== 0 && !existsSync(outFile)) {
      cb.onError('testssl', diagnoseSpawnError('testssl', code, stderr).render(false));
      continue;
    }

    if (existsSync(outFile)) {
      try {
        const content  = readFileSync(outFile, 'utf-8');
        const findings = parseTestsslJson(content, host.ip, port);
        for (const f of findings) { all.push(f); cb.onFinding(f); }
      } catch { /* ignore parse errors */ }
      try { unlinkSync(outFile); } catch { /* ignore */ }
    }
  }

  return all;
}
