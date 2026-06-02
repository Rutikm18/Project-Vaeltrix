import type { ScanOptions, ScanCallbacks, ScanSummary, LiveFinding, Severity } from './types';
import { runNaabu, runNmap, runNuclei, runTestssl } from './tool-runners';
import { parseTargets }                             from '../target-parser';
import { generateFindingId }                        from '../finding-id';

function bySeverityCount(findings: LiveFinding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

export async function runScan(opts: ScanOptions, cb: ScanCallbacks): Promise<void> {
  const scanId    = opts.scanId ?? `SCAN-${Date.now()}`;
  const startTime = new Date().toISOString();
  const allFindings: LiveFinding[] = [];
  const tools      = opts.tools;

  try {
    const targets = parseTargets(opts.targets);

    // ── Stage 1: naabu (port discovery) ──────────────────────────
    let hosts: import('./types').DiscoveredHost[] = [];
    if (tools.includes('naabu')) {
      cb.onStageStart('naabu');
      cb.onProgress(5, 'Port discovery starting…');
      try {
        hosts = await runNaabu(targets, opts.stealth, cb);
      } catch (e) {
        cb.onError('naabu', e instanceof Error ? e.message : String(e));
      }
      await cb.onStageComplete('naabu', `${hosts.length} host(s) with open ports`);
      cb.onProgress(25, 'Port discovery complete');
    }

    // ── Stage 2: nmap (service fingerprinting) ───────────────────
    if (tools.includes('nmap')) {
      cb.onStageStart('nmap');
      cb.onProgress(30, 'Service fingerprinting…');
      try {
        await runNmap(hosts, opts.stealth, cb);
      } catch (e) {
        cb.onError('nmap', e instanceof Error ? e.message : String(e));
      }
      await cb.onStageComplete('nmap', `${hosts.length} host(s) fingerprinted`);
      cb.onProgress(50, 'Service fingerprinting complete');
    }

    // ── Stages 3 + 4: nuclei + testssl in parallel ───────────────
    const nucleiFindings: LiveFinding[] = [];
    const testsslFindings: LiveFinding[] = [];

    await Promise.all([
      (async () => {
        if (!tools.includes('nuclei')) return;
        cb.onStageStart('nuclei');
        cb.onProgress(55, 'CVE scan starting…');
        try {
          const found = await runNuclei(hosts, cb);
          nucleiFindings.push(...found);
        } catch (e) {
          cb.onError('nuclei', e instanceof Error ? e.message : String(e));
        }
        await cb.onStageComplete('nuclei', `${nucleiFindings.length} match(es)`);
      })(),
      (async () => {
        if (!tools.includes('testssl')) return;
        cb.onStageStart('testssl');
        try {
          const found = await runTestssl(hosts, cb);
          testsslFindings.push(...found);
        } catch (e) {
          cb.onError('testssl', e instanceof Error ? e.message : String(e));
        }
        await cb.onStageComplete('testssl', `${testsslFindings.length} TLS issue(s)`);
      })(),
    ]);

    allFindings.push(...nucleiFindings, ...testsslFindings);
    cb.onProgress(80, 'Scanning complete');

    // ── Stage 5: AI triage (optional) ────────────────────────────
    if (process.env.ANTHROPIC_API_KEY) {
      try {
        const load = new Function('p', 'return import(p)') as (p: string) => Promise<{ triageFindings: (f: LiveFinding[]) => Promise<LiveFinding[]> }>;
        const m = await load('../ai-engine');
        const triaged = await m.triageFindings(allFindings);
        allFindings.length = 0;
        allFindings.push(...triaged);
        cb.onProgress(90, 'AI triage complete');
      } catch { /* skip silently */ }
    }

    // ── Stage 6: persist findings ─────────────────────────────────
    let savedCount = 0;
    if (opts.save) {
      try {
        const { saveFindings } = await import('../findings-store');
        savedCount = saveFindings(allFindings, opts.engagementId ?? scanId);
      } catch { /* skip silently */ }
    }

    cb.onProgress(100, 'Done');

    const endTime = new Date().toISOString();
    const summary: ScanSummary = {
      scanId,
      startTime,
      endTime,
      duration:      new Date(endTime).getTime() - new Date(startTime).getTime(),
      hostsScanned:  hosts.length,
      portsFound:    hosts.reduce((s, h) => s + h.ports.length, 0),
      totalFindings: allFindings.length,
      bySeverity:    bySeverityCount(allFindings),
      savedCount,
      engagementId:  opts.engagementId,
    };
    await cb.onComplete(summary);

  } catch (e) {
    cb.onError('pipeline', e instanceof Error ? e.message : String(e));
  }
}

// Re-export types for convenience
export { generateFindingId };
