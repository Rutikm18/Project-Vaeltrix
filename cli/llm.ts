/**
 * LLM commentary woven into the CLI scan flow.
 * Calls Claude for: stage narration, inline finding context, attack path, and chat.
 */
import Anthropic               from '@anthropic-ai/sdk';
import type { LiveFinding, DiscoveredHost, ScanSummary } from '../lib/engine/types';

const MODEL = 'claude-sonnet-4-6';

function client(): Anthropic | null {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  return new Anthropic({ apiKey: key });
}

const SYSTEM = `You are ADVERSA, an AI penetration testing assistant embedded in a CLI tool.
You provide concise, actionable security analysis for operators running authorized VAPT engagements.
Responses are shown directly in the terminal — be terse, specific, and technically accurate.
Never fabricate CVEs or exploits. Use plain text only (no markdown, no headers, no bullet points unless listing items).`;

// ── Stage commentary ─────────────────────────────────────────────
export async function commentOnStage(
  stage:    string,
  summary:  string,
  hosts:    DiscoveredHost[],
  findings: LiveFinding[],
): Promise<string | null> {
  const ai = client();
  if (!ai) return null;

  const hostSummary = hosts.slice(0, 5).map(
    (h) => `${h.ip} [${h.ports.join(',')}]${h.os ? ` OS:${h.os}` : ''}`,
  ).join('; ');

  const prompt = `Stage "${stage}" just completed: ${summary}.
${hosts.length > 0 ? `Hosts so far: ${hostSummary}` : ''}
${findings.length > 0 ? `Findings so far: ${findings.length} total, ${findings.filter(f => f.severity === 'CRITICAL').length} critical, ${findings.filter(f => f.severity === 'HIGH').length} high.` : ''}
In 1-2 sentences, narrate what this stage revealed and what it means for the engagement.`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 120,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    return (msg.content[0] as { text: string }).text.trim();
  } catch {
    return null;
  }
}

// ── Inline finding context (batched per stage) ───────────────────
export async function explainFindings(findings: LiveFinding[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (findings.length === 0) return out;
  const ai = client();
  if (!ai) return out;

  const list = findings.slice(0, 10).map(
    (f, i) => `${i + 1}. [${f.severity}] ${f.host}${f.port ? `:${f.port}` : ''} — ${f.title}${f.cveIds?.length ? ` (${f.cveIds[0]})` : ''}`,
  ).join('\n');

  const prompt = `For each finding below, write a single sentence: what it means and whether it is immediately exploitable.
Format: N. <one sentence>
Findings:\n${list}`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 400,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    const text = (msg.content[0] as { text: string }).text.trim();
    const lines = text.split('\n');
    for (const line of lines) {
      const m = line.match(/^(\d+)\.\s+(.+)/);
      if (m) {
        const idx = parseInt(m[1]) - 1;
        if (idx >= 0 && idx < findings.length) {
          out.set(findings[idx].id, m[2].trim());
        }
      }
    }
  } catch { /* non-fatal */ }

  return out;
}

// ── Attack path suggestion (after all stages) ────────────────────
export async function suggestAttackPath(
  hosts:    DiscoveredHost[],
  findings: LiveFinding[],
  summary:  ScanSummary,
): Promise<string | null> {
  const ai = client();
  if (!ai) return null;
  if (findings.length === 0) return null;

  const top = findings
    .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 8)
    .map((f) => `- [${f.severity}] ${f.host}${f.port ? `:${f.port}` : ''}: ${f.title}${f.cveIds?.[0] ? ` (${f.cveIds[0]})` : ''}`)
    .join('\n');

  const prompt = `Network VAPT scan completed.
Hosts: ${summary.hostsScanned}, Findings: ${summary.totalFindings} (${summary.bySeverity.CRITICAL} critical, ${summary.bySeverity.HIGH} high).
Top findings:\n${top}

Recommend the 2-3 most promising attack paths in order of exploitability. Be specific about which host/port/CVE to start with and why.`;

  try {
    const msg = await ai.messages.create({
      model:      MODEL,
      max_tokens: 350,
      system:     SYSTEM,
      messages:   [{ role: 'user', content: prompt }],
    });
    return (msg.content[0] as { text: string }).text.trim();
  } catch {
    return null;
  }
}

// ── Interactive ask (streaming) ──────────────────────────────────
export async function streamAsk(
  question:      string,
  findings:      LiveFinding[],
  hosts:         DiscoveredHost[],
  onChunk:       (text: string) => void,
  history:       { role: 'user' | 'assistant'; content: string }[] = [],
): Promise<void> {
  const ai = client();
  if (!ai) {
    onChunk('ANTHROPIC_API_KEY not set — cannot use AI features.\n');
    return;
  }

  const context = findings.length > 0
    ? `Current scan context: ${findings.length} findings (${findings.filter(f => f.severity === 'CRITICAL').length} critical, ${findings.filter(f => f.severity === 'HIGH').length} high). Hosts: ${hosts.map(h => h.ip).slice(0, 10).join(', ')}.`
    : '';

  const messages: Anthropic.MessageParam[] = [
    ...history,
    { role: 'user', content: context ? `${context}\n\n${question}` : question },
  ];

  const stream = ai.messages.stream({
    model:      MODEL,
    max_tokens: 1024,
    system:     SYSTEM,
    messages,
  });

  for await (const chunk of stream) {
    if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text_delta') {
      onChunk(chunk.delta.text);
    }
  }
}
