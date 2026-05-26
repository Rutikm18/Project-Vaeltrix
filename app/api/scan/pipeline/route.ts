import { NextRequest } from "next/server";
import {
  createInitialPipelineState,
  computeOverallProgress,
  getPipeline,
  setPipeline,
  pushScanEvent,
  drainScanEvents,
  PROFILE_TOOLS,
  type ScanTool,
  type ScanProfile,
  type PipelineState,
  type StageState,
} from "../../../../lib/scan-pipeline";
import { parseNucleiLine, nucleiMatchToFinding, countBySeverity, type NucleiRawLine } from "../../../../lib/nuclei-parser";
import { parseTestsslOutput, type TestsslOutput } from "../../../../lib/testssl-parser";
import { parseNmapXml } from "../../scan/nmap/route";
import { createFinding } from "../../../../lib/findings-store";
import { spawn } from "child_process";
import { writeFileSync, readFileSync, existsSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

const SAFE_TARGET = /^[a-zA-Z0-9.\-_/:,]+$/;

/* ── Nuclei templates shipped in the image (installed at build time) ── */
const NUCLEI_TEMPLATES = "/opt/nuclei-templates";

/* ── Shell out helper ─────────────────────────────────────────────── */
async function runCmd(
  cmd: string,
  args: string[],
  timeoutMs = 300_000,
  extraEnv: Record<string, string> = {},
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    const proc = spawn(cmd, args, {
      timeout: timeoutMs,
      env: { ...process.env, ...extraEnv },
    });
    proc.stdout?.on("data", (d: Buffer) => { stdout += d.toString(); });
    proc.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
    proc.on("error", (e) => resolve({ stdout, stderr: e.message, code: -1 }));
    proc.on("close", (code) => resolve({ stdout, stderr, code }));
  });
}

/* ── Severity → risk bucket ──────────────────────────────────────── */
function severityToRisk(sev: string): "critical" | "high" | "medium" | "low" | "none" {
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high")     return "high";
  if (s === "medium")   return "medium";
  if (s === "low")      return "low";
  return "none";
}

/* ── STAGE: naabu — fast port discovery ──────────────────────────── */
async function runNaabuStage(
  scanId: string,
  targets: string[],
  update: (s: Partial<StageState>) => void,
): Promise<Record<string, number[]>> {
  update({ status: "running", progress: 10, message: "Discovering open ports…" });

  const targetsFile = join(tmpdir(), `pipeline-naabu-${Date.now()}.txt`);
  const outputFile  = join(tmpdir(), `pipeline-naabu-out-${Date.now()}.json`);
  writeFileSync(targetsFile, targets.join("\n"));

  const { stderr, code } = await runCmd("naabu", [
    "-list", targetsFile,
    "-rate", "1000",
    "-json", "-o", outputFile,
    "-silent",
    "-top-ports", "1000",
    // TCP connect scan — works without CAP_NET_RAW (fallback for non-root)
    "-scan-type", "connect",
  ], 300_000);

  try { unlinkSync(targetsFile); } catch { /* ignore */ }

  if (code === -1) {
    // naabu binary not found
    update({ status: "error", progress: 0, message: `naabu not found: ${stderr.slice(0, 200)}` });
    return {};
  }

  const portMap: Record<string, number[]> = {};
  if (existsSync(outputFile)) {
    const lines = readFileSync(outputFile, "utf-8").split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const obj = JSON.parse(line) as { ip: string; port: number };
        portMap[obj.ip] = [...(portMap[obj.ip] ?? []), obj.port];
      } catch { /* skip */ }
    }
    try { unlinkSync(outputFile); } catch { /* ignore */ }
  }

  // Emit a host_discovered event for each IP naabu found
  const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 5000]);
  for (const [ip, ports] of Object.entries(portMap)) {
    const hasWeb = ports.some((p) => WEB_PORTS.has(p));
    pushScanEvent(scanId, {
      type: "host_discovered",
      host: { ip, ports: ports.length, hasWeb, hasAD: false, risk: "none" },
    });
  }

  const hostCount = Object.keys(portMap).length;
  const portCount = Object.values(portMap).reduce((s, p) => s + p.length, 0);
  update({ status: "done", progress: 100, message: `${hostCount} hosts · ${portCount} open ports` });
  return portMap;
}

/* ── STAGE: nmap — service/OS fingerprinting ─────────────────────── */
async function runNmapStage(
  scanId: string,
  targets: string[],
  naabuPorts: Record<string, number[]>,
  update: (s: Partial<StageState>) => void,
): Promise<unknown[]> {
  update({ status: "running", progress: 10, message: "Fingerprinting services…" });

  // Prefer the specific IPs naabu discovered; fall back to original targets
  const scanTargets = Object.keys(naabuPorts).length > 0
    ? Object.keys(naabuPorts)
    : targets;

  const allPorts = [...new Set(Object.values(naabuPorts).flat())].sort((a, b) => a - b);
  const portArg  = allPorts.length > 0 ? allPorts.join(",") : "top-1000";

  const xmlFile = join(tmpdir(), `pipeline-nmap-${Date.now()}.xml`);

  // -sT: TCP connect scan (no raw socket, works without root)
  // -sV: service version detection
  // --version-intensity 5: balanced speed vs accuracy
  const args = [
    "-sT", "-sV", "--version-intensity", "5",
    "-p", portArg,
    "-oX", xmlFile,
    ...scanTargets,
  ];

  const { stderr, code } = await runCmd("nmap", args, 600_000);
  if (code === -1) {
    update({ status: "error", progress: 0, message: `nmap not found: ${stderr.slice(0, 200)}` });
    return [];
  }

  update({ status: "running", progress: 80, message: "Parsing service data…" });

  let hosts: unknown[] = [];
  if (existsSync(xmlFile)) {
    const xml = readFileSync(xmlFile, "utf-8");
    hosts = parseNmapXml(xml);
    try { unlinkSync(xmlFile); } catch { /* ignore */ }
  }

  // Re-emit hosts with richer service data now that nmap has finished
  const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 5000]);
  const AD_PORTS  = new Set([88, 389, 445, 636, 3268, 3269]);
  for (const h of hosts as Array<{ ip: string; ports: Array<{ port: number; state: string }>; hostname: string }>) {
    const openPorts = h.ports.filter((p) => p.state === "open").map((p) => p.port);
    const hasWeb = openPorts.some((p) => WEB_PORTS.has(p));
    const hasAD  = openPorts.some((p) => AD_PORTS.has(p));
    pushScanEvent(scanId, {
      type: "host_discovered",
      host: {
        ip: h.ip,
        hostname: h.hostname !== h.ip ? h.hostname : undefined,
        ports: openPorts.length,
        hasWeb,
        hasAD,
        risk: hasAD ? "high" : hasWeb ? "medium" : "low",
      },
    });
  }

  update({ status: "done", progress: 100, message: `${hosts.length} hosts fingerprinted` });
  return hosts;
}

/* ── STAGE: nuclei — CVE + misconfiguration scanning ─────────────── */
async function runNucleiStage(
  scanId: string,
  targets: string[],
  createFindings: boolean,
  update: (s: Partial<StageState>) => void,
): Promise<{ matches: unknown[]; findingIds: string[] }> {
  update({ status: "running", progress: 10, message: "Running vulnerability scan…" });

  const targetsFile = join(tmpdir(), `pipeline-nuclei-targets-${Date.now()}.txt`);
  const outputFile  = join(tmpdir(), `pipeline-nuclei-out-${Date.now()}.jsonl`);
  writeFileSync(targetsFile, targets.join("\n"));

  const args = [
    "-l", targetsFile,
    "-tags", "cves,misconfigs,default-logins,exposed-panels,ssl,network",
    "-severity", "critical,high,medium",
    "-json-export", outputFile,
    "-rate-limit", "50",
    "-c", "25",
    "-retries", "1",
    "-timeout", "5",
    "-duc",     // disable update check
    "-silent",
  ];

  // Use pre-fetched templates if available; nuclei will skip network fetch
  if (existsSync(NUCLEI_TEMPLATES)) {
    args.push("-t", NUCLEI_TEMPLATES);
  }

  const { stderr, code } = await runCmd("nuclei", args, 600_000, { HOME: "/opt" });

  try { unlinkSync(targetsFile); } catch { /* ignore */ }

  if (code === -1) {
    update({ status: "error", progress: 0, message: `nuclei not found: ${stderr.slice(0, 200)}` });
    return { matches: [], findingIds: [] };
  }

  const matches = [];
  const findingIds: string[] = [];

  if (existsSync(outputFile)) {
    const lines = readFileSync(outputFile, "utf-8").split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const raw = JSON.parse(line) as NucleiRawLine;
        const match = parseNucleiLine(raw);
        matches.push(match);

        // Stream finding to UI immediately
        const sev = (match.severity.toUpperCase()) as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
        pushScanEvent(scanId, {
          type: "finding",
          finding: {
            id:        `nuclei-${Date.now()}-${matches.length}`,
            title:     match.templateName,
            severity:  sev,
            host:      match.ip,
            source:    "CVE Engine",
            timestamp: new Date().toISOString(),
          },
        });

        if (createFindings && match.severity !== "info") {
          try {
            const f = createFinding({ ...nucleiMatchToFinding(match) });
            findingIds.push(f.id);
          } catch { /* skip */ }
        }

        // Update progress as we find things
        update({ progress: Math.min(90, 10 + matches.length * 5), message: `${matches.length} matches found…` });
      } catch { /* skip malformed lines */ }
    }
    try { unlinkSync(outputFile); } catch { /* ignore */ }
  }

  const stats = countBySeverity(matches as ReturnType<typeof parseNucleiLine>[]);
  update({
    status: "done", progress: 100,
    message: `${matches.length} matches · ${stats.critical} critical · ${stats.high} high`,
  });
  return { matches, findingIds };
}

/* ── STAGE: testssl.sh — TLS analysis ───────────────────────────── */
async function runTestsslStage(
  scanId: string,
  nmapHosts: unknown[],
  createFindings: boolean,
  update: (s: Partial<StageState>) => void,
): Promise<unknown[]> {
  update({ status: "running", progress: 10, message: "Analyzing TLS configuration…" });

  const webPorts = [443, 8443, 4443];
  const tlsTargets = (nmapHosts as Array<{ ip: string; ports: Array<{ port: number; state: string }> }>)
    .filter((h) => h.ports?.some((p) => webPorts.includes(p.port) && p.state === "open"))
    .map((h) => h.ip);

  if (tlsTargets.length === 0) {
    update({ status: "done", progress: 100, message: "No TLS services found" });
    return [];
  }

  const allFindings: ReturnType<typeof parseTestsslOutput> = [];
  for (const target of tlsTargets.slice(0, 10)) {
    const outFile = join(tmpdir(), `pipeline-testssl-${Date.now()}.json`);
    const { code } = await runCmd(
      "testssl.sh",
      ["--jsonfile", outFile, "--severity", "LOW", "--color", "0", "--fast", "--quiet", target],
      300_000,
    );
    if (code === -1) {
      update({ status: "error", progress: 0, message: "testssl.sh not found" });
      return [];
    }
    if (existsSync(outFile)) {
      try {
        const data = JSON.parse(readFileSync(outFile, "utf-8")) as TestsslOutput;
        const findings = parseTestsslOutput(data, target);
        allFindings.push(...findings);

        // Stream TLS findings to UI
        for (const f of findings) {
          pushScanEvent(scanId, {
            type: "finding",
            finding: {
              id:        `testssl-${Date.now()}`,
              title:     (f as { title?: string }).title ?? "TLS Issue",
              severity:  (f as { severity?: string }).severity ?? "MEDIUM",
              host:      target,
              source:    "TLS Analyzer",
              timestamp: new Date().toISOString(),
            },
          });
        }

        if (createFindings) {
          for (const f of findings) {
            try { createFinding(f as Parameters<typeof createFinding>[0]); } catch { /* skip */ }
          }
        }
        unlinkSync(outFile);
      } catch { /* ignore parse errors */ }
    }
  }

  update({ status: "done", progress: 100, message: `${allFindings.length} TLS issues` });
  return allFindings;
}

/* ── STAGE: eyewitness — web screenshots ────────────────────────── */
async function runEyewitnessStage(
  nmapHosts: unknown[],
  createFindings: boolean,
  update: (s: Partial<StageState>) => void,
): Promise<unknown[]> {
  update({ status: "running", progress: 10, message: "Capturing web screenshots…" });

  const WEB_PORTS: Record<number, string> = {
    80: "http", 443: "https", 8080: "http", 8443: "https",
    8000: "http", 8888: "http", 3000: "http", 5000: "http",
  };
  const hosts = nmapHosts as Array<{ ip: string; ports: Array<{ port: number; state: string }> }>;
  const urls = hosts.flatMap((h) =>
    (h.ports ?? [])
      .filter((p) => p.state === "open" && WEB_PORTS[p.port])
      .map((p) => `${WEB_PORTS[p.port]}://${h.ip}:${p.port}`),
  );

  if (urls.length === 0) {
    update({ status: "done", progress: 100, message: "No web services found" });
    return [];
  }

  const urlFile   = join(tmpdir(), `pipeline-ew-urls-${Date.now()}.txt`);
  const outputDir = join(tmpdir(), `pipeline-ew-out-${Date.now()}`);
  writeFileSync(urlFile, urls.join("\n"));

  const { code } = await runCmd(
    "eyewitness",
    ["-f", urlFile, "-d", outputDir, "--no-prompt", "--timeout", "15", "--threads", "5", "--web", "--compress"],
    600_000,
  );
  try { unlinkSync(urlFile); } catch { /* ignore */ }

  if (code === -1) {
    update({ status: "error", progress: 0, message: "eyewitness not installed (optional)" });
    return [];
  }

  update({ status: "done", progress: 100, message: `${urls.length} URLs captured` });
  return urls;
}

/* ── Background pipeline orchestrator ───────────────────────────── */
async function runPipelineBackground(
  state: PipelineState,
  tools: ScanTool[],
  createFindings: boolean,
): Promise<void> {
  const { scanId, context } = state;

  function updateStage(tool: ScanTool, partial: Partial<StageState>) {
    const current = getPipeline(scanId);
    if (!current) return;
    const next = {
      ...current,
      stages: { ...current.stages, [tool]: { ...current.stages[tool], ...partial } },
    };
    next.overallProgress = computeOverallProgress(next.stages, tools);
    setPipeline(scanId, next);
  }

  function update(partial: Partial<PipelineState>) {
    const current = getPipeline(scanId);
    if (!current) return;
    setPipeline(scanId, { ...current, ...partial });
  }

  update({ status: "running" });

  let naabuPorts: Record<string, number[]> = {};
  let nmapHosts: unknown[] = [];
  const allFindingIds: string[] = [];

  try {
    // ── Port discovery
    if (tools.includes("naabu")) {
      naabuPorts = await runNaabuStage(scanId, context.targets, (s) => updateStage("naabu", s));
    }

    // ── Service fingerprinting (uses naabu port list)
    if (tools.includes("nmap")) {
      nmapHosts = await runNmapStage(scanId, context.targets, naabuPorts, (s) => updateStage("nmap", s));
    }

    // ── Vuln scan + TLS analysis in parallel
    const nucleiPromise = tools.includes("nuclei")
      ? runNucleiStage(scanId, context.targets, createFindings, (s) => updateStage("nuclei", s))
      : Promise.resolve({ matches: [], findingIds: [] as string[] });

    const testsslPromise = tools.includes("testssl")
      ? runTestsslStage(scanId, nmapHosts, createFindings, (s) => updateStage("testssl", s))
      : Promise.resolve([]);

    const [nucleiResult] = await Promise.all([nucleiPromise, testsslPromise]);
    allFindingIds.push(...nucleiResult.findingIds);

    // ── Screenshots (optional, non-blocking)
    if (tools.includes("eyewitness")) {
      await runEyewitnessStage(nmapHosts, createFindings, (s) => updateStage("eyewitness", s));
    }

    // ── AD modules — require agent + credentials, mark informational
    if (tools.includes("netexec")) {
      updateStage("netexec", { status: "skipped", progress: 100, message: "Requires domain credentials via agent" });
    }
    if (tools.includes("impacket")) {
      updateStage("impacket", { status: "skipped", progress: 100, message: "Requires domain credentials via agent" });
    }
    if (tools.includes("openvas")) {
      updateStage("openvas", { status: "skipped", progress: 100, message: "Start via /api/scan/openvas (long-running)" });
    }

    update({
      status: "complete",
      completedAt: new Date().toISOString(),
      totalFindings: allFindingIds.length,
      findingIds: allFindingIds,
      overallProgress: 100,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    update({ status: "error", completedAt: new Date().toISOString() });
    pushScanEvent(scanId, { type: "error", error: msg });
  }
}

/* ── POST /api/scan/pipeline ─────────────────────────────────────── */
export async function POST(req: NextRequest) {
  const body = await req.json() as {
    targets: string[];
    profile?: ScanProfile;
    tools?: ScanTool[];
    credentials?: { domain?: string; username?: string; password?: string; dcIp?: string };
    createFindings?: boolean;
    engagementId?: string;
  };

  const {
    targets,
    profile = "standard",
    tools = PROFILE_TOOLS[profile],
    credentials = {},
    createFindings = false,
  } = body;

  if (!targets || targets.length === 0 || !targets.every((t) => SAFE_TARGET.test(t) && t.length < 200)) {
    return new Response(
      `data: ${JSON.stringify({ type: "error", error: "Invalid or missing targets." })}\n\n`,
      { headers: { "Content-Type": "text/event-stream" } },
    );
  }

  const scanId = `pipeline-${Date.now()}`;
  const state  = createInitialPipelineState(scanId, targets, profile, credentials, tools);
  setPipeline(scanId, state);

  // Launch pipeline in background (non-blocking)
  runPipelineBackground(state, tools, createFindings);

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: unknown) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch { /* client disconnected */ }
      };

      send({ type: "pipeline_started", scanId, profile, tools, targets });

      let lastProgress = -1;
      const pollMs = 500;   // 500ms — fast enough for real-time UX
      let waited   = 0;
      const maxWait = 7_200_000; // 2 h hard cap

      while (waited < maxWait) {
        await new Promise((r) => setTimeout(r, pollMs));
        waited += pollMs;

        const current = getPipeline(scanId);
        if (!current) break;

        // Drain and forward all queued finding/host events first
        for (const ev of drainScanEvents(scanId)) {
          send(ev);
        }

        // Forward progress update when it changes
        if (current.overallProgress !== lastProgress) {
          lastProgress = current.overallProgress;
          send({
            type: "progress",
            scanId,
            overallProgress: current.overallProgress,
            stages: current.stages,
          });
        }

        if (current.status === "complete" || current.status === "error") {
          send({
            type: "pipeline_complete",
            scanId,
            status: current.status,
            totalFindings: current.totalFindings,
            findingIds: current.findingIds,
            stages: current.stages,
          });
          break;
        }
      }

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection":    "keep-alive",
    },
  });
}
