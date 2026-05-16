import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import os from "os";
import path from "path";
import fs from "fs";

/* ─── Types ─── */
export interface ScanPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  extrainfo: string;
  cpe: string[];
}

export interface ScanHost {
  ip: string;
  hostname: string;
  state: string;
  os: string;
  osAccuracy: number;
  ports: ScanPort[];
  openCount: number;
  macAddress?: string;
  macVendor?: string;
}

export interface ScanResult {
  target: string;
  scanType: string;
  command: string;
  startTime: string;
  endTime: string;
  hosts: ScanHost[];
  totalHosts: number;
  upHosts: number;
  elapsed: string;
  rawXml?: string;
}

/* ─── Validation ─── */
const SAFE_TARGET = /^[a-zA-Z0-9.\-_/: ,]+$/;

function validateTarget(target: string): boolean {
  return SAFE_TARGET.test(target) && target.length < 200;
}

const SCAN_PROFILES: Record<string, string[]> = {
  quick:   ["-sV", "-F", "--version-intensity", "3"],
  service: ["-sV", "-sC", "-p", "21,22,23,25,53,80,110,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"],
  full:    ["-sV", "-sC", "-p-"],
  os:      ["-sV", "-O", "--osscan-guess"],
  vuln:    ["-sV", "--script", "vuln", "-F"],
  stealth: ["-sS", "-T2", "-F"],
};

/* ─── Parse nmap XML ─── */
function parseNmapXml(xml: string): ScanHost[] {
  const hosts: ScanHost[] = [];

  const hostMatches = xml.match(/<host[\s\S]*?<\/host>/g) ?? [];

  for (const hostXml of hostMatches) {
    const stateMatch = hostXml.match(/<status state="([^"]+)"/);
    const state = stateMatch?.[1] ?? "unknown";

    const ipMatch   = hostXml.match(/<address addr="([^"]+)" addrtype="ipv4"/);
    const macMatch  = hostXml.match(/<address addr="([^"]+)" addrtype="mac"(?:[^>]*vendor="([^"]*)")?/);
    const hostMatch = hostXml.match(/<hostname name="([^"]+)"/);
    const osMatch   = hostXml.match(/<osmatch name="([^"]+)"[^>]*accuracy="(\d+)"/);

    const ip       = ipMatch?.[1] ?? "unknown";
    const hostname = hostMatch?.[1] ?? ip;
    const osName   = osMatch?.[1] ?? "";
    const osAcc    = Number(osMatch?.[2] ?? 0);
    const mac      = macMatch?.[1];
    const macVendor= macMatch?.[2];

    /* Parse ports */
    const ports: ScanPort[] = [];
    const portMatches = hostXml.match(/<port[\s\S]*?<\/port>/g) ?? [];

    for (const portXml of portMatches) {
      const portId   = portXml.match(/portid="(\d+)"/)?.[1] ?? "0";
      const proto    = portXml.match(/protocol="([^"]+)"/)?.[1] ?? "tcp";
      const portState= portXml.match(/<state state="([^"]+)"/)?.[1] ?? "unknown";
      const svcName  = portXml.match(/<service name="([^"]+)"/)?.[1] ?? "";
      const product  = portXml.match(/product="([^"]+)"/)?.[1] ?? "";
      const version  = portXml.match(/version="([^"]+)"/)?.[1] ?? "";
      const extra    = portXml.match(/extrainfo="([^"]+)"/)?.[1] ?? "";

      const cpeMatches = portXml.match(/<cpe>([^<]+)<\/cpe>/g)?.map((c) => c.replace(/<\/?cpe>/g, "")) ?? [];

      ports.push({
        port: Number(portId), protocol: proto, state: portState,
        service: svcName, product, version, extrainfo: extra, cpe: cpeMatches,
      });
    }

    hosts.push({
      ip, hostname, state, os: osName, osAccuracy: osAcc,
      ports, openCount: ports.filter((p) => p.state === "open").length,
      macAddress: mac, macVendor,
    });
  }

  return hosts;
}

/* ─── Route Handler ─── */
export async function POST(req: NextRequest) {
  const body = await req.json();
  const { target, scanType = "quick" } = body as { target: string; scanType: string };

  if (!target || !validateTarget(target)) {
    return NextResponse.json({ error: "Invalid target. Use IP, hostname, or CIDR notation." }, { status: 400 });
  }

  const profileArgs = SCAN_PROFILES[scanType] ?? SCAN_PROFILES.quick;

  /* Write XML to a temp file */
  const xmlFile = path.join(os.tmpdir(), `adversa-scan-${Date.now()}.xml`);

  const args = [...profileArgs, "-oX", xmlFile, ...target.split(",").map((t) => t.trim())];
  const command = `nmap ${args.join(" ")}`;

  return new Promise<NextResponse>((resolve) => {
    let stdout = "";
    let stderr = "";
    const startTime = new Date().toISOString();
    const t0 = Date.now();

    const proc = spawn("nmap", args, { timeout: 300_000 });

    proc.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on("error", (err) => {
      resolve(NextResponse.json({ error: `nmap not found or failed to start: ${err.message}` }, { status: 503 }));
    });

    proc.on("close", (code) => {
      const endTime = new Date().toISOString();
      const elapsed = `${((Date.now() - t0) / 1000).toFixed(1)}s`;

      let xml = "";
      try {
        xml = fs.readFileSync(xmlFile, "utf-8");
        fs.unlinkSync(xmlFile);
      } catch {
        /* file may not exist if nmap errored */
      }

      if (code !== 0 && !xml) {
        resolve(NextResponse.json({
          error: `nmap exited with code ${code}. ${stderr.slice(0, 500)}`,
          stdout, stderr,
        }, { status: 400 }));
        return;
      }

      const hosts = parseNmapXml(xml);

      const result: ScanResult = {
        target,
        scanType,
        command,
        startTime,
        endTime,
        elapsed,
        hosts,
        totalHosts: hosts.length,
        upHosts: hosts.filter((h) => h.state === "up").length,
      };

      resolve(NextResponse.json(result));
    });
  });
}
