"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  Terminal, Play, Square, Download, ChevronDown, ChevronRight,
  Wifi, Server, Monitor, Shield, AlertTriangle, Copy, Check, Plus,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
interface ScanPort { port: number; protocol: string; state: string; service: string; product: string; version: string; extrainfo: string; cpe: string[]; }
interface ScanHost { ip: string; hostname: string; state: string; os: string; osAccuracy: number; ports: ScanPort[]; openCount: number; macAddress?: string; macVendor?: string; }
interface ScanResult { target: string; scanType: string; command: string; startTime: string; endTime: string; elapsed: string; hosts: ScanHost[]; totalHosts: number; upHosts: number; }

/* ─── Scan Profiles ─── */
const PROFILES: { key: string; label: string; desc: string; time: string; color: string }[] = [
  { key: "quick",   label: "Quick Scan",       desc: "Top 100 ports, service detection",              time: "~30s",  color: "#00D4FF" },
  { key: "service", label: "Service Detection", desc: "Common service ports + version fingerprinting", time: "~60s",  color: "#00FF88" },
  { key: "full",    label: "Full Port Scan",    desc: "All 65535 ports, scripts, version detection",   time: "5-20m", color: "#FFD600" },
  { key: "os",      label: "OS Detection",      desc: "OS fingerprinting + version detection",         time: "~90s",  color: "#FF9900" },
  { key: "vuln",    label: "Vulnerability",     desc: "NSE vuln scripts on common ports",              time: "2-5m",  color: "#FF6D00" },
  { key: "stealth", label: "Stealth (SYN)",     desc: "Low-noise SYN scan, slow timing",               time: "2-10m", color: "#9C27B0" },
];

/* ─── Helpers ─── */
function portRisk(port: number): string {
  const critical = [21, 22, 23, 25, 445, 1433, 3389, 5432, 27017];
  const high     = [80, 443, 8080, 8443, 3306, 6379, 5900, 9200];
  if (critical.includes(port)) return "CRITICAL";
  if (high.includes(port)) return "HIGH";
  return "INFO";
}

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", INFO: "#3D7A94",
};

function HostTypeIcon({ host }: { host: ScanHost }) {
  const label = (host.hostname + host.os).toLowerCase();
  if (label.includes("windows") || label.includes("dc")) return <Monitor size={14} color="#00D4FF" />;
  if (label.includes("linux") || label.includes("ubuntu") || label.includes("centos")) return <Server size={14} color="#00FF88" />;
  if (label.includes("firewall") || label.includes("palo") || label.includes("cisco")) return <Shield size={14} color="#FF9900" />;
  return <Wifi size={14} color="#3D7A94" />;
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={copy} style={{ background: "none", border: "none", cursor: "pointer", color: copied ? "#00FF88" : "#3D7A94", padding: "2px 4px" }}>
      {copied ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}

/* ─── Host Card ─── */
function HostCard({ host, onExportFinding }: { host: ScanHost; onExportFinding: (h: ScanHost, p: ScanPort) => void }) {
  const [expanded, setExpanded] = useState(host.openCount > 0);
  const riskPorts = host.ports.filter((p) => p.state === "open" && portRisk(p.port) !== "INFO");

  return (
    <div
      className="card-hover stagger-item"
      style={{ background: "#0A1520", border: "1px solid #1A3A50", borderRadius: 6, marginBottom: 8, overflow: "hidden" }}
    >
      {/* Host header */}
      <div
        onClick={() => setExpanded((p) => !p)}
        style={{ padding: "12px 16px", display: "flex", alignItems: "center", gap: 12, cursor: "pointer" }}
      >
        <HostTypeIcon host={host} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 13, color: "#00D4FF" }}>{host.ip}</span>
            {host.hostname !== host.ip && (
              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>{host.hostname}</span>
            )}
            <span style={{
              fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
              color: host.state === "up" ? "#00FF88" : "#FF1744",
              background: host.state === "up" ? "rgba(0,255,136,0.1)" : "rgba(255,23,68,0.1)",
              border: `1px solid ${host.state === "up" ? "rgba(0,255,136,0.25)" : "rgba(255,23,68,0.25)"}`,
              borderRadius: 3, padding: "1px 5px",
            }}>
              {host.state.toUpperCase()}
            </span>
          </div>
          <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 12, color: "#3D7A94", marginTop: 2 }}>
            {host.os ? `${host.os}${host.osAccuracy ? ` (${host.osAccuracy}%)` : ""}` : "OS unknown"}
            {host.macVendor ? ` · ${host.macVendor}` : ""}
          </div>
        </div>

        {/* Badges */}
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          {riskPorts.length > 0 && (
            <span style={{
              fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#FF1744",
              background: "rgba(255,23,68,0.1)", border: "1px solid rgba(255,23,68,0.25)",
              borderRadius: 3, padding: "1px 6px",
            }}>
              {riskPorts.length} HIGH RISK
            </span>
          )}
          <span style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00D4FF",
            background: "rgba(0,212,255,0.1)", border: "1px solid rgba(0,212,255,0.2)",
            borderRadius: 3, padding: "1px 6px",
          }}>
            {host.openCount} OPEN
          </span>
          {expanded ? <ChevronDown size={14} color="#3D7A94" /> : <ChevronRight size={14} color="#3D7A94" />}
        </div>
      </div>

      {/* Port table */}
      {expanded && host.ports.length > 0 && (
        <div style={{ borderTop: "1px solid #1A3A50", overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 500 }}>
            <thead>
              <tr style={{ background: "#050A0E" }}>
                {["PORT", "STATE", "SERVICE", "VERSION", "RISK", "ACTION"].map((h) => (
                  <th key={h} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", padding: "8px 12px", textAlign: "left", borderBottom: "1px solid #1A3A50" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {host.ports.filter((p) => p.state === "open").map((p, i) => {
                const risk = portRisk(p.port);
                return (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(26,58,80,0.2)" }}>
                    <td style={{ padding: "8px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00D4FF" }}>
                      {p.port}/{p.protocol}
                    </td>
                    <td style={{ padding: "8px 12px" }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00FF88", background: "rgba(0,255,136,0.08)", borderRadius: 3, padding: "1px 5px" }}>
                        {p.state}
                      </span>
                    </td>
                    <td style={{ padding: "8px 12px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>
                      {p.service || "—"}
                    </td>
                    <td style={{ padding: "8px 12px", fontFamily: "'Rajdhani', sans-serif", fontSize: 12, color: "#3D7A94", maxWidth: 200 }}>
                      {[p.product, p.version, p.extrainfo].filter(Boolean).join(" ") || "—"}
                    </td>
                    <td style={{ padding: "8px 12px" }}>
                      {risk !== "INFO" && (
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: RISK_COLOR[risk], background: `${RISK_COLOR[risk]}15`, border: `1px solid ${RISK_COLOR[risk]}30`, borderRadius: 3, padding: "1px 5px" }}>
                          {risk}
                        </span>
                      )}
                    </td>
                    <td style={{ padding: "8px 12px" }}>
                      {risk !== "INFO" && (
                        <button
                          onClick={() => onExportFinding(host, p)}
                          style={{
                            display: "flex", alignItems: "center", gap: 4, padding: "3px 8px",
                            background: "rgba(255,23,68,0.08)", border: "1px solid rgba(255,23,68,0.2)",
                            borderRadius: 3, color: "#FF4444", cursor: "pointer",
                            fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
                          }}
                        >
                          <Plus size={9} /> FINDING
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ─── Main Page ─── */
export default function ScanPage() {
  const { success, error: toastError, info } = useToast();
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [showRaw, setShowRaw] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const appendLog = useCallback((line: string) => {
    setLogs((prev) => [...prev.slice(-200), line]);
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 0);
  }, []);

  const runScan = useCallback(async () => {
    if (!target.trim()) { toastError("Target required", "Enter an IP, hostname, or CIDR range."); return; }
    setScanning(true);
    setResult(null);
    setLogs([]);
    appendLog(`[${new Date().toISOString()}] Starting ${scanType} scan against ${target}`);
    appendLog(`[INFO] Sending request to /api/scan/nmap...`);

    abortRef.current = new AbortController();

    try {
      const res = await fetch("/api/scan/nmap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), scanType }),
        signal: abortRef.current.signal,
      });

      const data = await res.json();

      if (!res.ok) {
        appendLog(`[ERROR] ${data.error}`);
        toastError("Scan failed", data.error?.slice(0, 100));
        return;
      }

      const r = data as ScanResult;
      setResult(r);

      appendLog(`[INFO] Command: ${r.command}`);
      appendLog(`[INFO] Scan started: ${r.startTime}`);
      appendLog(`[INFO] Elapsed: ${r.elapsed}`);
      appendLog(`[RESULTS] ${r.totalHosts} hosts scanned, ${r.upHosts} up`);
      r.hosts.forEach((h) => {
        if (h.state === "up") {
          appendLog(`[HOST] ${h.ip}${h.hostname !== h.ip ? ` (${h.hostname})` : ""} — ${h.openCount} open ports${h.os ? ` — ${h.os}` : ""}`);
          h.ports.filter((p) => p.state === "open").forEach((p) => {
            const svc = [p.service, p.product, p.version].filter(Boolean).join(" ");
            appendLog(`  ${h.ip}  ${p.port}/${p.protocol}  open  ${svc}`);
          });
        }
      });
      appendLog(`[DONE] Scan completed in ${r.elapsed}`);
      success("Scan complete", `${r.upHosts} hosts up, scan finished in ${r.elapsed}`);
    } catch (e: unknown) {
      if (e instanceof Error && e.name === "AbortError") {
        appendLog("[INFO] Scan aborted by user.");
        info("Scan aborted", "");
      } else {
        appendLog(`[ERROR] ${String(e)}`);
        toastError("Scan error", String(e).slice(0, 100));
      }
    } finally {
      setScanning(false);
    }
  }, [target, scanType, appendLog, success, toastError, info]);

  const stopScan = () => { abortRef.current?.abort(); };

  const exportToFindings = useCallback((host: ScanHost, port: ScanPort) => {
    const svc = [port.product, port.version].filter(Boolean).join(" ");
    const msg = `${host.ip}:${port.port} (${port.service}${svc ? " " + svc : ""}) — tagged for manual finding creation.`;
    info("Export to Findings", msg);
    success("Port tagged", `${host.ip}:${port.port}/${port.service} added to finding queue.`);
  }, [info, success]);

  const exportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `adversa-scan-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const selectedProfile = PROFILES.find((p) => p.key === scanType)!;

  return (
    <PageShell
      title="NETWORK SCANNER"
      subtitle="NMAP v7+ · REAL-TIME · EVIDENCE CAPTURE"
      statusItems={
        result
          ? [
              { label: "HOSTS UP", value: String(result.upHosts), color: "#00FF88" },
              { label: "SCANNED", value: String(result.totalHosts), color: "#C8E8F0" },
              { label: "ELAPSED", value: result.elapsed, color: "#00D4FF" },
            ]
          : []
      }
    >
      <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 16, height: "100%" }}>

        {/* ── LEFT: Scan Config ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>

          {/* Target */}
          <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, padding: "14px 16px" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94", marginBottom: 8 }}>TARGET</div>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !scanning && runScan()}
              placeholder="192.168.1.1, 10.0.0.0/24"
              style={{
                width: "100%", boxSizing: "border-box",
                background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 5,
                padding: "8px 12px", color: "#C8E8F0",
                fontFamily: "'Share Tech Mono', monospace", fontSize: 12, outline: "none",
              }}
            />
            <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 11, color: "#3D7A94", marginTop: 5 }}>
              IP, hostname, CIDR, or comma-separated list
            </div>
          </div>

          {/* Scan Type */}
          <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, padding: "14px 16px" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94", marginBottom: 8 }}>SCAN PROFILE</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {PROFILES.map((p) => (
                <button
                  key={p.key}
                  onClick={() => setScanType(p.key)}
                  style={{
                    display: "flex", alignItems: "flex-start", gap: 10, padding: "8px 10px", borderRadius: 5, cursor: "pointer",
                    background: scanType === p.key ? `${p.color}10` : "transparent",
                    border: `1px solid ${scanType === p.key ? `${p.color}40` : "#1A3A50"}`,
                    textAlign: "left",
                  }}
                >
                  <div style={{ width: 6, height: 6, borderRadius: "50%", background: p.color, marginTop: 4, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: scanType === p.key ? p.color : "#C8E8F0" }}>{p.label}</span>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>{p.time}</span>
                    </div>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 11, color: "#3D7A94", marginTop: 2 }}>{p.desc}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Run Button */}
          <button
            onClick={scanning ? stopScan : runScan}
            disabled={!target.trim() && !scanning}
            style={{
              width: "100%", padding: "12px", borderRadius: 6,
              border: `1px solid ${scanning ? "rgba(255,23,68,0.4)" : target.trim() ? `${selectedProfile.color}50` : "#1A3A50"}`,
              background: scanning
                ? "rgba(255,23,68,0.15)"
                : target.trim() ? `${selectedProfile.color}20` : "rgba(61,122,148,0.1)",
              color: scanning ? "#FF1744" : target.trim() ? selectedProfile.color : "#3D7A94",
              fontFamily: "'Share Tech Mono', monospace", fontSize: 12, cursor: "pointer",
              display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
              transition: "all 0.15s ease",
            }}
          >
            {scanning ? (
              <><Square size={14} /> STOP SCAN</>
            ) : (
              <><Play size={14} /> RUN {selectedProfile.label.toUpperCase()}</>
            )}
          </button>

          {/* Nmap Reference */}
          <div style={{ background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 6, padding: "12px 14px" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginBottom: 8 }}>COMMON FLAGS</div>
            {[
              ["-sV",  "Service/version detection"],
              ["-sC",  "Default NSE scripts"],
              ["-O",   "OS fingerprinting"],
              ["-p-",  "All 65535 ports"],
              ["-F",   "Fast (top 100 ports)"],
              ["-T2",  "Slow / stealthy timing"],
              ["-sS",  "TCP SYN (stealth)"],
            ].map(([flag, desc]) => (
              <div key={flag} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#00D4FF", width: 36, flexShrink: 0 }}>{flag}</span>
                <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 11, color: "#3D7A94" }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── RIGHT: Results ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12, minWidth: 0 }}>

          {/* Live terminal */}
          <div style={{ background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6, overflow: "hidden" }}>
            <div style={{ padding: "8px 14px", borderBottom: "1px solid #1A3A50", display: "flex", alignItems: "center", gap: 8, justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Terminal size={13} color="#00D4FF" />
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>SCAN OUTPUT</span>
                {scanning && <span className="animate-pulse-dot" style={{ display: "inline-block", width: 7, height: 7, borderRadius: "50%", background: "#00FF88" }} />}
              </div>
              {logs.length > 0 && <CopyBtn text={logs.join("\n")} />}
            </div>
            <div
              ref={logRef}
              style={{ height: 200, overflowY: "auto", padding: "10px 14px", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, lineHeight: 1.6 }}
            >
              {logs.length === 0 ? (
                <span style={{ color: "#3D7A94" }}>Ready. Configure target and press RUN SCAN.</span>
              ) : (
                logs.map((line, i) => {
                  const color = line.startsWith("[ERROR]") ? "#FF1744"
                    : line.startsWith("[DONE]") ? "#00FF88"
                    : line.startsWith("[HOST]") ? "#00D4FF"
                    : line.startsWith("[RESULTS]") ? "#FFD600"
                    : "#C8E8F0";
                  return (
                    <div key={i} style={{ color, marginBottom: 1 }}>{line}</div>
                  );
                })
              )}
            </div>
          </div>

          {/* Results */}
          {result && (
            <>
              {/* Summary bar */}
              <div style={{
                display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1,
                background: "#1A3A50", borderRadius: 6, overflow: "hidden",
              }}>
                {[
                  { label: "TOTAL HOSTS",  value: result.totalHosts, color: "#C8E8F0" },
                  { label: "HOSTS UP",     value: result.upHosts,    color: "#00FF88" },
                  { label: "OPEN PORTS",   value: result.hosts.reduce((a, h) => a + h.openCount, 0), color: "#00D4FF" },
                  { label: "ELAPSED",      value: result.elapsed,    color: "#FFD600" },
                ].map((m) => (
                  <div key={m.label} style={{ background: "#0D1B26", padding: "10px 14px", textAlign: "center" }}>
                    <div className="animate-fade-up" style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 22, fontWeight: 700, color: m.color, lineHeight: 1 }}>{m.value}</div>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginTop: 3 }}>{m.label}</div>
                  </div>
                ))}
              </div>

              {/* Host cards */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>
                  {result.hosts.filter((h) => h.state === "up").length} host(s) up · {result.scanType} · {result.target}
                </span>
                <div style={{ display: "flex", gap: 8 }}>
                  <button
                    onClick={() => setShowRaw(!showRaw)}
                    style={{ padding: "5px 12px", background: "transparent", border: "1px solid #1A3A50", borderRadius: 4, color: "#3D7A94", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, cursor: "pointer" }}
                  >
                    {showRaw ? "HIDE" : "RAW"} JSON
                  </button>
                  <button
                    onClick={exportJson}
                    style={{ padding: "5px 12px", background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)", borderRadius: 4, color: "#00D4FF", fontFamily: "'Share Tech Mono', monospace", fontSize: 10, cursor: "pointer", display: "flex", alignItems: "center", gap: 4 }}
                  >
                    <Download size={11} /> EXPORT JSON
                  </button>
                </div>
              </div>

              {showRaw && (
                <pre style={{ background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6, padding: 14, overflow: "auto", maxHeight: 300, fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#C8E8F0" }}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              )}

              <div>
                {result.hosts
                  .filter((h) => h.state === "up")
                  .map((h, i) => <HostCard key={i} host={h} onExportFinding={exportToFindings} />)}
              </div>
            </>
          )}

          {!result && !scanning && (
            <div style={{
              flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
              border: "1px dashed #1A3A50", borderRadius: 8, padding: 40, gap: 12,
            }}>
              <Terminal size={36} color="#1A3A50" />
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 13, color: "#3D7A94" }}>NO SCAN RESULTS</div>
              <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 13, color: "#3D7A94", textAlign: "center", maxWidth: 300 }}>
                Enter a target IP, hostname, or CIDR range and select a scan profile to begin.
              </div>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
