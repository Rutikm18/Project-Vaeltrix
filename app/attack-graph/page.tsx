"use client";

import React, { useState } from "react";
import { Menu, Network, Filter, ZoomIn, ZoomOut, Maximize2 } from "lucide-react";
import { Sidebar } from "../../components/Sidebar";

/* ─── Types ─── */
interface GraphNode {
  id: string;
  label: string;
  type: "workstation" | "server" | "dc" | "firewall" | "target" | "dmz";
  zone: string;
  x: number;
  y: number;
  compromised?: boolean;
}

interface GraphEdge {
  from: string;
  to: string;
  technique: string;
  ttpId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  validated: boolean;
}

interface PathDetail {
  id: string;
  name: string;
  steps: string[];
  technique: string;
  ttpId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  confidence: number;
  status: "VALIDATED" | "SIMULATING" | "PENDING";
}

/* ─── Data ─── */
const graphNodes: GraphNode[] = [
  { id: "fw1",        label: "FW-EXT",        type: "firewall",    zone: "PERIMETER", x: 60,  y: 200, compromised: false },
  { id: "web01",      label: "WEB-01",         type: "dmz",         zone: "DMZ",       x: 170, y: 140, compromised: false },
  { id: "web02",      label: "WEB-02",         type: "dmz",         zone: "DMZ",       x: 170, y: 280, compromised: false },
  { id: "fw2",        label: "FW-INT",         type: "firewall",    zone: "PERIMETER", x: 290, y: 200, compromised: false },
  { id: "ws042",      label: "WS-042",         type: "workstation", zone: "CORP",      x: 410, y: 130, compromised: true  },
  { id: "ws128",      label: "WS-128",         type: "workstation", zone: "CORP",      x: 410, y: 270, compromised: false },
  { id: "svcsql",     label: "SVC-SQL",        type: "server",      zone: "CORP",      x: 540, y: 130, compromised: true  },
  { id: "mgmtsrv",    label: "MGMT-SRV",       type: "server",      zone: "MGMT",      x: 540, y: 270, compromised: false },
  { id: "dc01",       label: "DC01",           type: "dc",          zone: "CORP",      x: 670, y: 130, compromised: true  },
  { id: "domadmin",   label: "DOMAIN ADMIN",   type: "target",      zone: "CORP",      x: 790, y: 130, compromised: true  },
];

const graphEdges: GraphEdge[] = [
  { from: "fw1",    to: "web01",    technique: "Port Traversal",        ttpId: "T1190",     severity: "MEDIUM",   validated: true  },
  { from: "fw1",    to: "web02",    technique: "Port Traversal",        ttpId: "T1190",     severity: "MEDIUM",   validated: true  },
  { from: "web01",  to: "fw2",      technique: "Pivot",                 ttpId: "T1572",     severity: "HIGH",     validated: false },
  { from: "web02",  to: "fw2",      technique: "Pivot",                 ttpId: "T1572",     severity: "HIGH",     validated: false },
  { from: "fw2",    to: "ws042",    technique: "LLMNR Poisoning",       ttpId: "T1557.001", severity: "CRITICAL", validated: true  },
  { from: "ws042",  to: "svcsql",   technique: "Kerberoasting",         ttpId: "T1558.003", severity: "CRITICAL", validated: true  },
  { from: "ws042",  to: "ws128",    technique: "Lateral Move (WMI)",    ttpId: "T1021.003", severity: "HIGH",     validated: true  },
  { from: "svcsql", to: "dc01",     technique: "Silver Ticket",         ttpId: "T1558.004", severity: "CRITICAL", validated: true  },
  { from: "mgmtsrv",to: "dc01",     technique: "DCSync Attempt",        ttpId: "T1003.006", severity: "HIGH",     validated: false },
  { from: "ws128",  to: "mgmtsrv",  technique: "WMI Remote Exec",       ttpId: "T1021.003", severity: "HIGH",     validated: false },
  { from: "dc01",   to: "domadmin", technique: "Unconstrained Deleg.",  ttpId: "T1134.001", severity: "CRITICAL", validated: true  },
];

const attackPaths: PathDetail[] = [
  {
    id: "AP-001",
    name: "LLMNR → Kerberoast → DC01 → DA",
    steps: ["WS-042", "SVC-SQL", "DC01", "DOMAIN ADMIN"],
    technique: "Kerberoasting + Unconstrained Delegation",
    ttpId: "T1558.003 / T1134.001",
    severity: "CRITICAL",
    confidence: 97,
    status: "VALIDATED",
  },
  {
    id: "AP-002",
    name: "WMI Lateral → MGMT → DCSync",
    steps: ["WS-042", "WS-128", "MGMT-SRV", "DC01"],
    technique: "WMI Remote Execution + DCSync",
    ttpId: "T1021.003 / T1003.006",
    severity: "HIGH",
    confidence: 82,
    status: "SIMULATING",
  },
  {
    id: "AP-003",
    name: "Web Pivot → CORP Breakout",
    steps: ["WEB-01", "FW-INT", "WS-042"],
    technique: "Network Pivot via Proxy",
    ttpId: "T1572",
    severity: "HIGH",
    confidence: 74,
    status: "SIMULATING",
  },
  {
    id: "AP-004",
    name: "VLAN30 → VLAN10 Bypass",
    steps: ["WS-128", "MGMT-SRV"],
    technique: "ACL Misconfiguration",
    ttpId: "T1599.001",
    severity: "MEDIUM",
    confidence: 71,
    status: "PENDING",
  },
];

const zoneColors: Record<string, string> = {
  PERIMETER: "#3D7A94",
  DMZ:       "#FF9900",
  CORP:      "#00D4FF",
  MGMT:      "#FF4444",
};

/* ─── Helpers ─── */
function severityColor(s: "CRITICAL" | "HIGH" | "MEDIUM") {
  if (s === "CRITICAL") return "#FF4444";
  if (s === "HIGH")     return "#FF9900";
  return "#FFD500";
}

function nodeColor(n: GraphNode) {
  if (n.compromised) return "#FF4444";
  if (n.type === "firewall") return "#3D7A94";
  if (n.type === "target")   return "#FF4444";
  if (n.type === "dc")       return "#FF9900";
  if (n.type === "dmz")      return "#FF9900";
  return "#00D4FF";
}

function edgeStroke(e: GraphEdge) {
  if (!e.validated) return "#3D7A94";
  return severityColor(e.severity);
}

/* ─── SVG Helpers ─── */
function getNode(id: string) {
  return graphNodes.find((n) => n.id === id)!;
}

/* ─── Main Page ─── */
export default function AttackGraphPage() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedPath, setSelectedPath] = useState<string | null>("AP-001");
  const [filterZone, setFilterZone] = useState<string>("ALL");
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const activePath = attackPaths.find((p) => p.id === selectedPath);

  const isNodeInPath = (nodeId: string) => {
    if (!selectedPath) return false;
    const path = attackPaths.find((p) => p.id === selectedPath);
    if (!path) return false;
    return path.steps.some((s) => {
      const n = graphNodes.find((nd) => nd.label === s);
      return n?.id === nodeId;
    });
  };

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: "#050A0E",
        fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
        overflow: "hidden",
      }}
    >
      {sidebarOpen && (
        <div
          className="md:hidden"
          onClick={() => setSidebarOpen(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(5,10,14,0.75)", zIndex: 40 }}
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Header */}
        <header
          style={{
            height: 52,
            borderBottom: "1px solid #1A3A50",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 20px",
            flexShrink: 0,
            background: "#050A0E",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              className="md:hidden"
              onClick={() => setSidebarOpen(true)}
              style={{ background: "none", border: "none", cursor: "pointer", padding: 0 }}
            >
              <Menu size={20} color="#00D4FF" />
            </button>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 18, color: "#00D4FF", letterSpacing: 3 }}>ADVERSA</span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>ATTACK GRAPH v0.9.1</span>
            <Network size={14} color="#00D4FF" style={{ marginLeft: 4 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF4444" }}>
              {graphNodes.filter((n) => n.compromised).length} NODES COMPROMISED
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#FF9900" }}>
              {attackPaths.length} ATTACK PATHS
            </span>
          </div>
        </header>

        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          {/* Main Graph Area */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {/* Toolbar */}
            <div
              style={{
                padding: "8px 16px",
                borderBottom: "1px solid #1A3A50",
                display: "flex",
                alignItems: "center",
                gap: 12,
                flexShrink: 0,
                background: "#050A0E",
              }}
            >
              <Filter size={13} color="#3D7A94" />
              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>ZONE:</span>
              {["ALL", "DMZ", "CORP", "MGMT", "PERIMETER"].map((z) => (
                <button
                  key={z}
                  onClick={() => setFilterZone(z)}
                  style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 10,
                    padding: "3px 10px",
                    borderRadius: 4,
                    border: "1px solid",
                    borderColor: filterZone === z ? "#00D4FF" : "#1A3A50",
                    background: filterZone === z ? "rgba(0,212,255,0.08)" : "transparent",
                    color: filterZone === z ? "#00D4FF" : "#3D7A94",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  {z}
                </button>
              ))}
              <div style={{ flex: 1 }} />
              <div style={{ display: "flex", gap: 4 }}>
                {[
                  { label: "CRITICAL", color: "#FF4444" },
                  { label: "HIGH",     color: "#FF9900" },
                  { label: "MEDIUM",   color: "#FFD500" },
                  { label: "UNVALIDATED", color: "#3D7A94" },
                ].map((l) => (
                  <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <div style={{ width: 20, height: 2, background: l.color }} />
                    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: l.color }}>{l.label}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* SVG Graph */}
            <div style={{ flex: 1, overflow: "hidden", position: "relative" }}>
              {/* Zone Labels */}
              <div
                style={{
                  position: "absolute",
                  top: 12,
                  left: 16,
                  display: "flex",
                  gap: 12,
                  zIndex: 2,
                }}
              >
                {Object.entries(zoneColors).map(([zone, color]) => (
                  <span
                    key={zone}
                    style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 9,
                      color,
                      letterSpacing: 1,
                      opacity: filterZone === "ALL" || filterZone === zone ? 1 : 0.2,
                    }}
                  >
                    ■ {zone}
                  </span>
                ))}
              </div>

              <svg
                width="100%"
                height="100%"
                viewBox="0 0 880 420"
                style={{ display: "block" }}
              >
                {/* Zone background bands */}
                <rect x="0"   y="0" width="120"  height="420" fill="rgba(61,122,148,0.04)" />
                <rect x="120" y="0" width="160"  height="420" fill="rgba(255,153,0,0.04)" />
                <rect x="280" y="0" width="400"  height="420" fill="rgba(0,212,255,0.03)" />
                <rect x="680" y="0" width="200"  height="420" fill="rgba(255,68,68,0.04)" />

                {/* Zone separators */}
                {[120, 280, 680].map((x) => (
                  <line key={x} x1={x} y1={0} x2={x} y2={420} stroke="#1A3A50" strokeWidth={1} strokeDasharray="4,4" />
                ))}

                {/* Zone labels */}
                {[
                  { x: 10,  label: "PERIMETER", color: "#3D7A94" },
                  { x: 130, label: "DMZ",        color: "#FF9900"  },
                  { x: 290, label: "CORP",        color: "#00D4FF"  },
                  { x: 690, label: "MGMT",        color: "#FF4444"  },
                ].map((z) => (
                  <text
                    key={z.label}
                    x={z.x}
                    y={14}
                    fill={z.color}
                    fontSize={8}
                    fontFamily="'Share Tech Mono', monospace"
                    opacity={0.5}
                  >
                    {z.label}
                  </text>
                ))}

                {/* Defs */}
                <defs>
                  <marker id="arrow-critical" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="#FF4444" />
                  </marker>
                  <marker id="arrow-high" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="#FF9900" />
                  </marker>
                  <marker id="arrow-medium" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="#FFD500" />
                  </marker>
                  <marker id="arrow-muted" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill="#3D7A94" />
                  </marker>
                  <filter id="glow-red">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                    <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                  <filter id="glow-cyan">
                    <feGaussianBlur stdDeviation="2" result="coloredBlur" />
                    <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                </defs>

                {/* Edges */}
                {graphEdges
                  .filter((e) => filterZone === "ALL" || true)
                  .map((edge, i) => {
                    const from = getNode(edge.from);
                    const to = getNode(edge.to);
                    if (!from || !to) return null;
                    const color = edge.validated ? severityColor(edge.severity) : "#3D7A94";
                    const markerId = edge.validated
                      ? edge.severity === "CRITICAL" ? "arrow-critical"
                        : edge.severity === "HIGH" ? "arrow-high" : "arrow-medium"
                      : "arrow-muted";
                    const inActivePath =
                      selectedPath &&
                      (() => {
                        const path = attackPaths.find((p) => p.id === selectedPath);
                        if (!path) return false;
                        const pathNodeIds = path.steps
                          .map((s) => graphNodes.find((n) => n.label === s)?.id)
                          .filter(Boolean);
                        const idx = pathNodeIds.indexOf(edge.from);
                        return idx >= 0 && pathNodeIds[idx + 1] === edge.to;
                      })();

                    return (
                      <g key={i}>
                        <line
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          stroke={color}
                          strokeWidth={inActivePath ? 2.5 : 1}
                          strokeOpacity={inActivePath ? 1 : 0.35}
                          strokeDasharray={edge.validated ? "none" : "5,3"}
                          markerEnd={`url(#${markerId})`}
                        />
                        {inActivePath && (
                          <text
                            x={(from.x + to.x) / 2}
                            y={(from.y + to.y) / 2 - 6}
                            fill={color}
                            fontSize={7.5}
                            fontFamily="'Share Tech Mono', monospace"
                            textAnchor="middle"
                          >
                            {edge.ttpId}
                          </text>
                        )}
                      </g>
                    );
                  })}

                {/* Nodes */}
                {graphNodes
                  .filter(
                    (n) =>
                      filterZone === "ALL" ||
                      n.zone === filterZone
                  )
                  .map((node) => {
                    const color = nodeColor(node);
                    const inPath = isNodeInPath(node.id);
                    const isHovered = hoveredNode === node.id;
                    const r = node.type === "target" ? 18 : node.type === "dc" ? 16 : 14;

                    return (
                      <g
                        key={node.id}
                        style={{ cursor: "pointer" }}
                        onMouseEnter={() => setHoveredNode(node.id)}
                        onMouseLeave={() => setHoveredNode(null)}
                      >
                        {/* Outer glow ring for active path nodes */}
                        {inPath && (
                          <circle
                            cx={node.x}
                            cy={node.y}
                            r={r + 8}
                            fill="none"
                            stroke={color}
                            strokeWidth={1}
                            strokeOpacity={0.3}
                            className="animate-pulse-dot"
                          />
                        )}
                        <circle
                          cx={node.x}
                          cy={node.y}
                          r={r}
                          fill={inPath ? `${color}22` : "#0D1B26"}
                          stroke={color}
                          strokeWidth={inPath ? 2 : 1}
                          filter={node.compromised ? "url(#glow-red)" : inPath ? "url(#glow-cyan)" : "none"}
                        />
                        {/* Node type icon shorthand */}
                        <text
                          x={node.x}
                          y={node.y + 4}
                          fill={color}
                          fontSize={node.type === "target" ? 8 : 7}
                          fontFamily="'Share Tech Mono', monospace"
                          textAnchor="middle"
                          fontWeight={inPath ? "bold" : "normal"}
                        >
                          {node.type === "dc" ? "DC" :
                           node.type === "firewall" ? "FW" :
                           node.type === "target" ? "DA" :
                           node.type === "dmz" ? "WEB" : "WS"}
                        </text>
                        {/* Label below node */}
                        <text
                          x={node.x}
                          y={node.y + r + 12}
                          fill={inPath ? color : "#3D7A94"}
                          fontSize={8.5}
                          fontFamily="'Share Tech Mono', monospace"
                          textAnchor="middle"
                        >
                          {node.label}
                        </text>
                        {/* Compromised marker */}
                        {node.compromised && (
                          <text x={node.x + r - 4} y={node.y - r + 4} fill="#FF4444" fontSize={9} textAnchor="middle">●</text>
                        )}
                        {/* Hover tooltip */}
                        {isHovered && (
                          <g>
                            <rect
                              x={node.x + 20}
                              y={node.y - 30}
                              width={120}
                              height={42}
                              rx={3}
                              fill="#0D1B26"
                              stroke="#1A3A50"
                              strokeWidth={1}
                            />
                            <text x={node.x + 28} y={node.y - 16} fill="#C8E8F0" fontSize={8} fontFamily="'Share Tech Mono', monospace">{node.label}</text>
                            <text x={node.x + 28} y={node.y - 5} fill={zoneColors[node.zone] || "#3D7A94"} fontSize={7.5} fontFamily="'Share Tech Mono', monospace">ZONE: {node.zone}</text>
                            <text x={node.x + 28} y={node.y + 6} fill={node.compromised ? "#FF4444" : "#00FF88"} fontSize={7.5} fontFamily="'Share Tech Mono', monospace">{node.compromised ? "COMPROMISED" : "INTACT"}</text>
                          </g>
                        )}
                      </g>
                    );
                  })}
              </svg>
            </div>
          </div>

          {/* Right Panel: Attack Paths */}
          <aside
            style={{
              width: 320,
              borderLeft: "1px solid #1A3A50",
              display: "flex",
              flexDirection: "column",
              flexShrink: 0,
              overflow: "hidden",
            }}
            className="hidden lg:flex"
          >
            <div
              style={{
                padding: "12px 16px",
                borderBottom: "1px solid #1A3A50",
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 12,
                color: "#C8E8F0",
                letterSpacing: 1,
              }}
            >
              ATTACK PATHS
            </div>

            <div style={{ flex: 1, overflowY: "auto" }}>
              {attackPaths.map((path) => {
                const isSelected = selectedPath === path.id;
                return (
                  <div
                    key={path.id}
                    onClick={() => setSelectedPath(isSelected ? null : path.id)}
                    style={{
                      padding: "12px 16px",
                      borderBottom: "1px solid rgba(26,58,80,0.4)",
                      cursor: "pointer",
                      background: isSelected ? "rgba(0,212,255,0.04)" : "transparent",
                      borderLeft: isSelected ? `2px solid ${severityColor(path.severity)}` : "2px solid transparent",
                      transition: "background 0.15s ease",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00D4FF" }}>{path.id}</span>
                      <span
                        style={{
                          fontFamily: "'Share Tech Mono', monospace",
                          fontSize: 9,
                          padding: "2px 6px",
                          borderRadius: 3,
                          background: `${severityColor(path.severity)}15`,
                          color: severityColor(path.severity),
                        }}
                      >
                        {path.severity}
                      </span>
                    </div>
                    <div
                      style={{
                        fontFamily: "'Rajdhani', sans-serif",
                        fontSize: 13,
                        color: "#C8E8F0",
                        marginBottom: 6,
                        fontWeight: 500,
                      }}
                    >
                      {path.name}
                    </div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 6 }}>
                      {path.steps.map((step, i) => (
                        <React.Fragment key={step}>
                          <span
                            style={{
                              fontFamily: "'Share Tech Mono', monospace",
                              fontSize: 9,
                              color: "#3D7A94",
                              padding: "1px 5px",
                              border: "1px solid #1A3A50",
                              borderRadius: 3,
                            }}
                          >
                            {step}
                          </span>
                          {i < path.steps.length - 1 && (
                            <span style={{ color: "#1A3A50", fontSize: 9 }}>→</span>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>{path.ttpId}</span>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <div
                          style={{
                            width: 50,
                            height: 3,
                            background: "rgba(26,58,80,0.4)",
                            borderRadius: 2,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              height: "100%",
                              width: `${path.confidence}%`,
                              background: path.confidence >= 90 ? "#00FF88" : path.confidence >= 75 ? "#00D4FF" : "#FF9900",
                            }}
                          />
                        </div>
                        <span
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: path.confidence >= 90 ? "#00FF88" : path.confidence >= 75 ? "#00D4FF" : "#FF9900",
                          }}
                        >
                          {path.confidence}%
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Selected path detail */}
            {activePath && (
              <div
                style={{
                  borderTop: "1px solid #1A3A50",
                  padding: "12px 16px",
                  background: "#050A0E",
                }}
              >
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginBottom: 8, letterSpacing: 1 }}>
                  PATH DETAIL
                </div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0", marginBottom: 4 }}>
                  Technique: <span style={{ color: "#00D4FF" }}>{activePath.technique}</span>
                </div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0", marginBottom: 4 }}>
                  MITRE ATT&CK: <span style={{ color: "#FF9900" }}>{activePath.ttpId}</span>
                </div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>
                  Status:{" "}
                  <span
                    style={{
                      color:
                        activePath.status === "VALIDATED"
                          ? "#00FF88"
                          : activePath.status === "SIMULATING"
                          ? "#FF9900"
                          : "#3D7A94",
                    }}
                  >
                    {activePath.status}
                  </span>
                </div>
              </div>
            )}
          </aside>
        </div>

        {/* Footer */}
        <footer
          style={{
            height: 32,
            borderTop: "1px solid #1A3A50",
            background: "#0D1B26",
            display: "flex",
            alignItems: "center",
            padding: "0 20px",
            gap: 16,
            flexShrink: 0,
          }}
        >
          {[
            { label: "NODES", value: graphNodes.length, color: "#C8E8F0" },
            { label: "EDGES", value: graphEdges.length, color: "#C8E8F0" },
            { label: "COMPROMISED", value: graphNodes.filter((n) => n.compromised).length, color: "#FF4444" },
            { label: "VALIDATED PATHS", value: attackPaths.filter((p) => p.status === "VALIDATED").length, color: "#00FF88" },
          ].map((s, i) => (
            <React.Fragment key={s.label}>
              {i > 0 && <span style={{ color: "#1A3A50" }}>|</span>}
              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>
                {s.label}: <span style={{ color: s.color }}>{s.value}</span>
              </span>
            </React.Fragment>
          ))}
        </footer>
      </div>
    </div>
  );
}
