"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis,
  Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import { RefreshCw, AlertTriangle, TrendingUp, Users, Eye } from "lucide-react";
import Link from "next/link";

/* ─── Types ─── */
interface TimelinePoint { date: string; CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; }
interface Engagement {
  id: string; name: string; findingsBySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  findingCount: number; assetCount: number; status: string;
}
interface ActivityItem { id: string; timestamp: string; actor: string; action: string; detail: string; engagementId: string; }

const SEV_COLORS = { CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676" };

/* ─── Skeleton shimmer ─── */
function Shimmer({ w, h }: { w: number | string; h: number }) {
  return <div className="shimmer" style={{ width: w, height: h, borderRadius: 4 }} />;
}

/* ─── Custom Tooltip ─── */
function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 5, padding: "8px 12px" }}>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", marginBottom: 4 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ display: "flex", gap: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
          <span style={{ color: p.color }}>{p.name}</span>
          <span style={{ color: "var(--adv-text)" }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ─── Main component ─── */
export function DashboardCharts() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => fetch("/api/engagements").then((r) => r.json()),
  });

  const { data: detData } = useQuery({
    queryKey: ["detection-coverage"],
    queryFn: () => fetch(`/api/engagements/ENG-001/detection-validation/coverage`).then((r) => r.json()).catch(() => null),
    staleTime: 60_000,
  });

  const engagements: Engagement[] = data?.engagements ?? [];
  const timeline: TimelinePoint[]  = data?.timeline ?? [];
  const activity: ActivityItem[]   = data?.activity ?? [];
  const stats = data?.stats ?? {};

  // Aggregate severity breakdown across all engagements
  const sevTotals = engagements.reduce(
    (acc, e) => ({
      CRITICAL: acc.CRITICAL + e.findingsBySeverity.CRITICAL,
      HIGH:     acc.HIGH     + e.findingsBySeverity.HIGH,
      MEDIUM:   acc.MEDIUM   + e.findingsBySeverity.MEDIUM,
      LOW:      acc.LOW      + e.findingsBySeverity.LOW,
    }),
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  );

  const pieData = Object.entries(sevTotals)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value, color: SEV_COLORS[name as keyof typeof SEV_COLORS] }));

  const detectionCoverage = detData?.coverage?.coveragePct ?? 53;
  const activeEngagements = stats.activeEngagements ?? engagements.filter((e) => e.status === "ACTIVE").length;
  const totalFindings     = stats.totalFindings ?? engagements.reduce((s, e) => s + e.findingCount, 0);
  const totalAssets       = stats.totalAssets ?? engagements.reduce((s, e) => s + e.assetCount, 0);

  // Slim 30-day timeline (show every 5th label)
  const slimTimeline = timeline.map((t, i) => ({
    ...t,
    displayDate: i % 5 === 0 ? t.date.slice(5) : "",
  }));

  // Top 5 critical findings (simulated from engagement data)
  const TOP_FINDINGS = [
    { id: "VAPT-CRIT-001", title: "Unconstrained Delegation — DC01",       host: "DC01",      score: 970, age: "10d", status: "OPEN"         },
    { id: "VAPT-CRIT-002", title: "Kerberoastable Service Account",         host: "SVC-SQL",   score: 920, age: "10d", status: "IN_REMEDIATION"},
    { id: "VAPT-CRIT-003", title: "Log4Shell (CVE-2021-44228)",             host: "WEB-01",    score: 910, age: "10d", status: "VERIFIED"      },
    { id: "VAPT-HIGH-001", title: "SMB Signing Not Required — 4 Hosts",     host: "WS-042",    score: 730, age: "10d", status: "OPEN"          },
    { id: "VAPT-HIGH-003", title: "AD CS ESC1 — UserAuthentication Tmpl",  host: "corp-CA",   score: 720, age: "10d", status: "OPEN"          },
  ];

  const STATUS_COLOR: Record<string, string> = {
    OPEN: "#FF1744", IN_REVIEW: "#FF9900", IN_REMEDIATION: "#2563EB",
    VERIFIED: "#059669", CLOSED: "#64748B",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, marginBottom: 20 }}>
      {/* ── Metric Cards ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        {isLoading ? (
          [1,2,3,4].map((i) => (
            <div key={i} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 16 }}>
              <Shimmer w={80} h={10} />
              <div style={{ marginTop: 10 }}><Shimmer w={60} h={28} /></div>
            </div>
          ))
        ) : isError ? (
          <div style={{ gridColumn: "1/-1", display: "flex", alignItems: "center", gap: 8, color: "#FF1744" }}>
            <AlertTriangle size={16} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>Failed to load metrics</span>
          </div>
        ) : (
          [
            { label: "TOTAL FINDINGS",        value: totalFindings,       icon: <AlertTriangle size={14} color="#FF1744" />,   color: "#FF1744" },
            { label: "ACTIVE ENGAGEMENTS",    value: activeEngagements,   icon: <TrendingUp size={14} color="#00E676" />,      color: "#00E676" },
            { label: "ASSETS DISCOVERED",     value: totalAssets,         icon: <Users size={14} color="var(--adv-accent)" />, color: "var(--adv-accent)" },
            { label: "DETECTION COVERAGE",    value: `${detectionCoverage}%`, icon: <Eye size={14} color="#FFD600" />,        color: "#FFD600" },
          ].map((m) => (
            <div key={m.label} style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: "14px 16px", position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: m.color }} />
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                {m.icon}
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{m.label}</span>
              </div>
              <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 30, fontWeight: 700, color: m.color, lineHeight: 1 }}>{m.value}</div>
            </div>
          ))
        )}
      </div>

      {/* ── Charts row ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 220px", gap: 12 }}>
        {/* Line chart: findings over time */}
        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 16 }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", marginBottom: 12 }}>
            FINDINGS OVER TIME — Last 30 Days
          </div>
          {isLoading ? (
            <Shimmer w="100%" h={160} />
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={slimTimeline} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <defs>
                  {(["CRITICAL","HIGH","MEDIUM"] as const).map((s) => (
                    <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={SEV_COLORS[s]} stopOpacity={0.25} />
                      <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <XAxis dataKey="displayDate" tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, fill: "var(--adv-text-muted)" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, fill: "var(--adv-text-muted)" }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<ChartTooltip />} />
                {(["CRITICAL","HIGH","MEDIUM"] as const).map((s) => (
                  <Area key={s} type="monotone" dataKey={s} stroke={SEV_COLORS[s]}
                    fill={`url(#grad-${s})`} strokeWidth={1.5} dot={false} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Donut: severity breakdown */}
        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, padding: 16 }}>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)", marginBottom: 8 }}>
            BY SEVERITY
          </div>
          {isLoading ? (
            <Shimmer w="100%" h={160} />
          ) : pieData.length === 0 ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 160, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>
              No findings
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={30} outerRadius={52}
                    dataKey="value" strokeWidth={0}>
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(v: number, name: string) => [v, name]}
                    contentStyle={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {pieData.map((d) => (
                  <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", flex: 1 }}>{d.name}</span>
                    <span style={{ fontFamily: "'Inter', sans-serif", fontSize: 13, fontWeight: 700, color: d.color }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Top 5 critical findings + Activity feed ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 12 }}>
        {/* Top findings table */}
        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
          <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>TOP 5 CRITICAL FINDINGS</span>
            <Link href="/findings" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-accent)", textDecoration: "none" }}>VIEW ALL →</Link>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["TITLE","ASSET","RISK SCORE","AGE","STATUS"].map((h) => (
                  <th key={h} style={{ padding: "7px 12px", textAlign: "left", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)", borderBottom: "1px solid var(--adv-border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TOP_FINDINGS.map((f, i) => (
                <tr key={f.id} style={{ borderBottom: i < TOP_FINDINGS.length - 1 ? "1px solid var(--adv-border)" : "none" }}>
                  <td style={{ padding: "9px 12px", fontFamily: "'Inter', sans-serif", fontSize: 12, color: "var(--adv-text)", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</td>
                  <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--adv-accent)" }}>{f.host}</td>
                  <td style={{ padding: "9px 12px", fontFamily: "'Inter', sans-serif", fontSize: 14, fontWeight: 700, color: f.score >= 800 ? "#FF1744" : f.score >= 600 ? "#FF6D00" : "#FFD600" }}>{f.score}</td>
                  <td style={{ padding: "9px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-text-muted)" }}>{f.age}</td>
                  <td style={{ padding: "9px 12px" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: STATUS_COLOR[f.status] ?? "#64748B", background: `${STATUS_COLOR[f.status] ?? "#64748B"}15`, borderRadius: 3, padding: "1px 5px" }}>
                      {f.status.replace("_", " ")}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Activity feed */}
        <div style={{ background: "var(--adv-panel)", border: "1px solid var(--adv-border)", borderRadius: 6, overflow: "hidden" }}>
          <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "var(--adv-text)" }}>RECENT ACTIVITY</span>
            <Link href="/engagements" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: "var(--adv-accent)", textDecoration: "none" }}>ALL →</Link>
          </div>
          <div style={{ overflowY: "auto", maxHeight: 210 }}>
            {isLoading ? (
              [1,2,3].map((i) => (
                <div key={i} style={{ padding: "10px 14px", borderBottom: "1px solid var(--adv-border)" }}>
                  <Shimmer w="80%" h={10} />
                  <div style={{ marginTop: 5 }}><Shimmer w="60%" h={8} /></div>
                </div>
              ))
            ) : activity.length === 0 ? (
              <div style={{ padding: "30px 0", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "var(--adv-text-muted)" }}>No activity</div>
            ) : activity.slice(0, 8).map((a) => (
              <div key={a.id} style={{ padding: "9px 14px", borderBottom: "1px solid var(--adv-border)", display: "flex", gap: 8 }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--adv-accent)", marginTop: 5, flexShrink: 0 }} />
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: "var(--adv-accent)", marginBottom: 1 }}>{a.action}</div>
                  <div style={{ fontFamily: "'Inter', sans-serif", fontSize: 11, color: "var(--adv-text)", lineHeight: 1.3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.detail}</div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 8, color: "var(--adv-text-muted)", marginTop: 1 }}>
                    {new Date(a.timestamp).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
