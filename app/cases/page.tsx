"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  Briefcase, Clock, MessageSquare, AlertTriangle, CheckCircle,
  ChevronRight, ChevronLeft, X, Send, Mail, MessageCircle, ExternalLink,
  User, Calendar, Filter, RefreshCw, Plus, Search,
} from "lucide-react";
import { PageShell } from "../../components/PageShell";
import { useToast } from "../../hooks/useToast";

/* ─── Types ─── */
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Status   = "OPEN" | "IN_REVIEW" | "IN_REMEDIATION" | "VERIFIED" | "CLOSED";

interface CaseComment { id: string; author: string; content: string; timestamp: string; }
interface CaseActivity { id: string; action: string; actor: string; timestamp: string; field?: string; oldValue?: string; newValue?: string; }
interface Case {
  id: string; findingId: string; title: string; severity: Severity; status: Status;
  assignee: string; category: string; cvss: string; affectedHost: string;
  createdAt: string; updatedAt: string; dueDate: string; slaHours: number;
  mitre: { id: string; name: string }[];
  comments: CaseComment[]; activities: CaseActivity[];
  integrations: { jiraKey?: string; jiraUrl?: string; slackNotified?: boolean; emailSent?: boolean; emailSentAt?: string; };
}

/* ─── Helpers ─── */
const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#FF1744", HIGH: "#FF6D00", MEDIUM: "#FFD600", LOW: "#00E676",
};

const STATUS_COLUMNS: { key: Status; label: string; color: string }[] = [
  { key: "OPEN",           label: "OPEN",           color: "#FF1744" },
  { key: "IN_REVIEW",      label: "IN REVIEW",      color: "#FF9900" },
  { key: "IN_REMEDIATION", label: "IN REMEDIATION", color: "#00D4FF" },
  { key: "VERIFIED",       label: "VERIFIED",        color: "#00FF88" },
  { key: "CLOSED",         label: "CLOSED",          color: "#3D7A94" },
];

const STATUS_NEXT: Partial<Record<Status, Status>> = {
  OPEN: "IN_REVIEW",
  IN_REVIEW: "IN_REMEDIATION",
  IN_REMEDIATION: "VERIFIED",
  VERIFIED: "CLOSED",
};

const STATUS_PREV: Partial<Record<Status, Status>> = {
  IN_REVIEW: "OPEN",
  IN_REMEDIATION: "IN_REVIEW",
  VERIFIED: "IN_REMEDIATION",
  CLOSED: "VERIFIED",
};

function getSlaInfo(c: Case) {
  const due = new Date(c.dueDate).getTime();
  const created = new Date(c.createdAt).getTime();
  const now = Date.now();
  const totalMs = due - created;
  const leftMs = due - now;
  const hoursLeft = Math.max(0, leftMs / 3_600_000);
  const pctLeft = Math.max(0, Math.min(100, (leftMs / totalMs) * 100));
  const breached = now > due;
  let color = "#00E676";
  if (breached || pctLeft < 10) color = "#FF1744";
  else if (pctLeft < 25) color = "#FF6D00";
  else if (pctLeft < 50) color = "#FFD600";
  return { hoursLeft, pctLeft, breached, color };
}

function fmtHours(h: number) {
  if (h < 1) return "< 1h";
  if (h < 24) return `${Math.round(h)}h`;
  return `${Math.round(h / 24)}d`;
}

function fmtRelative(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 60) return `${m}m ago`;
  if (m < 1440) return `${Math.floor(m / 60)}h ago`;
  return `${Math.floor(m / 1440)}d ago`;
}

function Initials({ name }: { name: string }) {
  const parts = name.split(" ");
  const ini = parts.length > 1 ? parts[0][0] + parts[parts.length - 1][0] : name.slice(0, 2);
  const colors = ["#00D4FF", "#00FF88", "#FF9900", "#FF6D00", "#9C27B0", "#2196F3"];
  const color = colors[(name.charCodeAt(0) + name.charCodeAt(1)) % colors.length];
  return (
    <div style={{
      width: 24, height: 24, borderRadius: "50%",
      background: `${color}22`, border: `1px solid ${color}55`,
      display: "flex", alignItems: "center", justifyContent: "center",
      fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color, flexShrink: 0,
    }}>
      {ini.toUpperCase()}
    </div>
  );
}

/* ─── SLA Bar ─── */
function SlaBar({ c }: { c: Case }) {
  const { hoursLeft, pctLeft, breached, color } = getSlaInfo(c);
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>SLA</span>
        <span
          className={breached ? "sla-pulse" : ""}
          style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color,
            padding: "1px 5px", borderRadius: 4,
            background: `${color}15`,
            border: `1px solid ${color}30`,
          }}
        >
          {breached ? "BREACHED" : `${fmtHours(hoursLeft)} left`}
        </span>
      </div>
      <div style={{ height: 3, background: "#1A3A50", borderRadius: 2, overflow: "hidden" }}>
        <div className="progress-bar-fill" style={{ height: "100%", width: `${pctLeft}%`, background: color, borderRadius: 2 }} />
      </div>
    </div>
  );
}

/* ─── Case Card ─── */
function CaseCard({ c, onClick, onMoveNext, onMovePrev }: {
  c: Case; onClick: () => void; onMoveNext: () => void; onMovePrev: () => void;
}) {
  const sev = SEV_COLOR[c.severity];
  const nextStatus = STATUS_NEXT[c.status];
  const prevStatus = STATUS_PREV[c.status];

  return (
    <div
      className="card-hover stagger-item"
      onClick={onClick}
      style={{
        background: "#0A1520",
        border: `1px solid #1A3A50`,
        borderLeft: `3px solid ${sev}`,
        borderRadius: 6,
        padding: "12px",
        cursor: "pointer",
        position: "relative",
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
            color: sev, background: `${sev}15`, border: `1px solid ${sev}30`,
            borderRadius: 3, padding: "1px 5px",
          }}>
            {c.severity}
          </span>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94",
            background: "rgba(61,122,148,0.1)", border: "1px solid #1A3A50",
            borderRadius: 3, padding: "1px 5px",
          }}>
            {c.id}
          </span>
        </div>
        {c.comments.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: 3, color: "#3D7A94" }}>
            <MessageSquare size={10} />
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9 }}>{c.comments.length}</span>
          </div>
        )}
      </div>

      {/* Title */}
      <div style={{
        fontFamily: "'Rajdhani', sans-serif", fontSize: 13, fontWeight: 600,
        color: "#C8E8F0", lineHeight: 1.3, marginBottom: 8,
      }}>
        {c.title}
      </div>

      {/* Meta */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <Initials name={c.assignee} />
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>
          CVSS {c.cvss}
        </span>
      </div>

      {/* SLA */}
      <SlaBar c={c} />

      {/* Integration badges */}
      {(c.integrations.jiraKey || c.integrations.slackNotified || c.integrations.emailSent) && (
        <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
          {c.integrations.jiraKey && (
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#2196F3", background: "rgba(33,150,243,0.1)", border: "1px solid rgba(33,150,243,0.2)", borderRadius: 3, padding: "1px 4px" }}>
              JIRA {c.integrations.jiraKey}
            </span>
          )}
          {c.integrations.slackNotified && (
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#9C27B0", background: "rgba(156,39,176,0.1)", border: "1px solid rgba(156,39,176,0.2)", borderRadius: 3, padding: "1px 4px" }}>
              SLACK
            </span>
          )}
          {c.integrations.emailSent && (
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 8, color: "#00FF88", background: "rgba(0,255,136,0.08)", border: "1px solid rgba(0,255,136,0.2)", borderRadius: 3, padding: "1px 4px" }}>
              EMAIL
            </span>
          )}
        </div>
      )}

      {/* Move buttons */}
      <div style={{ display: "flex", gap: 4, marginTop: 10 }} onClick={(e) => e.stopPropagation()}>
        {prevStatus && (
          <button
            onClick={onMovePrev}
            style={{
              flex: 1, padding: "4px 0", background: "rgba(61,122,148,0.1)", border: "1px solid #1A3A50",
              borderRadius: 4, color: "#3D7A94", fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
              cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 3,
            }}
          >
            <ChevronLeft size={10} /> BACK
          </button>
        )}
        {nextStatus && (
          <button
            onClick={onMoveNext}
            style={{
              flex: 1, padding: "4px 0", background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)",
              borderRadius: 4, color: "#00D4FF", fontFamily: "'Share Tech Mono', monospace", fontSize: 9,
              cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 3,
            }}
          >
            ADVANCE <ChevronRight size={10} />
          </button>
        )}
      </div>
    </div>
  );
}

/* ─── Case Detail Modal ─── */
function CaseModal({ c, onClose, onUpdate }: { c: Case; onClose: () => void; onUpdate: (updated: Case) => void }) {
  const { success, error: toastError, info } = useToast();
  const [comment, setComment] = useState("");
  const [sending, setSending] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"detail" | "activity" | "integrations">("detail");
  const sla = getSlaInfo(c);

  const postComment = async () => {
    if (!comment.trim()) return;
    setSending("comment");
    try {
      const res = await fetch(`/api/cases/${c.id}/comment`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ author: "Security Engineer", content: comment }),
      });
      if (!res.ok) throw new Error(await res.text());
      const updated: Case = await res.json();
      setComment("");
      onUpdate(updated);
      success("Comment added", "Your note has been saved to the case.");
    } catch {
      toastError("Failed to add comment");
    } finally {
      setSending(null);
    }
  };

  const sendIntegration = async (type: "email" | "slack" | "jira") => {
    setSending(type);
    try {
      const res = await fetch(`/api/integrations/${type}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingId: c.findingId, caseId: c.id, title: c.title, severity: c.severity }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? res.statusText);

      const patch: Partial<Case["integrations"]> = {};
      if (type === "email") { patch.emailSent = true; patch.emailSentAt = new Date().toISOString(); }
      if (type === "slack") { patch.slackNotified = true; }
      if (type === "jira")  { patch.jiraKey = data.key; patch.jiraUrl = data.url; }

      const updRes = await fetch(`/api/cases/${c.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ integrations: { ...c.integrations, ...patch }, actor: "Security Engineer" }),
      });
      if (updRes.ok) onUpdate(await updRes.json());
      success(`${type.toUpperCase()} sent`, data.message ?? "Notification dispatched.");
    } catch (e) {
      info(`${type.toUpperCase()} preview`, String(e));
    } finally {
      setSending(null);
    }
  };

  const tabs = [
    { key: "detail",       label: "DETAILS" },
    { key: "activity",     label: `ACTIVITY (${c.activities.length})` },
    { key: "integrations", label: "INTEGRATIONS" },
  ] as const;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="animate-scale-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "#0D1B26", border: "1px solid #1A3A50",
          borderRadius: 8, width: "min(780px, 95vw)", maxHeight: "90vh",
          display: "flex", flexDirection: "column", overflow: "hidden",
        }}
      >
        {/* Modal Header */}
        <div style={{
          padding: "16px 20px", borderBottom: "1px solid #1A3A50",
          display: "flex", justifyContent: "space-between", alignItems: "flex-start",
        }}>
          <div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
              <span style={{
                fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94",
                background: "rgba(61,122,148,0.1)", border: "1px solid #1A3A50", borderRadius: 3, padding: "2px 6px",
              }}>
                {c.id}
              </span>
              <span style={{
                fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
                color: SEV_COLOR[c.severity], background: `${SEV_COLOR[c.severity]}15`,
                border: `1px solid ${SEV_COLOR[c.severity]}30`, borderRadius: 3, padding: "2px 6px",
              }}>
                {c.severity}
              </span>
              <span style={{
                fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
                color: sla.color, background: `${sla.color}10`,
                border: `1px solid ${sla.color}30`, borderRadius: 3, padding: "2px 6px",
              }}
                className={sla.breached ? "sla-pulse" : ""}
              >
                {sla.breached ? "⚠ SLA BREACHED" : `SLA: ${fmtHours(sla.hoursLeft)} left`}
              </span>
            </div>
            <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 17, fontWeight: 700, color: "#C8E8F0" }}>
              {c.title}
            </div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginTop: 4 }}>
              {c.findingId} · {c.category} · Assigned to {c.assignee}
            </div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "#3D7A94", padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", borderBottom: "1px solid #1A3A50", flexShrink: 0 }}>
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              style={{
                padding: "10px 16px", background: activeTab === t.key ? "rgba(0,212,255,0.04)" : "transparent",
                border: "none", borderBottom: activeTab === t.key ? "2px solid #00D4FF" : "2px solid transparent",
                color: activeTab === t.key ? "#C8E8F0" : "#3D7A94",
                fontFamily: "'Share Tech Mono', monospace", fontSize: 11, letterSpacing: 1,
                cursor: "pointer", transition: "color 0.15s",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>

          {/* ── Detail Tab ── */}
          {activeTab === "detail" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* Left: finding info */}
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {[
                  { label: "Finding ID",    value: c.findingId },
                  { label: "Affected Host", value: c.affectedHost },
                  { label: "CVSS Score",    value: c.cvss },
                  { label: "Category",      value: c.category },
                  { label: "Created",       value: new Date(c.createdAt).toLocaleString() },
                  { label: "Due Date",      value: new Date(c.dueDate).toLocaleString() },
                ].map((row) => (
                  <div key={row.label}>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginBottom: 3 }}>{row.label}</div>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 14, color: "#C8E8F0" }}>{row.value}</div>
                  </div>
                ))}
              </div>

              {/* Right: SLA + MITRE + comment thread */}
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {/* SLA gauge */}
                <div style={{ background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6, padding: 12 }}>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginBottom: 8 }}>SLA PROGRESS</div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: sla.color }}>
                      {sla.breached ? "BREACHED" : `${fmtHours(sla.hoursLeft)} remaining`}
                    </span>
                    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>
                      {Math.round(sla.pctLeft)}% left
                    </span>
                  </div>
                  <div style={{ height: 8, background: "#1A3A50", borderRadius: 4, overflow: "hidden" }}>
                    <div className="progress-bar-fill" style={{ height: "100%", width: `${sla.pctLeft}%`, background: sla.color, borderRadius: 4 }} />
                  </div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginTop: 6 }}>
                    Window: {c.slaHours}h · Policy: {c.severity}
                  </div>
                </div>

                {/* MITRE tags */}
                {c.mitre.length > 0 && (
                  <div style={{ background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6, padding: 12 }}>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginBottom: 8 }}>MITRE ATT&CK</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {c.mitre.map((m) => (
                        <div key={m.id} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#00D4FF", flexShrink: 0 }}>{m.id}</span>
                          <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 12, color: "#3D7A94" }}>{m.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Activity Tab ── */}
          {activeTab === "activity" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
              {/* Activity timeline */}
              <div style={{ marginBottom: 20 }}>
                {[...c.activities].reverse().map((act, i) => (
                  <div key={act.id} className="stagger-item" style={{ display: "flex", gap: 12, paddingBottom: 16, position: "relative" }}>
                    {i < c.activities.length - 1 && (
                      <div style={{ position: "absolute", left: 7, top: 18, bottom: 0, width: 1, background: "#1A3A50" }} />
                    )}
                    <div style={{ width: 16, height: 16, borderRadius: "50%", background: "#1A3A50", border: "2px solid #3D7A94", flexShrink: 0, marginTop: 2 }} />
                    <div>
                      <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 13, color: "#C8E8F0" }}>{act.action}</div>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94", marginTop: 2 }}>
                        {act.actor} · {fmtRelative(act.timestamp)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Comment thread */}
              <div style={{ borderTop: "1px solid #1A3A50", paddingTop: 16 }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94", marginBottom: 12 }}>COMMENTS</div>
                {c.comments.length === 0 && (
                  <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 13, color: "#3D7A94", marginBottom: 12 }}>No comments yet.</div>
                )}
                {c.comments.map((cm) => (
                  <div key={cm.id} style={{ background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6, padding: "10px 12px", marginBottom: 8 }}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                      <Initials name={cm.author} />
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0" }}>{cm.author}</span>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: "#3D7A94" }}>{fmtRelative(cm.timestamp)}</span>
                    </div>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 14, color: "#C8E8F0", lineHeight: 1.5 }}>{cm.content}</div>
                  </div>
                ))}

                {/* Add comment */}
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <textarea
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Add a comment..."
                    rows={2}
                    style={{
                      flex: 1, background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6,
                      padding: "8px 12px", color: "#C8E8F0", fontFamily: "'Rajdhani', sans-serif",
                      fontSize: 13, resize: "none", outline: "none",
                    }}
                  />
                  <button
                    onClick={postComment}
                    disabled={!comment.trim() || sending === "comment"}
                    style={{
                      padding: "0 14px", borderRadius: 6, border: "none",
                      background: comment.trim() ? "#00D4FF" : "rgba(0,212,255,0.1)",
                      color: comment.trim() ? "#050A0E" : "#3D7A94",
                      cursor: comment.trim() ? "pointer" : "not-allowed",
                      display: "flex", alignItems: "center", gap: 4,
                      fontFamily: "'Share Tech Mono', monospace", fontSize: 11,
                    }}
                  >
                    <Send size={13} />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── Integrations Tab ── */}
          {activeTab === "integrations" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {[
                {
                  key: "email", icon: Mail, label: "Email Notification",
                  desc: "Send finding summary to configured recipients via SMTP.",
                  active: c.integrations.emailSent,
                  activeLabel: c.integrations.emailSent ? `Sent ${c.integrations.emailSentAt ? fmtRelative(c.integrations.emailSentAt) : ""}` : "Not sent",
                  buttonLabel: c.integrations.emailSent ? "Resend Email" : "Send Email",
                  color: "#00FF88",
                },
                {
                  key: "slack", icon: MessageCircle, label: "MessageCircle Notification",
                  desc: "Post rich finding block to configured MessageCircle channel.",
                  active: c.integrations.slackNotified,
                  activeLabel: c.integrations.slackNotified ? "Notified" : "Not notified",
                  buttonLabel: c.integrations.slackNotified ? "Resend to MessageCircle" : "Notify MessageCircle",
                  color: "#9C27B0",
                },
                {
                  key: "jira", icon: ExternalLink, label: "Jira Ticket",
                  desc: "Create or link a Jira issue for remediation tracking.",
                  active: !!c.integrations.jiraKey,
                  activeLabel: c.integrations.jiraKey ? c.integrations.jiraKey : "No ticket",
                  buttonLabel: c.integrations.jiraKey ? "Update Jira" : "Create Jira Ticket",
                  color: "#2196F3",
                },
              ].map((intg) => {
                const Icon = intg.icon;
                return (
                  <div key={intg.key} style={{ background: "#050A0E", border: "1px solid #1A3A50", borderRadius: 6, padding: "14px 16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                        <div style={{ width: 32, height: 32, borderRadius: 6, background: `${intg.color}15`, border: `1px solid ${intg.color}30`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                          <Icon size={15} color={intg.color} />
                        </div>
                        <div>
                          <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 14, fontWeight: 600, color: "#C8E8F0" }}>{intg.label}</div>
                          <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 12, color: "#3D7A94" }}>{intg.desc}</div>
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: intg.active ? "#00FF88" : "#3D7A94" }}>
                          {intg.activeLabel}
                        </span>
                        <button
                          onClick={() => sendIntegration(intg.key as "email" | "slack" | "jira")}
                          disabled={sending === intg.key}
                          style={{
                            padding: "6px 14px", borderRadius: 4, border: `1px solid ${intg.color}50`,
                            background: `${intg.color}10`, color: intg.color,
                            fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
                            cursor: "pointer", opacity: sending === intg.key ? 0.6 : 1,
                          }}
                        >
                          {sending === intg.key ? "Sending..." : intg.buttonLabel}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}

              {/* Jira link if exists */}
              {c.integrations.jiraUrl && (
                <a
                  href={c.integrations.jiraUrl}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "10px 14px",
                    background: "rgba(33,150,243,0.08)", border: "1px solid rgba(33,150,243,0.2)",
                    borderRadius: 6, color: "#2196F3", textDecoration: "none",
                    fontFamily: "'Share Tech Mono', monospace", fontSize: 11,
                  }}
                >
                  <ExternalLink size={13} />
                  Open {c.integrations.jiraKey} in Jira
                </a>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Main Page ─── */
export default function CasesPage() {
  const { success, info } = useToast();
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<Severity | "ALL">("ALL");
  const [filterAssignee, setFilterAssignee] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/cases");
      if (!res.ok) throw new Error();
      setCases(await res.json());
    } catch {
      info("Using offline data", "Could not reach cases API.");
    } finally {
      setLoading(false);
    }
  }, [info]);

  useEffect(() => { load(); }, [load]);

  /* SLA breach auto-refresh every 60s */
  useEffect(() => {
    const id = setInterval(() => setCases((prev) => [...prev]), 60_000);
    return () => clearInterval(id);
  }, []);

  const moveCase = useCallback(async (id: string, newStatus: Status) => {
    const old = cases.find((c) => c.id === id);
    setCases((prev) => prev.map((c) => c.id === id ? { ...c, status: newStatus, updatedAt: new Date().toISOString() } : c));
    try {
      const res = await fetch(`/api/cases/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus, actor: "Security Engineer" }),
      });
      if (!res.ok) throw new Error();
      const updated: Case = await res.json();
      setCases((prev) => prev.map((c) => c.id === id ? updated : c));
      if (selectedCase?.id === id) setSelectedCase(updated);
      success("Case advanced", `${id} → ${newStatus}`);
    } catch {
      setCases((prev) => prev.map((c) => c.id === id ? { ...c, status: old?.status ?? c.status } : c));
      info("Offline mode", "Status updated locally only.");
    }
  }, [cases, selectedCase, success, info]);

  const handleUpdate = useCallback((updated: Case) => {
    setCases((prev) => prev.map((c) => c.id === updated.id ? updated : c));
    setSelectedCase(updated);
  }, []);

  const assignees = useMemo(() => ["ALL", ...Array.from(new Set(cases.map((c) => c.assignee)))], [cases]);

  const filtered = useMemo(() => cases.filter((c) => {
    if (filterSeverity !== "ALL" && c.severity !== filterSeverity) return false;
    if (filterAssignee !== "ALL" && c.assignee !== filterAssignee) return false;
    if (searchQuery && !c.title.toLowerCase().includes(searchQuery.toLowerCase()) && !c.id.includes(searchQuery)) return false;
    return true;
  }), [cases, filterSeverity, filterAssignee, searchQuery]);

  /* Stats */
  const stats = useMemo(() => ({
    total:     cases.length,
    open:      cases.filter((c) => c.status === "OPEN").length,
    breached:  cases.filter((c) => getSlaInfo(c).breached && c.status !== "CLOSED").length,
    critical:  cases.filter((c) => c.severity === "CRITICAL" && c.status !== "CLOSED").length,
    closedToday: cases.filter((c) => c.status === "CLOSED" && new Date(c.updatedAt).toDateString() === new Date().toDateString()).length,
  }), [cases]);

  const Col = ({ col }: { col: typeof STATUS_COLUMNS[number] }) => {
    const colCases = filtered.filter((c) => c.status === col.key);
    return (
      <div style={{ flex: 1, minWidth: 200, display: "flex", flexDirection: "column", gap: 0 }}>
        {/* Column header */}
        <div style={{
          padding: "10px 12px", marginBottom: 8,
          background: "#0A1520", border: "1px solid #1A3A50", borderTop: `3px solid ${col.color}`,
          borderRadius: 6, display: "flex", justifyContent: "space-between", alignItems: "center",
        }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#C8E8F0", letterSpacing: 1 }}>
            {col.label}
          </span>
          <span style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
            color: col.color, background: `${col.color}15`, border: `1px solid ${col.color}30`,
            borderRadius: 10, padding: "1px 7px",
          }}>
            {colCases.length}
          </span>
        </div>

        {/* Cards */}
        <div style={{ display: "flex", flexDirection: "column", gap: 8, flex: 1, minHeight: 120 }}>
          {loading ? (
            Array.from({ length: 2 }).map((_, i) => (
              <div key={i} className="skeleton" style={{ height: 120, borderRadius: 6 }} />
            ))
          ) : colCases.length === 0 ? (
            <div style={{
              border: "1px dashed #1A3A50", borderRadius: 6, padding: "20px",
              textAlign: "center", fontFamily: "'Share Tech Mono', monospace",
              fontSize: 10, color: "#3D7A94",
            }}>
              No cases
            </div>
          ) : (
            colCases.map((c) => (
              <CaseCard
                key={c.id}
                c={c}
                onClick={() => setSelectedCase(c)}
                onMoveNext={() => STATUS_NEXT[c.status] && moveCase(c.id, STATUS_NEXT[c.status]!)}
                onMovePrev={() => STATUS_PREV[c.status] && moveCase(c.id, STATUS_PREV[c.status]!)}
              />
            ))
          )}
        </div>
      </div>
    );
  };

  return (
    <PageShell
      title="CASE MANAGEMENT"
      subtitle="SLA TRACKING · WORKFLOW · INTEGRATIONS"
      noPadding
      statusItems={[
        { label: "OPEN", value: String(stats.open), color: "#FF1744" },
        { label: "BREACHED", value: String(stats.breached), color: stats.breached > 0 ? "#FF1744" : "#3D7A94" },
        { label: "CRITICAL", value: String(stats.critical), color: "#FF6D00" },
      ]}
      headerActions={
        <button
          onClick={load}
          style={{
            background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)",
            borderRadius: 4, padding: "5px 12px", color: "#00D4FF",
            fontFamily: "'Share Tech Mono', monospace", fontSize: 10, cursor: "pointer",
            display: "flex", alignItems: "center", gap: 5,
          }}
        >
          <RefreshCw size={12} /> REFRESH
        </button>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
        {/* ── Metric Bar ── */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 1,
          borderBottom: "1px solid #1A3A50", flexShrink: 0, background: "#1A3A50",
        }}>
          {[
            { label: "TOTAL CASES",  value: stats.total,       color: "#C8E8F0" },
            { label: "OPEN",         value: stats.open,        color: "#FF1744" },
            { label: "SLA BREACHED", value: stats.breached,    color: stats.breached > 0 ? "#FF1744" : "#3D7A94" },
            { label: "CRITICAL OPEN",value: stats.critical,    color: "#FF6D00" },
            { label: "CLOSED TODAY", value: stats.closedToday, color: "#00FF88" },
          ].map((m) => (
            <div key={m.label} style={{ background: "#0D1B26", padding: "12px 16px", textAlign: "center" }}>
              <div className="animate-fade-up" style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 24, fontWeight: 700, color: m.color, lineHeight: 1 }}>
                {m.value}
              </div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginTop: 4 }}>
                {m.label}
              </div>
            </div>
          ))}
        </div>

        {/* ── Filter Bar ── */}
        <div style={{
          padding: "10px 20px", borderBottom: "1px solid #1A3A50",
          display: "flex", gap: 10, alignItems: "center", flexShrink: 0,
          background: "#050A0E", flexWrap: "wrap",
        }}>
          <Filter size={13} color="#3D7A94" />
          {/* Search */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 4, padding: "4px 10px", minWidth: 180 }}>
            <Search size={11} color="#3D7A94" />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search cases..."
              style={{ background: "none", border: "none", outline: "none", color: "#C8E8F0", fontFamily: "'Share Tech Mono', monospace", fontSize: 11, width: "100%" }}
            />
          </div>
          {/* Severity filter */}
          {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setFilterSeverity(s)}
              style={{
                padding: "4px 10px", borderRadius: 4, cursor: "pointer",
                fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
                border: `1px solid ${filterSeverity === s ? (s === "ALL" ? "#00D4FF" : SEV_COLOR[s as Severity]) : "#1A3A50"}`,
                background: filterSeverity === s ? (s === "ALL" ? "rgba(0,212,255,0.1)" : `${SEV_COLOR[s as Severity]}15`) : "transparent",
                color: filterSeverity === s ? (s === "ALL" ? "#00D4FF" : SEV_COLOR[s as Severity]) : "#3D7A94",
              }}
            >
              {s}
            </button>
          ))}
          {/* Assignee filter */}
          <select
            value={filterAssignee}
            onChange={(e) => setFilterAssignee(e.target.value)}
            style={{
              background: "#0D1B26", border: "1px solid #1A3A50", borderRadius: 4,
              color: "#3D7A94", fontFamily: "'Share Tech Mono', monospace", fontSize: 10,
              padding: "4px 8px", outline: "none", cursor: "pointer",
            }}
          >
            {assignees.map((a) => <option key={a} value={a}>{a === "ALL" ? "All Assignees" : a}</option>)}
          </select>
        </div>

        {/* ── Kanban Board ── */}
        <div style={{ flex: 1, overflowX: "auto", overflowY: "hidden" }}>
          <div style={{ display: "flex", gap: 12, padding: "16px 20px", minWidth: 900, height: "100%", boxSizing: "border-box", overflowY: "auto" }}>
            {STATUS_COLUMNS.map((col) => <Col key={col.key} col={col} />)}
          </div>
        </div>
      </div>

      {/* Case Detail Modal */}
      {selectedCase && (
        <CaseModal
          c={selectedCase}
          onClose={() => setSelectedCase(null)}
          onUpdate={handleUpdate}
        />
      )}
    </PageShell>
  );
}
