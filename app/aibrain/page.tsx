"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { Menu, Send } from "lucide-react";
import { Sidebar } from "../../components/Sidebar";

/* ─── Types ─── */
interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
}

interface Agent {
  name: string;
  status: "ACTIVE" | "THINKING" | "IDLE";
  activity: string;
}

interface Finding {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  title: string;
  confidence: number;
  path: string;
}

/* ─── Data ─── */
const quickPrompts = [
  "Analyze attack paths to Domain Admin in BFSI network",
  "Kerberoasting chain from standard user to DA",
  "Lateral movement past Palo Alto NGFW",
  "Model ransomware blast radius from SMB foothold",
  "Credential relay attack vectors in flat enterprise network",
];

const initialMessage: Message = {
  id: "init",
  role: "assistant",
  content: `[ADVERSA ONLINE]
AI Offensive Brain initialized. Multi-agent framework active.

[READY]
Provide a target scope, attack scenario, or threat model query.`,
  timestamp: new Date().toISOString(),
};

const defaultAgents: Agent[] = [
  { name: "Recon Agent", status: "IDLE", activity: "Standby" },
  { name: "Exploit Agent", status: "IDLE", activity: "Standby" },
  { name: "Lateral Agent", status: "IDLE", activity: "Standby" },
  { name: "AD Trust Analyzer", status: "IDLE", activity: "Standby" },
  { name: "Stealth Agent", status: "IDLE", activity: "Standby" },
];

const findings: Finding[] = [
  { id: "F001", severity: "CRITICAL", title: "Unconstrained Delegation — DC01", confidence: 97, path: "WS-042→SVC-SQL→DC01" },
  { id: "F002", severity: "CRITICAL", title: "Kerberoastable Service Account", confidence: 94, path: "Any user→svc_backup→DA" },
  { id: "F003", severity: "HIGH", title: "SMB Relay via LLMNR Poisoning", confidence: 88, path: "Internal→NTLM capture" },
  { id: "F004", severity: "HIGH", title: "Lateral Movement via WMI", confidence: 82, path: "WS-042→10.10.10.0/24" },
  { id: "F005", severity: "MEDIUM", title: "Segmentation Bypass VLAN30→10", confidence: 71, path: "ACL misconfiguration" },
];

const graphStats = [
  { label: "Attack paths found", value: 14, color: "#FF4444" },
  { label: "Validated exploitable", value: 6, color: "#FF4444" },
  { label: "AD paths to DA", value: 3, color: "#FF9900" },
  { label: "Lateral move vectors", value: 9, color: "#FF9900" },
  { label: "Segmentation gaps", value: 2, color: "#00D4FF" },
  { label: "Evidence confidence avg", value: "87%", color: "#00FF88" },
];

const criticalChain = [
  { step: "WS-042", action: "LLMNR Poison", accent: "#00D4FF" },
  { step: "svc_backup", action: "Kerberoast", accent: "#FF9900" },
  { step: "DC01", action: "Silver Ticket", accent: "#FF4444" },
  { step: "DOMAIN ADMIN", action: "Impersonation", accent: "#FF4444", warning: "⚠" },
];

/* ─── Helpers ─── */
function formatTime(iso: string) {
  const d = new Date(iso);
  return d.toTimeString().slice(0, 8);
}

function severityColor(s: Finding["severity"]) {
  switch (s) {
    case "CRITICAL":
      return "#FF4444";
    case "HIGH":
      return "#FF9900";
    case "MEDIUM":
      return "#FFD500";
    default:
      return "#3D7A94";
  }
}

function barColor(v: number) {
  if (v >= 90) return "#00FF88";
  if (v >= 70) return "#00D4FF";
  if (v >= 50) return "#FF9900";
  return "#FF4444";
}

/* ─── Subcomponents ─── */

function StatusDot({ status }: { status: Agent["status"] }) {
  const color = status === "ACTIVE" ? "#00FF88" : status === "THINKING" ? "#FF9900" : "#3D7A94";
  return (
    <span
      className={status === "ACTIVE" || status === "THINKING" ? "animate-pulse-dot" : ""}
      style={{
        display: "inline-block",
        width: 7,
        height: 7,
        borderRadius: "50%",
        background: color,
        flexShrink: 0,
      }}
    />
  );
}

function AnimatedMessage({ content, isUser }: { content: string; isUser: boolean }) {
  const [displayed, setDisplayed] = useState(isUser ? content : "");
  const indexRef = useRef(0);

  useEffect(() => {
    if (isUser) { return; }
    indexRef.current = 0;
    setDisplayed("");
    const interval = setInterval(() => {
      indexRef.current++;
      setDisplayed(content.slice(0, indexRef.current));
      if (indexRef.current >= content.length) {
        clearInterval(interval);
      }
    }, 8);
    return () => clearInterval(interval);
  }, [content, isUser]);

  const lines = displayed.split("\n");

  return (
    <div>
      {lines.map((line, i) => {
        const isSectionHeader = /^\[.*?\]$/.test(line);
        return (
          <div key={i} style={{ marginBottom: 2 }}>
            {isSectionHeader ? (
              <span
                style={{
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#00D4FF",
                  letterSpacing: 1,
                }}
              >
                {line}
              </span>
            ) : (
              <span
                style={{
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 12,
                  color: "#C8E8F0",
                  whiteSpace: "pre-wrap",
                }}
              >
                {isUser && i === 0 ? "❱ " : ""}
                {line}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ─── Main Page ─── */
export default function AIBrainPage() {
  const [messages, setMessages] = useState<Message[]>([initialMessage]);
  const [inputValue, setInputValue] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [agents, setAgents] = useState<Agent[]>(defaultAgents.map((a) => ({ ...a })));
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [exchangeCount, setExchangeCount] = useState(0);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const tabs = ["Agents", "Findings", "Graph"];

  /* Auto-scroll to latest */
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  /* Auto-resize textarea */
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
    }
  }, [inputValue]);

  /* Simulate agent activity based on query */
  const activateAgents = useCallback((query: string, isProcessing: boolean) => {
    const lower = query.toLowerCase();
    const newAgents = defaultAgents.map((a) => ({ ...a }));

    if (isProcessing) {
      newAgents.forEach((a) => { a.status = "THINKING"; });
      if (/exploit|vuln|cve|exploitation|payload/.test(lower)) {
        newAgents[1] = { ...newAgents[1], status: "ACTIVE", activity: "Analyzing CVE database..." };
      }
      if (/lateral|pivot|move|wmi|psxec|remote/.test(lower)) {
        newAgents[2] = { ...newAgents[2], status: "ACTIVE", activity: "Modeling lateral spread..." };
      }
      if (/ad|domain|kerberos|ldap|trust|delegation/.test(lower)) {
        newAgents[3] = { ...newAgents[3], status: "ACTIVE", activity: "Analyzing domain hierarchy..." };
      }
      if (/recon|scan|enumerate|discover/.test(lower)) {
        newAgents[0] = { ...newAgents[0], status: "ACTIVE", activity: "Enumerating targets..." };
      }
      if (/stealth|evade|bypass|edr/.test(lower)) {
        newAgents[4] = { ...newAgents[4], status: "ACTIVE", activity: "Evaluating detection posture..." };
      }
    } else {
      newAgents.forEach((a) => {
        a.status = "IDLE";
        a.activity = "Standby";
      });
    }
    setAgents(newAgents);
  }, []);

  /* API Call */
  const sendMessage = useCallback(async () => {
    if (!inputValue.trim() || isLoading) { return; }

    const userMsg: Message = {
      id: `msg-${Date.now()}`,
      role: "user",
      content: inputValue.trim(),
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue("");
    setIsLoading(true);
    activateAgents(userMsg.content, true);

    try {
      const res = await fetch("/api/brain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1500,
          system:
            "You are ADVERSA's AI Offensive Brain — an elite autonomous red-team AI.\nThink like a real offensive security operator. Respond in this structure:\n[THREAT ASSESSMENT] brief analysis of the query\n[ATTACK REASONING] step-by-step red team thinking\n[RECOMMENDED ATTACK VECTORS] numbered list of specific vectors\n[CONFIDENCE SCORE] X% — risk statement\nUse offensive security terminology. Reference real CVEs and TTPs.",
          messages: [
            ...messages.map((m) => ({ role: m.role, content: m.content })),
            { role: "user", content: userMsg.content },
          ],
        }),
      });

      let aiContent: string;
      if (res.ok) {
        const data = await res.json();
        aiContent = data.content[0].text;
      } else {
        aiContent = `[ERROR]
Unable to connect to AI Offensive Brain. Check API configuration.

[STATUS]
API response: ${res.statusText} (${res.status})`;
      }

      const assistantMsg: Message = {
        id: `msg-${Date.now() + 1}`,
        role: "assistant",
        content: aiContent,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
      setExchangeCount((prev) => prev + 1);
    } catch (err) {
      const errorMsg: Message = {
        id: `msg-${Date.now() + 1}`,
        role: "assistant",
        content: `[ERROR]
Failed to reach AI Offensive Brain.

[DETAIL]
${err instanceof Error ? err.message : "Unknown network error"}

[RECOMMENDATION]
Verify network connectivity and API key configuration.`,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
      activateAgents("", false);
    }
  }, [inputValue, isLoading, messages, activateAgents]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleQuickPrompt = (prompt: string) => {
    setInputValue(prompt);
    setTimeout(() => {
      if (textareaRef.current) {
        textareaRef.current.style.height = "auto";
        textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
      }
    }, 0);
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

      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Top Nav */}
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
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 18, color: "#00D4FF", letterSpacing: 3 }}>
              ADVERSA
            </span>
            <span style={{ color: "#1A3A50" }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>
              AI OFFENSIVE BRAIN v0.9.1
            </span>
            <span
              className="animate-pulse-dot"
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "#00FF88",
              }}
            />
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#00FF88" }}>ONLINE</span>
          </div>
        </header>

        <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
          {/* Center Panel */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {/* Quick Prompts */}
            <div
              style={{
                padding: "10px 20px",
                borderBottom: "1px solid #1A3A50",
                display: "flex",
                gap: 8,
                overflowX: "auto",
                flexShrink: 0,
              }}
            >
              {quickPrompts.map((p, i) => (
                <button
                  key={i}
                  onClick={() => handleQuickPrompt(p)}
                  style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 10,
                    color: "#3D7A94",
                    border: "1px solid #1A3A50",
                    borderRadius: 6,
                    padding: "6px 12px",
                    background: "transparent",
                    cursor: "pointer",
                    whiteSpace: "nowrap",
                    transition: "color 0.15s ease, border-color 0.15s ease",
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLElement).style.color = "#00D4FF";
                    (e.currentTarget as HTMLElement).style.borderColor = "#00D4FF";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.color = "#3D7A94";
                    (e.currentTarget as HTMLElement).style.borderColor = "#1A3A50";
                  }}
                >
                  {p}
                </button>
              ))}
            </div>

            {/* Messages Area */}
            <div
              style={{
                flex: 1,
                overflowY: "auto",
                padding: "16px 20px",
                display: "flex",
                flexDirection: "column",
                gap: 16,
              }}
            >
              {messages.map((msg) => (
                <div
                  key={msg.id}
                  style={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                  }}
                >
                  <div style={{ maxWidth: "80%" }}>
                    <div
                      style={{
                        background:
                          msg.role === "user"
                            ? "rgba(0,212,255,0.04)"
                            : "#0D1B26",
                        border:
                          msg.role === "user"
                            ? "1px solid #1E4560"
                            : "1px solid #1A3A50",
                        borderRadius:
                          msg.role === "user" ? "8px 2px 8px 8px" : "2px 8px 8px 8px",
                        padding: "12px 16px",
                        position: "relative",
                      }}
                    >
                      {msg.role === "assistant" && (
                        <div
                          style={{
                            position: "absolute",
                            top: -10,
                            left: 12,
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: "#00D4FF",
                            border: "1px solid #1A3A50",
                            borderRadius: 4,
                            padding: "1px 6px",
                            background: "#0D1B26",
                          }}
                        >
                          AI
                        </div>
                      )}
                      <AnimatedMessage content={msg.content} isUser={msg.role === "user"} />
                    </div>
                    <div
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 10,
                        color: "#3D7A94",
                        marginTop: 4,
                        textAlign: msg.role === "user" ? "right" : "left",
                      }}
                    >
                      {formatTime(msg.timestamp)}
                    </div>
                  </div>
                </div>
              ))}

              {isLoading && (
                <div style={{ display: "flex", justifyContent: "flex-start" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ display: "flex", gap: 4 }}>
                      {[0, 1, 2].map((i) => (
                        <span
                          key={i}
                          className="animate-pulse-dot"
                          style={{
                            width: 6,
                            height: 6,
                            borderRadius: "50%",
                            background: "#00D4FF",
                            animationDelay: `${i * 200}ms`,
                          }}
                        />
                      ))}
                    </div>
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono', monospace",
                        fontSize: 11,
                        color: "#00D4FF",
                      }}
                    >
                      Offensive brain reasoning...
                    </span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div
              style={{
                borderTop: "1px solid #1A3A50",
                padding: "12px 20px",
                flexShrink: 0,
                background: "#050A0E",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-end",
                  gap: 8,
                  background: "#0D1B26",
                  border: "1px solid #1A3A50",
                  borderRadius: 6,
                  padding: "8px 12px",
                }}
              >
                <span style={{ fontFamily: "monospace", fontSize: 14, color: "#00D4FF", paddingBottom: 4 }}>❱</span>
                <textarea
                  ref={textareaRef}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Query the AI Offensive Brain..."
                  rows={1}
                  style={{
                    flex: 1,
                    background: "transparent",
                    border: "none",
                    outline: "none",
                    color: "#C8E8F0",
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 12,
                    resize: "none",
                    minHeight: 20,
                    maxHeight: 100,
                    overflow: "auto",
                    lineHeight: 1.5,
                  }}
                />
                <button
                  onClick={sendMessage}
                  disabled={isLoading || !inputValue.trim()}
                  style={{
                    padding: "6px 14px",
                    borderRadius: 4,
                    border: "none",
                    background: inputValue.trim() ? "#00D4FF" : "rgba(0,212,255,0.15)",
                    color: inputValue.trim() ? "#050A0E" : "#3D7A94",
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 11,
                    cursor: inputValue.trim() ? "pointer" : "not-allowed",
                    transition: "background 0.15s ease, color 0.15s ease",
                    display: "flex",
                    alignItems: "center",
                    gap: 4,
                  }}
                >
                  <Send size={12} />
                  SEND
                </button>
              </div>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginTop: 6,
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 10,
                  color: "#3D7A94",
                }}
              >
                <span>ENTER to send · SHIFT+ENTER for newline</span>
                <span>
                  {exchangeCount} exchange{exchangeCount !== 1 ? "s" : ""}
                </span>
              </div>
            </div>
          </div>

          {/* Right Panel */}
          <aside
            className="hidden lg:block"
            style={{
              width: 300,
              borderLeft: "1px solid #1A3A50",
              background: "#0D1B26",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
              flexShrink: 0,
            }}
          >
            {/* Tabs */}
            <div
              style={{
                display: "flex",
                borderBottom: "1px solid #1A3A50",
              }}
            >
              {tabs.map((t, i) => (
                <button
                  key={t}
                  onClick={() => setActiveTab(i)}
                  style={{
                    flex: 1,
                    padding: "10px 0",
                    background: activeTab === i ? "rgba(0,212,255,0.04)" : "transparent",
                    border: "none",
                    borderBottom: activeTab === i ? "2px solid #00D4FF" : "2px solid transparent",
                    color: activeTab === i ? "#C8E8F0" : "#3D7A94",
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 11,
                    letterSpacing: 1,
                    cursor: "pointer",
                    textTransform: "uppercase",
                    transition: "color 0.15s ease",
                  }}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
              {activeTab === 0 && (
                <div>
                  {agents.map((agent, i) => (
                    <div
                      key={agent.name}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "10px 16px",
                        borderBottom: i < agents.length - 1 ? "1px solid rgba(26,58,80,0.25)" : "none",
                      }}
                    >
                      <StatusDot status={agent.status} />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 12,
                            color: "#C8E8F0",
                          }}
                        >
                          {agent.name}
                        </div>
                        <div
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: "#3D7A94",
                            marginTop: 2,
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {agent.activity}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 1 && (
                <div style={{ padding: "8px 12px", display: "flex", flexDirection: "column", gap: 8 }}>
                  {findings.map((f) => (
                    <div
                      key={f.id}
                      style={{
                        background: "#050A0E",
                        border: "1px solid #1A3A50",
                        borderRadius: 4,
                        padding: "10px 12px",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                        <span
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: "#3D7A94",
                          }}
                        >
                          {f.id}
                        </span>
                        <span
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 9,
                            padding: "1px 6px",
                            borderRadius: 3,
                            background: `${severityColor(f.severity)}15`,
                            color: severityColor(f.severity),
                          }}
                        >
                          {f.severity}
                        </span>
                      </div>
                      <div
                        style={{
                          fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
                          fontSize: 13,
                          fontWeight: 500,
                          color: "#C8E8F0",
                          lineHeight: 1.4,
                          marginBottom: 6,
                        }}
                      >
                        {f.title}
                      </div>
                      <div
                        style={{
                          fontFamily: "'Share Tech Mono', monospace",
                          fontSize: 10,
                          color: "#3D7A94",
                          marginBottom: 6,
                        }}
                      >
                        {f.path}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div
                          style={{
                            flex: 1,
                            height: 3,
                            background: "rgba(26,58,80,0.3)",
                            borderRadius: 1,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              height: "100%",
                              width: `${f.confidence}%`,
                              background: barColor(f.confidence),
                              borderRadius: 1,
                            }}
                          />
                        </div>
                        <span
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: barColor(f.confidence),
                            width: 30,
                            textAlign: "right",
                          }}
                        >
                          {f.confidence}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 2 && (
                <div style={{ padding: "12px 16px" }}>
                  <div style={{ marginBottom: 16 }}>
                    {graphStats.map((s) => (
                      <div
                        key={s.label}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          padding: "6px 0",
                          borderBottom: "1px solid rgba(26,58,80,0.2)",
                        }}
                      >
                        <span
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 11,
                            color: "#3D7A94",
                          }}
                        >
                          {s.label}
                        </span>
                        <span
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 11,
                            color: s.color,
                            fontWeight: 600,
                          }}
                        >
                          {s.value}
                        </span>
                      </div>
                    ))}
                  </div>

                  <div
                    style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 12,
                      color: "#C8E8F0",
                      letterSpacing: 1,
                      marginBottom: 10,
                      paddingTop: 8,
                      borderTop: "1px solid #1A3A50",
                    }}
                  >
                    CRITICAL PATH CHAIN
                  </div>

                  <div style={{ position: "relative", paddingLeft: 8 }}>
                    <div
                      style={{
                        position: "absolute",
                        left: 0,
                        top: 0,
                        bottom: 0,
                        width: 2,
                        background: "#1A3A50",
                      }}
                    />
                    {criticalChain.map((c, i) => (
                      <div
                        key={i}
                        style={{
                          padding: "8px 0 8px 12px",
                          borderLeft: `2px solid ${c.accent}`,
                          marginBottom: i < criticalChain.length - 1 ? 4 : 0,
                        }}
                      >
                        <div
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 11,
                            color: "#C8E8F0",
                            display: "flex",
                            alignItems: "center",
                            gap: 6,
                          }}
                        >
                          {c.step}
                          {c.warning && <span style={{ color: "#FF4444", fontSize: 12 }}>{c.warning}</span>}
                        </div>
                        <div
                          style={{
                            fontFamily: "'Share Tech Mono', monospace",
                            fontSize: 10,
                            color: "#3D7A94",
                            marginTop: 2,
                          }}
                        >
                          {c.action}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
