"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { Menu } from "lucide-react";
import { Sidebar } from "./Sidebar";

interface PageShellProps {
  title: string;
  subtitle?: string;
  headerActions?: React.ReactNode;
  statusItems?: Array<{ label: string; value: string; color?: string }>;
  children: React.ReactNode;
  noPadding?: boolean;
}

export function PageShell({
  title,
  subtitle,
  headerActions,
  statusItems,
  children,
  noPadding,
}: PageShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [utcTime, setUtcTime] = useState("");
  const [sessionTime, setSessionTime] = useState(0);
  const sessionStart = useRef(Date.now());

  useEffect(() => {
    const update = () =>
      setUtcTime(new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      setSessionTime(Math.floor((Date.now() - sessionStart.current) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const fmtSession = useCallback((s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  }, []);

  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: "#08090D",
        fontFamily: "'Inter', sans-serif",
        overflow: "hidden",
      }}
    >
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="md:hidden"
          onClick={() => setSidebarOpen(false)}
          style={{
            position: "fixed", inset: 0,
            background: "rgba(8,9,13,0.7)",
            zIndex: 40,
            backdropFilter: "blur(4px)",
          }}
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>

        {/* ── Header ─────────────────────────────────────────────────── */}
        <header
          style={{
            height: 52,
            background: "#12141A",
            borderBottom: "0.5px solid #1E2028",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 20px",
            flexShrink: 0,
            gap: 16,
          }}
        >
          {/* Left — title */}
          <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
            <button
              className="md:hidden"
              onClick={() => setSidebarOpen(true)}
              style={{
                background: "none", border: "none", cursor: "pointer",
                padding: 0, flexShrink: 0,
              }}
            >
              <Menu size={20} color="#00C882" />
            </button>

            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
              <span
                style={{
                  fontFamily: "'Inter', sans-serif",
                  fontSize: 14,
                  fontWeight: 600,
                  color: "#E8ECF0",
                  flexShrink: 0,
                }}
              >
                {title}
              </span>

              {subtitle && (
                <>
                  <span style={{ color: "#2A2D38", flexShrink: 0, fontSize: 16 }}>/</span>
                  <span
                    style={{
                      fontFamily: "'Inter', sans-serif",
                      fontSize: 12,
                      color: "#8C95A0",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      fontWeight: 400,
                    }}
                  >
                    {subtitle}
                  </span>
                </>
              )}
            </div>

            {/* Live indicator */}
            <span
              className="animate-pulse-dot"
              style={{
                display: "inline-block",
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: "#00C882",
                flexShrink: 0,
              }}
            />
          </div>

          {/* Right — status + actions */}
          <div style={{ display: "flex", alignItems: "center", gap: 14, flexShrink: 0 }}>
            {headerActions && (
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {headerActions}
              </div>
            )}

            {statusItems?.map((item, i) => (
              <React.Fragment key={i}>
                <span style={{ height: 14, width: 1, background: "#1E2028", flexShrink: 0 }} />
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 10,
                      color: "#555C68",
                      letterSpacing: 0.5,
                    }}
                  >
                    {item.label}
                  </span>
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      fontWeight: 500,
                      color: item.color ?? "#E8ECF0",
                    }}
                  >
                    {item.value}
                  </span>
                </div>
              </React.Fragment>
            ))}

            <span style={{ height: 14, width: 1, background: "#1E2028" }} />

            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                color: "#555C68",
                letterSpacing: 0.3,
              }}
            >
              {fmtSession(sessionTime)}
            </span>
          </div>
        </header>

        {/* ── Page content ───────────────────────────────────────────── */}
        <main
          style={{
            flex: 1,
            overflowY: "auto",
            padding: noPadding ? 0 : 20,
            position: "relative",
            background: "#08090D",
          }}
        >
          {children}
        </main>

        {/* ── Footer status bar ──────────────────────────────────────── */}
        <footer
          style={{
            height: 28,
            background: "#0D0F14",
            borderTop: "0.5px solid #1E2028",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 20px",
            flexShrink: 0,
            gap: 16,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            {[
              { label: "ENGINE", color: "#00C882" },
              { label: "API",    color: "#00C882" },
              { label: "DB",     color: "#00C882" },
            ].map((s, i) => (
              <React.Fragment key={i}>
                {i > 0 && <span style={{ width: 1, height: 10, background: "#1E2028" }} />}
                <span
                  style={{
                    fontFamily: "'Inter', sans-serif",
                    fontSize: 10,
                    color: "#555C68",
                    display: "flex",
                    alignItems: "center",
                    gap: 5,
                  }}
                >
                  <span
                    style={{
                      width: 5,
                      height: 5,
                      borderRadius: "50%",
                      background: s.color,
                      display: "inline-block",
                    }}
                  />
                  {s.label}
                </span>
              </React.Fragment>
            ))}
          </div>

          <div
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: "#555C68",
            }}
          >
            {utcTime} · ADVERSA v1.0
          </div>
        </footer>

      </div>
    </div>
  );
}
