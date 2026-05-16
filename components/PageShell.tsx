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

  /* UTC clock */
  useEffect(() => {
    const update = () =>
      setUtcTime(new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC");
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  /* Session timer */
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
        background: "#050A0E",
        fontFamily: "'Rajdhani', 'Segoe UI', sans-serif",
        overflow: "hidden",
      }}
    >
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="md:hidden"
          onClick={() => setSidebarOpen(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(5,10,14,0.8)",
            zIndex: 40,
            backdropFilter: "blur(2px)",
          }}
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* Main area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>
        {/* Top header */}
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
            gap: 16,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
            <button
              className="md:hidden"
              onClick={() => setSidebarOpen(true)}
              style={{ background: "none", border: "none", cursor: "pointer", padding: 0, flexShrink: 0 }}
            >
              <Menu size={20} color="#00D4FF" />
            </button>
            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
              <span
                style={{
                  fontFamily: "'Share Tech Mono', monospace",
                  fontSize: 15,
                  color: "#00D4FF",
                  letterSpacing: 2,
                  flexShrink: 0,
                }}
              >
                {title}
              </span>
              {subtitle && (
                <>
                  <span style={{ color: "#1A3A50", flexShrink: 0 }}>|</span>
                  <span
                    style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 11,
                      color: "#3D7A94",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {subtitle}
                  </span>
                </>
              )}
            </div>
            <span
              className="animate-pulse-dot"
              style={{
                display: "inline-block",
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: "#00FF88",
                flexShrink: 0,
              }}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 16, flexShrink: 0 }}>
            {headerActions && (
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {headerActions}
              </div>
            )}
            {statusItems?.map((item, i) => (
              <React.Fragment key={i}>
                <span style={{ color: "#1A3A50", fontSize: 14 }}>|</span>
                <span
                  style={{
                    fontFamily: "'Share Tech Mono', monospace",
                    fontSize: 11,
                    color: item.color ?? "#C8E8F0",
                  }}
                >
                  {item.label}: <span style={{ color: item.color ?? "#C8E8F0" }}>{item.value}</span>
                </span>
              </React.Fragment>
            ))}
            <span style={{ color: "#1A3A50", fontSize: 14 }}>|</span>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 11, color: "#3D7A94" }}>
              {fmtSession(sessionTime)}
            </span>
          </div>
        </header>

        {/* Page content */}
        <main
          style={{
            flex: 1,
            overflowY: "auto",
            padding: noPadding ? 0 : 20,
            position: "relative",
          }}
        >
          {children}
        </main>

        {/* Footer status bar */}
        <footer
          style={{
            height: 28,
            borderTop: "1px solid #1A3A50",
            background: "#0D1B26",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "0 20px",
            flexShrink: 0,
            gap: 16,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {[
              { label: "ENGINE", color: "#00FF88" },
              { label: "API",    color: "#00FF88" },
              { label: "DB",     color: "#00FF88" },
            ].map((s, i) => (
              <React.Fragment key={i}>
                {i > 0 && <span style={{ color: "#1A3A50" }}>|</span>}
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>
                  {s.label} <span style={{ color: s.color }}>●</span>
                </span>
              </React.Fragment>
            ))}
          </div>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94" }}>
            {utcTime} · ADVERSA v1.0
          </div>
        </footer>
      </div>
    </div>
  );
}
