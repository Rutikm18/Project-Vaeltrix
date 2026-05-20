"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, Brain, Network, Users, Grid,
  AlertTriangle, Eye, FileText, X,
  Terminal, Briefcase, Settings, Zap, Cpu,
} from "lucide-react";

const NAV_SECTIONS = [
  {
    label: "OPERATIONS",
    items: [
      { icon: Shield,        label: "Dashboard",        href: "/" },
      { icon: Briefcase,     label: "Engagements",      href: "/engagements" },
      { icon: Brain,         label: "AI Brain",         href: "/aibrain" },
      { icon: Terminal,      label: "Scanner",          href: "/scan" },
      { icon: Zap,           label: "Exploit Engine",   href: "/exploit" },
      { icon: Cpu,           label: "AI Engine",        href: "/ai-report" },
      { icon: Network,       label: "Agents",           href: "/agents" },
    ],
  },
  {
    label: "ANALYSIS",
    items: [
      { icon: Network,       label: "Attack Graph",     href: "/attack-graph" },
      { icon: Users,         label: "Active Directory", href: "/active-directory" },
      { icon: Grid,          label: "Segmentation",     href: "/segmentation" },
    ],
  },
  {
    label: "MANAGEMENT",
    items: [
      { icon: AlertTriangle, label: "Findings",         href: "/findings" },
      { icon: Briefcase,     label: "Cases",            href: "/cases" },
      { icon: Eye,           label: "Detection",        href: "/detection" },
      { icon: FileText,      label: "Reports",          href: "/reports" },
      { icon: Settings,      label: "Settings",         href: "/settings" },
    ],
  },
];

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside
      className={[
        "fixed md:static",
        "transition-transform duration-200 ease-in-out",
        open ? "translate-x-0" : "-translate-x-full",
        "md:translate-x-0",
        "z-50",
      ].join(" ")}
      style={{
        width: 220,
        background: "#12141A",
        borderRight: "0.5px solid #1E2028",
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        flexShrink: 0,
        overflowY: "auto",
      }}
    >
      {/* ── Logo ─────────────────────────────────────────────────────── */}
      <div
        style={{
          padding: "18px 16px 16px",
          borderBottom: "0.5px solid #1E2028",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: "rgba(0,200,130,0.12)",
              border: "1px solid rgba(0,200,130,0.25)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <Shield size={16} color="#00C882" />
          </div>
          <div>
            <div
              style={{
                fontFamily: "'Sora', sans-serif",
                fontSize: 14,
                fontWeight: 700,
                color: "#E8ECF0",
                letterSpacing: 2,
                lineHeight: 1,
              }}
            >
              ADVERSA
            </div>
            <div
              style={{
                fontFamily: "'Inter', sans-serif",
                fontSize: 10,
                color: "#555C68",
                letterSpacing: 0.3,
                marginTop: 3,
                fontWeight: 500,
              }}
            >
              v1.0 Enterprise
            </div>
          </div>
        </div>

        <button
          className="md:hidden"
          onClick={onClose}
          style={{
            background: "none", border: "none", cursor: "pointer",
            padding: "4px", borderRadius: 6,
            display: "flex", alignItems: "center", color: "#555C68",
          }}
        >
          <X size={16} />
        </button>
      </div>

      {/* ── Navigation ───────────────────────────────────────────────── */}
      <nav style={{ paddingTop: 10, flex: 1 }}>
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} style={{ marginBottom: 4 }}>
            <div
              style={{
                fontFamily: "'Inter', sans-serif",
                fontSize: 10,
                fontWeight: 600,
                color: "#555C68",
                letterSpacing: 1.2,
                padding: "8px 16px 4px",
                textTransform: "uppercase",
              }}
            >
              {section.label}
            </div>

            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.label}
                  href={item.href}
                  onClick={onClose}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "8px 12px",
                    margin: "1px 8px",
                    borderRadius: 6,
                    textDecoration: "none",
                    background: isActive ? "rgba(0,200,130,0.10)" : "transparent",
                    transition: "background 0.12s ease",
                    position: "relative",
                    borderLeft: isActive ? "2px solid #00C882" : "2px solid transparent",
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive)
                      (e.currentTarget as HTMLElement).style.background = "#181B22";
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive)
                      (e.currentTarget as HTMLElement).style.background = "transparent";
                  }}
                >
                  <Icon
                    size={15}
                    color={isActive ? "#00C882" : "#8C95A0"}
                    style={{ flexShrink: 0 }}
                  />
                  <span
                    style={{
                      fontFamily: "'Inter', sans-serif",
                      fontSize: 13,
                      fontWeight: isActive ? 600 : 400,
                      color: isActive ? "#E8ECF0" : "#8C95A0",
                    }}
                  >
                    {item.label}
                  </span>

                  {item.href === "/cases" && (
                    <span
                      style={{
                        marginLeft: "auto",
                        background: "rgba(255,75,75,0.15)",
                        color: "#FF4B4B",
                        fontSize: 10,
                        fontFamily: "'Inter', sans-serif",
                        fontWeight: 700,
                        borderRadius: 10,
                        padding: "1px 6px",
                        lineHeight: 1.5,
                      }}
                    >
                      12
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* ── Footer ───────────────────────────────────────────────────── */}
      <div
        style={{
          padding: "12px 16px",
          borderTop: "0.5px solid #1E2028",
          background: "#12141A",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <span
            className="animate-pulse-dot"
            style={{
              display: "inline-block",
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: "#00C882",
              flexShrink: 0,
            }}
          />
          <span
            style={{
              fontFamily: "'Inter', sans-serif",
              fontSize: 11,
              fontWeight: 500,
              color: "#00C882",
            }}
          >
            System Nominal
          </span>
        </div>

        <div
          style={{
            fontFamily: "'Inter', sans-serif",
            fontSize: 10,
            color: "#555C68",
            marginTop: 4,
          }}
        >
          ADVERSA v1.0.0 · Enterprise
        </div>
      </div>
    </aside>
  );
}
