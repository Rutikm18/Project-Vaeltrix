"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, Brain, Network, Users, Grid,
  AlertTriangle, Eye, FileText, X,
  Terminal, Briefcase, Settings,
} from "lucide-react";

const NAV_SECTIONS = [
  {
    label: "OPERATIONS",
    items: [
      { icon: Shield,        label: "Dashboard",       href: "/" },
      { icon: Brain,         label: "AI Brain",         href: "/aibrain" },
      { icon: Terminal,      label: "Scanner",          href: "/scan" },
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
        background: "#0D1B26",
        borderRight: "1px solid #1A3A50",
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        flexShrink: 0,
        overflowY: "auto",
      }}
    >
      {/* Logo */}
      <div
        style={{
          padding: "16px",
          borderBottom: "1px solid #1A3A50",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: "rgba(0,212,255,0.1)",
              border: "1px solid rgba(0,212,255,0.3)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={16} color="#00D4FF" />
          </div>
          <div>
            <div
              style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 13,
                color: "#00D4FF",
                letterSpacing: 2,
                lineHeight: 1,
              }}
            >
              ADVERSA
            </div>
            <div
              style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 9,
                color: "#3D7A94",
                letterSpacing: 1,
                marginTop: 2,
              }}
            >
              v1.0 ENTERPRISE
            </div>
          </div>
        </div>
        <button
          className="md:hidden"
          onClick={onClose}
          style={{ background: "none", border: "none", cursor: "pointer", padding: 4 }}
        >
          <X size={16} color="#3D7A94" />
        </button>
      </div>

      {/* Nav Sections */}
      <nav style={{ paddingTop: 8, flex: 1 }}>
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} style={{ marginBottom: 8 }}>
            <div
              style={{
                fontFamily: "'Share Tech Mono', monospace",
                fontSize: 9,
                color: "#3D7A94",
                letterSpacing: 2,
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
                    padding: "9px 16px",
                    textDecoration: "none",
                    borderLeft: isActive ? "2px solid #00D4FF" : "2px solid transparent",
                    background: isActive ? "rgba(0,212,255,0.06)" : "transparent",
                    transition: "background 0.15s ease, border-left 0.15s ease",
                    position: "relative",
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) {
                      (e.currentTarget as HTMLElement).style.background = "rgba(0,212,255,0.03)";
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) {
                      (e.currentTarget as HTMLElement).style.background = "transparent";
                    }
                  }}
                >
                  <Icon size={14} color={isActive ? "#00D4FF" : "#3D7A94"} />
                  <span
                    style={{
                      fontFamily: "'Share Tech Mono', monospace",
                      fontSize: 11,
                      color: isActive ? "#C8E8F0" : "#3D7A94",
                      letterSpacing: 0.3,
                    }}
                  >
                    {item.label}
                  </span>
                  {item.href === "/cases" && (
                    <span
                      style={{
                        marginLeft: "auto",
                        background: "#FF1744",
                        color: "#fff",
                        fontSize: 9,
                        fontFamily: "'Share Tech Mono', monospace",
                        borderRadius: 8,
                        padding: "1px 5px",
                        lineHeight: 1.4,
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

      {/* Footer */}
      <div
        style={{
          padding: "10px 16px",
          borderTop: "1px solid #1A3A50",
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span
            className="animate-pulse-dot"
            style={{
              display: "inline-block",
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: "#00FF88",
            }}
          />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#00FF88" }}>
            SYSTEM NOMINAL
          </span>
        </div>
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 9, color: "#3D7A94", marginTop: 3 }}>
          ADVERSA v1.0.0 · ENTERPRISE
        </div>
      </div>
    </aside>
  );
}
