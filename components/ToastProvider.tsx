"use client";

import React, { createContext, useState, useCallback, useRef } from "react";
import { CheckCircle, AlertTriangle, XCircle, Info, X } from "lucide-react";

/* ─── Types ─── */
export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
  dismissing?: boolean;
}

interface ToastContextValue {
  toast: (opts: Omit<Toast, "id">) => void;
  success: (title: string, message?: string) => void;
  error: (title: string, message?: string) => void;
  warning: (title: string, message?: string) => void;
  info: (title: string, message?: string) => void;
  dismiss: (id: string) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

/* ─── Style per type ─── */
const TOAST_STYLES: Record<ToastType, { icon: React.ElementType; accent: string; bg: string; border: string }> = {
  success: { icon: CheckCircle, accent: "#00FF88", bg: "rgba(0,255,136,0.06)", border: "rgba(0,255,136,0.25)" },
  error:   { icon: XCircle,     accent: "#FF1744", bg: "rgba(255,23,68,0.06)",  border: "rgba(255,23,68,0.3)"  },
  warning: { icon: AlertTriangle,accent: "#FFD600", bg: "rgba(255,214,0,0.06)", border: "rgba(255,214,0,0.25)" },
  info:    { icon: Info,         accent: "#00D4FF", bg: "rgba(0,212,255,0.06)", border: "rgba(0,212,255,0.25)" },
};

/* ─── Single Toast ─── */
function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  const style = TOAST_STYLES[toast.type];
  const Icon = style.icon;

  return (
    <div
      className={toast.dismissing ? "animate-slide-out-right" : "animate-slide-in-right"}
      style={{
        background: "#0D1B26",
        border: `1px solid ${style.border}`,
        borderLeft: `3px solid ${style.accent}`,
        borderRadius: 8,
        padding: "12px 16px",
        display: "flex",
        gap: 12,
        alignItems: "flex-start",
        minWidth: 300,
        maxWidth: 380,
        boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        cursor: "default",
      }}
    >
      <Icon size={16} color={style.accent} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontFamily: "'Share Tech Mono', monospace",
            fontSize: 12,
            color: "#C8E8F0",
            fontWeight: 600,
          }}
        >
          {toast.title}
        </div>
        {toast.message && (
          <div
            style={{
              fontFamily: "'Rajdhani', sans-serif",
              fontSize: 13,
              color: "#3D7A94",
              marginTop: 3,
              lineHeight: 1.4,
            }}
          >
            {toast.message}
          </div>
        )}
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          padding: 0,
          color: "#3D7A94",
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          marginTop: 1,
        }}
      >
        <X size={14} />
      </button>
    </div>
  );
}

/* ─── Provider ─── */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, dismissing: true } : t)));
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 280);
    const timer = timersRef.current.get(id);
    if (timer) clearTimeout(timer);
    timersRef.current.delete(id);
  }, []);

  const toast = useCallback(
    (opts: Omit<Toast, "id">) => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      setToasts((prev) => {
        const next = [...prev, { ...opts, id }];
        return next.length > 3 ? next.slice(next.length - 3) : next;
      });
      const duration = opts.duration ?? 4000;
      const timer = setTimeout(() => dismiss(id), duration);
      timersRef.current.set(id, timer);
    },
    [dismiss]
  );

  const success = useCallback((title: string, message?: string) => toast({ type: "success", title, message }), [toast]);
  const error   = useCallback((title: string, message?: string) => toast({ type: "error", title, message }), [toast]);
  const warning = useCallback((title: string, message?: string) => toast({ type: "warning", title, message }), [toast]);
  const info    = useCallback((title: string, message?: string) => toast({ type: "info", title, message }), [toast]);

  return (
    <ToastContext.Provider value={{ toast, success, error, warning, info, dismiss }}>
      {children}

      {/* Toast Container — top-right fixed */}
      <div
        style={{
          position: "fixed",
          top: 16,
          right: 16,
          zIndex: 9999,
          display: "flex",
          flexDirection: "column",
          gap: 8,
          pointerEvents: "none",
        }}
      >
        {toasts.map((t) => (
          <div key={t.id} style={{ pointerEvents: "auto" }}>
            <ToastItem toast={t} onDismiss={dismiss} />
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
