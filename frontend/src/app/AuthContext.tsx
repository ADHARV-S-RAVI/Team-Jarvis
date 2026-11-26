import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api";

export interface ActiveSessionState {
  actorId: string;
  deviceId: string;
  sessionId: string;
  sessionToken: string;
  peerId: string;
  role?: string;
  displayLabel?: string;
  email?: string | null;
  issuedAt?: string;
  expiresAt?: string;
  identityVerified?: boolean;
  verificationMethod?: string | null;
  sessionSecretBound?: boolean;
}

interface AuthContextValue {
  session: ActiveSessionState | null;
  authLoading: boolean;
  setSession: (s: ActiveSessionState | null) => void;
  logout: () => Promise<void>;
  theme: "dark" | "light";
  toggleTheme: () => void;
  reducedMotion: boolean;
  toggleReducedMotion: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Never store sessionToken in localStorage; backend HttpOnly cookies + in-memory state only.
  const [session, setSession] = useState<ActiveSessionState | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [reducedMotion, setReducedMotion] = useState(false);
  const qc = useQueryClient();

  useEffect(() => {
    let active = true;
    api
      .getSessionStatus()
      .then((st) => {
        if (!active || !st?.valid) return;
        setSession({
          actorId: st.actor_id,
          deviceId: st.device_id,
          sessionId: st.session_id,
          sessionToken: "", // Cookie-backed in browser; never exposed in JS storage
          peerId: "web-console",
          role: st.role,
          displayLabel: st.display_label,
          email: st.email,
          issuedAt: st.issued_at,
          expiresAt: st.expires_at,
          identityVerified: st.identity_verified,
          verificationMethod: st.verification_method,
          sessionSecretBound: st.session_secret_bound,
        });
      })
      .catch(() => {
        if (active) setSession(null);
      })
      .finally(() => {
        if (active) setAuthLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const logout = useCallback(async () => {
    window.dispatchEvent(new Event("qshield:logout"));
    try {
      const base =
        (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ??
        (typeof window !== "undefined" && window.location.port === "5173"
          ? "http://127.0.0.1:8000"
          : "");
      await fetch(`${base}/api/v1/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers:
          session?.sessionId && session?.sessionToken
            ? {
                "Content-Type": "application/json",
                "X-Session-Id": session.sessionId,
                Authorization: `Bearer ${session.sessionToken}`,
              }
            : { "Content-Type": "application/json" },
      });
    } catch {
      // Clear local state even if network call fails
    }
    setSession(null);
    qc.clear();
  }, [session, qc]);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.classList.toggle("dark", next === "dark");
    document.documentElement.classList.toggle("light", next === "light");
  };

  const toggleReducedMotion = () => {
    const next = !reducedMotion;
    setReducedMotion(next);
    document.documentElement.classList.toggle("reduced-motion", next);
  };

  return (
    <AuthContext.Provider
      value={{ session, authLoading, setSession, logout, theme, toggleTheme, reducedMotion, toggleReducedMotion }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
