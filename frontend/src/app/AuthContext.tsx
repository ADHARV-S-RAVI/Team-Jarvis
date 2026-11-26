import React, { createContext, useContext, useState } from "react";

export interface ActiveSessionState {
  actorId: string;
  deviceId: string;
  sessionId: string;
  sessionToken: string;
  peerId: string;
}

interface AuthContextValue {
  session: ActiveSessionState | null;
  setSession: (s: ActiveSessionState | null) => void;
  theme: "dark" | "light";
  toggleTheme: () => void;
  reducedMotion: boolean;
  toggleReducedMotion: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // Never store sessionToken in localStorage; keep in memory only.
  const [session, setSession] = useState<ActiveSessionState | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [reducedMotion, setReducedMotion] = useState(false);

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
      value={{ session, setSession, theme, toggleTheme, reducedMotion, toggleReducedMotion }}
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
