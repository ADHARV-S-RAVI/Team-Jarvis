import React, { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertOctagon,
  Award,
  Bell,
  Clock,
  FileCheck2,
  Gauge,
  KeyRound,
  Laptop,
  Lock,
  Menu,
  MessageSquareLock,
  Moon,
  Network,
  Radar,
  RotateCcw,
  Settings,
  Shield,
  ShieldAlert,
  Sun,
  Users,
  X,
} from "lucide-react";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { useTheme } from "../app/ThemeContext";
import { StatusBadge, useToast } from "./ui";

const NAV_ITEMS = [
  { to: "/overview", label: "Dashboard", icon: Activity },
  { to: "/identities", label: "Identities", icon: Users },
  { to: "/devices", label: "Devices", icon: Laptop },
  { to: "/vault", label: "Vault", icon: Lock },
  { to: "/keys", label: "Keys & Backups", icon: KeyRound },
  { to: "/nodes", label: "Nodes (Sim)", icon: Network },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/detector", label: "Threats & Graph", icon: Radar },
  { to: "/messaging", label: "Messaging", icon: MessageSquareLock },
  { to: "/audit", label: "Audit Ledger", icon: FileCheck2 },
  { to: "/datalab", label: "Data Verification Lab", icon: Activity },
  { to: "/security-integrity", label: "Security Integrity", icon: Shield },
  { to: "/scenarios", label: "Simulation", icon: AlertOctagon },
  { to: "/benchmarks", label: "Benchmarks", icon: Gauge },
  { to: "/scorecard", label: "Scorecard", icon: Award },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function ConsoleLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { session } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const qc = useQueryClient();
  const { push } = useToast();

  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 15000,
  });
  const alertsQuery = useQuery({
    queryKey: ["detector-alerts"],
    queryFn: api.detectorAlerts,
    refetchInterval: 15000,
  });

  const resetMut = useMutation({
    mutationFn: api.resetSimulation,
    onSuccess: () => {
      qc.invalidateQueries();
      push("Synthetic telemetry reset cleanly", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const alertCount = alertsQuery.data?.length ?? 0;

  const navContent = (
    <div className="flex flex-col h-full bg-white dark:bg-[#0b0f13]">
      <div className="flex items-center justify-center lg:justify-start gap-2.5 px-4 py-4 border-b border-slate-200 dark:border-[#1c242d]">
        <div className="w-8 h-8 rounded-full bg-emerald-50 dark:bg-emerald-500/15 border border-emerald-200 dark:border-emerald-500/40 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
          <Shield className="w-4 h-4" />
        </div>
        <div>
          <div className="text-sm font-bold tracking-wider text-slate-900 dark:text-slate-100">Q-SHIELD</div>
          <div className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase tracking-widest">Trust Plane</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-1" aria-label="Primary Navigation">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-all ${
                  isActive
                    ? "bg-emerald-50 dark:bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/35 shadow-[inset_2px_0_0_#059669]"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-[#141b22] border border-transparent"
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="p-3 border-t border-slate-200 dark:border-[#1c242d] space-y-2 text-[11px] bg-slate-50 dark:bg-[#090c10]">
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Engine</span>
          {healthQuery.isSuccess ? (
            <StatusBadge label="ONLINE" tone="success" />
          ) : (
            <StatusBadge label="OFFLINE" tone="danger" />
          )}
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Cluster</span>
          <StatusBadge label="SIMULATED" tone="violet" />
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Actor</span>
          <span className="font-mono text-emerald-700 dark:text-emerald-400 truncate max-w-[100px]">
            {session ? session.actorId : "guest"}
          </span>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-[#080b0e] text-slate-900 dark:text-slate-100">
      {/* Desktop sidebar */}
      <aside className="hidden lg:block w-52 shrink-0 bg-white dark:bg-[#0b0f13] border-r border-slate-200 dark:border-[#1c242d]">
        {navContent}
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden flex">
          <div className="w-56 bg-white dark:bg-[#0b0f13] border-r border-slate-200 dark:border-[#1c242d] h-full">{navContent}</div>
          <div className="flex-1 bg-slate-900/30 dark:bg-black/70" onClick={() => setMobileOpen(false)} />
        </div>
      )}

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-13 py-2 border-b border-slate-200 dark:border-[#1c242d] bg-white/95 dark:bg-[#0b0f13]/95 backdrop-blur flex flex-wrap items-center justify-between gap-2 px-4 md:px-6 z-20">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileOpen((v) => !v)}
              aria-label="Toggle navigation"
              className="lg:hidden p-1.5 rounded text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-[#141b22]"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-500 dark:text-slate-400">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="hidden sm:inline">Q-SHIELD · Track 4 Proof-Carrying Control Plane</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-50 dark:bg-[#11181f] border border-emerald-200 dark:border-emerald-500/25 text-[11px] font-mono text-emerald-700 dark:text-emerald-300">
              <Clock className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>LIVE TELEMETRY · LOCAL OFFLINE</span>
            </div>

            <button
              type="button"
              onClick={toggleTheme}
              aria-label={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
              title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-white dark:bg-[#141b22] hover:bg-slate-100 dark:hover:bg-[#1b242e] border border-slate-300 dark:border-[#26313d] text-[11px] font-mono text-slate-700 dark:text-slate-200 transition-colors"
            >
              {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-violet-600" />}
              <span className="hidden sm:inline">{isDark ? "Light" : "Dark"}</span>
            </button>

            <button
              type="button"
              onClick={() => resetMut.mutate()}
              disabled={resetMut.isPending}
              title="Reset synthetic data"
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-white dark:bg-[#141b22] hover:bg-slate-100 dark:hover:bg-[#1b242e] border border-slate-300 dark:border-[#26313d] text-[11px] font-mono text-slate-700 dark:text-slate-200 transition-colors"
            >
              <RotateCcw className={`w-3 h-3 text-emerald-600 dark:text-emerald-400 ${resetMut.isPending ? "animate-spin" : ""}`} />
              <span className="hidden sm:inline">Reset Demo</span>
            </button>

            <NavLink
              to="/detector"
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-white dark:bg-[#141b22] border border-slate-300 dark:border-[#26313d] text-xs font-mono text-slate-700 dark:text-slate-200 hover:border-emerald-400"
              title="Active detector alerts"
            >
              <Bell className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>{alertCount}</span>
            </NavLink>

            <NavLink
              to="/login"
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 dark:bg-emerald-500/20 hover:bg-emerald-100 dark:hover:bg-emerald-500/30 border border-emerald-200 dark:border-emerald-500/40 text-xs font-semibold text-emerald-700 dark:text-emerald-300"
            >
              <span className="w-5 h-5 rounded-full bg-emerald-600 text-white flex items-center justify-center text-[10px] font-bold uppercase">
                {(session?.actorId ?? "DL").slice(0, 2)}
              </span>
              <span className="hidden sm:inline">{session ? session.actorId : "Demo Login"}</span>
            </NavLink>
          </div>
        </header>

        <main className="flex-1 p-4 md:p-5 overflow-y-auto max-w-[1600px] w-full mx-auto relative">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
