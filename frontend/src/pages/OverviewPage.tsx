import React, { Suspense, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Database,
  KeyRound,
  Laptop,
  Lock,
  MessageSquareLock,
  MoreVertical,
  Network,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import { api, API_BASE_URL } from "../services/api";
import { useTheme } from "../app/ThemeContext";
import { LoadingSpinner, StatusBadge } from "../components/ui";
import {
  InteractiveTopologyGraph,
  TelemetrySparkGrid,
  TopoEdge,
  TopoNode,
} from "../components/TopologyTelemetryPanel";
import AeroShards from "./AeroShards";
import type { CyberEdge, CyberNodeEntity } from "../components/CyberCommand3D";

const CyberCommand3D = React.lazy(() => import("../components/CyberCommand3D"));

const SEV_COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#10b981",
};

const REMED_COLORS = {
  Open: "#f97316",
  Contained: "#10b981",
  Revocations: "#06b6d4",
};

function PanelHeader({
  title,
  to,
  extra,
}: {
  title: string;
  to?: string;
  extra?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between mb-3 gap-2">
      <div className="flex items-center gap-2 min-w-0">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
        <h2 className="text-[13px] font-semibold text-slate-900 dark:text-slate-100 tracking-tight truncate">
          {title}
        </h2>
      </div>
      <div className="flex items-center gap-1.5 shrink-0">
        {extra}
        {to && (
          <NavLink
            to={to}
            title={`Open ${title}`}
            className="text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors"
          >
            <MoreVertical className="w-3.5 h-3.5" />
          </NavLink>
        )}
      </div>
    </div>
  );
}

export function OverviewPage() {
  const { isDark } = useTheme();
  const qc = useQueryClient();
  const [sseConnected, setSseConnected] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedRemed, setSelectedRemed] = useState<string | null>(null);
  const [latencyChartType, setLatencyChartType] = useState<"area" | "bar">("area");
  const [showAllowed, setShowAllowed] = useState(true);
  const [showDenied, setShowDenied] = useState(true);
  const [trendBuckets, setTrendBuckets] = useState<5 | 8>(5);

  useEffect(() => {
    if (typeof EventSource === "undefined") return;
    const es = new EventSource(`${API_BASE_URL}/api/v1/telemetry/stream`);
    es.onopen = () => setSseConnected(true);
    es.onerror = () => setSseConnected(false);
    es.addEventListener("file_verified", () => qc.invalidateQueries({ queryKey: ["datalab-files"] }));
    es.addEventListener("upload_progress", () => qc.invalidateQueries({ queryKey: ["datalab-jobs"] }));
    return () => es.close();
  }, [qc]);

  const sysMetrics = useQuery({ queryKey: ["system-metrics"], queryFn: api.systemMetrics, refetchInterval: 10000 });

  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const identities = useQuery({ queryKey: ["identities"], queryFn: api.listIdentities });
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.listDevices });
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: api.listSessions });
  const resources = useQuery({ queryKey: ["resources"], queryFn: api.listResources });
  const keys = useQuery({ queryKey: ["keys"], queryFn: api.listKeys });
  const nodes = useQuery({ queryKey: ["nodes"], queryFn: api.listNodes });
  const nodeMetrics = useQuery({ queryKey: ["node-metrics"], queryFn: api.nodeMetrics });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.listIncidents });
  const alerts = useQuery({ queryKey: ["detector-alerts"], queryFn: api.detectorAlerts });
  const audit = useQuery({ queryKey: ["audit-events"], queryFn: () => api.listAuditEvents() });
  const messages = useQuery({ queryKey: ["messages"], queryFn: api.listMessages });
  const bench = useQuery({ queryKey: ["benchmarks-latest"], queryFn: api.benchmarksLatest });

  if (health.isLoading) return <LoadingSpinner label="Loading control plane telemetry..." />;

  const idList = identities.data ?? [];
  const devList = devices.data ?? [];
  const sessList = sessions.data ?? [];
  const resList = resources.data ?? [];
  const keyList = keys.data ?? [];
  const nodeList = nodes.data ?? [];
  const incList = incidents.data ?? [];
  const alertList = alerts.data ?? [];
  const auditList = audit.data ?? [];
  const msgList = messages.data ?? [];

  const tooltipStyle = {
    backgroundColor: isDark ? "#0b0f13" : "#ffffff",
    borderColor: isDark ? "#1c242d" : "#e2e8f0",
    color: isDark ? "#f8fafc" : "#0f172a",
    fontSize: 11,
    borderRadius: 6,
  };
  const gridStroke = isDark ? "#1c242d" : "#e2e8f0";
  const axisStroke = isDark ? "#64748b" : "#64748b";

  // 1. Alerts & Incident Severity Distribution
  const criticalCount =
    alertList.filter((a) => a.severity === "CRITICAL").length +
    devList.filter((d) => d.state === "REVOKED").length +
    keyList.filter((k) => k.state === "COMPROMISED").length;
  const highCount =
    alertList.filter((a) => a.severity === "HIGH").length +
    incList.filter((i) => i.status !== "CONTAINED").length;
  const mediumCount =
    alertList.filter((a) => a.severity === "MEDIUM").length +
    auditList.filter((a) => a.decision === "DENY").length;
  const lowCount = auditList.filter((a) => a.decision === "ALLOW" || a.decision === "COMMITTED").length;

  const alertDonutRaw = [
    { name: "Critical", value: criticalCount, color: SEV_COLORS.Critical },
    { name: "High", value: highCount, color: SEV_COLORS.High },
    { name: "Medium", value: mediumCount, color: SEV_COLORS.Medium },
    { name: "Low", value: lowCount, color: SEV_COLORS.Low },
  ];
  const alertTotal = criticalCount + highCount + mediumCount + lowCount;
  const alertChartSlices = alertDonutRaw.filter((d) => d.value > 0);
  const selectedAlertSlice = alertDonutRaw.find((s) => s.name === selectedSeverity);

  // 2. High-Risk Entities
  const highRiskRows = [
    ...devList
      .filter((d) => d.state !== "TRUSTED")
      .map((d) => ({
        type: "Device",
        source: d.id,
        owner: d.owner_actor_id,
        priority: d.state === "REVOKED" ? "Critical" : "High",
      })),
    ...keyList
      .filter((k) => k.state === "COMPROMISED" || k.state === "REVOKED")
      .map((k) => ({
        type: "Key",
        source: k.id,
        owner: `v${k.version}`,
        priority: "Critical",
      })),
    ...alertList.slice(0, 4).map((a) => ({
      type: "Alert",
      source: a.actor,
      owner: a.rule_id,
      priority: a.severity === "CRITICAL" ? "Critical" : "High",
    })),
  ].slice(0, 5);

  // 3. Pipeline Funnel Counts
  const totalEventsCount = Math.max(auditList.length, 1);
  const policyChecksCount = auditList.filter(
    (e) => e.action.includes("read") || e.action.includes("authz") || e.action.includes("policy")
  ).length;
  const blockedOrFlaggedCount = auditList.filter((e) => e.decision === "DENY").length + alertList.length;
  const verifiedReceiptsCount =
    incList.filter((i) => i.confirmed).length + keyList.filter((k) => k.state === "ACTIVE").length;

  // 4. Top Deterministic Rules
  const ruleBuckets = new Map<string, number>();
  for (const a of alertList) {
    ruleBuckets.set(a.rule_id, (ruleBuckets.get(a.rule_id) ?? 0) + 1);
  }
  for (const ev of auditList) {
    if (ev.decision === "DENY") {
      const k = ev.reason || ev.action;
      ruleBuckets.set(k, (ruleBuckets.get(k) ?? 0) + 1);
    }
  }
  const topRules = Array.from(ruleBuckets.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);

  // 5. Latest Threats & Events feed (optionally filtered by clicked donut severity)
  const latestFeed = [
    ...alertList.map((a) => ({
      id: a.id,
      sev: a.severity === "CRITICAL" ? "Critical" : a.severity === "HIGH" ? "High" : "Medium",
      title: `${a.rule_id}: ${a.explanation}`,
      meta: `${a.created_at.slice(0, 19).replace("T", " ")} · Actor: ${a.actor}`,
      tone: a.severity === "CRITICAL" ? "danger" : "warning",
    })),
    ...incList.map((inc) => ({
      id: inc.id,
      sev: inc.status === "CONTAINED" ? "Low" : "High",
      title: `${inc.incident_type}: ${inc.target_subject_id} (${inc.reason})`,
      meta: `${inc.created_at.slice(0, 19).replace("T", " ")} · Status: ${inc.status}`,
      tone: inc.status === "CONTAINED" ? "success" : "danger",
    })),
    ...auditList
      .filter((ev) => ev.decision === "DENY")
      .slice(-6)
      .reverse()
      .map((ev) => ({
        id: ev.event_id,
        sev: "Medium",
        title: `Policy DENY: ${ev.action} on ${ev.target} (${ev.reason})`,
        meta: `${ev.timestamp.slice(0, 19).replace("T", " ")} · Actor: ${ev.actor_id}`,
        tone: "warning",
      })),
  ]
    .filter((item) => !selectedSeverity || item.sev === selectedSeverity)
    .slice(0, 4);

  // 6. SLA / Posture Percentages
  const healthyNodes = nodeList.filter((n) => n.health === "HEALTHY").length;
  const nodePct = nodeList.length > 0 ? Math.round((healthyNodes / nodeList.length) * 100) : 100;
  const trustedDevs = devList.filter((d) => d.state === "TRUSTED").length;
  const devPct = devList.length > 0 ? Math.round((trustedDevs / devList.length) * 100) : 100;
  const activeKeys = keyList.filter((k) => k.state === "ACTIVE" || k.state === "ACTIVE_NEW").length;
  const keyPct = keyList.length > 0 ? Math.max(20, Math.round((activeKeys / keyList.length) * 100)) : 100;

  // 7. Remediation Donut
  const openInc = incList.filter((i) => i.status !== "CONTAINED").length;
  const containedInc = incList.filter((i) => i.status === "CONTAINED").length;
  const verifiedOps =
    keyList.filter((k) => k.state === "RETIRED").length + devList.filter((d) => d.state === "REVOKED").length;
  const remedTotal = openInc + containedInc + verifiedOps;
  const remedData = [
    { name: "Open", value: openInc, color: REMED_COLORS.Open },
    { name: "Contained", value: containedInc, color: REMED_COLORS.Contained },
    { name: "Revocations", value: verifiedOps, color: REMED_COLORS.Revocations },
  ].filter((d) => d.value > 0);
  const activeRemed = remedData.find((r) => r.name === selectedRemed);

  // 8. Latency Trend
  const latencyTrend =
    nodeList.length > 0
      ? nodeList.map((n, idx) => ({
          label: n.id.replace("sim-", ""),
          latency: Number(n.delay_ms || (idx + 1) * 1.2),
        }))
      : (bench.data?.benchmarks ?? []).slice(0, 6).map((b) => ({
          label: b.operation.slice(0, 8),
          latency: Number(b.p50_ms),
        }));

  // 9. Audit Allow vs Deny Trend
  const bucketSize = Math.max(1, Math.ceil(auditList.length / trendBuckets));
  const auditTrend = Array.from({ length: Math.min(trendBuckets, Math.max(1, auditList.length)) }, (_, bIdx) => {
    const slice = auditList.slice(bIdx * bucketSize, (bIdx + 1) * bucketSize);
    return {
      bucket: `T${bIdx + 1}`,
      allowed: slice.filter((e) => e.decision === "ALLOW" || e.decision === "COMMITTED").length,
      denied: slice.filter((e) => e.decision !== "ALLOW" && e.decision !== "COMMITTED").length,
    };
  });

  const activeSessions = sessList.filter((s) => !s.revoked_at).length;
  const cardGlass =
    "bg-white/85 dark:bg-[#0f1419]/85 backdrop-blur-md border border-slate-200 dark:border-[#1c242d] rounded-lg p-4 shadow-sm";

  // Live 3D Cyber Command Center entities & trust edges
  const cyberEntities: CyberNodeEntity[] = [
    {
      id: "qshield-core",
      label: "Q-SHIELD Core",
      kind: "core",
      trustState: health.isSuccess ? "HEALTHY" : "OFFLINE",
      meta: `9-Step Authz | Active Keys: ${activeKeys} | Worker: ${sysMetrics.data?.worker_running ? "ONLINE" : "STANDBY"}`,
      route: "/scorecard",
    },
    ...idList.map((i) => ({
      id: `id-${i.id}`,
      label: i.id,
      kind: "identity" as const,
      trustState: i.enabled ? "TRUSTED" : "REVOKED",
      meta: `${i.display_label} (${i.role})`,
      route: "/identities",
    })),
    ...devList.map((d) => ({
      id: `dev-${d.id}`,
      label: d.id,
      kind: "device" as const,
      trustState: d.state,
      meta: `Owner: ${d.owner_actor_id} | Ver: ${d.state_version}`,
      route: "/devices",
    })),
    ...resList.map((r) => ({
      id: `res-${r.id}`,
      label: r.id,
      kind: "resource" as const,
      trustState: r.state,
      meta: `Owner: ${r.owner_actor_id} | Key v${r.key_version}`,
      route: "/vault",
    })),
    ...nodeList.map((n) => ({
      id: `node-${n.id}`,
      label: n.id,
      kind: "node" as const,
      trustState: n.health,
      meta: `Delay: ${n.delay_ms}ms | Seq: ${n.last_sequence} | Key v${n.accepted_key_version}`,
      route: "/nodes",
    })),
    ...incList.slice(0, 4).map((inc) => ({
      id: `inc-${inc.id}`,
      label: inc.target_subject_id,
      kind: "incident" as const,
      trustState: inc.status === "CONTAINED" ? "CONTAINED" : "CRITICAL",
      meta: `${inc.incident_type}: ${inc.reason}`,
      route: "/incidents",
    })),
  ];

  const cyberEdges: CyberEdge[] = [
    ...idList.map((i) => ({ from: "qshield-core", to: `id-${i.id}`, kind: i.enabled ? ("trust" as const) : ("revoked" as const) })),
    ...devList.map((d) => ({ from: `id-${d.owner_actor_id}`, to: `dev-${d.id}`, kind: d.state === "TRUSTED" ? ("trust" as const) : ("revoked" as const) })),
    ...resList.map((r) => ({ from: `id-${r.owner_actor_id}`, to: `res-${r.id}`, kind: "trust" as const })),
    ...nodeList.map((n) => ({ from: "qshield-core", to: `node-${n.id}`, kind: n.health === "HEALTHY" ? ("trust" as const) : ("revoked" as const) })),
  ];

  // Live Interactive Topology Graph (Image 2 style) driven by real backend state
  const avgLatencyMs =
    latencyTrend.length > 0
      ? (latencyTrend.reduce((acc, p) => acc + p.latency, 0) / latencyTrend.length).toFixed(1)
      : "0.0";
  const topoNodes: TopoNode[] = [
    {
      id: "edge-policy",
      label: "9-Step Policy Gate",
      sublabel: "Zero-Trust AuthZ",
      layer: 0,
      status: health.isSuccess ? "OK" : "ALERT",
      metric: `${activeSessions} active sessions`,
    },
    ...(idList.length > 0
      ? idList.slice(0, 3).map((i) => ({
          id: `topo-id-${i.id}`,
          label: i.id,
          sublabel: i.role,
          layer: 1,
          status: (i.enabled ? "OK" : "ALERT") as TopoNode["status"],
          metric: i.enabled ? "ENABLED" : "DISABLED",
        }))
      : [{ id: "topo-id-idle", label: "Identity Plane", sublabel: "Standby", layer: 1, status: "OK" as const }]),
    ...(devList.length > 0
      ? devList.slice(0, 3).map((d) => ({
          id: `topo-dev-${d.id}`,
          label: d.id,
          sublabel: d.state,
          layer: 2,
          status: (d.state === "TRUSTED" ? "OK" : d.state === "SUSPENDED" ? "WARN" : "ALERT") as TopoNode["status"],
          metric: `v${d.state_version}`,
        }))
      : [{ id: "topo-dev-idle", label: "Device Trust", sublabel: "Standby", layer: 2, status: "OK" as const }]),
    ...(nodeList.length > 0
      ? nodeList.slice(0, 4).map((n) => ({
          id: `topo-node-${n.id}`,
          label: n.id,
          sublabel: `${n.delay_ms} ms`,
          layer: 3,
          status: (n.health === "HEALTHY" ? "OK" : "ALERT") as TopoNode["status"],
          metric: `Key v${n.accepted_key_version}`,
        }))
      : [{ id: "topo-node-idle", label: "sim-node-1", sublabel: "Standby", layer: 3, status: "OK" as const }]),
  ];

  const topoEdges: TopoEdge[] = [];
  const layer1 = topoNodes.filter((n) => n.layer === 1);
  const layer2 = topoNodes.filter((n) => n.layer === 2);
  const layer3 = topoNodes.filter((n) => n.layer === 3);
  for (const n1 of layer1) {
    topoEdges.push({ from: "edge-policy", to: n1.id, label: "authz", status: n1.status });
  }
  for (const n1 of layer1) {
    for (const n2 of layer2) {
      topoEdges.push({ from: n1.id, to: n2.id, label: "bind", status: n2.status });
    }
  }
  for (const n2 of layer2) {
    for (const n3 of layer3) {
      topoEdges.push({ from: n2.id, to: n3.id, label: `${avgLatencyMs}ms`, status: n3.status });
    }
  }

  const topoHistory =
    auditTrend.length > 0
      ? auditTrend.map((b) => ({ label: b.bucket, primary: b.allowed, secondary: b.denied }))
      : [{ label: "T1", primary: 0, secondary: 0 }];

  return (
    <div className="relative min-h-[600px]">
      {/* AeroShards Interactive Background */}
      <div
        style={{ width: "100%", height: "600px", position: "absolute", top: 0, left: 0, zIndex: 0 }}
        className="pointer-events-none overflow-hidden rounded-xl"
      >
        <AeroShards
          shardColor="#896ABD"
          accentColor="#A855F7"
          placement="full"
          material="glass"
          markers="plus"
          count={1300}
          depthOfField={0.75}
          vignette={0.3}
          mouseInteraction
          pulseOnClick
          holdToGather
          lightMode={!isDark}
          shardSize={1}
          spread={1}
          twist={1}
          billow={1}
          speed={1}
          scale={1}
          glow={0.35}
          grain={0.06}
          intro
          mouseStrength={0.6}
          parallax={0.5}
          paused={false}
        />
      </div>

      {/* Foreground Telemetry Grid */}
      <div className="relative z-10 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h1 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">
              Security Operations Overview
            </h1>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Real-time telemetry from FastAPI + SQLite control plane &middot; Click chart slices or toggle series to inspect
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge label={health.isSuccess ? "API HEALTHY" : "API OFFLINE"} tone={health.isSuccess ? "success" : "danger"} />
            <StatusBadge label={sseConnected ? "SSE: LIVE" : "SSE: POLLING"} tone={sseConnected ? "success" : "info"} />
            <StatusBadge label="NODES: SIMULATED" tone="violet" />
            <StatusBadge label="FS: NOT ESTABLISHED" tone="warning" />
            <StatusBadge
              label={bench.data?.status === "PASS" ? `BENCHMARKS: ${bench.data.benchmarks.length} OPS` : "BENCHMARKS: READY"}
              tone="info"
            />
          </div>
        </div>

        {/* Live High-Density Telemetry Sparklines */}
        <TelemetrySparkGrid
          stats={[
            {
              label: "Avg Node Latency",
              value: `${avgLatencyMs} ms`,
              tone: "emerald",
              series: latencyTrend.length > 0 ? latencyTrend.map((p) => p.latency) : [0, 0],
            },
            {
              label: "Trusted Devices",
              value: `${trustedDevs} / ${devList.length}`,
              tone: devPct >= 80 ? "emerald" : "amber",
              series: [1, trustedDevs, devList.length || 1],
            },
            {
              label: "Healthy Nodes",
              value: `${healthyNodes} / ${nodeList.length}`,
              tone: nodePct >= 80 ? "cyan" : "rose",
              series: [1, healthyNodes, nodeList.length || 1],
            },
            {
              label: "Active Keys",
              value: String(activeKeys),
              tone: "cyan",
              series: [1, activeKeys, activeKeys],
            },
            {
              label: "Audit Events",
              value: String(auditList.length),
              tone: "emerald",
              series: auditTrend.length > 0 ? auditTrend.map((b) => b.allowed + b.denied) : [0],
            },
            {
              label: "Control Plane",
              value: health.isSuccess ? "Healthy" : "Offline",
              tone: health.isSuccess ? "emerald" : "rose",
              series: [1, 1, 1, 1],
            },
          ]}
        />

        {/* Interactive Hop-by-Hop Control Plane Topology Graph */}
        <InteractiveTopologyGraph
          title="Live Trust & Revocation Control-Plane Topology"
          summaryStrip={[
            { label: "Avg Latency", value: `${avgLatencyMs} ms` },
            { label: "Identities", value: String(idList.length) },
            { label: "Devices", value: String(devList.length) },
            { label: "Simulated Nodes", value: String(nodeList.length) },
            { label: "Audit Events", value: String(auditList.length) },
          ]}
          nodes={topoNodes}
          edges={topoEdges}
          history={topoHistory}
          historyLabel="Control-Plane Audit Activity (Green = Allow/Commit, Red = Deny/Revoke)"
        />

        {/* 3D Cyber Command Center */}
        <Suspense fallback={<div className="h-[340px] rounded-xl bg-slate-100 dark:bg-[#0f1419] animate-pulse" />}>
          <CyberCommand3D entities={cyberEntities} edges={cyberEdges} isDark={isDark} />
        </Suspense>

        {/* ROW 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
          {/* Panel 1: Interactive Alerts Distribution Donut */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader
              title="Alerts Distribution"
              to="/detector"
              extra={
                selectedSeverity && (
                  <button
                    type="button"
                    onClick={() => setSelectedSeverity(null)}
                    className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 hover:underline"
                  >
                    Clear ({selectedSeverity})
                  </button>
                )
              }
            />
            <div className="flex items-center justify-between gap-2">
              <div className="relative w-36 h-36 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={alertChartSlices}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={44}
                      outerRadius={58}
                      paddingAngle={2}
                      stroke="none"
                      onClick={(entry) =>
                        setSelectedSeverity((prev) => (prev === entry.name ? null : entry.name))
                      }
                      className="cursor-pointer"
                    >
                      {alertChartSlices.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={entry.color}
                          opacity={!selectedSeverity || selectedSeverity === entry.name ? 1 : 0.35}
                        />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-xl font-bold font-mono text-slate-900 dark:text-white">
                    {selectedAlertSlice ? selectedAlertSlice.value : alertTotal}
                  </span>
                  <span className="text-[9px] uppercase text-slate-500">
                    {selectedAlertSlice ? selectedAlertSlice.name : "Signals"}
                  </span>
                </div>
              </div>
              <div className="space-y-1.5 text-xs flex-1">
                {alertDonutRaw.map((item) => (
                  <button
                    key={item.name}
                    type="button"
                    onClick={() => setSelectedSeverity((prev) => (prev === item.name ? null : item.name))}
                    className={`w-full flex items-center justify-between px-1.5 py-0.5 rounded transition-colors ${
                      selectedSeverity === item.name ? "bg-slate-100 dark:bg-slate-800/70" : "hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    }`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-0.5 rounded-full" style={{ backgroundColor: item.color }} />
                      <span className="text-slate-700 dark:text-slate-300 text-[11px]">{item.name}</span>
                    </div>
                    <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">{item.value}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Panel 2: Entity Risk & Trust Summary */}
          <div className={`lg:col-span-6 ${cardGlass} flex flex-col justify-between`}>
            <PanelHeader title="Entity Risk & Trust Summary" to="/identities" />
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-auto">
              <NavLink to="/vault" className="p-3 rounded-md bg-slate-50/90 dark:bg-[#131a21]/90 border border-slate-200 dark:border-[#1f2933] hover:border-emerald-500/50 transition-colors">
                <div className="flex items-center gap-2 text-rose-500 mb-1.5">
                  <Lock className="w-4 h-4" />
                  <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">{resList.length}</span>
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Vault Resources</div>
              </NavLink>

              <NavLink to="/identities" className="p-3 rounded-md bg-slate-50/90 dark:bg-[#131a21]/90 border border-slate-200 dark:border-[#1f2933] hover:border-emerald-500/50 transition-colors">
                <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 mb-1.5">
                  <Users className="w-4 h-4" />
                  <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">{idList.length}</span>
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Human Identities</div>
              </NavLink>

              <NavLink to="/devices" className="p-3 rounded-md bg-slate-50/90 dark:bg-[#131a21]/90 border border-slate-200 dark:border-[#1f2933] hover:border-emerald-500/50 transition-colors">
                <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400 mb-1.5">
                  <Laptop className="w-4 h-4" />
                  <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">{devList.length}</span>
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Enrolled Devices</div>
              </NavLink>

              <NavLink to="/nodes" className="p-3 rounded-md bg-slate-50/90 dark:bg-[#131a21]/90 border border-slate-200 dark:border-[#1f2933] hover:border-emerald-500/50 transition-colors">
                <div className="flex items-center gap-2 text-amber-500 mb-1.5">
                  <Network className="w-4 h-4" />
                  <span className="text-2xl font-bold font-mono text-slate-900 dark:text-white">
                    {healthyNodes}/{nodeList.length}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">Sim Nodes Healthy</div>
              </NavLink>
            </div>
          </div>

          {/* Panel 3: Latest Threats & Events */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader title={selectedSeverity ? `Filtered (${selectedSeverity})` : "Latest Threats & Events"} to="/incidents" />
            <div className="space-y-2.5 max-h-36 overflow-y-auto pr-1">
              {latestFeed.length === 0 ? (
                <div className="text-[11px] text-slate-500 py-8 text-center">
                  No matching threats or denials recorded.
                </div>
              ) : (
                latestFeed.map((item) => (
                  <div key={item.id} className="border-b border-slate-200 dark:border-[#1c242d] pb-2 last:border-0 last:pb-0">
                    <div className="flex items-start gap-1.5">
                      <ShieldAlert
                        className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${
                          item.tone === "danger" ? "text-rose-500" : item.tone === "success" ? "text-emerald-500" : "text-amber-500"
                        }`}
                      />
                      <div className="min-w-0">
                        <div className="text-[11px] text-slate-800 dark:text-slate-200 leading-snug line-clamp-2">{item.title}</div>
                        <div className="text-[10px] font-mono text-slate-500 mt-0.5">{item.meta}</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ROW 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
          {/* Panel 4: High Risk Entities */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader title="High Risk Entities" to="/devices" />
            <div className="space-y-2">
              <div className="grid grid-cols-3 text-[10px] font-mono uppercase text-slate-500 pb-1 border-b border-slate-200 dark:border-[#1c242d]">
                <span>Type</span>
                <span>Entity</span>
                <span className="text-right">Priority</span>
              </div>
              {highRiskRows.length === 0 ? (
                <div className="text-[11px] text-emerald-600 dark:text-emerald-400 py-8 text-center">
                  All devices &amp; keys currently trusted.
                </div>
              ) : (
                highRiskRows.map((row, idx) => (
                  <div
                    key={`${row.source}-${idx}`}
                    className="grid grid-cols-3 items-center text-[11px] py-1.5 border-b border-slate-200 dark:border-[#171f27] last:border-0"
                  >
                    <span className="text-slate-700 dark:text-slate-300 font-medium">{row.type}</span>
                    <span className="font-mono text-slate-500 dark:text-slate-400 truncate pr-1" title={row.source}>
                      {row.source}
                    </span>
                    <span className="text-right">
                      <span className={`font-semibold ${row.priority === "Critical" ? "text-rose-500" : "text-amber-500"}`}>
                        {row.priority}
                      </span>
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Panel 5 & 6: Funnel + Top Rules */}
          <div className="lg:col-span-6 grid grid-cols-1 md:grid-cols-2 gap-3.5">
            <div className={`${cardGlass} flex flex-col justify-between`}>
              <PanelHeader title="Trust Pipeline Funnel" to="/audit" />
              <div className="flex flex-col items-center justify-center space-y-1.5 py-2">
                <NavLink to="/audit" className="w-[92%] py-2 rounded-t-md bg-emerald-50 dark:bg-emerald-500/20 border border-emerald-200 dark:border-emerald-500/30 text-center hover:scale-[1.01] transition-transform">
                  <div className="text-sm font-bold font-mono text-slate-900 dark:text-white">{totalEventsCount}</div>
                  <div className="text-[10px] text-emerald-700 dark:text-emerald-300">Audit Ledger Events</div>
                </NavLink>
                <NavLink to="/identities" className="w-[74%] py-2 bg-emerald-50/80 dark:bg-emerald-500/15 border border-emerald-200 dark:border-emerald-500/30 text-center hover:scale-[1.01] transition-transform">
                  <div className="text-sm font-bold font-mono text-slate-900 dark:text-white">{policyChecksCount}</div>
                  <div className="text-[10px] text-emerald-700 dark:text-emerald-300">9-Step Policy Checks</div>
                </NavLink>
                <NavLink to="/detector" className="w-[56%] py-2 bg-amber-50 dark:bg-amber-500/20 border border-amber-200 dark:border-amber-500/30 text-center hover:scale-[1.01] transition-transform">
                  <div className="text-sm font-bold font-mono text-slate-900 dark:text-white">{blockedOrFlaggedCount}</div>
                  <div className="text-[10px] text-amber-700 dark:text-amber-300">Denials &amp; Alerts</div>
                </NavLink>
                <NavLink to="/incidents" className="w-[40%] py-2 rounded-b-md bg-cyan-50 dark:bg-cyan-500/20 border border-cyan-200 dark:border-cyan-500/30 text-center hover:scale-[1.01] transition-transform">
                  <div className="text-sm font-bold font-mono text-slate-900 dark:text-white">{verifiedReceiptsCount}</div>
                  <div className="text-[10px] text-cyan-700 dark:text-cyan-300">Verified Proofs</div>
                </NavLink>
              </div>
            </div>

            <div className={cardGlass}>
              <PanelHeader title="Top Deterministic Rules & Denials" to="/detector" />
              <div className="space-y-1.5">
                <div className="flex justify-between text-[10px] font-mono text-emerald-600 dark:text-emerald-400 pb-1 border-b border-slate-200 dark:border-[#1c242d]">
                  <span>Rule / Reason</span>
                  <span>Hits</span>
                </div>
                {topRules.length === 0 ? (
                  <div className="text-[11px] text-slate-500 py-8 text-center">
                    Run Attack Simulation or Detector to populate rule hits.
                  </div>
                ) : (
                  topRules.map(([rule, count]) => (
                    <div
                      key={rule}
                      className="flex items-center justify-between text-[11px] py-1 border-b border-slate-200 dark:border-[#171f27] last:border-0"
                    >
                      <span className="font-mono text-slate-700 dark:text-slate-300 truncate pr-2" title={rule}>
                        {rule}
                      </span>
                      <span className="font-mono font-semibold text-slate-900 dark:text-white">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Panel 7: Control-Plane Inventory */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader title="Control-Plane Inventory" to="/settings" />
            <div className="space-y-2 text-[11px]">
              {[
                { label: "Simulated Nodes", val: nodeList.length, icon: Network },
                { label: "Identities", val: idList.length, icon: Users },
                { label: "Vault Resources", val: resList.length, icon: Lock },
                { label: "Key Versions", val: keyList.length, icon: KeyRound },
                { label: "Active Sessions", val: activeSessions, icon: ShieldCheck },
                { label: "Encrypted Messages", val: msgList.length, icon: MessageSquareLock },
                { label: "Audit Events", val: auditList.length, icon: Database },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <div
                    key={item.label}
                    className="flex items-center justify-between py-1 border-b border-slate-200 dark:border-[#171f27] last:border-0"
                  >
                    <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                      <Icon className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                      <span>{item.label}</span>
                    </div>
                    <span className="font-mono font-semibold text-slate-900 dark:text-white">{item.val}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ROW 3 */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-3.5">
          {/* Panel 8: Trust Posture & SLA */}
          <div className={`lg:col-span-3 ${cardGlass} space-y-3.5`}>
            <PanelHeader title="Trust Posture & SLA" to="/scorecard" />
            {[
              { label: "Simulated Node Convergence", actual: `${nodePct}%`, pct: nodePct, color: "bg-emerald-500" },
              { label: "Trusted Devices Ratio", actual: `${devPct}%`, pct: devPct, color: devPct >= 80 ? "bg-cyan-500" : "bg-amber-500" },
              { label: "Active Key Coverage", actual: `${keyPct}%`, pct: keyPct, color: "bg-rose-500" },
            ].map((bar) => (
              <div key={bar.label} className="space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-700 dark:text-slate-300">{bar.label}</span>
                  <span className="font-mono text-slate-500 dark:text-slate-400">{bar.actual}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-slate-200 dark:bg-[#1a222b] overflow-hidden">
                  <div className={`h-full rounded-full ${bar.color} transition-all`} style={{ width: `${bar.pct}%` }} />
                </div>
              </div>
            ))}
          </div>

          {/* Panel 9: Interactive Remediation Donut */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader title="Remediation Status" to="/incidents" />
            <div className="flex items-center justify-between gap-2">
              <div className="relative w-32 h-32 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={remedData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={38}
                      outerRadius={50}
                      paddingAngle={2}
                      stroke="none"
                      onClick={(e) => setSelectedRemed((p) => (p === e.name ? null : e.name))}
                      className="cursor-pointer"
                    >
                      {remedData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={entry.color}
                          opacity={!selectedRemed || selectedRemed === entry.name ? 1 : 0.35}
                        />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-lg font-bold font-mono text-slate-900 dark:text-white">
                    {activeRemed ? activeRemed.value : remedTotal}
                  </span>
                  <span className="text-[9px] text-slate-500">{activeRemed ? activeRemed.name : "Actions"}</span>
                </div>
              </div>
              <div className="space-y-1.5 text-[11px] flex-1">
                {remedData.map((r) => (
                  <button
                    key={r.name}
                    type="button"
                    onClick={() => setSelectedRemed((p) => (p === r.name ? null : r.name))}
                    className="w-full flex justify-between text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/40 px-1 py-0.5 rounded"
                  >
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-0.5" style={{ backgroundColor: r.color }} />
                      {r.name}
                    </span>
                    <span className="font-mono text-slate-500 dark:text-slate-400">{r.value}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Panel 10: Interactive Convergence Latency Chart (Area / Bar Toggle) */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader
              title="Node Convergence Trend (ms)"
              to="/benchmarks"
              extra={
                <div className="flex rounded border border-slate-200 dark:border-[#1c242d] overflow-hidden text-[10px] font-mono">
                  <button
                    type="button"
                    onClick={() => setLatencyChartType("area")}
                    className={`px-1.5 py-0.5 ${latencyChartType === "area" ? "bg-emerald-500 text-white" : "text-slate-500"}`}
                  >
                    Area
                  </button>
                  <button
                    type="button"
                    onClick={() => setLatencyChartType("bar")}
                    className={`px-1.5 py-0.5 ${latencyChartType === "bar" ? "bg-emerald-500 text-white" : "text-slate-500"}`}
                  >
                    Bar
                  </button>
                </div>
              }
            />
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mb-1">
              <span className="text-emerald-600 dark:text-emerald-400">p50: {nodeMetrics.data?.p50_ms ?? "0.0"} ms</span>
              <span>p95: {nodeMetrics.data?.p95_ms ?? "0.0"} ms</span>
            </div>
            <div className="h-32">
              {latencyTrend.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[11px] text-slate-500">
                  No node delay samples yet
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  {latencyChartType === "area" ? (
                    <AreaChart data={latencyTrend}>
                      <defs>
                        <linearGradient id="emeraldGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
                      <XAxis dataKey="label" stroke={axisStroke} fontSize={10} />
                      <YAxis stroke={axisStroke} fontSize={10} width={28} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Area type="monotone" dataKey="latency" stroke="#10b981" strokeWidth={2} fill="url(#emeraldGrad)" />
                    </AreaChart>
                  ) : (
                    <BarChart data={latencyTrend}>
                      <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
                      <XAxis dataKey="label" stroke={axisStroke} fontSize={10} />
                      <YAxis stroke={axisStroke} fontSize={10} width={28} />
                      <Tooltip contentStyle={tooltipStyle} />
                      <Bar dataKey="latency" fill="#10b981" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  )}
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Panel 11: Interactive Policy Allow vs Deny Trend */}
          <div className={`lg:col-span-3 ${cardGlass}`}>
            <PanelHeader
              title="Policy Allow vs Deny Trend"
              to="/audit"
              extra={
                <button
                  type="button"
                  onClick={() => setTrendBuckets((b) => (b === 5 ? 8 : 5))}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-200 dark:border-[#1c242d] text-slate-500 hover:text-emerald-600"
                >
                  {trendBuckets}T
                </button>
              }
            />
            <div className="flex items-center gap-3 text-[10px] font-mono mb-1">
              <button
                type="button"
                onClick={() => setShowAllowed((v) => !v)}
                className={`flex items-center gap-1 ${showAllowed ? "text-cyan-600 dark:text-cyan-400" : "text-slate-400 line-through"}`}
              >
                <span className="w-2 h-0.5 bg-cyan-500" /> Allowed
              </button>
              <button
                type="button"
                onClick={() => setShowDenied((v) => !v)}
                className={`flex items-center gap-1 ${showDenied ? "text-emerald-600 dark:text-emerald-400" : "text-slate-400 line-through"}`}
              >
                <span className="w-2 h-0.5 bg-emerald-500" /> Denied / Held
              </button>
            </div>
            <div className="h-32">
              {auditList.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[11px] text-slate-500">
                  No audit trend slices yet
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={auditTrend}>
                    <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
                    <XAxis dataKey="bucket" stroke={axisStroke} fontSize={10} />
                    <YAxis stroke={axisStroke} fontSize={10} width={24} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    {showAllowed && <Line type="monotone" dataKey="allowed" stroke="#06b6d4" strokeWidth={2} dot={{ r: 2.5 }} />}
                    {showDenied && <Line type="monotone" dataKey="denied" stroke="#10b981" strokeWidth={2} dot={{ r: 2.5 }} />}
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
