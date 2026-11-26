import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";
import {
  InteractiveTopologyGraph,
  TelemetrySparkGrid,
  TopoEdge,
  TopoNode,
} from "../components/TopologyTelemetryPanel";

const SAMPLE_LATERAL_EVENTS = [
  {
    event_id: "ui-evt-1",
    event_time_utc: "2026-02-01T10:00:00Z",
    actor: "syn-demo-user",
    source_service: "portal",
    target_service: "identity",
    action: "role_change",
    role_before: "viewer",
    role_after: "operator",
    outcome: "success",
    session_id: "sess-demo-1",
    correlation_id: "flow-demo",
  },
  {
    event_id: "ui-evt-2",
    event_time_utc: "2026-02-01T10:00:05Z",
    actor: "syn-demo-user",
    source_service: "reports",
    target_service: "billing",
    action: "read",
    outcome: "deny",
    session_id: "sess-demo-1",
    correlation_id: "flow-demo",
  },
  {
    event_id: "ui-evt-3",
    event_time_utc: "2026-02-01T10:00:08Z",
    actor: "syn-demo-user",
    source_service: "billing",
    target_service: "archive",
    action: "read",
    outcome: "deny",
    session_id: "sess-demo-1",
    correlation_id: "flow-demo",
  },
];

function parsePath(pathJson: string): string[] {
  try {
    const parsed = JSON.parse(pathJson);
    if (Array.isArray(parsed)) return parsed.map(String);
  } catch {
    // fallback if string
  }
  return pathJson ? [pathJson] : [];
}

export function DetectorPage() {
  const qc = useQueryClient();
  const { push } = useToast();
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const alerts = useQuery({ queryKey: ["detector-alerts"], queryFn: api.detectorAlerts });
  const rules = useQuery({ queryKey: ["detector-rules"], queryFn: api.detectorRules });

  const runDemoMut = useMutation({
    mutationFn: async () => {
      await api.detectorIngest(SAMPLE_LATERAL_EVENTS);
      return api.detectorRun([]);
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["detector-alerts"] });
      push(`Deterministic detector produced ${res.length} explainable alerts`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const alertList = alerts.data ?? [];
  const ruleList = rules.data ?? [];
  const criticalCount = alertList.filter((a) => a.severity === "CRITICAL").length;
  const highCount = alertList.filter((a) => a.severity === "HIGH").length;

  const ruleCountsMap = new Map<string, number>();
  for (const a of alertList) {
    ruleCountsMap.set(a.rule_id, (ruleCountsMap.get(a.rule_id) ?? 0) + 1);
  }
  const chartData = Array.from(ruleCountsMap.entries()).map(([rule, hits]) => ({
    rule: rule.replace("RULE_", ""),
    hits,
  }));

  // Build Interactive Directed Lateral-Movement & Service Mesh Graph
  const hopSet = new Map<string, TopoNode>();
  const hopEdges: TopoEdge[] = [];

  if (alertList.length > 0) {
    alertList.slice(0, 5).forEach((al) => {
      const hops = parsePath(al.path_json);
      hops.forEach((h, idx) => {
        if (!hopSet.has(h)) {
          hopSet.set(h, {
            id: h,
            label: h,
            sublabel: idx === 0 ? "Origin" : idx === hops.length - 1 ? "Target" : "Lateral Hop",
            layer: Math.min(3, idx),
            status: al.severity === "CRITICAL" ? "ALERT" : "WARN",
            metric: al.rule_id,
          });
        }
        if (idx < hops.length - 1) {
          hopEdges.push({
            from: h,
            to: hops[idx + 1],
            label: al.rule_id.replace("RULE_", ""),
            status: al.severity === "CRITICAL" ? "ALERT" : "WARN",
          });
        }
      });
    });
  } else {
    const baselineNodes: TopoNode[] = [
      { id: "portal", label: "portal", sublabel: "Edge Entry", layer: 0, status: "OK" },
      { id: "identity", label: "identity", sublabel: "AuthN / RBAC", layer: 1, status: "OK" },
      { id: "reports", label: "reports", sublabel: "Telemetry", layer: 1, status: "OK" },
      { id: "billing", label: "billing", sublabel: "Protected Tier", layer: 2, status: "OK" },
      { id: "archive", label: "archive", sublabel: "Vault Storage", layer: 3, status: "OK" },
    ];
    baselineNodes.forEach((n) => hopSet.set(n.id, n));
    hopEdges.push(
      { from: "portal", to: "identity", label: "monitored", status: "OK" },
      { from: "portal", to: "reports", label: "monitored", status: "OK" },
      { from: "identity", to: "billing", label: "policy gate", status: "OK" },
      { from: "reports", to: "billing", label: "monitored", status: "OK" },
      { from: "billing", to: "archive", label: "vault acl", status: "OK" }
    );
  }

  const history =
    chartData.length > 0
      ? chartData.map((d) => ({ label: d.rule.slice(0, 10), primary: d.hits }))
      : ruleList.slice(0, 6).map((r) => ({ label: r.rule_id.replace("RULE_", "").slice(0, 10), primary: 0 }));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">
            Detection &amp; Lateral Movement (Zero ML)
          </h1>
          <p className="text-xs text-slate-500">
            Deterministic rules, clock-offset handling, and time-aware service graph
          </p>
        </div>
        <Button onClick={() => runDemoMut.mutate()} disabled={runDemoMut.isPending}>
          Ingest &amp; Run Sample Detection
        </Button>
      </div>

      <TelemetrySparkGrid
        stats={[
          { label: "Active Rules", value: String(ruleList.length), tone: "cyan", series: [4, 6, 8, ruleList.length] },
          { label: "Total Alerts", value: String(alertList.length), tone: alertList.length > 0 ? "amber" : "emerald", series: [0, 1, alertList.length] },
          { label: "Critical", value: String(criticalCount), tone: criticalCount > 0 ? "rose" : "emerald", series: [0, criticalCount] },
          { label: "High Severity", value: String(highCount), tone: highCount > 0 ? "amber" : "emerald", series: [0, highCount] },
          { label: "ML Runtime", value: "0 (ZERO)", tone: "emerald", series: [1, 1, 1, 1] },
          { label: "Graph Mode", value: alertList.length > 0 ? "LATERAL PATH" : "MONITORING", tone: alertList.length > 0 ? "rose" : "cyan", series: [1, 2, 2, 3] },
        ]}
      />

      <InteractiveTopologyGraph
        title="Time-Aware Lateral Movement & Service Hop Graph"
        summaryStrip={[
          { label: "Rules Loaded", value: String(ruleList.length) },
          { label: "Triggered Alerts", value: String(alertList.length) },
          { label: "Critical", value: String(criticalCount) },
          { label: "Engine", value: "Deterministic (0 ML)" },
        ]}
        nodes={Array.from(hopSet.values())}
        edges={hopEdges}
        history={history}
        historyLabel="Deterministic Rule Hit Distribution"
      />

      <div className="grid lg:grid-cols-2 gap-4">
        <Card title="Extracted Lateral Movement Hop Paths" subtitle="Service hop paths from live detector alerts">
          {alertList.length === 0 ? (
            <div className="text-xs text-slate-500 py-10 text-center">
              Click &quot;Ingest &amp; Run Sample Detection&quot; above to ingest sample events and highlight lateral-movement paths.
            </div>
          ) : (
            <div className="space-y-3 max-h-56 overflow-y-auto pr-1">
              {alertList.map((al) => {
                const hops = parsePath(al.path_json);
                return (
                  <div key={al.id} className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-emerald-600">{al.rule_id}</span>
                      <StatusBadge label={al.severity} tone={al.severity === "CRITICAL" ? "danger" : "warning"} />
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {hops.map((hop, idx) => (
                        <div key={`${hop}-${idx}`} className="flex items-center gap-1.5">
                          <span className="px-2 py-0.5 rounded bg-white dark:bg-[#0b0f13] border border-emerald-500/35 text-[11px] font-mono text-slate-800 dark:text-slate-200">
                            {hop}
                          </span>
                          {idx < hops.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-rose-400" />}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        <Card title="Alert Distribution by Deterministic Rule" subtitle="Real counts from backend /api/v1/detector/alerts">
          <div className="h-52">
            {chartData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                No alerts triggered yet
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="rule" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", fontSize: 11, color: "#0f172a" }} />
                  <Bar
                    dataKey="hits"
                    name="Alerts Triggered"
                    radius={[4, 4, 0, 0]}
                    className="cursor-pointer"
                    onClick={(d) => setSelectedRule((prev) => (prev === d.rule ? null : d.rule))}
                  >
                    {chartData.map((entry) => (
                      <Cell
                        key={entry.rule}
                        fill={!selectedRule || selectedRule === entry.rule ? "#ef4444" : "#fca5a5"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <Card
        title="Explainable Alerts"
        action={
          selectedRule ? (
            <button
              type="button"
              onClick={() => setSelectedRule(null)}
              className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 hover:underline"
            >
              Clear filter ({selectedRule})
            </button>
          ) : undefined
        }
      >
        <DataTable
          rows={
            (selectedRule
              ? alertList.filter((a) => a.rule_id.replace("RULE_", "") === selectedRule)
              : alertList) as unknown as Record<string, unknown>[]
          }
          columns={[
            { key: "rule_id", header: "Rule" },
            { key: "actor_id", header: "Actor" },
            { key: "severity", header: "Severity" },
            { key: "explanation", header: "Explanation" },
            {
              key: "uncertainty_flag",
              header: "Uncertainty",
              render: (r) =>
                r.uncertainty_flag ? (
                  <StatusBadge label="REORDER_UNCERTAIN" tone="warning" />
                ) : (
                  <StatusBadge label="ORDERED" tone="success" />
                ),
            },
          ]}
        />
      </Card>

      <Card title="Deterministic Rule Catalog (No ML)">
        <DataTable
          rows={(rules.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "rule_id", header: "Rule ID" },
            { key: "name", header: "Name" },
            { key: "description", header: "Logic" },
          ]}
        />
      </Card>
    </div>
  );
}
