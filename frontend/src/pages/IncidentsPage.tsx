import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, IncidentReceiptItem } from "../services/api";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";
import {
  InteractiveTopologyGraph,
  TelemetrySparkGrid,
  TopoEdge,
  TopoNode,
} from "../components/TopologyTelemetryPanel";

export function IncidentsPage() {
  const qc = useQueryClient();
  const { push } = useToast();
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.listIncidents });
  const nodes = useQuery({ queryKey: ["nodes"], queryFn: api.listNodes });
  const audit = useQuery({ queryKey: ["audit-inc"], queryFn: () => api.listAuditEvents() });
  const [receipt, setReceipt] = useState<IncidentReceiptItem | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);

  const loadMut = useMutation({
    mutationFn: async (id: string) => {
      const r = await api.getIncidentReceipt(id);
      const v = await api.verifyIncident(id);
      return { r, v };
    },
    onSuccess: ({ r, v }) => {
      setReceipt(r);
      setVerified(v.valid);
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const drillMut = useMutation({
    mutationFn: async () => {
      await api.resetSimulation();
      return api.reportLostDevice({
        operator_actor_id: "secop",
        device_id: "dev-alice-01",
        reason: "Interactive lost-device containment drill",
        confirmed: true,
      });
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: ["nodes"] });
      qc.invalidateQueries({ queryKey: ["audit-inc"] });
      push(`Lost-device incident ${res.incident.id} contained (${res.incident.status})`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const incList = incidents.data ?? [];
  const nodeList = nodes.data ?? [];
  const auditList = audit.data ?? [];
  const containedCount = incList.filter((i) => i.status === "CONTAINED").length;
  const openCount = incList.length - containedCount;
  const avgDelay =
    nodeList.length > 0
      ? (nodeList.reduce((acc, n) => acc + Number(n.delay_ms || 1.2), 0) / nodeList.length).toFixed(1)
      : "0.0";

  // Build live Containment Topology Graph
  const topoNodes: TopoNode[] = [
    {
      id: "gateway",
      label: "9-Step Policy Gate",
      sublabel: "Fail-Closed",
      layer: 0,
      status: openCount > 0 ? "WARN" : "OK",
      metric: `${auditList.length} audit events`,
    },
    ...(incList.length > 0
      ? incList.slice(0, 3).map((inc) => ({
          id: `inc-${inc.id}`,
          label: inc.target_subject_id,
          sublabel: inc.incident_type,
          layer: 1,
          status: (inc.status === "CONTAINED" ? "OK" : "ALERT") as TopoNode["status"],
          metric: inc.status,
        }))
      : [
          {
            id: "inc-standby",
            label: "Device Trust Plane",
            sublabel: "No active incidents",
            layer: 1,
            status: "OK" as const,
          },
        ]),
    ...(nodeList.length > 0
      ? nodeList.slice(0, 4).map((n) => ({
          id: n.id,
          label: n.id,
          sublabel: n.health,
          layer: 2,
          status: (n.health === "HEALTHY" ? "OK" : "ALERT") as TopoNode["status"],
          metric: `delay ${n.delay_ms} ms`,
        }))
      : [{ id: "node-sim", label: "sim-node-1", sublabel: "Standby", layer: 2, status: "OK" as const }]),
    {
      id: "ledger",
      label: "SHA-256 Audit Ledger",
      sublabel: "Proof Receipts",
      layer: 3,
      status: verified === false ? "ALERT" : "OK",
      metric: `${containedCount} contained`,
    },
  ];

  const topoEdges: TopoEdge[] = [];
  const midNodes = topoNodes.filter((n) => n.layer === 1);
  const simNodes = topoNodes.filter((n) => n.layer === 2);
  for (const m of midNodes) {
    topoEdges.push({ from: "gateway", to: m.id, label: "enforce", status: m.status });
    for (const s of simNodes) {
      topoEdges.push({ from: m.id, to: s.id, label: `${avgDelay}ms`, status: s.status });
    }
  }
  for (const s of simNodes) {
    topoEdges.push({ from: s.id, to: "ledger", label: "receipt", status: s.status });
  }

  const history =
    auditList.length > 0
      ? auditList.slice(0, 12).reverse().map((ev, idx) => ({
          label: `#${idx + 1}`,
          primary: ev.decision === "ALLOW" || ev.decision === "COMMITTED" ? 1 : 0,
          secondary: ev.decision === "DENY" || ev.decision === "REVOKED" ? 1 : 0,
        }))
      : [{ label: "Idle", primary: 0, secondary: 0 }];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">
            Incident Center &amp; Proof-Carrying Receipts
          </h1>
          <p className="text-xs text-slate-500">
            Live containment topology, simulated node propagation, and SHA-256 verifiable receipts
          </p>
        </div>
        <Button onClick={() => drillMut.mutate()} disabled={drillMut.isPending}>
          Run Lost-Device Containment Drill
        </Button>
      </div>

      <TelemetrySparkGrid
        stats={[
          { label: "Total Incidents", value: String(incList.length), tone: "cyan", series: [0, 1, 1, incList.length] },
          { label: "Contained", value: String(containedCount), tone: "emerald", series: [0, 1, containedCount, containedCount] },
          { label: "Open / Active", value: String(openCount), tone: openCount > 0 ? "rose" : "emerald", series: [0, openCount, openCount] },
          { label: "Node Delay Avg", value: `${avgDelay} ms`, tone: "cyan", series: nodeList.map((n) => Number(n.delay_ms || 1.2)).concat([1.2]) },
          { label: "Audit Events", value: String(auditList.length), tone: "emerald", series: [2, 5, 9, auditList.length] },
          { label: "Receipt Chain", value: verified === false ? "BROKEN" : "VERIFIED", tone: verified === false ? "rose" : "emerald", series: [1, 1, 1, 1] },
        ]}
      />

      <InteractiveTopologyGraph
        title="Incident Containment & Tombstone Propagation Path"
        summaryStrip={[
          { label: "Incidents", value: String(incList.length) },
          { label: "Contained", value: String(containedCount) },
          { label: "Avg Node Delay", value: `${avgDelay} ms` },
          { label: "Nodes", value: String(nodeList.length) },
        ]}
        nodes={topoNodes}
        edges={topoEdges}
        history={history}
        historyLabel="Recent Audit Decisions (Green = Allow/Commit, Red = Deny/Revoke)"
      />

      <Card title="Recorded Security Incidents">
        <DataTable
          rows={(incidents.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Incident ID" },
            { key: "incident_type", header: "Type" },
            { key: "target_subject_id", header: "Target" },
            {
              key: "status",
              header: "Status",
              render: (r) => (
                <StatusBadge
                  label={String(r.status)}
                  tone={r.status === "CONTAINED" ? "success" : "warning"}
                />
              ),
            },
            { key: "reason", header: "Reason" },
            {
              key: "receipt",
              header: "Receipt",
              render: (r) => (
                <Button size="sm" variant="secondary" onClick={() => loadMut.mutate(String(r.id))}>
                  Inspect Proof
                </Button>
              ),
            },
          ]}
        />
      </Card>

      {receipt && (
        <Card
          title={`Proof-Carrying Receipt (${receipt.id})`}
          action={
            <StatusBadge
              label={verified ? "AUDIT CHAIN VERIFIED" : "UNVERIFIED"}
              tone={verified ? "success" : "danger"}
            />
          }
        >
          <div className="grid md:grid-cols-2 gap-3 text-xs font-mono">
            <div>Policy Decision: {receipt.policy_decision}</div>
            <div>State Transition: {receipt.state_transition}</div>
            <div>Verification: {receipt.verification}</div>
            <div>Audit Ref: {receipt.audit_ref}</div>
            <div>Convergence: {receipt.convergence_ms ?? "NOT_CONVERGED"} ms</div>
          </div>
          <pre className="mt-3 p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] text-[11px] font-mono text-slate-600 dark:text-slate-300 overflow-x-auto">
            {receipt.node_acks_json}
          </pre>
        </Card>
      )}
    </div>
  );
}
