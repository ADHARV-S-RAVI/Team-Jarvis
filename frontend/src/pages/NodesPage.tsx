import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";

export function NodesPage() {
  const qc = useQueryClient();
  const { push } = useToast();

  const nodes = useQuery({ queryKey: ["nodes"], queryFn: api.listNodes });
  const metrics = useQuery({ queryKey: ["node-metrics"], queryFn: api.nodeMetrics });

  const cfgMut = useMutation({
    mutationFn: (count: number) => api.configureNodes(count),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["nodes"] });
      push(`Configured ${res.length} simulated nodes`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const partMut = useMutation({
    mutationFn: (id: string) => api.partitionNode(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["nodes"] });
      push("Node marked UNREACHABLE / PARTITIONED", "info");
    },
  });

  const recMut = useMutation({
    mutationFn: (id: string) => api.recoverNode(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["nodes"] });
      push("Node recovered to HEALTHY", "success");
    },
  });

  const reconcileMut = useMutation({
    mutationFn: api.reconcileNodes,
    onSuccess: (res) => {
      qc.invalidateQueries();
      push(
        `Reconcile: ${res.status} (${res.converged_nodes}/${res.total_nodes})`,
        res.status === "CONVERGED" ? "success" : "error"
      );
    },
  });

  const nodeList = nodes.data ?? [];
  const allHealthy = nodeList.every((n) => n.health === "HEALTHY");
  const chartData = nodeList.map((n) => ({
    name: n.id,
    delayMs: n.delay_ms,
    healthy: n.health === "HEALTHY",
    keyVer: n.accepted_key_version,
  }));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Node Control Plane &amp; Convergence Map</h1>
          <p className="text-xs text-slate-500">
            Local deterministic 3&ndash;7 node simulator (not physical distributed servers)
          </p>
        </div>
        <StatusBadge
          label={allHealthy ? "SIMULATED: CONVERGED" : "NOT CONVERGED"}
          tone={allHealthy ? "success" : "danger"}
        />
      </div>

      <Card
        title="Simulated Node Delay & Convergence Graph"
        subtitle="Real-time node health (green = HEALTHY, red = PARTITIONED / NOT CONVERGED)"
      >
        <div className="h-52">
          {chartData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-slate-500">
              No simulated nodes configured
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} unit="ms" />
                <Tooltip contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", fontSize: 11 }} />
                <Bar dataKey="delayMs" name="Delay (ms)" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={entry.healthy ? "#10b981" : "#ef4444"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </Card>

      <Card
        title="Cluster Topology Controls (SIMULATED)"
        action={
          <div className="flex flex-wrap gap-2">
            {[3, 5, 7].map((c) => (
              <Button key={c} size="sm" variant="secondary" onClick={() => cfgMut.mutate(c)}>
                {c} Nodes
              </Button>
            ))}
            <Button size="sm" onClick={() => reconcileMut.mutate()}>
              Reconcile Nodes
            </Button>
          </div>
        }
      >
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4 text-xs">
          <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">Samples</div>
            <div className="font-mono text-lg text-slate-900 dark:text-slate-100">{metrics.data?.sample_count ?? 0}</div>
          </div>
          <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">p50 Delay</div>
            <div className="font-mono text-lg text-emerald-600">{metrics.data?.p50_ms ?? "—"} ms</div>
          </div>
          <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">p95 Delay</div>
            <div className="font-mono text-lg text-cyan-400">{metrics.data?.p95_ms ?? "—"} ms</div>
          </div>
          <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">Max Delay</div>
            <div className="font-mono text-lg text-amber-400">{metrics.data?.max_ms ?? "—"} ms</div>
          </div>
        </div>

        <DataTable
          rows={nodeList as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Node ID" },
            { key: "service_name", header: "Service (SIMULATED)" },
            { key: "accepted_key_version", header: "Key Ver" },
            { key: "last_sequence", header: "Seq" },
            { key: "delay_ms", header: "Delay (ms)" },
            {
              key: "health",
              header: "Health",
              render: (r) => (
                <StatusBadge
                  label={r.health === "HEALTHY" ? "HEALTHY" : "NOT CONVERGED"}
                  tone={r.health === "HEALTHY" ? "success" : "danger"}
                />
              ),
            },
            {
              key: "actions",
              header: "Fault Injection",
              render: (r) =>
                r.health === "HEALTHY" ? (
                  <Button size="sm" variant="danger" onClick={() => partMut.mutate(String(r.id))}>
                    Partition
                  </Button>
                ) : (
                  <Button size="sm" variant="primary" onClick={() => recMut.mutate(String(r.id))}>
                    Recover
                  </Button>
                ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
