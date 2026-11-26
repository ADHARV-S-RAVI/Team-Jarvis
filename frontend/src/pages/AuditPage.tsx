import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";

export function AuditPage() {
  const { push } = useToast();
  const [actorFilter, setActorFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("");
  const events = useQuery({
    queryKey: ["audit-events", actorFilter, decisionFilter],
    queryFn: () =>
      api.listAuditEvents({
        actor_id: actorFilter.trim() || undefined,
        decision: decisionFilter.trim() || undefined,
      }),
  });
  const [verifyRes, setVerifyRes] = useState<{ valid: boolean; checked_events: number; canonical_version: string } | null>(null);
  const [tamperRes, setTamperRes] = useState<{ detected: boolean } | null>(null);

  const verifyMut = useMutation({
    mutationFn: api.verifyAudit,
    onSuccess: (res) => {
      setVerifyRes(res);
      push(res.valid ? `Audit chain verified (${res.checked_events} events)` : "Tampering detected!", res.valid ? "success" : "error");
    },
  });

  const tamperMut = useMutation({
    mutationFn: api.tamperDemoAudit,
    onSuccess: (res) => {
      setTamperRes(res);
      push(res.detected ? "Non-destructive tamper fixture detected actor mutation" : "Tamper not detected", "info");
    },
  });

  const evList = events.data ?? [];
  const countsMap = new Map<string, number>();
  for (const e of evList) {
    countsMap.set(e.decision, (countsMap.get(e.decision) ?? 0) + 1);
  }
  const decisionChart = Array.from(countsMap.entries()).map(([decision, count]) => ({ decision, count }));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Audit &amp; Evidence Ledger</h1>
          <p className="text-xs text-slate-500">Append-only canonical v1 JSON ledger with SHA-256 hash chaining</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => tamperMut.mutate()}>
            Run Tamper Demo (Non-Destructive)
          </Button>
          <Button onClick={() => verifyMut.mutate()}>Verify Hash Chain</Button>
        </div>
      </div>

      {(verifyRes || tamperRes) && (
        <div className="flex flex-wrap gap-3">
          {verifyRes && (
            <StatusBadge
              label={verifyRes.valid ? `CHAIN VALID (${verifyRes.checked_events} events, ${verifyRes.canonical_version})` : "CHAIN INVALID"}
              tone={verifyRes.valid ? "success" : "danger"}
            />
          )}
          {tamperRes && (
            <StatusBadge
              label={tamperRes.detected ? "TAMPER FIXTURE DETECTED" : "NOT DETECTED"}
              tone={tamperRes.detected ? "violet" : "danger"}
            />
          )}
        </div>
      )}

      <div className="grid lg:grid-cols-3 gap-4">
        <Card title="Decision Breakdown Graph" subtitle="Live counts by audit decision" className="lg:col-span-2">
          <div className="h-44">
            {decisionChart.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">No audit events</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={decisionChart}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="decision" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {decisionChart.map((d) => (
                      <Cell
                        key={d.decision}
                        fill={d.decision === "DENY" || d.decision === "FAILED" ? "#ef4444" : "#10b981"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="Filter Ledger" subtitle="Search by actor or decision">
          <div className="space-y-2.5">
            <input
              type="text"
              placeholder="Actor ID (e.g. alice)"
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
              className="w-full rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
            />
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="w-full rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="">All Decisions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="DENY">DENY</option>
              <option value="COMMITTED">COMMITTED</option>
            </select>
          </div>
        </Card>
      </div>

      <Card title="Audit Events">
        <DataTable
          rows={evList as unknown as Record<string, unknown>[]}
          columns={[
            { key: "sequence", header: "Seq" },
            { key: "actor_id", header: "Actor" },
            { key: "action", header: "Action" },
            { key: "target", header: "Target" },
            {
              key: "decision",
              header: "Decision",
              render: (r) => (
                <StatusBadge
                  label={String(r.decision)}
                  tone={r.decision === "DENY" ? "danger" : r.decision === "ALLOW" || r.decision === "COMMITTED" ? "success" : "info"}
                />
              ),
            },
            { key: "reason", header: "Reason" },
            {
              key: "event_hash",
              header: "Event Hash",
              render: (r) => <span className="font-mono text-[11px] text-slate-500">{String(r.event_hash).slice(0, 16)}...</span>,
            },
          ]}
        />
      </Card>
    </div>
  );
}
