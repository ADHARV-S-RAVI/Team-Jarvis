import { useQuery } from "@tanstack/react-query";
import { api } from "../services/api";
import { Card, DataTable, StatusBadge } from "../components/ui";

export function ScorecardPage() {
  const scorecard = useQuery({ queryKey: ["scorecard"], queryFn: api.scorecard });

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Requirements & Acceptance Gate Scorecard</h1>
          <p className="text-xs text-slate-500">Live honest status from GET /api/v1/evidence/scorecard</p>
        </div>
        <div className="flex gap-2">
          <StatusBadge label={`Nodes: ${scorecard.data?.nodes_mode ?? "SIMULATED"}`} tone="violet" />
          <StatusBadge label={`Forward Secrecy: ${scorecard.data?.forward_secrecy ?? "NOT_ESTABLISHED"}`} tone="warning" />
        </div>
      </div>

      <Card title="Track 4 Acceptance Gates (G0–G10)">
        <DataTable
          rows={(scorecard.data?.gates ?? []) as unknown as Record<string, unknown>[]}
          pageSize={15}
          columns={[
            { key: "gate", header: "Gate" },
            { key: "name", header: "Scope" },
            {
              key: "status",
              header: "Status",
              render: (r) => (
                <StatusBadge
                  label={String(r.status)}
                  tone={r.status === "PASS" ? "success" : r.status === "IN_PROGRESS" ? "info" : "neutral"}
                />
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
