import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, DataTable, ErrorBanner, StatusBadge, useToast } from "../components/ui";

export function IdentityAccessPage() {
  const qc = useQueryClient();
  const { session } = useAuth();
  const { push } = useToast();

  const [id, setId] = useState("");
  const [label, setLabel] = useState("");
  const [role, setRole] = useState("Owner/User");
  const [resourceId, setResourceId] = useState("vault-brief-alice");
  const [action, setAction] = useState("resource:read");

  const identities = useQuery({ queryKey: ["identities"], queryFn: api.listIdentities });

  const createMut = useMutation({
    mutationFn: () => api.createIdentity({ id, display_label: label, role }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identities"] });
      setId("");
      setLabel("");
      push("Synthetic identity created", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const evalMut = useMutation({
    mutationFn: () =>
      api.evaluatePolicy({
        actor_id: session?.actorId ?? "alice",
        session_id: session?.sessionId ?? "missing",
        device_id: session?.deviceId ?? "missing",
        resource_id: resourceId,
        action,
        peer_id: session?.peerId,
        session_token: session?.sessionToken,
      }),
  });

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Identity & Access Control</h1>

      <div className="grid lg:grid-cols-2 gap-4">
        <Card title="Register Synthetic Identity">
          <div className="space-y-3">
            <input
              type="text"
              placeholder="Actor ID (e.g. carol)"
              value={id}
              onChange={(e) => setId(e.target.value)}
              className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              placeholder="Display Label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="Owner/User">Owner/User</option>
              <option value="Security Operator">Security Operator</option>
              <option value="Admin">Admin</option>
              <option value="Auditor">Auditor</option>
            </select>
            <Button onClick={() => createMut.mutate()} disabled={!id || !label || createMut.isPending}>
              Create Identity
            </Button>
          </div>
        </Card>

        <Card title="9-Step Zero-Trust Policy Evaluator" subtitle="Runs server-side fail-closed decision pipeline">
          <div className="space-y-3">
            <input
              type="text"
              value={resourceId}
              onChange={(e) => setResourceId(e.target.value)}
              placeholder="Resource ID"
              className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              value={action}
              onChange={(e) => setAction(e.target.value)}
              placeholder="Action (e.g. resource:read)"
              className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
            />
            <Button onClick={() => evalMut.mutate()} disabled={evalMut.isPending}>
              Evaluate Policy
            </Button>
            {evalMut.isError && <ErrorBanner message={(evalMut.error as Error).message} />}
            {evalMut.data && (
              <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] space-y-1.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-slate-600 dark:text-slate-300">Decision</span>
                  <StatusBadge label={evalMut.data.decision} tone={evalMut.data.decision === "ALLOW" ? "success" : "danger"} />
                </div>
                <div className="font-mono text-slate-500">Reason: {evalMut.data.reason_code}</div>
                <div className="font-mono text-slate-500">
                  Checks passed: {evalMut.data.checks_passed.length} / 9
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      <Card title="Registered Identities">
        <DataTable
          rows={(identities.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Actor ID" },
            { key: "display_label", header: "Label" },
            { key: "role", header: "Role" },
            {
              key: "enabled",
              header: "Status",
              render: (r) => (
                <StatusBadge label={r.enabled ? "ENABLED" : "DISABLED"} tone={r.enabled ? "success" : "danger"} />
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
