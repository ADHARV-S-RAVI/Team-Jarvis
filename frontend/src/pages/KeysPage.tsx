import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api";
import { Button, Card, ConfirmDialog, DataTable, StatusBadge, useToast } from "../components/ui";

export function KeysPage() {
  const qc = useQueryClient();
  const { push } = useToast();
  const keys = useQuery({ queryKey: ["keys"], queryFn: api.listKeys });

  const [operatorId, setOperatorId] = useState("secop");
  const [retirePolicy, setRetirePolicy] = useState<"RETIRED" | "REVOKED">("RETIRED");
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [compromiseTarget, setCompromiseTarget] = useState<string | null>(null);
  const [lastBackup, setLastBackup] = useState<Record<string, unknown> | null>(null);
  const [backupVerifyResult, setBackupVerifyResult] = useState<{ valid: boolean; reason: string } | null>(null);

  const rotateMut = useMutation({
    mutationFn: (reason: string) =>
      api.rotateKeys({ operator_actor_id: operatorId, reason, retire_policy: retirePolicy }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["keys"] });
      qc.invalidateQueries({ queryKey: ["nodes"] });
      push(`Rotated v${res.previous_version} → v${res.new_version} (${res.node_status})`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const compMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.compromiseKey(id, { operator_actor_id: operatorId, reason }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["keys"] });
      push(`Key ${res.id} marked COMPROMISED`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const backupMut = useMutation({
    mutationFn: () => api.createBackup({ operator_actor_id: operatorId }),
    onSuccess: (res) => {
      setLastBackup(res);
      setBackupVerifyResult(null);
      push("HMAC-authenticated backup manifest created", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const verifyBackupMut = useMutation({
    mutationFn: (tamper: boolean) => {
      if (!lastBackup) throw new Error("Create a backup manifest first");
      const copy = tamper ? { ...lastBackup, manifest_sha256: "0".repeat(64) } : lastBackup;
      return api.verifyBackup(copy);
    },
    onSuccess: (res) => {
      setBackupVerifyResult(res);
      push(res.valid ? "Backup HMAC verified" : `Backup rejected: ${res.reason}`, res.valid ? "success" : "info");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Key Lifecycle & Rotation</h1>

      <Card title="4-Phase Key Rotation" subtitle="PREPARE → DISTRIBUTE → COMMIT → RETIRE (zero-grace default)">
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            value={operatorId}
            onChange={(e) => setOperatorId(e.target.value)}
            placeholder="Operator ID"
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
          />
          <select
            value={retirePolicy}
            onChange={(e) => setRetirePolicy(e.target.value as "RETIRED" | "REVOKED")}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
          >
            <option value="RETIRED">Retire Policy: RETIRED</option>
            <option value="REVOKED">Retire Policy: REVOKED</option>
          </select>
          <Button onClick={() => setConfirmRotate(true)} disabled={rotateMut.isPending}>
            Rotate Active Key
          </Button>
          <Button variant="secondary" onClick={() => backupMut.mutate()} disabled={backupMut.isPending}>
            Create Backup Manifest
          </Button>
        </div>
        {lastBackup && (
          <div className="mt-3 p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] text-xs font-mono text-slate-600 dark:text-slate-300 flex flex-wrap items-center justify-between gap-2">
            <span>
              Manifest {String(lastBackup.manifest_id)} &middot; SHA256: {String(lastBackup.manifest_sha256).slice(0, 24)}...
            </span>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="secondary" onClick={() => verifyBackupMut.mutate(false)}>
                Verify Backup
              </Button>
              <Button size="sm" variant="danger" onClick={() => verifyBackupMut.mutate(true)}>
                Test Tampered Backup
              </Button>
              {backupVerifyResult && (
                <StatusBadge
                  label={backupVerifyResult.valid ? "VALID" : `REJECTED (${backupVerifyResult.reason})`}
                  tone={backupVerifyResult.valid ? "success" : "danger"}
                />
              )}
            </div>
          </div>
        )}
      </Card>

      <Card title="Key Metadata Inventory" subtitle="Secret KEK material is isolated in KeyMaterialStore and never exposed">
        <DataTable
          rows={(keys.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Key ID" },
            { key: "version", header: "Version" },
            { key: "algorithm", header: "Algorithm" },
            {
              key: "state",
              header: "State",
              render: (r) => (
                <StatusBadge
                  label={String(r.state)}
                  tone={
                    r.state === "ACTIVE" || r.state === "ACTIVE_NEW"
                      ? "success"
                      : r.state === "COMPROMISED" || r.state === "REVOKED"
                      ? "danger"
                      : "neutral"
                  }
                />
              ),
            },
            {
              key: "actions",
              header: "Actions",
              render: (r) => (
                <Button
                  size="sm"
                  variant="danger"
                  disabled={r.state === "COMPROMISED"}
                  onClick={() => setCompromiseTarget(String(r.id))}
                >
                  Mark Compromised
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <ConfirmDialog
        open={confirmRotate}
        title="Confirm 4-Phase Key Rotation"
        description="Stages a new key version across all simulated nodes, commits atomically, and enforces zero-grace cutoff on the previous key."
        confirmLabel="Execute Rotation"
        onCancel={() => setConfirmRotate(false)}
        onConfirm={(reason) => {
          setConfirmRotate(false);
          rotateMut.mutate(reason);
        }}
      />

      <ConfirmDialog
        open={compromiseTarget !== null}
        title={`Confirm Terminal Compromise (${compromiseTarget})`}
        description="COMPROMISED is terminal. The key can never be reactivated."
        confirmLabel="Mark Compromised"
        onCancel={() => setCompromiseTarget(null)}
        onConfirm={(reason) => {
          if (compromiseTarget) compMut.mutate({ id: compromiseTarget, reason });
          setCompromiseTarget(null);
        }}
      />
    </div>
  );
}
