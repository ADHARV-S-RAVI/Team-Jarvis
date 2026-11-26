import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, DataTable, ErrorBanner, StatusBadge, useToast } from "../components/ui";

export function VaultPage() {
  const qc = useQueryClient();
  const { session } = useAuth();
  const { push } = useToast();

  const resources = useQuery({ queryKey: ["resources"], queryFn: api.listResources });
  const [resId, setResId] = useState("");
  const [ownerId, setOwnerId] = useState("alice");
  const [plaintext, setPlaintext] = useState("");
  const [inFlight, setInFlight] = useState(false);

  const storeMut = useMutation({
    mutationFn: () => api.storeVault({ resource_id: resId, owner_actor_id: ownerId, plaintext }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["resources"] });
      setResId("");
      setPlaintext("");
      push(`Encrypted & stored ${res.resource_id} (key v${res.key_version})`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const readMut = useMutation({
    mutationFn: (id: string) =>
      api.readVault(id, {
        actor_id: session?.actorId ?? "alice",
        session_id: session?.sessionId ?? "none",
        device_id: session?.deviceId ?? "none",
        session_token: session?.sessionToken,
        peer_id: session?.peerId,
        in_flight: inFlight,
      }),
  });

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Secure Vault (AES-256-GCM)</h1>

      <Card title="Encrypt & Store Protected Resource" subtitle="Plaintext is encrypted before persistence and never stored in SQLite">
        <div className="grid md:grid-cols-3 gap-3">
          <input
            type="text"
            placeholder="Resource ID"
            value={resId}
            onChange={(e) => setResId(e.target.value)}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
          />
          <input
            type="text"
            placeholder="Owner Actor ID"
            value={ownerId}
            onChange={(e) => setOwnerId(e.target.value)}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
          />
          <input
            type="text"
            placeholder="Synthetic Plaintext Body"
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
          />
        </div>
        <div className="pt-3">
          <Button onClick={() => storeMut.mutate()} disabled={!resId || !plaintext || storeMut.isPending}>
            Encrypt & Store
          </Button>
        </div>
      </Card>

      <Card
        title="Protected Vault Resources"
        action={
          <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
            <input type="checkbox" checked={inFlight} onChange={(e) => setInFlight(e.target.checked)} />
            <span>Explicit in-flight migration flag</span>
          </label>
        }
      >
        <DataTable
          rows={(resources.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Resource ID" },
            { key: "owner_actor_id", header: "Owner" },
            { key: "key_version", header: "Key Ver" },
            { key: "state", header: "State", render: (r) => <StatusBadge label={String(r.state)} tone="info" /> },
            {
              key: "read",
              header: "Authorized Read",
              render: (r) => (
                <Button size="sm" variant="secondary" onClick={() => readMut.mutate(String(r.id))}>
                  Decrypt
                </Button>
              ),
            },
          ]}
        />
        <div className="mt-4 space-y-2">
          {readMut.isError && <ErrorBanner message={`Access Denied: ${(readMut.error as Error).message}`} />}
          {readMut.data && (
            <div className="p-3 rounded bg-emerald-50 border border-emerald-500/30 text-xs space-y-1">
              <div className="font-semibold text-emerald-700">
                Authorized Decryption ({readMut.data.resource_id} · {readMut.data.algorithm} v{readMut.data.key_version})
              </div>
              <div className="font-mono text-slate-900 dark:text-slate-100">{readMut.data.plaintext}</div>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
