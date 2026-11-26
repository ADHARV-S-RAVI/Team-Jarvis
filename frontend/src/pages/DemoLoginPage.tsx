import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { LogIn, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, ErrorBanner, StatusBadge, useToast } from "../components/ui";

export function DemoLoginPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { session, setSession } = useAuth();
  const { push } = useToast();

  const [actorId, setActorId] = useState("alice");
  const [deviceId, setDeviceId] = useState("dev-alice-01");
  const [peerId, setPeerId] = useState("vault");

  const identitiesQuery = useQuery({ queryKey: ["identities"], queryFn: api.listIdentities });
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: api.listDevices });

  const resetMut = useMutation({
    mutationFn: api.resetSimulation,
    onSuccess: (res) => {
      qc.invalidateQueries();
      push(`Synthetic data reset (${res.seeded_actors} actors, ${res.seeded_nodes} simulated nodes)`, "success");
    },
    onError: (err: Error) => push(err.message, "error"),
  });

  const loginMut = useMutation({
    mutationFn: () => api.demoLogin({ actor_id: actorId, device_id: deviceId, peer_id: peerId }),
    onSuccess: (res) => {
      setSession({
        actorId: res.actor_id,
        deviceId: res.device_id,
        sessionId: res.id,
        sessionToken: res.session_token,
        peerId: res.peer_id,
      });
      qc.invalidateQueries({ queryKey: ["sessions"] });
      push(`Authenticated as ${res.actor_id} on ${res.device_id}`, "success");
      navigate("/overview");
    },
    onError: (err: Error) => push(`Login failed: ${err.message}`, "error"),
  });

  return (
    <div className="max-w-xl mx-auto space-y-4">
      <Card
        title="Synthetic Demo Login"
        subtitle="Offline-first session issuance backed by POST /api/v1/auth/demo-login (token held in memory only)"
        action={
          <Button size="sm" variant="secondary" onClick={() => resetMut.mutate()} disabled={resetMut.isPending}>
            <RefreshCw className="w-3.5 h-3.5" /> Reset Demo Data
          </Button>
        }
      >
        <div className="space-y-4">
          {identitiesQuery.data?.length === 0 && (
            <div className="p-3 rounded bg-amber-950/40 border border-amber-500/30 text-xs text-amber-800">
              Database has no seeded demo identities yet. Click <strong>Reset Demo Data</strong> to seed
              synthetic actors, devices, nodes, and vault resources.
            </div>
          )}

          {loginMut.isError && <ErrorBanner message={(loginMut.error as Error).message} />}

          <div className="space-y-3">
            <div>
              <label className="block text-xs text-slate-600 dark:text-slate-300 mb-1">Synthetic Actor ID</label>
              <select
                value={actorId}
                onChange={(e) => {
                  setActorId(e.target.value);
                  const matching = devicesQuery.data?.find((d) => d.owner_actor_id === e.target.value);
                  if (matching) setDeviceId(matching.id);
                }}
                className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
              >
                {(identitiesQuery.data ?? []).map((id) => (
                  <option key={id.id} value={id.id}>
                    {id.id} — {id.display_label} ({id.role})
                  </option>
                ))}
                {!identitiesQuery.data?.length && <option value="alice">alice</option>}
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-600 dark:text-slate-300 mb-1">Bound Device ID</label>
              <input
                type="text"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-600 dark:text-slate-300 mb-1">Target Peer ID</label>
              <input
                type="text"
                value={peerId}
                onChange={(e) => setPeerId(e.target.value)}
                className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            {session ? (
              <StatusBadge label={`Active: ${session.actorId}`} tone="success" />
            ) : (
              <StatusBadge label="No active session" tone="neutral" />
            )}
            <Button onClick={() => loginMut.mutate()} disabled={loginMut.isPending}>
              <LogIn className="w-4 h-4" /> Issue Backend Session
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
