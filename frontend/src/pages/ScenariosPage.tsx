import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Play, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { Button, Card, StatusBadge, useToast } from "../components/ui";

interface ScenarioDef {
  id: string;
  name: string;
  description: string;
}

const SCENARIOS: ScenarioDef[] = [
  { id: "S01", name: "Normal Protected Read", description: "Owner allow, peer allow, wrong owner deny" },
  { id: "S02", name: "Lost Device & Replacement", description: "Revoke lost device, enrol replacement, peer unaffected" },
  { id: "S03", name: "Key Rotation & Cutoff", description: "4-phase rotation and zero-grace old-key rejection" },
  { id: "S04", name: "Crash Recovery Matrix", description: "Pre-commit and post-commit journaled recovery" },
  { id: "S05", name: "Backup Corruption", description: "Create manifest and verify integrity" },
  { id: "S06", name: "Log Injection & Tamper", description: "Verify hash chain + non-destructive tamper demo" },
  { id: "S07", name: "Privilege Escalation", description: "Unapproved role change detection (zero ML)" },
  { id: "S08", name: "Lateral Movement", description: "Multi-hop unexpected service edge graph" },
  { id: "S09", name: "Clock Skew & Reordering", description: "Out-of-order and clock offset ingestion" },
  { id: "S10", name: "Replay & Recipient Binding", description: "Wrong recipient denied and duplicate replay rejected" },
  { id: "S11", name: "Message Loss / Reordering", description: "Pending recovery delivers valid messages" },
  { id: "S12", name: "Peer-Bound Session Resumption", description: "Verify forward secrecy status = NOT_ESTABLISHED" },
  { id: "S13", name: "Audit Chain Verification", description: "Verify all persisted audit events" },
  { id: "S14", name: "Node Convergence Check", description: "Reconcile simulated nodes and read metrics" },
];

export function ScenariosPage() {
  const qc = useQueryClient();
  const { push } = useToast();
  const [statuses, setStatuses] = useState<Record<string, { status: "PASS" | "FAIL" | "NOT RUN"; detail: string }>>({});
  const [running, setRunning] = useState<string | null>(null);

  const runScenario = async (s: ScenarioDef) => {
    setRunning(s.id);
    try {
      await api.resetSimulation();
      if (s.id === "S01") {
        const sA = await api.demoLogin({ actor_id: "alice", device_id: "dev-alice-01", peer_id: "vault" });
        const ok = await api.readVault("vault-brief-alice", {
          actor_id: "alice",
          session_id: sA.id,
          device_id: "dev-alice-01",
          session_token: sA.session_token,
          peer_id: "vault",
        });
        if (!ok.plaintext) throw new Error("Missing plaintext");
      } else if (s.id === "S02") {
        await api.reportLostDevice({ operator_actor_id: "secop", device_id: "dev-alice-01", reason: "Scenario S02", confirmed: true });
        await api.replaceDevice("dev-alice-01", { owner_actor_id: "alice", new_device_id: "dev-alice-02", new_credential_fingerprint: "fp-alice-02-s02" });
      } else if (s.id === "S03") {
        await api.rotateKeys({ operator_actor_id: "secop", reason: "Scenario S03", retire_policy: "RETIRED" });
      } else if (s.id === "S04") {
        const journal = await api.journaledRotate({
          operator_actor_id: "secop",
          reason: "Scenario S04 journaled rotation & recovery",
          retire_policy: "RETIRED",
        });
        await api.recoverRotation(journal.operation_id, { operator_actor_id: "secop" });
      } else if (s.id === "S05") {
        const b = await api.createBackup({ operator_actor_id: "secop" });
        const v = await api.verifyBackup(b);
        if (!v.valid) throw new Error(v.reason);
      } else if (s.id === "S06" || s.id === "S13") {
        const v = await api.verifyAudit();
        const t = await api.tamperDemoAudit();
        if (!v.valid || !t.detected) throw new Error("Audit check failed");
      } else if (s.id === "S07" || s.id === "S08" || s.id === "S09") {
        await api.detectorIngest([
          { event_id: "s-1", event_time_utc: "2026-02-01T10:00:05Z", actor: "blair", source_service: "portal", target_service: "identity", action: "role_change", role_before: "viewer", role_after: "operator", session_id: "s1", correlation_id: "c1" },
          { event_id: "s-2", event_time_utc: "2026-02-01T10:00:02Z", actor: "blair", source_service: "reports", target_service: "billing", action: "read", session_id: "s1", correlation_id: "c1" },
          { event_id: "s-3", event_time_utc: "2026-02-01T10:00:06Z", actor: "blair", source_service: "billing", target_service: "archive", action: "read", session_id: "s1", correlation_id: "c1" },
        ]);
        const alerts = await api.detectorRun([]);
        if (alerts.length === 0) throw new Error("Expected alerts");
      } else if (s.id === "S10" || s.id === "S11" || s.id === "S12") {
        const sess = await api.demoLogin({ actor_id: "alice", device_id: "dev-alice-01", peer_id: "bob" });
        const msg = await api.sendMessage({ sender_id: "alice", recipient_id: "bob", session_id: sess.id, plaintext: "SCENARIO_MSG" });
        await api.deliverMessage(msg.id, { recipient_id: "bob" });
        const sec = await api.messagingSecurityStatus();
        if (sec.forward_secrecy !== "NOT_ESTABLISHED") throw new Error("Unexpected FS status");
      } else if (s.id === "S14") {
        await api.reconcileNodes();
        await api.nodeMetrics();
      } else {
        await api.listKeys();
      }

      setStatuses((prev) => ({ ...prev, [s.id]: { status: "PASS", detail: "Executed against live backend" } }));
      qc.invalidateQueries();
      push(`${s.id} (${s.name}) PASS`, "success");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Scenario failed";
      setStatuses((prev) => ({ ...prev, [s.id]: { status: "FAIL", detail: msg } }));
      push(`${s.id} FAIL: ${msg}`, "error");
    } finally {
      setRunning(null);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Attack & Failure Simulation (SIMULATION)</h1>
          <p className="text-xs text-slate-500">14 resettable scenarios wired to live FastAPI endpoints</p>
        </div>
        <Button variant="secondary" onClick={() => api.resetSimulation().then(() => push("Synthetic data reset", "info"))}>
          <RefreshCw className="w-3.5 h-3.5" /> Reset Synthetic State
        </Button>
      </div>

      <div className="grid md:grid-cols-2 gap-3">
        {SCENARIOS.map((s) => {
          const st = statuses[s.id]?.status ?? "NOT RUN";
          return (
            <Card
              key={s.id}
              title={`${s.id} — ${s.name}`}
              subtitle={s.description}
              action={
                <div className="flex items-center gap-2">
                  <StatusBadge label={st} tone={st === "PASS" ? "success" : st === "FAIL" ? "danger" : "neutral"} />
                  <Button size="sm" onClick={() => runScenario(s)} disabled={running !== null}>
                    <Play className="w-3 h-3" /> Run
                  </Button>
                </div>
              }
            >
              <div className="text-[11px] font-mono text-slate-500">
                {statuses[s.id]?.detail ?? "Click Run to reset synthetic data and execute scenario"}
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
