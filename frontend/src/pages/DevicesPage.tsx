import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api";
import { Button, Card, ConfirmDialog, DataTable, StatusBadge, useToast } from "../components/ui";

export function DevicesPage() {
  const qc = useQueryClient();
  const { push } = useToast();
  const devices = useQuery({ queryKey: ["devices"], queryFn: api.listDevices });

  const [operatorId, setOperatorId] = useState("secop");
  const [targetDevice, setTargetDevice] = useState<string | null>(null);

  const [lostId, setLostId] = useState("");
  const [ownerId, setOwnerId] = useState("alice");
  const [newDevId, setNewDevId] = useState("dev-alice-02");
  const [newFp, setNewFp] = useState("fp-alice-02-repl");

  const lostMut = useMutation({
    mutationFn: ({ deviceId, reason }: { deviceId: string; reason: string }) =>
      api.reportLostDevice({
        operator_actor_id: operatorId,
        device_id: deviceId,
        reason,
        confirmed: true,
      }),
    onSuccess: (res) => {
      qc.invalidateQueries();
      push(`Device ${res.device.id} REVOKED; Incident ${res.incident.id} created`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const suspendMut = useMutation({
    mutationFn: (deviceId: string) =>
      api.suspendDevice(deviceId, { operator_actor_id: operatorId, reason: "Operator temporary suspension" }),
    onSuccess: (dev) => {
      qc.invalidateQueries({ queryKey: ["devices"] });
      push(`Device ${dev.id} SUSPENDED`, "info");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const restoreMut = useMutation({
    mutationFn: (deviceId: string) =>
      api.restoreDevice(deviceId, { operator_actor_id: operatorId, reason: "Operator verified restoration" }),
    onSuccess: (dev) => {
      qc.invalidateQueries({ queryKey: ["devices"] });
      push(`Device ${dev.id} RESTORED to TRUSTED`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const replaceMut = useMutation({
    mutationFn: () =>
      api.replaceDevice(lostId, {
        owner_actor_id: ownerId,
        new_device_id: newDevId,
        new_credential_fingerprint: newFp,
      }),
    onSuccess: (dev) => {
      qc.invalidateQueries({ queryKey: ["devices"] });
      push(`Replacement device ${dev.id} enrolled`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Devices & Lost-Device Workflow</h1>

      <Card title="Operator Context" subtitle="Destructive actions require Security Operator / Admin authority">
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs text-slate-600 dark:text-slate-300">Acting Operator ID:</label>
          <input
            type="text"
            value={operatorId}
            onChange={(e) => setOperatorId(e.target.value)}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
          />
        </div>
      </Card>

      <Card title="Enrolled Devices">
        <DataTable
          rows={(devices.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Device ID" },
            { key: "owner_actor_id", header: "Owner" },
            {
              key: "state",
              header: "State",
              render: (r) => (
                <StatusBadge
                  label={String(r.state)}
                  tone={r.state === "TRUSTED" ? "success" : r.state === "REVOKED" ? "danger" : "warning"}
                />
              ),
            },
            { key: "state_version", header: "Ver" },
            {
              key: "actions",
              header: "Actions",
              render: (r) => (
                <div className="flex flex-wrap gap-1.5">
                  {r.state === "TRUSTED" && (
                    <Button size="sm" variant="secondary" onClick={() => suspendMut.mutate(String(r.id))}>
                      Suspend
                    </Button>
                  )}
                  {r.state === "SUSPENDED" && (
                    <Button size="sm" variant="primary" onClick={() => restoreMut.mutate(String(r.id))}>
                      Restore
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={r.state === "REVOKED"}
                    onClick={() => setTargetDevice(String(r.id))}
                  >
                    Report Lost
                  </Button>
                </div>
              ),
            },
          ]}
        />
      </Card>

      <Card title="Replacement Device Enrolment" subtitle="Enrols a new device for an owner after old device is REVOKED">
        <div className="grid md:grid-cols-4 gap-3">
          <input
            type="text"
            placeholder="Lost Device ID"
            value={lostId}
            onChange={(e) => setLostId(e.target.value)}
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
            placeholder="New Device ID"
            value={newDevId}
            onChange={(e) => setNewDevId(e.target.value)}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
          />
          <input
            type="text"
            placeholder="New Fingerprint"
            value={newFp}
            onChange={(e) => setNewFp(e.target.value)}
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
          />
        </div>
        <div className="pt-3">
          <Button onClick={() => replaceMut.mutate()} disabled={!lostId || replaceMut.isPending}>
            Enrol Replacement Device
          </Button>
        </div>
      </Card>

      <ConfirmDialog
        open={targetDevice !== null}
        title={`Confirm Lost-Device Revocation (${targetDevice})`}
        description="This commits a durable revocation tombstone, invalidates active sessions on the device, and propagates to simulated nodes."
        confirmLabel="Revoke Lost Device"
        onCancel={() => setTargetDevice(null)}
        onConfirm={(reason) => {
          if (targetDevice) lostMut.mutate({ deviceId: targetDevice, reason });
          setTargetDevice(null);
        }}
      />
    </div>
  );
}
