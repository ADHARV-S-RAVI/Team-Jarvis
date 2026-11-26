import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Trash2 } from "lucide-react";
import { api, API_BASE_URL } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";

function b64uToBuf(b64u: string): ArrayBuffer {
  const pad = b64u.length % 4 === 0 ? "" : "=".repeat(4 - (b64u.length % 4));
  const raw = atob(b64u.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64u(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function SettingsPage() {
  const { session, theme, toggleTheme, reducedMotion, toggleReducedMotion } = useAuth();
  const qc = useQueryClient();
  const { push } = useToast();

  const credsQuery = useQuery({
    queryKey: ["passkeys", session?.actorId],
    queryFn: () => api.listCredentials(session!.actorId),
    enabled: Boolean(session?.actorId),
  });

  const registerMut = useMutation({
    mutationFn: async () => {
      if (!session) throw new Error("Sign in first");
      if (!window.PublicKeyCredential || !navigator.credentials) {
        throw new Error("WebAuthn / Windows Hello is not supported in this browser.");
      }
      const rpId = window.location.hostname || "localhost";
      const opts = await api.registerOptions(session.actorId, rpId);
      const raw = opts.options as Record<string, unknown>;
      const userObj = (raw.user ?? {}) as Record<string, unknown>;
      const pubKeyOpts: PublicKeyCredentialCreationOptions = {
        challenge: b64uToBuf(String(raw.challenge)),
        rp: {
          name: String((raw.rp as Record<string, unknown>)?.name || "Q-SHIELD"),
          id: String((raw.rp as Record<string, unknown>)?.id || rpId),
        },
        user: {
          id: b64uToBuf(String(userObj.id || btoa(session.actorId))),
          name: String(userObj.name || session.actorId),
          displayName: String(userObj.displayName || session.displayLabel || session.actorId),
        },
        pubKeyCredParams: Array.isArray(raw.pubKeyCredParams)
          ? (raw.pubKeyCredParams as PublicKeyCredentialParameters[])
          : [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "preferred",
        },
        timeout: 60000,
      };
      const cred = (await navigator.credentials.create({ publicKey: pubKeyOpts })) as PublicKeyCredential | null;
      if (!cred) throw new Error("Passkey registration cancelled");
      const resp = cred.response as AuthenticatorAttestationResponse;
      return api.registerVerify({
        actor_id: session.actorId,
        challenge_id: opts.challenge_id,
        device_id: session.deviceId,
        rp_id: rpId,
        origin: window.location.origin,
        credential: {
          id: cred.id,
          rawId: bufToB64u(cred.rawId),
          type: cred.type,
          response: {
            clientDataJSON: bufToB64u(resp.clientDataJSON),
            attestationObject: bufToB64u(resp.attestationObject),
          },
        },
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["passkeys", session?.actorId] });
      push("Passkey / Windows Hello credential registered", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const revokeMut = useMutation({
    mutationFn: (credId: string) =>
      api.revokeCredential(credId, session!.actorId, "Removed from Security Settings"),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["passkeys", session?.actorId] });
      push("Passkey revoked", "info");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-900 dark:text-white">Security Settings, Accessibility &amp; Disclosures</h1>

      <Card
        title="Passkey / Windows Hello Management"
        subtitle="Biometric verification is handled locally by your device. Q-SHIELD stores public keys only."
        action={
          session ? (
            <Button size="sm" onClick={() => registerMut.mutate()} disabled={registerMut.isPending}>
              <Fingerprint className="w-3.5 h-3.5 mr-1 inline" /> Register Passkey
            </Button>
          ) : undefined
        }
      >
        <div className="space-y-3 text-xs">
          <div className="flex flex-wrap gap-2">
            <StatusBadge label="PASSKEY / WEBAUTHN: IMPLEMENTED, SUBJECT TO REAL-DEVICE VERIFICATION" tone="violet" />
            <StatusBadge label="FACIAL BIOMETRIC MATCHING: NOT IMPLEMENTED" tone="warning" />
          </div>
          <DataTable
            rows={(credsQuery.data ?? []) as unknown as Record<string, unknown>[]}
            columns={[
              { key: "credential_id", header: "Credential ID" },
              { key: "device_id", header: "Device" },
              { key: "status", header: "Status" },
              { key: "created_at", header: "Registered" },
              { key: "last_used_at", header: "Last Used" },
              {
                key: "remove",
                header: "Action",
                render: (r) => (
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={r.status !== "ACTIVE" || revokeMut.isPending}
                    onClick={() => revokeMut.mutate(String(r.id))}
                  >
                    <Trash2 className="w-3 h-3 mr-1 inline" /> Remove
                  </Button>
                ),
              },
            ]}
          />
        </div>
      </Card>

      <Card title="Display & Accessibility Preferences">
        <div className="flex flex-wrap gap-4 items-center text-xs">
          <Button variant="secondary" onClick={toggleTheme}>
            Theme: {theme === "dark" ? "Dark (Default)" : "Light"}
          </Button>
          <Button variant="secondary" onClick={toggleReducedMotion}>
            Reduced Motion: {reducedMotion ? "ON" : "OFF"}
          </Button>
        </div>
      </Card>

      <Card title="Backend Connection & Security Disclosures">
        <div className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
          <div>
            Backend API Base URL: <code className="font-mono text-teal-300">{API_BASE_URL || "same-origin"}</code>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            <StatusBadge label="OFFLINE-FIRST" tone="success" />
            <StatusBadge label="ZERO AI/ML" tone="info" />
            <StatusBadge label="NODES: SIMULATED" tone="violet" />
            <StatusBadge label="FORWARD SECRECY: NOT_ESTABLISHED" tone="warning" />
          </div>
          <ul className="list-disc pl-5 pt-2 space-y-1 text-slate-500">
            <li>Simulated nodes are local SQLite-backed logical nodes, not physical distributed consensus.</li>
            <li>Local KeyMaterialStore is a development key store, not a hardware HSM.</li>
            <li>No session tokens or secrets are persisted in browser localStorage.</li>
          </ul>
        </div>
      </Card>
    </div>
  );
}
