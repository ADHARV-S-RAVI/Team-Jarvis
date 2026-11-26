import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  Camera,
  CheckCircle2,
  Download,
  FileWarning,
  Fingerprint,
  FolderSearch,
  KeyRound,
  Lock,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { useTheme } from "../app/ThemeContext";
import { CameraDemoPreview } from "../components/CameraDemoPreview";
import { Button, Card, ConfirmDialog, DataTable, StatusBadge, useToast } from "../components/ui";

function bufToB64u(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uToBuf(s: string): ArrayBuffer {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

async function sha256HexFile(file: File): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle) return "";
  const buf = await file.arrayBuffer();
  const dig = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(dig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function SecurityIntegrityPage() {
  const { session } = useAuth();
  const { isDark } = useTheme();
  const { push } = useToast();
  const qc = useQueryClient();

  const actorId = session?.actorId ?? "alice";
  const [operatorId, setOperatorId] = useState("secop");
  const [activeTab, setActiveTab] = useState<"overview" | "identity" | "integrity">("overview");
  const [cameraOpen, setCameraOpen] = useState(false);

  // Identity states
  const [policyMode, setPolicyMode] = useState("OPTIONAL");
  const [freshnessSec, setFreshnessSec] = useState(300);
  const [revokeCredTarget, setRevokeCredTarget] = useState<string | null>(null);
  const [lastRegStatus, setLastRegStatus] = useState<string | null>(null);

  // Integrity states
  const [findingFilter, setFindingFilter] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Record<string, unknown> | null>(null);
  const [baselineReason, setBaselineReason] = useState("");
  const [confirmInitBaseline, setConfirmInitBaseline] = useState(false);

  // Queries
  const idStatus = useQuery({ queryKey: ["id-assurance-status", actorId], queryFn: () => api.identityAssuranceStatus(actorId) });
  const creds = useQuery({ queryKey: ["id-credentials"], queryFn: () => api.listCredentials() });
  const idHistory = useQuery({ queryKey: ["id-history"], queryFn: () => api.verificationHistory() });
  const intStatus = useQuery({ queryKey: ["integrity-status"], queryFn: api.integrityStatus });
  const findings = useQuery({
    queryKey: ["integrity-findings", findingFilter],
    queryFn: () => api.listIntegrityFindings(findingFilter || undefined),
  });
  const scans = useQuery({ queryKey: ["integrity-scans"], queryFn: api.listIntegrityScans });
  const changeReqs = useQuery({ queryKey: ["baseline-change-reqs"], queryFn: api.listBaselineChangeRequests });
  const timeline = useQuery({ queryKey: ["security-integrity-events"], queryFn: api.securityIntegrityEvents });

  const webauthnSupported = typeof window !== "undefined" && Boolean(window.PublicKeyCredential);
  const rpId = typeof window !== "undefined" && window.location.hostname ? window.location.hostname : "localhost";
  const origin = typeof window !== "undefined" && window.location.origin ? window.location.origin : "http://localhost:5173";

  const registerPasskeyMut = useMutation({
    mutationFn: async () => {
      if (!webauthnSupported || !navigator.credentials?.create) {
        throw new Error("Browser WebAuthn API unavailable in this environment");
      }
      const { challenge_id, options } = await api.registerOptions(actorId, rpId);
      const opts = options as Record<string, unknown>;
      const userObj = opts.user as Record<string, unknown>;
      const publicKey: PublicKeyCredentialCreationOptions = {
        ...(opts as unknown as PublicKeyCredentialCreationOptions),
        challenge: b64uToBuf(String(opts.challenge)),
        user: {
          ...(userObj as unknown as PublicKeyCredentialUserEntity),
          id: b64uToBuf(String(userObj.id)),
        },
      };
      const created = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
      if (!created) throw new Error("Passkey registration cancelled");
      const resp = created.response as AuthenticatorAttestationResponse;
      return api.registerVerify({
        actor_id: actorId,
        challenge_id,
        device_id: session?.deviceId,
        rp_id: rpId,
        origin,
        credential: {
          id: created.id,
          rawId: bufToB64u(created.rawId),
          type: created.type,
          response: {
            clientDataJSON: bufToB64u(resp.clientDataJSON),
            attestationObject: bufToB64u(resp.attestationObject),
          },
        },
      });
    },
    onSuccess: (res) => {
      setLastRegStatus(res.status);
      qc.invalidateQueries({ queryKey: ["id-assurance-status"] });
      qc.invalidateQueries({ queryKey: ["id-credentials"] });
      qc.invalidateQueries({ queryKey: ["security-integrity-events"] });
      push(res.status, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const verifyIdentityMut = useMutation({
    mutationFn: async () => {
      if (!webauthnSupported || !navigator.credentials?.get) {
        throw new Error("Browser WebAuthn API unavailable in this environment");
      }
      const { challenge_id, options } = await api.authOptions(actorId, rpId);
      const opts = options as Record<string, unknown>;
      const allow = Array.isArray(opts.allowCredentials)
        ? (opts.allowCredentials as Record<string, unknown>[]).map((c) => ({
            type: "public-key" as const,
            id: b64uToBuf(String(c.id)),
          }))
        : [];
      const publicKey: PublicKeyCredentialRequestOptions = {
        ...(opts as unknown as PublicKeyCredentialRequestOptions),
        challenge: b64uToBuf(String(opts.challenge)),
        allowCredentials: allow,
      };
      const assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
      if (!assertion) throw new Error("Verification cancelled");
      const resp = assertion.response as AuthenticatorAssertionResponse;
      return api.authVerify({
        actor_id: actorId,
        challenge_id,
        rp_id: rpId,
        origin,
        credential: {
          id: assertion.id,
          rawId: bufToB64u(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: bufToB64u(resp.clientDataJSON),
            authenticatorData: bufToB64u(resp.authenticatorData),
            signature: bufToB64u(resp.signature),
            userHandle: resp.userHandle ? bufToB64u(resp.userHandle) : null,
          },
        },
      });
    },
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["id-assurance-status"] });
      qc.invalidateQueries({ queryKey: ["id-history"] });
      qc.invalidateQueries({ queryKey: ["security-integrity-events"] });
      push(`Identity verified: ${res.assurance_level}`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const policyMut = useMutation({
    mutationFn: () =>
      api.updateAssurancePolicy({
        operator_actor_id: operatorId,
        policy_mode: policyMode,
        freshness_window_seconds: freshnessSec,
        require_user_verification: true,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["id-assurance-status"] });
      push(`Updated assurance policy (${policyMode})`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const revokeCredMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => api.revokeCredential(id, operatorId, reason),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["id-credentials"] });
      qc.invalidateQueries({ queryKey: ["id-assurance-status"] });
      push("Credential revoked cleanly", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const initBaseMut = useMutation({
    mutationFn: () => api.initIntegrityBaseline(operatorId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["integrity-status"] });
      qc.invalidateQueries({ queryKey: ["security-integrity-events"] });
      push(`Initialized baseline v${res.manifest_version}`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const verifyBaseMut = useMutation({
    mutationFn: api.verifyIntegrityBaseline,
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["integrity-status"] });
      push(res.valid ? `Manifest verified (${res.entry_count} entries)` : `Manifest check: ${res.status}`, res.valid ? "success" : "error");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const appScanMut = useMutation({
    mutationFn: () => api.runAppIntegrityScan(operatorId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["integrity-status"] });
      qc.invalidateQueries({ queryKey: ["integrity-findings"] });
      qc.invalidateQueries({ queryKey: ["integrity-scans"] });
      qc.invalidateQueries({ queryKey: ["security-integrity-events"] });
      push(`Scan ${res.scan_status}: ${res.files_verified} verified, ${res.files_modified} modified`, res.files_modified > 0 ? "error" : "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const handleUserSelectedFiles = async (fileListObj: FileList | null) => {
    if (!fileListObj || fileListObj.length === 0) return;
    try {
      const entries: Record<string, unknown>[] = [];
      for (const f of Array.from(fileListObj).slice(0, 100)) {
        const hash = await sha256HexFile(f);
        entries.push({
          relative_path: (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name,
          sha256_hash: hash || "0".repeat(64),
          file_size: f.size,
          file_type: f.type || "selected",
        });
      }
      const res = await api.runUserSelectedIntegrityScan(actorId, entries);
      qc.invalidateQueries({ queryKey: ["integrity-scans"] });
      qc.invalidateQueries({ queryKey: ["integrity-findings"] });
      push(`User-selected metadata scan complete (${res.files_scanned} files hashed locally)`, "success");
    } catch (e) {
      push((e as Error).message, "error");
    }
  };

  const reqBaseUpdateMut = useMutation({
    mutationFn: () =>
      api.requestBaselineUpdate({
        requested_by: actorId,
        reason: baselineReason,
        scan_id: intStatus.data?.latest_scan?.id,
      }),
    onSuccess: () => {
      setBaselineReason("");
      qc.invalidateQueries({ queryKey: ["baseline-change-reqs"] });
      push("Baseline update request submitted for operator review", "info");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const resolveBaseMut = useMutation({
    mutationFn: ({ id, approve }: { id: string; approve: boolean }) => api.resolveBaselineChange(id, operatorId, approve),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["baseline-change-reqs"] });
      qc.invalidateQueries({ queryKey: ["integrity-status"] });
      push(`Baseline request ${res.status}`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const latestScan = intStatus.data?.latest_scan;
  const integrityChartData = useMemo(
    () => [
      { name: "Verified", count: latestScan?.files_verified ?? 0, color: "#10b981" },
      { name: "Modified", count: latestScan?.files_modified ?? 0, color: "#ef4444" },
      { name: "Missing", count: latestScan?.files_missing ?? 0, color: "#f97316" },
      { name: "Unexpected", count: latestScan?.files_unexpected ?? 0, color: "#eab308" },
    ],
    [latestScan]
  );

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">
            Q-SHIELD SECURITY INTEGRITY CENTER
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Continuously verify identity assurance and application integrity.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge
            label={idStatus.data?.fresh_verified ? `ASSURANCE: ${idStatus.data.assurance_level}` : "ASSURANCE: STANDARD_SESSION"}
            tone={idStatus.data?.fresh_verified ? "success" : "info"}
          />
          <StatusBadge
            label={`BASELINE: ${intStatus.data?.baseline_status ?? "BASELINE_UNAVAILABLE"}`}
            tone={intStatus.data?.baseline_status === "ACTIVE" ? "success" : intStatus.data?.baseline_status === "TAMPERED" ? "danger" : "warning"}
          />
          <Button size="sm" variant="secondary" onClick={() => setCameraOpen((v) => !v)}>
            <Camera className="w-3.5 h-3.5" /> {cameraOpen ? "Hide Camera Demo" : "Camera Demo"}
          </Button>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-[#1c242d] pb-2">
        <div className="flex gap-2 text-xs font-mono">
          {(
            [
              { id: "overview", label: "Unified Overview" },
              { id: "identity", label: "Identity Assurance (WebAuthn)" },
              { id: "integrity", label: "File Integrity Intelligence" },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              className={`px-3 py-1.5 rounded-md border transition-colors ${
                activeTab === t.id
                  ? "bg-emerald-600 text-white border-emerald-600"
                  : "bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-500">Operator ID:</span>
          <input
            type="text"
            value={operatorId}
            onChange={(e) => setOperatorId(e.target.value)}
            className="w-24 rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2 py-1 text-xs font-mono text-slate-900 dark:text-white"
          />
        </div>
      </div>

      {/* PANEL A + PANEL B Overview */}
      {(activeTab === "overview" || activeTab === "identity") && (
        <div className="grid lg:grid-cols-2 gap-4">
          <Card
            title="Panel A: Identity Assurance (WebAuthn / Passkeys)"
            subtitle="Local OS authenticator (e.g., Windows Hello) handles biometrics; backend stores public keys only"
            action={
              <StatusBadge
                label={webauthnSupported ? "WEBAUTHN: SUPPORTED" : "WEBAUTHN: UNAVAILABLE"}
                tone={webauthnSupported ? "success" : "warning"}
              />
            }
          >
            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                  <div className="text-slate-500">Enrolled Passkeys</div>
                  <div className="font-mono text-lg font-bold text-slate-900 dark:text-white">
                    {idStatus.data?.counts?.total_enrolled_credentials ?? 0}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                  <div className="text-slate-500">Successful Verify</div>
                  <div className="font-mono text-lg font-bold text-emerald-600 dark:text-emerald-400">
                    {idStatus.data?.counts?.successful_verifications ?? 0}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                  <div className="text-slate-500">Failed / Revoked</div>
                  <div className="font-mono text-lg font-bold text-rose-500">
                    {idStatus.data?.counts?.failed_verifications ?? 0}
                  </div>
                </div>
              </div>

              {lastRegStatus && (
                <div className="p-2 rounded bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-500/30 font-mono text-emerald-700 dark:text-emerald-300">
                  {lastRegStatus}
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                <Button size="sm" onClick={() => registerPasskeyMut.mutate()} disabled={registerPasskeyMut.isPending}>
                  <Fingerprint className="w-3.5 h-3.5" /> Register Passkey
                </Button>
                <Button size="sm" variant="secondary" onClick={() => verifyIdentityMut.mutate()} disabled={verifyIdentityMut.isPending}>
                  <KeyRound className="w-3.5 h-3.5" /> Verify Identity
                </Button>
                <Button size="sm" variant="secondary" onClick={() => setCameraOpen(true)}>
                  <Camera className="w-3.5 h-3.5" /> Launch Camera Demo
                </Button>
              </div>

              <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] space-y-2">
                <div className="font-semibold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-emerald-600" /> Verification Policy ({idStatus.data?.policy?.policy_mode ?? "OPTIONAL"})
                </div>
                <div className="flex flex-wrap gap-2 items-center">
                  <select
                    value={policyMode}
                    onChange={(e) => setPolicyMode(e.target.value)}
                    className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2 py-1 text-xs"
                  >
                    <option value="OPTIONAL">OPTIONAL</option>
                    <option value="REQUIRED_FOR_SENSITIVE_ACTIONS">REQUIRED_FOR_SENSITIVE_ACTIONS</option>
                    <option value="REQUIRED_AFTER_LOGIN">REQUIRED_AFTER_LOGIN</option>
                  </select>
                  <input
                    type="number"
                    value={freshnessSec}
                    onChange={(e) => setFreshnessSec(Number(e.target.value))}
                    className="w-20 rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2 py-1 text-xs font-mono"
                    title="Freshness window (seconds)"
                  />
                  <Button size="sm" variant="secondary" onClick={() => policyMut.mutate()}>
                    Update Policy
                  </Button>
                </div>
              </div>
            </div>
          </Card>

          {activeTab === "overview" && (
            <Card
              title="Panel B: File Integrity Intelligence"
              subtitle="Scope A: Q-SHIELD app directory &bull; Scope B: Explicit user selection only (no silent disk access)"
              action={
                <Button size="sm" onClick={() => appScanMut.mutate()} disabled={appScanMut.isPending}>
                  <ShieldCheck className="w-3.5 h-3.5" /> Scan Application
                </Button>
              }
            >
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                    <div className="text-slate-500">Verified</div>
                    <div className="font-mono text-lg font-bold text-emerald-600">{latestScan?.files_verified ?? 0}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                    <div className="text-slate-500">Modified</div>
                    <div className="font-mono text-lg font-bold text-rose-500">{latestScan?.files_modified ?? 0}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                    <div className="text-slate-500">Missing</div>
                    <div className="font-mono text-lg font-bold text-orange-500">{latestScan?.files_missing ?? 0}</div>
                  </div>
                  <div className="p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
                    <div className="text-slate-500">Unexpected</div>
                    <div className="font-mono text-lg font-bold text-amber-500">{latestScan?.files_unexpected ?? 0}</div>
                  </div>
                </div>

                <div className="h-36">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={integrityChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#1c242d" : "#e2e8f0"} vertical={false} />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                      <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: isDark ? "#0b0f13" : "#ffffff",
                          borderColor: isDark ? "#1c242d" : "#e2e8f0",
                          fontSize: 11,
                        }}
                      />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {integrityChartData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" onClick={() => setConfirmInitBaseline(true)}>
                    Initialize Baseline
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => verifyBaseMut.mutate()}>
                    Verify Manifest
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => setActiveTab("integrity")}>
                    View All Findings
                  </Button>
                </div>
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Identity Tables */}
      {activeTab === "identity" && (
        <div className="grid lg:grid-cols-2 gap-4">
          <Card title="Enrolled Passkey Credentials">
            <DataTable
              rows={(creds.data ?? []) as unknown as Record<string, unknown>[]}
              columns={[
                { key: "actor_id", header: "Actor" },
                { key: "device_id", header: "Device", render: (r) => String(r.device_id ?? "unbound") },
                {
                  key: "credential_status",
                  header: "Status",
                  render: (r) => (
                    <StatusBadge label={String(r.credential_status)} tone={r.credential_status === "ACTIVE" ? "success" : "danger"} />
                  ),
                },
                { key: "sign_count", header: "Counter" },
                {
                  key: "actions",
                  header: "Action",
                  render: (r) => (
                    <Button
                      size="sm"
                      variant="danger"
                      disabled={r.credential_status === "REVOKED"}
                      onClick={() => setRevokeCredTarget(String(r.id))}
                    >
                      Revoke
                    </Button>
                  ),
                },
              ]}
            />
          </Card>

          <Card title="Identity Verification History">
            <DataTable
              rows={(idHistory.data ?? []) as unknown as Record<string, unknown>[]}
              columns={[
                { key: "actor_id", header: "Actor" },
                { key: "verification_method", header: "Method" },
                {
                  key: "verification_status",
                  header: "Status",
                  render: (r) => (
                    <StatusBadge
                      label={String(r.verification_status)}
                      tone={r.verification_status === "SUCCESS" ? "success" : "warning"}
                    />
                  ),
                },
                { key: "assurance_level", header: "Assurance" },
              ]}
            />
          </Card>
        </div>
      )}

      {/* File Integrity Full Section */}
      {activeTab === "integrity" && (
        <div className="space-y-4">
          <div className="grid lg:grid-cols-2 gap-4">
            <Card
              title="Scope A: Application File Integrity Controls"
              subtitle="Scans Q-SHIELD app directory against HMAC-protected manifest"
            >
              <div className="flex flex-wrap gap-2">
                <Button size="sm" onClick={() => appScanMut.mutate()}>
                  <CheckCircle2 className="w-3.5 h-3.5" /> Scan Application
                </Button>
                <Button size="sm" variant="secondary" onClick={() => setConfirmInitBaseline(true)}>
                  Initialize Baseline
                </Button>
                <Button size="sm" variant="secondary" onClick={() => verifyBaseMut.mutate()}>
                  Verify Manifest
                </Button>
                <a
                  href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(intStatus.data ?? {}, null, 2))}`}
                  download="qshield-integrity-status.json"
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <Download className="w-3.5 h-3.5" /> Export Report
                </a>
              </div>
            </Card>

            <Card
              title="Scope B: User-Selected Files & Folder Scan"
              subtitle="Hashed locally in browser (WebCrypto SHA-256); file contents are never uploaded"
            >
              <div className="flex items-center gap-3 text-xs">
                <FolderSearch className="w-5 h-5 text-emerald-600 shrink-0" />
                <input
                  type="file"
                  multiple
                  aria-label="Select files to hash locally"
                  onChange={(e) => void handleUserSelectedFiles(e.target.files)}
                  className="text-xs text-slate-700 dark:text-slate-300"
                />
              </div>
            </Card>
          </div>

          <div className="grid lg:grid-cols-12 gap-4">
            <Card
              title="File Integrity Findings"
              className="lg:col-span-8"
              action={
                <select
                  value={findingFilter}
                  onChange={(e) => setFindingFilter(e.target.value)}
                  className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2 py-1 text-xs"
                >
                  <option value="">All Statuses</option>
                  <option value="VERIFIED">VERIFIED</option>
                  <option value="MODIFIED">MODIFIED</option>
                  <option value="MISSING">MISSING</option>
                  <option value="UNEXPECTED">UNEXPECTED</option>
                  <option value="BASELINE_UNAVAILABLE">BASELINE_UNAVAILABLE</option>
                </select>
              }
            >
              <DataTable
                rows={(findings.data ?? []) as unknown as Record<string, unknown>[]}
                columns={[
                  {
                    key: "relative_path",
                    header: "Path",
                    render: (r) => (
                      <button
                        type="button"
                        onClick={() => setSelectedFinding(r)}
                        className="font-mono text-emerald-600 dark:text-emerald-400 hover:underline text-left"
                      >
                        {String(r.relative_path)}
                      </button>
                    ),
                  },
                  { key: "file_type", header: "Type" },
                  {
                    key: "finding_type",
                    header: "Status",
                    render: (r) => (
                      <StatusBadge
                        label={String(r.finding_type)}
                        tone={r.finding_type === "VERIFIED" ? "success" : r.finding_type === "BASELINE_UNAVAILABLE" ? "warning" : "danger"}
                      />
                    ),
                  },
                  {
                    key: "actual_hash",
                    header: "Actual SHA-256",
                    render: (r) => (
                      <span className="font-mono text-[11px] text-slate-500">
                        {r.actual_hash ? `${String(r.actual_hash).slice(0, 14)}...` : "N/A"}
                      </span>
                    ),
                  },
                ]}
              />
            </Card>

            <Card title="Finding Detail & Governance" className="lg:col-span-4">
              {selectedFinding ? (
                <div className="space-y-2 text-xs font-mono bg-slate-50 dark:bg-[#131a21] p-3 rounded border border-slate-200 dark:border-slate-800 mb-3">
                  <div className="font-bold text-slate-900 dark:text-white">{String(selectedFinding.relative_path)}</div>
                  <div>Status: {String(selectedFinding.finding_type)}</div>
                  <div className="break-all">Expected: {String(selectedFinding.expected_hash ?? "NONE")}</div>
                  <div className="break-all">Actual: {String(selectedFinding.actual_hash ?? "NONE")}</div>
                </div>
              ) : (
                <div className="text-xs text-slate-500 mb-3">Click a file row to inspect expected vs actual hashes.</div>
              )}

              <div className="space-y-2 border-t border-slate-200 dark:border-slate-800 pt-3">
                <div className="text-xs font-semibold text-slate-900 dark:text-white">Request Baseline Update</div>
                <input
                  type="text"
                  placeholder="Approval reason (required)..."
                  value={baselineReason}
                  onChange={(e) => setBaselineReason(e.target.value)}
                  className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2.5 py-1.5 text-xs"
                />
                <Button size="sm" disabled={!baselineReason.trim()} onClick={() => reqBaseUpdateMut.mutate()}>
                  <FileWarning className="w-3.5 h-3.5" /> Submit Change Request
                </Button>

                <div className="space-y-1.5 pt-2">
                  {(changeReqs.data ?? []).map((cr) => (
                    <div key={cr.id} className="p-2 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-slate-800 text-[11px] space-y-1">
                      <div className="flex justify-between">
                        <span className="font-mono">{cr.requested_by}</span>
                        <StatusBadge label={cr.status} tone={cr.status === "APPROVED" ? "success" : cr.status === "REJECTED" ? "danger" : "warning"} />
                      </div>
                      <div className="text-slate-600 dark:text-slate-300">{cr.reason}</div>
                      {cr.status === "PENDING" && (
                        <div className="flex gap-1.5 pt-1">
                          <Button size="sm" onClick={() => resolveBaseMut.mutate({ id: cr.id, approve: true })}>Approve</Button>
                          <Button size="sm" variant="danger" onClick={() => resolveBaseMut.mutate({ id: cr.id, approve: false })}>Reject</Button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* Unified Live Security Activity Timeline */}
      <Card title="Live Security Activity Timeline" subtitle="Audit-backed events across Identity Assurance & File Integrity">
        <div className="space-y-2 max-h-56 overflow-y-auto">
          {(timeline.data ?? []).length === 0 ? (
            <div className="text-xs text-slate-500 py-4 text-center">No identity or integrity events recorded yet.</div>
          ) : (
            (timeline.data ?? []).map((ev) => (
              <div
                key={ev.event_id}
                className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] text-xs"
              >
                <div>
                  <span className="font-mono font-semibold text-slate-900 dark:text-white">
                    #{ev.sequence} {ev.action}
                  </span>{" "}
                  <span className="text-slate-500">({ev.actor_id} &rarr; {ev.target})</span>
                  <div className="text-[11px] text-slate-600 dark:text-slate-300">{ev.reason}</div>
                </div>
                <StatusBadge label={ev.decision} tone={ev.decision === "ALLOW" ? "success" : "danger"} />
              </div>
            ))
          )}
        </div>
      </Card>

      <ConfirmDialog
        open={confirmInitBaseline}
        title="Initialize Integrity Baseline"
        description="Creates a new HMAC-protected canonical SHA-256 baseline manifest over permitted Q-SHIELD application files."
        requireReason={false}
        confirmLabel="Initialize"
        onCancel={() => setConfirmInitBaseline(false)}
        onConfirm={() => {
          setConfirmInitBaseline(false);
          initBaseMut.mutate();
        }}
      />

      <ConfirmDialog
        open={revokeCredTarget !== null}
        title="Revoke Passkey Credential"
        description="Revoked credentials cannot authenticate or be re-activated."
        confirmLabel="Revoke Credential"
        onCancel={() => setRevokeCredTarget(null)}
        onConfirm={(reason) => {
          if (revokeCredTarget) revokeCredMut.mutate({ id: revokeCredTarget, reason });
          setRevokeCredTarget(null);
        }}
      />

      <CameraDemoPreview open={cameraOpen} actorId={actorId} onClose={() => setCameraOpen(false)} />
    </div>
  );
}
