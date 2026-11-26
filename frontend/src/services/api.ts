/**
 * Centralized typed API client for Q-SHIELD FastAPI backend.
 * Base URL configured via VITE_API_BASE_URL (public URL only; no secrets).
 */

export const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ??
  (typeof window !== "undefined" && window.location.port === "5173"
    ? "http://127.0.0.1:8000"
    : "");

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

function authHeaders(sessionId?: string, sessionToken?: string): Record<string, string> | undefined {
  if (!sessionId) return undefined;
  const h: Record<string, string> = { "X-Session-Id": sessionId };
  if (sessionToken) {
    h.Authorization = `Bearer ${sessionToken}`;
  }
  return h;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }
  }

  if (!res.ok) {
    const obj = (data ?? {}) as Record<string, unknown>;
    const detailStr = typeof obj.detail === "string" ? obj.detail : undefined;
    const detail = typeof obj.detail === "object" && obj.detail !== null ? (obj.detail as Record<string, unknown>) : undefined;
    const msg =
      detailStr ||
      (detail?.reason_code as string | undefined) ||
      (obj.message as string | undefined) ||
      `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, data);
  }

  return data as T;
}

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  database: string;
}

export interface Identity {
  id: string;
  display_label: string;
  role: string;
  enabled: boolean;
  created_at: string;
}

export interface Device {
  id: string;
  owner_actor_id: string;
  credential_fingerprint: string;
  state: string;
  state_version: number;
  enrolled_at: string;
  revocation_reason?: string | null;
}

export interface SessionInfo {
  id: string;
  actor_id: string;
  device_id: string;
  peer_id: string;
  issued_at: string;
  expires_at: string;
  revoked_at?: string | null;
  version: number;
}

export interface SessionCreatedResponse extends SessionInfo {
  session_token: string;
}

export interface ResourceItem {
  id: string;
  owner_actor_id: string;
  content_ref: string;
  key_version: number;
  state: string;
  created_at: string;
}

export interface KeyMetadataItem {
  id: string;
  version: number;
  algorithm: string;
  state: string;
  created_at: string;
  activated_at?: string | null;
  retired_at?: string | null;
  compromised_at?: string | null;
}

export interface SimulatedNodeItem {
  id: string;
  service_name: string;
  accepted_key_version: number;
  last_sequence: number;
  health: string;
  delay_ms: number;
  fault_state: string;
  simulated: boolean;
}

export interface IncidentItem {
  id: string;
  incident_type: string;
  severity: string;
  status: string;
  initiator_actor_id: string;
  target_subject_type: string;
  target_subject_id: string;
  reason: string;
  confirmed: boolean;
  created_at: string;
}

export interface IncidentReceiptItem {
  id: string;
  incident_id: string;
  policy_decision: string;
  state_transition: string;
  node_acks_json: string;
  convergence_ms?: number | null;
  verification: string;
  audit_ref: string;
  created_at: string;
}

export interface AuditEventItem {
  event_id: string;
  sequence: number;
  timestamp: string;
  actor_id: string;
  action: string;
  target: string;
  decision: string;
  reason: string;
  correlation_id: string;
  metadata_json: string;
  prev_hash: string;
  event_hash: string;
}

export interface DetectorAlertItem {
  id: string;
  rule_id: string;
  severity: string;
  actor: string;
  score_breakdown_json: string;
  path_json: string;
  event_refs_json: string;
  created_at: string;
  explanation: string;
}

export interface MessageItem {
  id: string;
  sender_id: string;
  recipient_id: string;
  session_id: string;
  sequence: number;
  key_version: number;
  protocol_version: string;
  status: string;
  failure_reason?: string | null;
  created_at: string;
  expires_at: string;
  delivered_at?: string | null;
}

export const api = {
  health: () => requestJson<HealthResponse>("/api/v1/health"),
  resetSimulation: () =>
    requestJson<{ status: string; simulated: boolean; seeded_actors: number; seeded_nodes: number }>(
      "/api/v1/simulation/reset",
      { method: "POST" }
    ),
  createSession: (body: { actor_id: string; device_id: string; peer_id: string }) =>
    requestJson<SessionCreatedResponse>("/api/v1/sessions", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listIdentities: () => requestJson<Identity[]>("/api/v1/identities"),
  createIdentity: (body: { id: string; display_label: string; role: string; enabled?: boolean }) =>
    requestJson<Identity>("/api/v1/identities", { method: "POST", body: JSON.stringify(body) }),
  listDevices: () => requestJson<Device[]>("/api/v1/devices"),
  enrollDevice: (body: { id: string; owner_actor_id: string; credential_fingerprint: string }) =>
    requestJson<Device>("/api/v1/devices/enroll", { method: "POST", body: JSON.stringify(body) }),
  suspendDevice: (id: string, body: { operator_actor_id: string; reason: string }) =>
    requestJson<Device>(`/api/v1/devices/${id}/suspend`, { method: "POST", body: JSON.stringify(body) }),
  restoreDevice: (id: string, body: { operator_actor_id: string; reason: string }) =>
    requestJson<Device>(`/api/v1/devices/${id}/restore`, { method: "POST", body: JSON.stringify(body) }),
  revokeDevice: (id: string, body: { operator_actor_id: string; reason: string }) =>
    requestJson<Device>(`/api/v1/devices/${id}/revoke`, { method: "POST", body: JSON.stringify(body) }),
  replaceDevice: (id: string, body: { owner_actor_id: string; new_device_id: string; new_credential_fingerprint: string }) =>
    requestJson<Device>(`/api/v1/devices/${id}/replace`, { method: "POST", body: JSON.stringify(body) }),
  listSessions: () => requestJson<SessionInfo[]>("/api/v1/sessions"),
  revokeSession: (id: string, body: { actor_id: string; reason: string }) =>
    requestJson<SessionInfo>(`/api/v1/sessions/${id}/revoke`, { method: "POST", body: JSON.stringify(body) }),
  listResources: () => requestJson<ResourceItem[]>("/api/v1/resources"),
  storeVault: (body: { resource_id: string; owner_actor_id: string; plaintext: string; key_version?: number }) =>
    requestJson<{ resource_id: string; key_version: number; algorithm: string }>("/api/v1/vault/resources", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  readVault: (id: string, body: { actor_id: string; session_id: string; device_id: string; session_token?: string; peer_id?: string; in_flight?: boolean }) =>
    requestJson<{ decision: string; resource_id: string; key_version: number; algorithm: string; plaintext: string; correlation_id: string }>(
      `/api/v1/vault/resources/${id}/read`,
      { method: "POST", body: JSON.stringify(body) }
    ),
  evaluatePolicy: (body: { actor_id: string; session_id: string; device_id: string; resource_id: string; action: string; peer_id?: string; session_token?: string; in_flight?: boolean }) =>
    requestJson<{ decision: string; reason_code: string; failed_step?: number | null; checks_passed: string[]; correlation_id: string }>(
      "/api/v1/policy/evaluate",
      { method: "POST", body: JSON.stringify(body) }
    ),
  listKeys: () => requestJson<KeyMetadataItem[]>("/api/v1/keys"),
  rotateKeys: (body: { operator_actor_id: string; reason: string; retire_policy: "RETIRED" | "REVOKED" }) =>
    requestJson<{ operation_id: string; previous_version: number; new_version: number; phase: string; committed: boolean; node_status: string }>(
      "/api/v1/keys/rotate",
      { method: "POST", body: JSON.stringify(body) }
    ),
  journaledRotate: (body: { operator_actor_id: string; reason: string; retire_policy: "RETIRED" | "REVOKED"; crash_at?: string | null }) =>
    requestJson<{ operation_id: string; previous_version: number; proposed_version: number; phase: string; committed: boolean; integrity_hash: string }>(
      "/api/v1/keys/rotate/journaled",
      { method: "POST", body: JSON.stringify(body) }
    ),
  recoverRotation: (operationId: string, body: { operator_actor_id: string }) =>
    requestJson<Record<string, unknown>>(
      `/api/v1/keys/recover/${encodeURIComponent(operationId)}`,
      { method: "POST", body: JSON.stringify(body) }
    ),
  compromiseKey: (id: string, body: { operator_actor_id: string; reason: string }) =>
    requestJson<KeyMetadataItem>(`/api/v1/keys/${id}/compromise`, { method: "POST", body: JSON.stringify(body) }),
  createBackup: (body: { operator_actor_id: string }) =>
    requestJson<Record<string, unknown>>("/api/v1/keys/backups/create", { method: "POST", body: JSON.stringify(body) }),
  verifyBackup: (manifest: Record<string, unknown>) =>
    requestJson<{ valid: boolean; reason: string }>("/api/v1/keys/backups/verify", { method: "POST", body: JSON.stringify({ manifest }) }),
  listNodes: () => requestJson<SimulatedNodeItem[]>("/api/v1/nodes"),
  configureNodes: (count: number) =>
    requestJson<SimulatedNodeItem[]>("/api/v1/nodes/configure", { method: "POST", body: JSON.stringify({ count }) }),
  partitionNode: (id: string) =>
    requestJson<SimulatedNodeItem>(`/api/v1/nodes/${id}/partition`, { method: "POST" }),
  recoverNode: (id: string) =>
    requestJson<SimulatedNodeItem>(`/api/v1/nodes/${id}/recover`, { method: "POST" }),
  reconcileNodes: () =>
    requestJson<{ simulated: boolean; status: string; converged_nodes: number; total_nodes: number }>(
      "/api/v1/nodes/reconcile",
      { method: "POST" }
    ),
  nodeMetrics: () =>
    requestJson<{ sample_count: number; p50_ms: number | null; p95_ms: number | null; p99_ms: number | null; max_ms: number | null }>(
      "/api/v1/nodes/metrics"
    ),
  reportLostDevice: (body: { operator_actor_id: string; device_id: string; reason: string; confirmed: boolean }) =>
    requestJson<{ incident: IncidentItem; receipt: IncidentReceiptItem; device: Device }>(
      "/api/v1/incidents/lost-device",
      { method: "POST", body: JSON.stringify(body) }
    ),
  listIncidents: () => requestJson<IncidentItem[]>("/api/v1/incidents"),
  getIncidentReceipt: (id: string) => requestJson<IncidentReceiptItem>(`/api/v1/incidents/${id}/receipt`),
  verifyIncident: (id: string) =>
    requestJson<{ valid: boolean; audit_ref?: string; chain_valid?: boolean }>(`/api/v1/incidents/${id}/verify`),
  listAuditEvents: (params?: { actor_id?: string; decision?: string }) => {
    const qs = new URLSearchParams();
    if (params?.actor_id) qs.set("actor_id", params.actor_id);
    if (params?.decision) qs.set("decision", params.decision);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return requestJson<AuditEventItem[]>(`/api/v1/audit/events${suffix}`);
  },
  verifyAudit: () =>
    requestJson<{ valid: boolean; checked_events: number; canonical_version: string; genesis: string; failures: unknown[] }>(
      "/api/v1/audit/verify",
      { method: "POST" }
    ),
  tamperDemoAudit: () =>
    requestJson<{ demo: boolean; non_destructive: boolean; detected: boolean; verification: Record<string, unknown> }>(
      "/api/v1/audit/tamper-demo",
      { method: "POST" }
    ),
  detectorIngest: (events: Record<string, unknown>[]) =>
    requestJson<{ ingested_count: number; out_of_order_count: number; order_uncertain_count: number }>(
      "/api/v1/detector/ingest",
      { method: "POST", body: JSON.stringify({ events }) }
    ),
  detectorRun: (approvals: Record<string, unknown>[] = []) =>
    requestJson<DetectorAlertItem[]>("/api/v1/detector/run", { method: "POST", body: JSON.stringify({ approvals }) }),
  detectorAlerts: () => requestJson<DetectorAlertItem[]>("/api/v1/detector/alerts"),
  detectorRules: () => requestJson<{ rule_id: string; severity: string; description: string }[]>("/api/v1/detector/rules"),
  listMessages: () => requestJson<MessageItem[]>("/api/v1/messages"),
  sendMessage: (body: { sender_id: string; recipient_id: string; session_id: string; plaintext: string; simulate_pending_recovery?: boolean }) =>
    requestJson<MessageItem>("/api/v1/messages/send", { method: "POST", body: JSON.stringify(body) }),
  deliverMessage: (id: string, body: { recipient_id: string }) =>
    requestJson<{ message_id: string; status: string; plaintext: string }>(`/api/v1/messages/${id}/deliver`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  recoverMessages: (body: { session_id: string; recipient_id: string }) =>
    requestJson<{ delivered_count: number; failed_count: number }>("/api/v1/messages/recover", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  messagingSecurityStatus: () =>
    requestJson<{ protocol_version: string; aead_algorithm: string; forward_secrecy: string; forward_secrecy_note: string }>(
      "/api/v1/messages/security-status"
    ),
  scorecard: () =>
    requestJson<{ project: string; forward_secrecy: string; nodes_mode: string; gates: { gate: string; name: string; status: string }[] }>(
      "/api/v1/evidence/scorecard"
    ),
  benchmarksLatest: () =>
    requestJson<{
      status: string;
      environment?: {
        timestamp_utc?: string;
        os?: string;
        python_version?: string;
        cpu_count?: number;
        seed?: number;
        peak_rss_mb?: number;
        cpu_user_s?: number;
        cpu_system_s?: number;
        suite_duration_s?: number;
      } | null;
      benchmarks: {
        operation: string;
        samples: number;
        errors: number;
        mean_ms: number;
        p50_ms: number;
        p95_ms: number;
        p99_ms: number;
        max_ms: number;
        stddev_ms: number;
        throughput_ops_sec: number;
      }[];
    }>("/api/v1/benchmarks/latest"),
  issueResumptionToken: (body: { session_id: string; actor_id: string; peer_id: string; ttl_seconds?: number }) =>
    requestJson<{ token_id: string; nonce_b64: string; ciphertext_b64: string; tag_b64: string; expires_at: string }>(
      "/api/v1/messages/resumption-token",
      { method: "POST", body: JSON.stringify(body) }
    ),
  resumeSession: (body: { token_bundle: Record<string, string>; actor_id: string; peer_id: string }) =>
    requestJson<Record<string, unknown>>(
      "/api/v1/messages/resume",
      { method: "POST", body: JSON.stringify(body) }
    ),
  systemMetrics: () =>
    requestJson<{
      uptime_seconds: number;
      worker_running: boolean;
      worker_uptime_seconds: number;
      cpu_percent: number;
      process_rss_mb: number;
      disk_free_gb: number;
      disk_used_pct: number;
      queue_depth: number;
      failed_jobs: number;
      files_verified_count: number;
      storage_used_bytes: number;
      storage_quota_bytes: number;
      max_upload_bytes: number;
    }>("/api/v1/system/metrics"),
  listJobs: () =>
    requestJson<
      {
        id: string;
        job_type: string;
        target_id: string;
        status: string;
        progress_pct: number;
        attempts: number;
        error_message?: string | null;
        created_at: string;
        completed_at?: string | null;
      }[]
    >("/api/v1/jobs"),
  retryJob: (jobId: string) => requestJson<{ id: string; status: string }>(`/api/v1/jobs/${jobId}/retry`, { method: "POST" }),
  cancelJob: (jobId: string) => requestJson<{ id: string; status: string }>(`/api/v1/jobs/${jobId}/cancel`, { method: "POST" }),
  initDataUpload: (body: { filename: string; declared_size_bytes: number; chunk_size_bytes: number; reference_sha256?: string }) =>
    requestJson<{ upload_id: string; filename: string; total_chunks: number; chunk_size_bytes: number; status: string }>(
      "/api/v1/datalab/uploads/init",
      { method: "POST", body: JSON.stringify(body) }
    ),
  uploadDataChunk: async (uploadId: string, chunkIndex: number, blob: Blob, chunkSha256?: string) => {
    const res = await fetch(`${API_BASE_URL}/api/v1/datalab/uploads/${uploadId}/chunks/${chunkIndex}`, {
      method: "PUT",
      headers: chunkSha256 ? { "X-Chunk-SHA256": chunkSha256 } : undefined,
      body: blob,
    });
    if (!res.ok) throw new ApiError(res.status, `Chunk ${chunkIndex} failed (${res.status})`);
    return res.json() as Promise<{ chunk_index: number; status: string; chunk_sha256: string }>;
  },
  pauseDataUpload: (uploadId: string) => requestJson<{ upload_id: string; status: string }>(`/api/v1/datalab/uploads/${uploadId}/pause`, { method: "POST" }),
  resumeDataUpload: (uploadId: string) => requestJson<{ upload_id: string; status: string }>(`/api/v1/datalab/uploads/${uploadId}/resume`, { method: "POST" }),
  cancelDataUpload: (uploadId: string) => requestJson<{ upload_id: string; status: string }>(`/api/v1/datalab/uploads/${uploadId}/cancel`, { method: "POST" }),
  finalizeDataUpload: (uploadId: string, inline = false) =>
    requestJson<{ file_id: string; job_id: string; sha256: string; merkle_root: string; verification_status: string }>(
      `/api/v1/datalab/uploads/${uploadId}/finalize?inline=${inline}`,
      { method: "POST" }
    ),
  listVerifiedFiles: () =>
    requestJson<
      {
        id: string;
        filename: string;
        size_bytes: number;
        detected_mime: string;
        detected_category: string;
        sha256: string;
        merkle_root: string | null;
        merkle_leaf_count: number;
        reference_status: string;
        signature_status: string;
        crypto_readiness: string;
        risk_level: string;
        verification_status: string;
        created_at: string;
        verified_at: string | null;
      }[]
    >("/api/v1/datalab/files"),
  getVerifiedFileDetail: (fileId: string) =>
    requestJson<{
      id: string;
      filename: string;
      size_bytes: number;
      detected_mime: string;
      detected_category: string;
      sha256: string;
      merkle_root: string | null;
      merkle_leaf_count: number;
      reference_sha256: string | null;
      reference_status: string;
      signature_status: string;
      crypto_readiness: string;
      risk_level: string;
      verification_status: string;
      dataset_profile: Record<string, unknown> | null;
      findings: { severity: string; code: string; message: string }[];
      receipt: Record<string, unknown> | null;
      stages: {
        stage_order: number;
        stage_name: string;
        status: string;
        duration_ms: number;
        algorithm: string;
        summary: string;
      }[];
    }>(`/api/v1/datalab/files/${fileId}`),
  verifyFileReference: (fileId: string, reference_sha256: string) =>
    requestJson<{ file_id: string; reference_status: string; verification_status: string }>(
      `/api/v1/datalab/files/${fileId}/verify-reference`,
      { method: "POST", body: JSON.stringify({ reference_sha256 }) }
    ),
  identityAssuranceStatus: (actorId = "alice") =>
    requestJson<{
      actor_id: string;
      assurance_level: string;
      fresh_verified: boolean;
      fresh_until: string | null;
      latest_verification_at: string | null;
      policy: { policy_mode: string; freshness_window_seconds: number; require_user_verification: boolean; updated_by: string };
      counts: {
        total_enrolled_credentials: number;
        revoked_credentials: number;
        successful_verifications: number;
        failed_verifications: number;
        expired_challenges: number;
      };
    }>(`/api/v1/identity-assurance/status?actor_id=${encodeURIComponent(actorId)}`),
  listCredentials: (actorId?: string) =>
    requestJson<
      {
        id: string;
        actor_id: string;
        device_id: string | null;
        credential_id: string;
        sign_count: number;
        metadata: Record<string, unknown>;
        credential_status: string;
        created_at: string;
        last_used_at: string | null;
      }[]
    >(`/api/v1/identity-assurance/credentials${actorId ? `?actor_id=${encodeURIComponent(actorId)}` : ""}`),
  registerOptions: (actor_id: string, rp_id: string) =>
    requestJson<{ challenge_id: string; expires_at: string; options: Record<string, unknown> }>(
      "/api/v1/identity-assurance/register/options",
      { method: "POST", body: JSON.stringify({ actor_id, rp_id }) }
    ),
  registerVerify: (body: { actor_id: string; challenge_id: string; credential: Record<string, unknown>; device_id?: string; rp_id: string; origin: string }) =>
    requestJson<{ status: string; id: string; credential_id: string }>(
      "/api/v1/identity-assurance/register/verify",
      { method: "POST", body: JSON.stringify(body) }
    ),
  authOptions: (actor_id: string, rp_id: string) =>
    requestJson<{ challenge_id: string; expires_at: string; options: Record<string, unknown> }>(
      "/api/v1/identity-assurance/authenticate/options",
      { method: "POST", body: JSON.stringify({ actor_id, rp_id }) }
    ),
  authVerify: (body: { actor_id: string; challenge_id: string; credential: Record<string, unknown>; rp_id: string; origin: string }) =>
    requestJson<{ verification_status: string; assurance_level: string; fresh_until: string | null }>(
      "/api/v1/identity-assurance/authenticate/verify",
      { method: "POST", body: JSON.stringify(body) }
    ),
  revokeCredential: (id: string, actor_id: string, reason: string) =>
    requestJson<{ id: string; status: string }>(
      `/api/v1/identity-assurance/credentials/${id}/revoke`,
      { method: "POST", body: JSON.stringify({ actor_id, reason }) }
    ),
  updateAssurancePolicy: (body: { operator_actor_id: string; policy_mode: string; freshness_window_seconds: number; require_user_verification: boolean }) =>
    requestJson<Record<string, unknown>>("/api/v1/identity-assurance/policy", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  verificationHistory: (actorId?: string) =>
    requestJson<
      {
        id: string;
        actor_id: string;
        verification_method: string;
        verification_status: string;
        assurance_level: string;
        reason: string;
        created_at: string;
      }[]
    >(`/api/v1/identity-assurance/history${actorId ? `?actor_id=${encodeURIComponent(actorId)}` : ""}`),
  logCameraDemoEvent: (actor_id: string, state: "STARTED" | "STOPPED" | "PERMISSION_DENIED") =>
    requestJson<{ status: string }>("/api/v1/identity-assurance/camera-demo/event", {
      method: "POST",
      body: JSON.stringify({ actor_id, state }),
    }),
  integrityStatus: () =>
    requestJson<{
      baseline_status: string;
      manifest_id: string | null;
      manifest_version: number | null;
      manifest_root_hash: string | null;
      pending_change_requests: number;
      latest_scan: {
        id: string;
        scan_scope: string;
        scan_status: string;
        files_scanned: number;
        files_verified: number;
        files_modified: number;
        files_missing: number;
        files_unexpected: number;
        files_unreadable: number;
        duration_ms: number;
        started_at: string;
      } | null;
    }>("/api/v1/integrity/status"),
  initIntegrityBaseline: (operator_actor_id: string) =>
    requestJson<{ manifest_id: string; manifest_version: number; root_hash: string; status: string }>(
      "/api/v1/integrity/baseline/initialize",
      { method: "POST", body: JSON.stringify({ operator_actor_id }) }
    ),
  verifyIntegrityBaseline: () =>
    requestJson<{ valid: boolean; status: string; reason?: string; entry_count?: number }>(
      "/api/v1/integrity/baseline/verify",
      { method: "POST" }
    ),
  runAppIntegrityScan: (actor_id = "secop") =>
    requestJson<{ scan_id: string; scan_status: string; files_scanned: number; files_verified: number; files_modified: number; files_missing: number; files_unexpected: number }>(
      "/api/v1/integrity/scans",
      { method: "POST", body: JSON.stringify({ actor_id }) }
    ),
  runUserSelectedIntegrityScan: (actor_id: string, entries: Record<string, unknown>[]) =>
    requestJson<{ scan_id: string; files_scanned: number; files_verified: number }>(
      "/api/v1/integrity/scans/user-selected",
      { method: "POST", body: JSON.stringify({ actor_id, entries }) }
    ),
  listIntegrityFindings: (findingType?: string) =>
    requestJson<
      {
        id: string;
        scan_id: string;
        relative_path: string;
        file_type: string;
        file_size: number;
        expected_hash: string | null;
        actual_hash: string | null;
        finding_type: string;
        severity: string;
        created_at: string;
      }[]
    >(`/api/v1/integrity/findings${findingType ? `?finding_type=${encodeURIComponent(findingType)}` : ""}`),
  listIntegrityScans: () =>
    requestJson<{ id: string; scan_scope: string; scan_status: string; files_scanned: number; files_verified: number; files_modified: number; files_missing: number; files_unexpected: number; duration_ms: number; started_at: string }[]>("/api/v1/integrity/scans"),
  listBaselineChangeRequests: () =>
    requestJson<{ id: string; requested_by: string; reason: string; status: string; created_at: string }[]>("/api/v1/integrity/baseline/change-requests"),
  requestBaselineUpdate: (body: { requested_by: string; reason: string; scan_id?: string }) =>
    requestJson<{ id: string; status: string }>("/api/v1/integrity/baseline/change-requests", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  resolveBaselineChange: (id: string, operator_actor_id: string, approve: boolean) =>
    requestJson<{ id: string; status: string }>(
      `/api/v1/integrity/baseline/change-requests/${id}/${approve ? "approve" : "reject"}`,
      { method: "POST", body: JSON.stringify({ operator_actor_id }) }
    ),
  securityIntegrityEvents: () =>
    requestJson<{ event_id: string; sequence: number; timestamp: string; actor_id: string; action: string; target: string; decision: string; reason: string }[]>("/api/v1/security-integrity/events"),

  // Advanced RBAC Auth & Protected Files
  registerUser: (body: { actor_id: string; display_label: string; email: string; password: string; confirm_password: string }) =>
    requestJson<{
      actor_id: string;
      display_label: string;
      email: string;
      role: string;
      status: string;
      session_id: string;
      session_token: string;
      device_id: string;
      peer_id: string;
      issued_at: string;
      expires_at: string;
      session_secret_bound: boolean;
    }>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  passkeyLoginOptions: (identifier: string, rp_id: string) =>
    requestJson<{ challenge_id: string; expires_at: string; options: Record<string, unknown> }>(
      "/api/v1/auth/passkey-login/options",
      { method: "POST", body: JSON.stringify({ identifier, rp_id }) }
    ),
  passkeyLoginVerify: (body: {
    identifier: string;
    challenge_id: string;
    credential: Record<string, unknown>;
    rp_id: string;
    origin: string;
  }) =>
    requestJson<{
      session_id: string;
      session_token: string;
      actor_id: string;
      display_label: string;
      email: string | null;
      role: string;
      device_id: string;
      peer_id: string;
      issued_at: string;
      expires_at: string;
      session_secret_bound: boolean;
      identity_verified: boolean;
      verification_method: string | null;
    }>("/api/v1/auth/passkey-login/verify", { method: "POST", body: JSON.stringify(body) }),
  roleLogin: (body: { identifier: string; password: string; expected_role: "User" | "Employee" | "Admin"; device_id?: string }) =>
    requestJson<{
      session_id: string;
      session_token: string;
      actor_id: string;
      display_label: string;
      email: string | null;
      role: string;
      device_id: string;
      peer_id: string;
      issued_at: string;
      expires_at: string;
      session_secret_bound: boolean;
      identity_verified: boolean;
      verification_method: string | null;
    }>("/api/v1/auth/role-login", { method: "POST", body: JSON.stringify(body) }),
  getSessionStatus: (sessionId?: string, sessionToken?: string) =>
    requestJson<{
      valid: boolean;
      session_id: string;
      actor_id: string;
      display_label: string;
      email: string | null;
      role: string;
      device_id: string;
      issued_at: string;
      expires_at: string;
      seconds_remaining: number;
      identity_verified: boolean;
      verification_method: string | null;
      session_secret_bound: boolean;
    }>("/api/v1/auth/session-status", {
      headers: authHeaders(sessionId, sessionToken),
    }),
  cameraCheckpoint: (sessionId: string, sessionToken: string, body: { consent_granted: boolean; action: "COMPLETED" | "CANCELLED" | "DENIED" }) =>
    requestJson<{ camera_preview_completed: boolean; face_recognition: string; actor_id: string }>("/api/v1/auth/camera-checkpoint", {
      method: "POST",
      headers: authHeaders(sessionId, sessionToken),
      body: JSON.stringify(body),
    }),
  listProtectedFiles: (sessionId: string, sessionToken: string) =>
    requestJson<{ id: string; name: string; classification: string; required_role: string; assigned_actor_id: string | null; created_at: string }[]>(
      "/api/v1/files",
      { headers: authHeaders(sessionId, sessionToken) }
    ),
  downloadProtectedFile: (sessionId: string, sessionToken: string, fileId: string) =>
    requestJson<{ id: string; name: string; classification: string; required_role: string; content_text: string }>(
      `/api/v1/files/${encodeURIComponent(fileId)}/download`,
      { headers: authHeaders(sessionId, sessionToken) }
    ),
  createProtectedFile: (
    sessionId: string,
    sessionToken: string,
    body: { name: string; classification: string; required_role: "User" | "Employee" | "Admin"; assigned_actor_id?: string | null; content_text: string }
  ) =>
    requestJson<{ id: string; name: string; required_role: string }>("/api/v1/files", {
      method: "POST",
      headers: authHeaders(sessionId, sessionToken),
      body: JSON.stringify(body),
    }),
  adminListUsers: (sessionId: string, sessionToken: string) =>
    requestJson<{ id: string; display_label: string; email: string | null; role: string; enabled: boolean; locked: boolean; created_at: string }[]>(
      "/api/v1/admin/users",
      { headers: authHeaders(sessionId, sessionToken) }
    ),
  adminCreateUser: (
    sessionId: string,
    sessionToken: string,
    body: { actor_id: string; display_label: string; email: string; role: "User" | "Employee" | "Admin"; password: string; device_id: string }
  ) =>
    requestJson<{ id: string; role: string; email: string }>("/api/v1/admin/users", {
      method: "POST",
      headers: authHeaders(sessionId, sessionToken),
      body: JSON.stringify(body),
    }),
  adminUpdateRole: (sessionId: string, sessionToken: string, actorId: string, role: "User" | "Employee" | "Admin") =>
    requestJson<{ id: string; role: string }>(`/api/v1/admin/users/${encodeURIComponent(actorId)}/role`, {
      method: "POST",
      headers: authHeaders(sessionId, sessionToken),
      body: JSON.stringify({ role }),
    }),
  adminUpdateStatus: (sessionId: string, sessionToken: string, actorId: string, enabled: boolean) =>
    requestJson<{ id: string; enabled: boolean }>(`/api/v1/admin/users/${encodeURIComponent(actorId)}/status`, {
      method: "POST",
      headers: authHeaders(sessionId, sessionToken),
      body: JSON.stringify({ enabled }),
    }),
  adminAuditEvents: (sessionId: string, sessionToken: string) =>
    requestJson<{ seq: number; actor_id: string; action: string; target: string; decision: string; reason: string; timestamp: string }[]>(
      "/api/v1/admin/audit",
      { headers: authHeaders(sessionId, sessionToken) }
    ),
};
