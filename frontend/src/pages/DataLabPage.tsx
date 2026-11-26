import React, { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  Download,
  FileSearch,
  HardDrive,
  Pause,
  Play,
  RefreshCw,
  ShieldAlert,
  UploadCloud,
  XCircle,
} from "lucide-react";
import { api } from "../services/api";
import { useTheme } from "../app/ThemeContext";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";
import CyberCommand3D, { CyberEdge, CyberNodeEntity } from "../components/CyberCommand3D";

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  return "";
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function DataLabPage() {
  const { isDark } = useTheme();
  const { push } = useToast();
  const qc = useQueryClient();

  const files = useQuery({ queryKey: ["datalab-files"], queryFn: api.listVerifiedFiles, refetchInterval: 4000 });
  const jobs = useQuery({ queryKey: ["datalab-jobs"], queryFn: api.listJobs, refetchInterval: 3000 });
  const sys = useQuery({ queryKey: ["system-metrics"], queryFn: api.systemMetrics, refetchInterval: 5000 });

  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [selectedStageIdx, setSelectedStageIdx] = useState<number>(0);
  const [viewMode, setViewMode] = useState<"pipeline" | "3d" | "table" | "timeline">("pipeline");
  const [refHashInput, setRefHashInput] = useState("");
  const [verifyRefInput, setVerifyRefInput] = useState("");
  const [dragActive, setDragActive] = useState(false);

  // Active upload state
  const [uploadState, setUploadState] = useState<{
    uploadId: string | null;
    filename: string;
    totalChunks: number;
    completedChunks: number;
    speedMbps: number;
    paused: boolean;
    active: boolean;
  }>({ uploadId: null, filename: "", totalChunks: 0, completedChunks: 0, speedMbps: 0, paused: false, active: false });
  const pausedRef = useRef(false);
  const cancelledRef = useRef(false);

  const fileList = files.data ?? [];
  const activeFileId = selectedFileId ?? fileList[0]?.id ?? null;

  const detail = useQuery({
    queryKey: ["datalab-file-detail", activeFileId],
    queryFn: () => api.getVerifiedFileDetail(activeFileId!),
    enabled: Boolean(activeFileId),
    refetchInterval: 3000,
  });

  const verifyRefMut = useMutation({
    mutationFn: () => api.verifyFileReference(activeFileId!, verifyRefInput),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["datalab-files"] });
      qc.invalidateQueries({ queryKey: ["datalab-file-detail", activeFileId] });
      push(`Reference check: ${res.reference_status}`, res.reference_status === "MATCH" ? "success" : "error");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const retryJobMut = useMutation({
    mutationFn: api.retryJob,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["datalab-jobs"] });
      push("Job re-queued", "info");
    },
  });

  const startChunkedUpload = async (file: File) => {
    const chunkSize = 1024 * 1024; // 1 MiB streaming slices
    pausedRef.current = false;
    cancelledRef.current = false;

    try {
      const init = await api.initDataUpload({
        filename: file.name,
        declared_size_bytes: Math.max(1, file.size),
        chunk_size_bytes: chunkSize,
        reference_sha256: refHashInput.trim() || undefined,
      });

      setUploadState({
        uploadId: init.upload_id,
        filename: file.name,
        totalChunks: init.total_chunks,
        completedChunks: 0,
        speedMbps: 0,
        paused: false,
        active: true,
      });

      const tStart = performance.now();
      let sentBytes = 0;

      for (let i = 0; i < init.total_chunks; i++) {
        while (pausedRef.current && !cancelledRef.current) {
          await new Promise((r) => setTimeout(r, 250));
        }
        if (cancelledRef.current) {
          await api.cancelDataUpload(init.upload_id);
          setUploadState((s) => ({ ...s, active: false }));
          push("Upload cancelled", "info");
          return;
        }

        const start = i * chunkSize;
        const end = Math.min(file.size, start + chunkSize);
        const slice = file.slice(start, end);
        const buf = await slice.arrayBuffer();
        const cHash = await sha256Hex(buf);

        await api.uploadDataChunk(init.upload_id, i, slice, cHash || undefined);
        sentBytes += slice.size;
        const elapsedSec = Math.max(0.05, (performance.now() - tStart) / 1000);
        const mbps = Number(((sentBytes / (1024 * 1024)) / elapsedSec).toFixed(2));

        setUploadState((s) => ({
          ...s,
          completedChunks: i + 1,
          speedMbps: mbps,
        }));
      }

      const fin = await api.finalizeDataUpload(init.upload_id, false);
      setUploadState((s) => ({ ...s, active: false }));
      setSelectedFileId(fin.file_id);
      qc.invalidateQueries({ queryKey: ["datalab-files"] });
      qc.invalidateQueries({ queryKey: ["datalab-jobs"] });
      push(`Queued ${file.name} for 14-stage verification`, "success");
    } catch (err) {
      setUploadState((s) => ({ ...s, active: false }));
      push((err as Error).message, "error");
    }
  };

  const d = detail.data;
  const stages = d?.stages ?? [];
  const activeStage = stages[selectedStageIdx] ?? stages[0];

  // Build 3D Data Verification Topology from current file + stages
  const labEntities: CyberNodeEntity[] = [
    {
      id: "core",
      label: d ? d.filename : "Verification Engine",
      kind: "core",
      trustState: d?.verification_status ?? "READY",
      meta: d ? `SHA256: ${d.sha256.slice(0, 16)}... | ${fmtBytes(d.size_bytes)}` : "Streaming Worker Ready",
      route: "/datalab",
    },
    ...stages.slice(0, 8).map((s) => ({
      id: `st-${s.stage_order}`,
      label: s.stage_name,
      kind: "node" as const,
      trustState: s.status === "Failed" ? "CRITICAL" : s.status === "Warning" ? "SUSPENDED" : "HEALTHY",
      meta: `${s.algorithm} | ${s.duration_ms}ms | ${s.summary}`,
      route: "/datalab",
    })),
  ];
  const labEdges: CyberEdge[] = stages.slice(0, 8).map((s) => ({
    from: "core",
    to: `st-${s.stage_order}`,
    kind: s.status === "Failed" ? "alert" : "trust",
  }));

  const jobList = jobs.data ?? [];
  const activeJobs = jobList.filter((j) => j.status === "QUEUED" || j.status === "RUNNING").length;
  const passedCount = fileList.filter((f) => f.verification_status === "PASSED").length;
  const riskCount = fileList.filter((f) => f.risk_level === "HIGH" || f.risk_level === "CRITICAL").length;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">
            Data Intelligence &amp; Verification Lab
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Resumable chunked transfers &middot; Streaming SHA-256 &amp; Merkle trees &middot; Welford dataset profiling &middot; 24/7 Worker
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge
            label={sys.data?.worker_running ? `WORKER: ONLINE (${sys.data.worker_uptime_seconds}s)` : "WORKER: STANDBY"}
            tone={sys.data?.worker_running ? "success" : "warning"}
          />
          <StatusBadge label="STREAMING RAM: CONSTANT" tone="info" />
        </div>
      </div>

      {/* Top KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 text-xs">
        <div className="p-3 rounded-lg bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
          <div className="text-slate-500">Files Analyzed</div>
          <div className="font-mono text-xl font-bold text-slate-900 dark:text-white mt-0.5">{fileList.length}</div>
        </div>
        <div className="p-3 rounded-lg bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
          <div className="text-slate-500">Storage Used</div>
          <div className="font-mono text-xl font-bold text-cyan-600 dark:text-cyan-400 mt-0.5">
            {fmtBytes(sys.data?.storage_used_bytes ?? 0)}
          </div>
        </div>
        <div className="p-3 rounded-lg bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
          <div className="text-slate-500">Active Jobs</div>
          <div className="font-mono text-xl font-bold text-amber-500 mt-0.5">{activeJobs}</div>
        </div>
        <div className="p-3 rounded-lg bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
          <div className="text-slate-500">Passed Integrity</div>
          <div className="font-mono text-xl font-bold text-emerald-600 dark:text-emerald-400 mt-0.5">{passedCount}</div>
        </div>
        <div className="p-3 rounded-lg bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
          <div className="text-slate-500">High/Crit Findings</div>
          <div className="font-mono text-xl font-bold text-rose-500 mt-0.5">{riskCount}</div>
        </div>
        <div className="p-3 rounded-lg bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
          <div className="text-slate-500">Process RSS</div>
          <div className="font-mono text-xl font-bold text-violet-600 dark:text-violet-400 mt-0.5">
            {sys.data?.process_rss_mb ?? 0} MB
          </div>
        </div>
      </div>

      {/* Resumable Chunked Upload Zone */}
      <Card
        title="Streaming Resumable Upload (Multi-GB Capable)"
        subtitle="Slices files in 1 MiB chunks with WebCrypto SHA-256 verification; zero full-file browser RAM buffering"
      >
        <div className="grid lg:grid-cols-3 gap-4 items-center">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragActive(false);
              const f = e.dataTransfer.files?.[0];
              if (f) void startChunkedUpload(f);
            }}
            className={`lg:col-span-2 border-2 border-dashed rounded-lg p-6 text-center transition-colors ${
              dragActive
                ? "border-emerald-500 bg-emerald-50/60 dark:bg-emerald-500/10"
                : "border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#131a21]"
            }`}
          >
            <UploadCloud className="w-8 h-8 mx-auto text-emerald-600 dark:text-emerald-400 mb-2" />
            <div className="text-xs font-medium text-slate-800 dark:text-slate-200">
              Drag &amp; drop CSV, JSON/JSONL, LOG, ZIP/TAR, PDF, PEM Certificate, or Binary
            </div>
            <div className="mt-3">
              <input
                type="file"
                aria-label="Select file to verify"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void startChunkedUpload(f);
                }}
                className="text-xs text-slate-600 dark:text-slate-300"
              />
            </div>
          </div>

          <div className="space-y-2.5 text-xs">
            <label className="block font-medium text-slate-700 dark:text-slate-300">
              Optional Trusted Reference SHA-256
            </label>
            <input
              type="text"
              value={refHashInput}
              onChange={(e) => setRefHashInput(e.target.value)}
              placeholder="64-hex SHA-256 digest..."
              className="w-full rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
            />
            {uploadState.active && (
              <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex justify-between font-mono text-[11px]">
                  <span className="truncate">{uploadState.filename}</span>
                  <span>
                    {uploadState.completedChunks}/{uploadState.totalChunks} ({uploadState.speedMbps} MB/s)
                  </span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-300 dark:bg-slate-700 overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 transition-all"
                    style={{
                      width: `${Math.round((uploadState.completedChunks / Math.max(1, uploadState.totalChunks)) * 100)}%`,
                    }}
                  />
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => {
                      pausedRef.current = !pausedRef.current;
                      setUploadState((s) => ({ ...s, paused: pausedRef.current }));
                      if (uploadState.uploadId) {
                        void (pausedRef.current
                          ? api.pauseDataUpload(uploadState.uploadId)
                          : api.resumeDataUpload(uploadState.uploadId));
                      }
                    }}
                  >
                    {uploadState.paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
                    {uploadState.paused ? "Resume" : "Pause"}
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() => {
                      cancelledRef.current = true;
                    }}
                  >
                    <XCircle className="w-3 h-3" /> Cancel
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* Interactive Verification Pipeline + View Switcher */}
      <Card
        title={d ? `Verification Pipeline: ${d.filename}` : "Verification Pipeline"}
        subtitle="Click any stage to inspect algorithm, duration, and findings"
        action={
          <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
            {(["pipeline", "3d", "table", "timeline"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setViewMode(m)}
                className={`px-2.5 py-1 rounded border ${
                  viewMode === m
                    ? "bg-emerald-600 text-white border-emerald-600"
                    : "bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700"
                }`}
              >
                {m.toUpperCase()}
              </button>
            ))}
          </div>
        }
      >
        {!d ? (
          <div className="text-xs text-slate-500 py-8 text-center">
            Upload a file above to launch the 14-stage streaming verification pipeline.
          </div>
        ) : viewMode === "3d" ? (
          <CyberCommand3D entities={labEntities} edges={labEdges} isDark={isDark} />
        ) : viewMode === "table" ? (
          <DataTable
            rows={stages as unknown as Record<string, unknown>[]}
            columns={[
              { key: "stage_order", header: "#" },
              { key: "stage_name", header: "Stage" },
              { key: "algorithm", header: "Algorithm" },
              {
                key: "status",
                header: "Status",
                render: (r) => (
                  <StatusBadge
                    label={String(r.status)}
                    tone={r.status === "Passed" ? "success" : r.status === "Failed" ? "danger" : "warning"}
                  />
                ),
              },
              { key: "duration_ms", header: "ms" },
              { key: "summary", header: "Summary" },
            ]}
          />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
              {stages.map((s, idx) => (
                <button
                  key={s.stage_order}
                  type="button"
                  onClick={() => setSelectedStageIdx(idx)}
                  className={`p-2 rounded border text-left transition-all ${
                    selectedStageIdx === idx
                      ? "border-emerald-500 bg-emerald-50/70 dark:bg-emerald-500/15"
                      : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#131a21]"
                  }`}
                >
                  <div className="text-[10px] font-mono text-slate-500">#{s.stage_order}</div>
                  <div className="text-[11px] font-semibold text-slate-900 dark:text-white truncate">{s.stage_name}</div>
                  <div className="mt-1">
                    <StatusBadge
                      label={s.status}
                      tone={s.status === "Passed" ? "success" : s.status === "Failed" ? "danger" : s.status === "Warning" ? "warning" : "neutral"}
                    />
                  </div>
                </button>
              ))}
            </div>

            {activeStage && (
              <div className="p-3.5 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-slate-800 text-xs space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-bold text-slate-900 dark:text-white">
                    Stage {activeStage.stage_order}: {activeStage.stage_name}
                  </span>
                  <span className="font-mono text-emerald-600 dark:text-emerald-400">
                    {activeStage.algorithm} &middot; {activeStage.duration_ms} ms
                  </span>
                </div>
                <div className="text-slate-600 dark:text-slate-300 font-mono">{activeStage.summary}</div>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* File Explorer + Selected File Detail */}
      <div className="grid lg:grid-cols-12 gap-4">
        <Card title="Verified Files Explorer" className="lg:col-span-7">
          <DataTable
            rows={fileList as unknown as Record<string, unknown>[]}
            columns={[
              {
                key: "filename",
                header: "File",
                render: (r) => (
                  <button
                    type="button"
                    onClick={() => setSelectedFileId(String(r.id))}
                    className="font-mono text-emerald-600 dark:text-emerald-400 hover:underline text-left"
                  >
                    {String(r.filename)}
                  </button>
                ),
              },
              { key: "detected_category", header: "Type" },
              { key: "size_bytes", header: "Size", render: (r) => fmtBytes(Number(r.size_bytes)) },
              {
                key: "verification_status",
                header: "Status",
                render: (r) => (
                  <StatusBadge
                    label={String(r.verification_status)}
                    tone={r.verification_status === "PASSED" ? "success" : r.verification_status === "FAILED" ? "danger" : "warning"}
                  />
                ),
              },
              {
                key: "risk_level",
                header: "Risk",
                render: (r) => (
                  <StatusBadge
                    label={String(r.risk_level)}
                    tone={r.risk_level === "CRITICAL" || r.risk_level === "HIGH" ? "danger" : "info"}
                  />
                ),
              },
            ]}
          />
        </Card>

        <Card title="Cryptographic & Dataset Evidence" className="lg:col-span-5">
          {!d ? (
            <div className="text-xs text-slate-500 py-6 text-center">Select a file to inspect evidence.</div>
          ) : (
            <div className="space-y-3 text-xs">
              <div className="space-y-1 font-mono bg-slate-50 dark:bg-[#131a21] p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="truncate"><span className="text-slate-500">MIME:</span> {d.detected_mime}</div>
                <div className="truncate" title={d.sha256}><span className="text-slate-500">SHA256:</span> {d.sha256}</div>
                <div className="truncate" title={d.merkle_root ?? ""}><span className="text-slate-500">Merkle Root:</span> {d.merkle_root ?? "N/A"} ({d.merkle_leaf_count} leaves)</div>
                <div><span className="text-slate-500">Ref Integrity:</span> {d.reference_status}</div>
                <div><span className="text-slate-500">Crypto Readiness:</span> {d.crypto_readiness}</div>
                <div><span className="text-slate-500">Signature:</span> {d.signature_status}</div>
              </div>

              <div className="flex gap-2">
                <input
                  type="text"
                  value={verifyRefInput}
                  onChange={(e) => setVerifyRefInput(e.target.value)}
                  placeholder="Compare reference SHA-256..."
                  className="flex-1 rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2.5 py-1.5 text-xs font-mono"
                />
                <Button size="sm" onClick={() => verifyRefMut.mutate()} disabled={!verifyRefInput}>
                  <FileSearch className="w-3.5 h-3.5" /> Verify
                </Button>
              </div>

              {d.dataset_profile && (
                <div className="p-2.5 rounded bg-emerald-50/70 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30 font-mono text-[11px]">
                  Dataset Profile: {JSON.stringify(d.dataset_profile).slice(0, 260)}...
                </div>
              )}

              {d.findings.length > 0 && (
                <div className="space-y-1">
                  {d.findings.map((f, i) => (
                    <div key={i} className="flex items-start gap-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                      <ShieldAlert className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      <span>[{f.severity}] {f.code}: {f.message}</span>
                    </div>
                  ))}
                </div>
              )}

              {d.receipt && (
                <a
                  href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(d.receipt, null, 2))}`}
                  download={`${d.filename}.receipt.json`}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-600 dark:text-emerald-400 hover:underline"
                >
                  <Download className="w-3.5 h-3.5" /> Download Verification Receipt JSON
                </a>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* 24/7 Background Job Queue */}
      <Card title="24/7 Durable Background Worker Queue" subtitle="SQLite-persisted jobs survive disconnects & restarts">
        <DataTable
          rows={jobList as unknown as Record<string, unknown>[]}
          columns={[
            { key: "job_type", header: "Job Type" },
            { key: "target_id", header: "Target ID" },
            {
              key: "status",
              header: "Status",
              render: (r) => (
                <StatusBadge
                  label={String(r.status)}
                  tone={r.status === "COMPLETED" ? "success" : r.status === "FAILED" ? "danger" : "info"}
                />
              ),
            },
            { key: "progress_pct", header: "Progress", render: (r) => `${r.progress_pct}%` },
            { key: "attempts", header: "Attempts" },
            {
              key: "actions",
              header: "Actions",
              render: (r) => (
                <Button size="sm" variant="secondary" onClick={() => retryJobMut.mutate(String(r.id))}>
                  <RefreshCw className="w-3 h-3" /> Retry
                </Button>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
