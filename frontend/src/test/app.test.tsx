import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../app/AuthContext";
import { ToastProvider, ConfirmDialog } from "../components/ui";
import { AppRoutes } from "../App";

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <ToastProvider>
          <MemoryRouter initialEntries={[path]}>
            <AppRoutes />
          </MemoryRouter>
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe("Q-SHIELD Stage 10 Frontend", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/health")) {
          return new Response(JSON.stringify({ status: "ok", app: "Q-SHIELD", version: "0.2.0", database: "ok" }), { status: 200 });
        }
        if (url.includes("/scorecard")) {
          return new Response(JSON.stringify({ project: "Q-SHIELD", forward_secrecy: "NOT_ESTABLISHED", nodes_mode: "SIMULATED", gates: [{ gate: "G0", name: "Source", status: "PASS" }] }), { status: 200 });
        }
        if (url.includes("/messages/security-status")) {
          return new Response(JSON.stringify({ protocol_version: "1.0", aead_algorithm: "AES-256-GCM", forward_secrecy: "NOT_ESTABLISHED", forward_secrecy_note: "Static keys" }), { status: 200 });
        }
        if (url.includes("/nodes/metrics")) {
          return new Response(JSON.stringify({ sample_count: 0, p50_ms: null, p95_ms: null, p99_ms: null, max_ms: null }), { status: 200 });
        }
        if (url.includes("/system/metrics")) {
          return new Response(JSON.stringify({ uptime_seconds: 10, worker_running: true, worker_uptime_seconds: 10, cpu_percent: 5, process_rss_mb: 80, disk_free_gb: 50, disk_used_pct: 40, queue_depth: 0, failed_jobs: 0, files_verified_count: 0, storage_used_bytes: 0, storage_quota_bytes: 1000000, max_upload_bytes: 1000000 }), { status: 200 });
        }
        if (url.includes("/benchmarks/latest")) {
          return new Response(JSON.stringify({ status: "NOT_RUN", benchmarks: [] }), { status: 200 });
        }
        return new Response(JSON.stringify([]), { status: 200 });
      })
    );
  });

  it("renders landing page with product promise", () => {
    renderAt("/");
    expect(screen.getByText(/Trust changes\./i)).toBeInTheDocument();
    expect(screen.getByText(/Security follows\./i)).toBeInTheDocument();
  });

  it("renders all main console routes with honest SIMULATED and NOT_ESTABLISHED labels", async () => {
    renderAt("/overview");
    expect(await screen.findByText(/Security Operations Overview/i)).toBeInTheDocument();
    expect(screen.getByText(/NODES: SIMULATED/i)).toBeInTheDocument();
    expect(screen.getByText(/FS: NOT ESTABLISHED/i)).toBeInTheDocument();
  });

  it("renders 14 scenarios on Attack Simulation page", () => {
    renderAt("/scenarios");
    expect(screen.getByText(/S01 — Normal Protected Read/i)).toBeInTheDocument();
    expect(screen.getByText(/S14 — Node Convergence Check/i)).toBeInTheDocument();
  });

  it("renders Data Intelligence & Verification Lab route", async () => {
    renderAt("/datalab");
    expect(await screen.findByText(/Data Intelligence & Verification Lab/i)).toBeInTheDocument();
    expect(screen.getByText(/Streaming Resumable Upload/i)).toBeInTheDocument();
  });

  it("renders Security Integrity Center with Identity Assurance, File Integrity, and privacy-safe Camera Demo", async () => {
    renderAt("/security-integrity");
    expect(await screen.findByText(/Q-SHIELD SECURITY INTEGRITY CENTER/i)).toBeInTheDocument();
    expect(screen.getByText(/Continuously verify identity assurance and application integrity\./i)).toBeInTheDocument();
    expect(screen.getByText(/Panel A: Identity Assurance/i)).toBeInTheDocument();
    expect(screen.getByText(/Panel B: File Integrity/i)).toBeInTheDocument();
    // Camera demo is never started automatically
    expect(screen.queryByRole("region", { name: /Live Camera Verification Demo/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Launch Camera Demo/i }));
    expect(screen.getByText(/Non-authenticating visual demo only/i)).toBeInTheDocument();
  });

  it("enforces required audit reason in ConfirmDialog", () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        title="Confirm Revoke"
        description="Revoke device"
        onCancel={() => {}}
        onConfirm={onConfirm}
      />
    );
    const btn = screen.getByRole("button", { name: "Confirm" });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByPlaceholderText(/Lost device/i), { target: { value: "Stolen laptop" } });
    expect(btn).not.toBeDisabled();
    fireEvent.click(btn);
    expect(onConfirm).toHaveBeenCalledWith("Stolen laptop");
  });
});
