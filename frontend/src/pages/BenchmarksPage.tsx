import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { useTheme } from "../app/ThemeContext";
import { Card, StatusBadge } from "../components/ui";

export function BenchmarksPage() {
  const { isDark } = useTheme();
  const [category, setCategory] = useState<"all" | "crypto" | "control" | "api">("all");
  const [metric, setMetric] = useState<"latency" | "throughput">("latency");
  const nodeMetrics = useQuery({ queryKey: ["node-metrics"], queryFn: api.nodeMetrics });
  const latest = useQuery({ queryKey: ["benchmarks-latest"], queryFn: api.benchmarksLatest });

  const benchList = latest.data?.benchmarks ?? [];
  const env = latest.data?.environment;
  const hasBench = latest.data?.status === "PASS" && benchList.length > 0;

  const filteredBench = benchList.filter((b) => {
    if (category === "crypto") return b.operation.includes("ml_kem") || b.operation.includes("hkdf") || b.operation.includes("aes_256");
    if (category === "control") return b.operation.includes("policy") || b.operation.includes("audit") || b.operation.includes("backup") || b.operation.includes("node") || b.operation.includes("rotation") || b.operation.includes("crash");
    if (category === "api") return b.operation.includes("api_") || b.operation.includes("messaging") || b.operation.includes("detector") || b.operation.includes("adapter");
    return true;
  });

  const chartOps = filteredBench.slice(0, 10).map((b) => ({
    op: b.operation.replace("node_revocation_convergence_", "nodes_").replace("ml_kem_768_", "kem_").replace("aes_256_gcm_", "aes_"),
    p50: b.p50_ms,
    p95: b.p95_ms,
    throughput: b.throughput_ops_sec,
  }));

  const tooltipStyle = {
    backgroundColor: isDark ? "#0b0f13" : "#ffffff",
    borderColor: isDark ? "#1c242d" : "#e2e8f0",
    color: isDark ? "#f8fafc" : "#0f172a",
    fontSize: 11,
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Benchmark Lab</h1>
          <p className="text-xs text-slate-500">
            Reproducible <code className="text-emerald-600">time.perf_counter_ns()</code> measurements &mdash; raw samples in{" "}
            <code className="text-slate-600">reports/benchmarks/latest.json</code>
          </p>
        </div>
        <StatusBadge
          label={latest.isLoading ? "LOADING..." : hasBench ? `STAGE 11: PASS (${benchList.length} OPS)` : "STAGE 11 SUITE: NOT RUN"}
          tone={hasBench ? "success" : "neutral"}
        />
      </div>

      {env && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <div className="p-3 rounded bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
            <div className="text-slate-500">Operations</div>
            <div className="font-mono text-lg text-slate-900 dark:text-slate-100">{benchList.length}</div>
          </div>
          <div className="p-3 rounded bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
            <div className="text-slate-500">Suite Duration</div>
            <div className="font-mono text-lg text-emerald-600">{env.suite_duration_s} s</div>
          </div>
          <div className="p-3 rounded bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
            <div className="text-slate-500">CPU (user / sys)</div>
            <div className="font-mono text-lg text-cyan-400">
              {env.cpu_user_s ?? "—"}s / {env.cpu_system_s ?? "—"}s
            </div>
          </div>
          <div className="p-3 rounded bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
            <div className="text-slate-500">Peak RSS RAM</div>
            <div className="font-mono text-lg text-violet-400">{env.peak_rss_mb} MB</div>
          </div>
          <div className="p-3 rounded bg-white dark:bg-[#0f1419] border border-slate-200 dark:border-[#1c242d]">
            <div className="text-slate-500">Seed / Python</div>
            <div className="font-mono text-sm text-amber-400 mt-1">
              seed={env.seed} &middot; py {env.python_version}
            </div>
          </div>
        </div>
      )}

      {chartOps.length > 0 && (
        <Card
          title={metric === "latency" ? "Interactive Latency Profile (p50 vs p95 ms)" : "Interactive Throughput Profile (ops/sec)"}
          subtitle="Filter by subsystem or switch between latency & throughput"
          action={
            <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
              {(["all", "crypto", "control", "api"] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setCategory(cat)}
                  className={`px-2 py-0.5 rounded border ${
                    category === cat
                      ? "bg-emerald-600 text-white border-emerald-600"
                      : "bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700"
                  }`}
                >
                  {cat.toUpperCase()}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setMetric((m) => (m === "latency" ? "throughput" : "latency"))}
                className="px-2 py-0.5 rounded border border-cyan-500/40 bg-cyan-50 dark:bg-cyan-500/15 text-cyan-700 dark:text-cyan-300"
              >
                Mode: {metric}
              </button>
            </div>
          }
        >
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartOps} margin={{ top: 8, right: 16, left: 0, bottom: 28 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#1c242d" : "#e2e8f0"} vertical={false} />
                <XAxis dataKey="op" stroke="#64748b" fontSize={10} angle={-18} textAnchor="end" interval={0} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                {metric === "latency" ? (
                  <>
                    <Bar dataKey="p50" name="p50 (ms)" fill="#10b981" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="p95" name="p95 (ms)" fill="#06b6d4" radius={[3, 3, 0, 0]} />
                  </>
                ) : (
                  <Bar dataKey="throughput" name="Throughput (ops/s)" fill="#8b5cf6" radius={[3, 3, 0, 0]} />
                )}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}

      <Card title="Live Simulated Node Convergence Measurements" subtitle="Actual recorded NodeAcknowledgement delays in SQLite">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">Samples</div>
            <div className="font-mono text-lg text-slate-900 dark:text-slate-100">{nodeMetrics.data?.sample_count ?? 0}</div>
          </div>
          <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">p50</div>
            <div className="font-mono text-lg text-emerald-600">{nodeMetrics.data?.p50_ms ?? "—"} ms</div>
          </div>
          <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">p95</div>
            <div className="font-mono text-lg text-cyan-400">{nodeMetrics.data?.p95_ms ?? "—"} ms</div>
          </div>
          <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">p99</div>
            <div className="font-mono text-lg text-violet-400">{nodeMetrics.data?.p99_ms ?? "—"} ms</div>
          </div>
          <div className="p-3 rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933]">
            <div className="text-slate-500">Max</div>
            <div className="font-mono text-lg text-amber-400">{nodeMetrics.data?.max_ms ?? "—"} ms</div>
          </div>
        </div>
      </Card>

      {hasBench && (
        <Card title="Full 35-Operation Benchmark Matrix" subtitle="ML-DSA: NOT IMPLEMENTED · Simulated nodes labeled explicitly">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 font-mono">
                  <th className="py-2 pr-3">Operation</th>
                  <th className="py-2 pr-3 text-right">Samples</th>
                  <th className="py-2 pr-3 text-right">Errors</th>
                  <th className="py-2 pr-3 text-right">p50 (ms)</th>
                  <th className="py-2 pr-3 text-right">p95 (ms)</th>
                  <th className="py-2 pr-3 text-right">p99 (ms)</th>
                  <th className="py-2 text-right">Throughput (ops/s)</th>
                </tr>
              </thead>
              <tbody>
                {benchList.map((b) => (
                  <tr key={b.operation} className="border-b border-slate-200 hover:bg-slate-50">
                    <td className="py-1.5 pr-3 font-mono text-slate-800 dark:text-slate-200">{b.operation}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-slate-500">{b.samples}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-slate-500">{b.errors}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-emerald-600">{b.p50_ms}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-cyan-400">{b.p95_ms}</td>
                    <td className="py-1.5 pr-3 text-right font-mono text-violet-400">{b.p99_ms}</td>
                    <td className="py-1.5 text-right font-mono text-slate-900 dark:text-slate-100">{b.throughput_ops_sec}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
