import { useMemo, useState } from "react";
import { Maximize2, Minimize2, ZoomIn, ZoomOut } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export interface TopoNode {
  id: string;
  label: string;
  sublabel?: string;
  layer: number; // 0..4 left-to-right column
  status: "OK" | "WARN" | "ALERT";
  metric?: string;
}

export interface TopoEdge {
  from: string;
  to: string;
  label?: string;
  status: "OK" | "WARN" | "ALERT";
}

export interface HistoryPoint {
  label: string;
  primary: number;
  secondary?: number;
}

export interface SparkStat {
  label: string;
  value: string;
  tone: "emerald" | "cyan" | "amber" | "rose";
  series: number[];
}

export function TelemetrySparkGrid({ stats }: { stats: SparkStat[] }) {
  const toneClasses: Record<SparkStat["tone"], { bg: string; stroke: string; text: string }> = {
    emerald: {
      bg: "bg-emerald-500/10 border-emerald-500/30 dark:bg-emerald-950/40",
      stroke: "#10b981",
      text: "text-emerald-700 dark:text-emerald-300",
    },
    cyan: {
      bg: "bg-cyan-500/10 border-cyan-500/30 dark:bg-cyan-950/40",
      stroke: "#06b6d4",
      text: "text-cyan-700 dark:text-cyan-300",
    },
    amber: {
      bg: "bg-amber-500/10 border-amber-500/30 dark:bg-amber-950/40",
      stroke: "#f59e0b",
      text: "text-amber-700 dark:text-amber-300",
    },
    rose: {
      bg: "bg-rose-500/10 border-rose-500/30 dark:bg-rose-950/40",
      stroke: "#f43f5e",
      text: "text-rose-700 dark:text-rose-300",
    },
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2.5">
      {stats.map((s) => {
        const cfg = toneClasses[s.tone];
        const chartData = s.series.map((v, i) => ({ idx: i, v }));
        return (
          <div
            key={s.label}
            className={`rounded-lg border p-2.5 flex flex-col justify-between min-h-[78px] ${cfg.bg}`}
          >
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-600 dark:text-slate-300 truncate">
              {s.label}
            </div>
            <div className={`text-lg font-bold font-mono leading-tight ${cfg.text}`}>{s.value}</div>
            <div className="h-6 w-full mt-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
                  <Area
                    type="monotone"
                    dataKey="v"
                    stroke={cfg.stroke}
                    fill={cfg.stroke}
                    fillOpacity={0.22}
                    strokeWidth={1.5}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function InteractiveTopologyGraph({
  title,
  summaryStrip,
  nodes,
  edges,
  history,
  historyLabel = "Event & Latency History",
}: {
  title: string;
  summaryStrip: { label: string; value: string }[];
  nodes: TopoNode[];
  edges: TopoEdge[];
  history: HistoryPoint[];
  historyLabel?: string;
}) {
  const [zoom, setZoom] = useState(1);
  const [expanded, setExpanded] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const layout = useMemo(() => {
    const layers = new Map<number, TopoNode[]>();
    let maxLayer = 0;
    for (const n of nodes) {
      maxLayer = Math.max(maxLayer, n.layer);
      const arr = layers.get(n.layer) ?? [];
      arr.push(n);
      layers.set(n.layer, arr);
    }
    const width = 920;
    const height = 280;
    const padX = 85;
    const usableW = width - padX * 2;
    const positions = new Map<string, { x: number; y: number }>();

    for (const [layerIdx, group] of layers.entries()) {
      const x = maxLayer === 0 ? width / 2 : padX + (layerIdx / maxLayer) * usableW;
      const stepY = height / (group.length + 1);
      group.forEach((n, idx) => {
        positions.set(n.id, { x, y: stepY * (idx + 1) });
      });
    }
    return { width, height, positions };
  }, [nodes]);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) ?? null;

  const nodeColor = (status: TopoNode["status"]) => {
    if (status === "ALERT") return { ring: "#f43f5e", fill: "#4c0519", glow: "rgba(244,63,94,0.35)" };
    if (status === "WARN") return { ring: "#f59e0b", fill: "#451a03", glow: "rgba(245,158,11,0.35)" };
    return { ring: "#2dd4bf", fill: "#042f2e", glow: "rgba(45,212,191,0.35)" };
  };

  return (
    <div className="rounded-xl border border-slate-200 dark:border-[#1e2732] bg-slate-950 text-slate-100 overflow-hidden shadow-sm">
      {/* Header + Summary Strip */}
      <div className="px-4 py-2.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-[#0c1117]">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xs font-semibold tracking-wide text-slate-100">{title}</span>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono">
          {summaryStrip.map((item) => (
            <div key={item.label} className="flex items-center gap-1.5">
              <span className="text-slate-400">{item.label}:</span>
              <span className="text-emerald-300 font-semibold">{item.value}</span>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(1.5, Number((z + 0.15).toFixed(2))))}
            className="p-1 rounded hover:bg-slate-800 text-slate-300"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.7, Number((z - 0.15).toFixed(2))))}
            className="p-1 rounded hover:bg-slate-800 text-slate-300"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            className="p-1 rounded hover:bg-slate-800 text-slate-300"
            title="Toggle Height"
          >
            {expanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Directed Topology Canvas */}
      <div className={`relative overflow-auto bg-[#0a0e14] ${expanded ? "h-[360px]" : "h-[270px]"}`}>
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="w-full h-full min-w-[680px]"
          style={{ transform: `scale(${zoom})`, transformOrigin: "center center", transition: "transform 150ms ease" }}
        >
          <defs>
            <marker id="arrow-ok" markerWidth="7" markerHeight="7" refX="18" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#10b981" />
            </marker>
            <marker id="arrow-warn" markerWidth="7" markerHeight="7" refX="18" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#f59e0b" />
            </marker>
            <marker id="arrow-alert" markerWidth="7" markerHeight="7" refX="18" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#f43f5e" />
            </marker>
          </defs>

          {/* Subtle grid */}
          <g stroke="#141c26" strokeWidth="1">
            {Array.from({ length: 12 }).map((_, i) => (
              <line key={`v-${i}`} x1={i * 80} y1={0} x2={i * 80} y2={layout.height} />
            ))}
            {Array.from({ length: 5 }).map((_, i) => (
              <line key={`h-${i}`} x1={0} y1={i * 70} x2={layout.width} y2={i * 70} />
            ))}
          </g>

          {/* Edges */}
          {edges.map((e, idx) => {
            const p1 = layout.positions.get(e.from);
            const p2 = layout.positions.get(e.to);
            if (!p1 || !p2) return null;
            const stroke = e.status === "ALERT" ? "#f43f5e" : e.status === "WARN" ? "#f59e0b" : "#10b981";
            const marker =
              e.status === "ALERT" ? "url(#arrow-alert)" : e.status === "WARN" ? "url(#arrow-warn)" : "url(#arrow-ok)";
            const mx = (p1.x + p2.x) / 2;
            const my = (p1.y + p2.y) / 2;
            return (
              <g key={`${e.from}-${e.to}-${idx}`}>
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke={stroke}
                  strokeWidth={e.status === "ALERT" ? 2.4 : 1.8}
                  strokeOpacity={0.8}
                  markerEnd={marker}
                />
                {e.label && (
                  <text
                    x={mx}
                    y={my - 5}
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="ui-monospace, SFMono-Regular, monospace"
                  >
                    {e.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((n) => {
            const pos = layout.positions.get(n.id);
            if (!pos) return null;
            const c = nodeColor(n.status);
            const isSel = selectedNodeId === n.id;
            return (
              <g
                key={n.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                className="cursor-pointer"
                onClick={() => setSelectedNodeId((prev) => (prev === n.id ? null : n.id))}
              >
                <circle r={isSel ? 22 : 18} fill={c.glow} />
                <circle r={14} fill={c.fill} stroke={c.ring} strokeWidth={isSel ? 3 : 2} />
                <circle r={5} fill={c.ring} />
                <text
                  y={27}
                  textAnchor="middle"
                  fill="#e2e8f0"
                  fontSize="10"
                  fontWeight="600"
                  fontFamily="ui-monospace, SFMono-Regular, monospace"
                >
                  {n.label}
                </text>
                {n.sublabel && (
                  <text
                    y={38}
                    textAnchor="middle"
                    fill="#64748b"
                    fontSize="8.5"
                    fontFamily="ui-monospace, SFMono-Regular, monospace"
                  >
                    {n.sublabel}
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {selectedNode && (
          <div className="absolute top-2.5 right-2.5 bg-slate-900/95 border border-slate-700 rounded-md px-3 py-2 text-[11px] font-mono space-y-0.5 shadow-lg">
            <div className="text-emerald-300 font-semibold">{selectedNode.label}</div>
            <div className="text-slate-400">Status: {selectedNode.status}</div>
            {selectedNode.sublabel && <div className="text-slate-300">{selectedNode.sublabel}</div>}
            {selectedNode.metric && <div className="text-cyan-300">Metric: {selectedNode.metric}</div>}
          </div>
        )}
      </div>

      {/* Bottom History Bar Strip (inspired by Image 2) */}
      <div className="px-4 py-2.5 border-t border-slate-800 bg-[#0c1117]">
        <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1.5">
          <span>{historyLabel}</span>
          <span>Live Backend Telemetry</span>
        </div>
        <div className="h-20 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={history} margin={{ top: 2, right: 4, bottom: 0, left: -24 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="label" stroke="#64748b" fontSize={9} />
              <YAxis stroke="#64748b" fontSize={9} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#334155",
                  fontSize: 11,
                  color: "#f8fafc",
                }}
              />
              <Bar dataKey="primary" name="Events / Hops" fill="#34d399" radius={[2, 2, 0, 0]} />
              {history.some((h) => h.secondary !== undefined) && (
                <Bar dataKey="secondary" name="Alerts / Denials" fill="#f43f5e" radius={[2, 2, 0, 0]} />
              )}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
