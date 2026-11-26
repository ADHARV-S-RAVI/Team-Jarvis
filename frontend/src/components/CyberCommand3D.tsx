import React, { useEffect, useMemo, useRef, useState } from "react";
import { NavLink } from "react-router-dom";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { Box, Eye, Layers, RotateCcw, ShieldAlert, X } from "lucide-react";
import { StatusBadge } from "./ui";

export interface CyberNodeEntity {
  id: string;
  label: string;
  kind: "core" | "identity" | "device" | "resource" | "node" | "incident";
  trustState: string;
  meta: string;
  route: string;
}

export interface CyberEdge {
  from: string;
  to: string;
  kind: "trust" | "revoked" | "alert";
}

interface CyberCommand3DProps {
  entities: CyberNodeEntity[];
  edges: CyberEdge[];
  isDark?: boolean;
}

const KIND_COLOR: Record<CyberNodeEntity["kind"], string> = {
  core: "#10b981",
  identity: "#06b6d4",
  device: "#3b82f6",
  resource: "#8b5cf6",
  node: "#14b8a6",
  incident: "#ef4444",
};

function trustColor(e: CyberNodeEntity): string {
  if (e.trustState === "REVOKED" || e.trustState === "COMPROMISED" || e.trustState === "PARTITIONED" || e.trustState === "CRITICAL") {
    return "#ef4444";
  }
  if (e.trustState === "SUSPENDED" || e.trustState === "HIGH" || e.trustState === "OPEN") {
    return "#f59e0b";
  }
  return KIND_COLOR[e.kind];
}

export default function CyberCommand3D({ entities, edges, isDark = false }: CyberCommand3DProps) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [mode2D, setMode2D] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [filterKind, setFilterKind] = useState<string>("ALL");
  const [filterTrust, setFilterTrust] = useState<"ALL" | "TRUSTED" | "RISK">("ALL");
  const [showEdges, setShowEdges] = useState(true);
  const [showParticles, setShowParticles] = useState(true);
  const [selected, setSelected] = useState<CyberNodeEntity | null>(null);
  const [hovered, setHovered] = useState<CyberNodeEntity | null>(null);
  const [webglError, setWebglError] = useState(false);

  const visibleEntities = useMemo(() => {
    return entities.filter((e) => {
      if (e.kind === "core") return true;
      if (filterKind !== "ALL" && e.kind !== filterKind) return false;
      if (filterTrust === "TRUSTED" && ["REVOKED", "COMPROMISED", "PARTITIONED", "CRITICAL", "SUSPENDED"].includes(e.trustState)) return false;
      if (filterTrust === "RISK" && !["REVOKED", "COMPROMISED", "PARTITIONED", "CRITICAL", "SUSPENDED", "OPEN"].includes(e.trustState)) return false;
      return true;
    });
  }, [entities, filterKind, filterTrust]);

  // Deterministic 3D orbital coordinates per entity
  const positioned = useMemo(() => {
    const ringRadius: Record<CyberNodeEntity["kind"], number> = {
      core: 0,
      identity: 4.2,
      device: 7.4,
      resource: 10.2,
      node: 12.8,
      incident: 8.8,
    };
    const byKindCount: Record<string, number> = {};
    const byKindIdx: Record<string, number> = {};
    for (const e of visibleEntities) {
      byKindCount[e.kind] = (byKindCount[e.kind] ?? 0) + 1;
    }

    return visibleEntities.map((e) => {
      const total = Math.max(1, byKindCount[e.kind] ?? 1);
      const idx = byKindIdx[e.kind] ?? 0;
      byKindIdx[e.kind] = idx + 1;
      const r = ringRadius[e.kind];
      const theta = (idx / total) * Math.PI * 2 + (e.kind === "device" ? 0.4 : e.kind === "node" ? 0.8 : 0);
      const y = e.kind === "core" ? 0 : Math.sin(idx * 1.7) * 1.4;
      return {
        entity: e,
        pos: new THREE.Vector3(Math.cos(theta) * r, y, Math.sin(theta) * r),
        color: trustColor(e),
      };
    });
  }, [visibleEntities]);

  useEffect(() => {
    if (mode2D || webglError) return;
    const container = mountRef.current;
    if (!container) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    } catch {
      setWebglError(true);
      return;
    }

    const w = Math.max(1, container.clientWidth);
    const h = Math.max(1, container.clientHeight);
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(48, w / h, 0.1, 200);
    camera.position.set(0, 12, 21);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.06;
    controls.maxDistance = 42;
    controls.minDistance = 6;

    // Lights
    scene.add(new THREE.AmbientLight(0xffffff, isDark ? 0.75 : 0.9));
    const keyLight = new THREE.PointLight(0x10b981, 2.2, 60);
    keyLight.position.set(8, 14, 10);
    scene.add(keyLight);

    // Orbital Trust Zone Rings
    const ringGeo = new THREE.RingGeometry(4.15, 4.22, 64);
    const ringMat = new THREE.MeshBasicMaterial({
      color: isDark ? 0x1e293b : 0xcbd5e1,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.5,
    });
    for (const r of [4.2, 7.4, 10.2, 12.8]) {
      const mesh = new THREE.Mesh(ringGeo.clone(), ringMat);
      mesh.scale.setScalar(r / 4.2);
      mesh.rotation.x = Math.PI / 2;
      scene.add(mesh);
    }

    // Instanced ambient particles (1 draw call!)
    let instanced: THREE.InstancedMesh | null = null;
    if (showParticles) {
      const pCount = 240;
      const pGeo = new THREE.BoxGeometry(0.09, 0.09, 0.09);
      const pMat = new THREE.MeshBasicMaterial({
        color: isDark ? 0x38bdf8 : 0x6366f1,
        transparent: true,
        opacity: isDark ? 0.35 : 0.25,
      });
      instanced = new THREE.InstancedMesh(pGeo, pMat, pCount);
      const dummy = new THREE.Object3D();
      for (let i = 0; i < pCount; i++) {
        const ang = (i / pCount) * Math.PI * 2 * 5;
        const rad = 3 + (i % 15);
        dummy.position.set(Math.cos(ang) * rad, ((i % 9) - 4) * 0.9, Math.sin(ang) * rad);
        dummy.updateMatrix();
        instanced.setMatrixAt(i, dummy.matrix);
      }
      scene.add(instanced);
    }

    // Entity Node Meshes
    const nodeMeshes: THREE.Mesh[] = [];
    const posMap = new Map<string, THREE.Vector3>();
    const sphereGeo = new THREE.SphereGeometry(0.45, 20, 20);
    const coreGeo = new THREE.IcosahedronGeometry(1.15, 1);

    for (const item of positioned) {
      posMap.set(item.entity.id, item.pos);
      const isCore = item.entity.kind === "core";
      const mat = new THREE.MeshStandardMaterial({
        color: new THREE.Color(item.color),
        emissive: new THREE.Color(item.color),
        emissiveIntensity: isCore ? 0.6 : 0.35,
        roughness: 0.25,
        metalness: 0.4,
      });
      const mesh = new THREE.Mesh(isCore ? coreGeo : sphereGeo, mat);
      mesh.position.copy(item.pos);
      mesh.userData = { entity: item.entity };
      scene.add(mesh);
      nodeMeshes.push(mesh);
    }

    // Trust Edges
    if (showEdges) {
      for (const edge of edges) {
        const a = posMap.get(edge.from);
        const b = posMap.get(edge.to);
        if (!a || !b) continue;
        const lineGeo = new THREE.BufferGeometry().setFromPoints([a, b]);
        const lineColor = edge.kind === "revoked" || edge.kind === "alert" ? 0xef4444 : isDark ? 0x14b8a6 : 0x0d9488;
        const lineMat = new THREE.LineBasicMaterial({
          color: lineColor,
          transparent: true,
          opacity: edge.kind === "trust" ? 0.35 : 0.85,
        });
        scene.add(new THREE.Line(lineGeo, lineMat));
      }
    }

    // Raycasting for hover & click
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const updatePointer = (ev: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
    };

    const onMove = (ev: MouseEvent) => {
      updatePointer(ev);
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(nodeMeshes, false);
      if (hits.length > 0) {
        setHovered(hits[0].object.userData.entity as CyberNodeEntity);
        renderer.domElement.style.cursor = "pointer";
      } else {
        setHovered(null);
        renderer.domElement.style.cursor = "grab";
      }
    };

    const onClick = (ev: MouseEvent) => {
      updatePointer(ev);
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(nodeMeshes, false);
      if (hits.length > 0) {
        setSelected(hits[0].object.userData.entity as CyberNodeEntity);
      }
    };

    renderer.domElement.addEventListener("mousemove", onMove);
    renderer.domElement.addEventListener("click", onClick);

    const onResize = () => {
      if (!container) return;
      const nw = Math.max(1, container.clientWidth);
      const nh = Math.max(1, container.clientHeight);
      camera.aspect = nw / nh;
      camera.updateProjectionMatrix();
      renderer.setSize(nw, nh);
    };
    const ro = new ResizeObserver(onResize);
    ro.observe(container);

    let raf = 0;
    const animate = () => {
      raf = requestAnimationFrame(animate);
      if (!reducedMotion && !document.hidden) {
        if (instanced) instanced.rotation.y += 0.0008;
        if (nodeMeshes[0]) nodeMeshes[0].rotation.y += 0.006;
      }
      controls.update();
      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      renderer.domElement.removeEventListener("mousemove", onMove);
      renderer.domElement.removeEventListener("click", onClick);
      controls.dispose();
      renderer.dispose();
    };
  }, [positioned, edges, isDark, mode2D, reducedMotion, showEdges, showParticles, webglError]);

  return (
    <div className="bg-white/90 dark:bg-[#0f1419]/90 backdrop-blur-md border border-slate-200 dark:border-[#1c242d] rounded-xl overflow-hidden shadow-sm">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-slate-200 dark:border-[#1c242d] bg-slate-50/80 dark:bg-[#0b0f13]/80">
        <div className="flex items-center gap-2">
          <Box className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          <span className="text-xs font-bold tracking-wide text-slate-900 dark:text-white">
            3D Cyber Command Topology
          </span>
          <StatusBadge label={`${visibleEntities.length} ENTITIES`} tone="info" />
          <StatusBadge label={mode2D || webglError ? "2D FALLBACK" : "WEBGL 3D"} tone="violet" />
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          <select
            value={filterKind}
            onChange={(e) => setFilterKind(e.target.value)}
            aria-label="Filter entity type"
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2 py-0.5 text-slate-700 dark:text-slate-200"
          >
            <option value="ALL">All Types</option>
            <option value="identity">Identities</option>
            <option value="device">Devices</option>
            <option value="resource">Vault Resources</option>
            <option value="node">Simulated Nodes</option>
            <option value="incident">Incidents</option>
          </select>

          <select
            value={filterTrust}
            onChange={(e) => setFilterTrust(e.target.value as "ALL" | "TRUSTED" | "RISK")}
            aria-label="Filter trust state"
            className="rounded bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 px-2 py-0.5 text-slate-700 dark:text-slate-200"
          >
            <option value="ALL">All States</option>
            <option value="TRUSTED">Trusted Only</option>
            <option value="RISK">Revoked / Risk</option>
          </select>

          <button
            type="button"
            onClick={() => setShowEdges((v) => !v)}
            className={`px-2 py-0.5 rounded border ${showEdges ? "bg-emerald-600 text-white border-emerald-600" : "bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700"}`}
          >
            <Layers className="w-3 h-3 inline mr-1" />Edges
          </button>

          <button
            type="button"
            onClick={() => setShowParticles((v) => !v)}
            className={`px-2 py-0.5 rounded border ${showParticles ? "bg-cyan-600 text-white border-cyan-600" : "bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700"}`}
          >
            Particles
          </button>

          <button
            type="button"
            onClick={() => setReducedMotion((v) => !v)}
            className="px-2 py-0.5 rounded border bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700"
          >
            <RotateCcw className="w-3 h-3 inline mr-1" />{reducedMotion ? "Motion Off" : "Motion On"}
          </button>

          <button
            type="button"
            onClick={() => setMode2D((v) => !v)}
            className="px-2 py-0.5 rounded border bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700"
          >
            <Eye className="w-3 h-3 inline mr-1" />{mode2D ? "3D View" : "2D Fallback"}
          </button>
        </div>
      </div>

      {/* Viewport */}
      <div className="relative h-[340px] w-full bg-slate-50/70 dark:bg-[#070a0f]/80">
        {mode2D || webglError ? (
          <svg viewBox="-16 -16 32 32" className="w-full h-full">
            {[4.2, 7.4, 10.2, 12.8].map((r) => (
              <circle key={r} cx={0} cy={0} r={r} fill="none" stroke={isDark ? "#1e293b" : "#cbd5e1"} strokeWidth={0.08} />
            ))}
            {showEdges &&
              edges.map((ed, i) => {
                const a = positioned.find((p) => p.entity.id === ed.from);
                const b = positioned.find((p) => p.entity.id === ed.to);
                if (!a || !b) return null;
                return (
                  <line
                    key={i}
                    x1={a.pos.x}
                    y1={a.pos.z}
                    x2={b.pos.x}
                    y2={b.pos.z}
                    stroke={ed.kind === "trust" ? "#10b981" : "#ef4444"}
                    strokeWidth={0.08}
                    opacity={0.5}
                  />
                );
              })}
            {positioned.map((p) => (
              <g key={p.entity.id} onClick={() => setSelected(p.entity)} className="cursor-pointer">
                <circle cx={p.pos.x} cy={p.pos.z} r={p.entity.kind === "core" ? 1.1 : 0.45} fill={p.color} />
                <text x={p.pos.x + 0.6} y={p.pos.z + 0.15} fontSize={0.6} fill={isDark ? "#cbd5e1" : "#334155"}>
                  {p.entity.label}
                </text>
              </g>
            ))}
          </svg>
        ) : (
          <div ref={mountRef} className="w-full h-full" />
        )}

        {/* Hover Pill */}
        {hovered && (
          <div className="absolute top-3 left-3 pointer-events-none px-2.5 py-1.5 rounded bg-white/95 dark:bg-[#0b0f13]/95 border border-slate-200 dark:border-slate-700 text-[11px] shadow">
            <div className="font-mono font-bold text-slate-900 dark:text-white">{hovered.label}</div>
            <div className="text-slate-500 dark:text-slate-400">
              {hovered.kind.toUpperCase()} &middot; {hovered.trustState}
            </div>
          </div>
        )}

        {/* Selected Entity Inspector Drawer */}
        {selected && (
          <div className="absolute top-3 right-3 w-72 p-3.5 rounded-lg bg-white/95 dark:bg-[#0f1419]/95 border border-slate-200 dark:border-slate-700 shadow-xl space-y-2 text-xs z-10">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-mono font-bold text-slate-900 dark:text-white">{selected.label}</div>
                <div className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 uppercase">
                  {selected.kind} &middot; {selected.id}
                </div>
              </div>
              <button type="button" onClick={() => setSelected(null)} className="text-slate-400 hover:text-slate-700 dark:hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex items-center gap-2">
              <StatusBadge
                label={selected.trustState}
                tone={["REVOKED", "COMPROMISED", "PARTITIONED", "CRITICAL"].includes(selected.trustState) ? "danger" : "success"}
              />
            </div>
            <p className="text-[11px] text-slate-600 dark:text-slate-300 font-mono break-words">{selected.meta}</p>
            <NavLink
              to={selected.route}
              className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 hover:underline"
            >
              <ShieldAlert className="w-3.5 h-3.5" /> Open {selected.kind} module &rarr;
            </NavLink>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-2.5 left-3 flex flex-wrap gap-3 px-2.5 py-1 rounded bg-white/85 dark:bg-[#0b0f13]/85 border border-slate-200 dark:border-slate-800 text-[10px] font-mono text-slate-600 dark:text-slate-400">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" />Core/Nodes</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-500" />Identities</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" />Devices</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-violet-500" />Vault</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500" />Revoked/Alert</span>
        </div>
      </div>
    </div>
  );
}
