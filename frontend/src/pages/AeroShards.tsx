import React, { useEffect, useRef } from "react";

export interface AeroShardsProps {
  shardColor?: string;
  accentColor?: string;
  placement?: "full" | "center";
  material?: "glass" | "solid";
  markers?: "plus" | "none";
  count?: number;
  depthOfField?: number;
  vignette?: number;
  mouseInteraction?: boolean;
  pulseOnClick?: boolean;
  holdToGather?: boolean;
  lightMode?: boolean;
  shardSize?: number;
  spread?: number;
  twist?: number;
  billow?: number;
  speed?: number;
  scale?: number;
  glow?: number;
  grain?: number;
  intro?: boolean;
  mouseStrength?: number;
  parallax?: number;
  paused?: boolean;
}

interface Shard {
  x: number;
  y: number;
  z: number;
  vx: number;
  vy: number;
  angle: number;
  spin: number;
  w: number;
  h: number;
  accent: boolean;
  marker: boolean;
}

function hexToRgb(hex: string): [number, number, number] {
  const clean = hex.replace("#", "");
  const full =
    clean.length === 3
      ? clean
          .split("")
          .map((c) => c + c)
          .join("")
      : clean;
  const num = parseInt(full || "896ABD", 16);
  return [(num >> 16) & 255, (num >> 8) & 255, num & 255];
}

export default function AeroShards({
  shardColor = "#896ABD",
  accentColor = "#A855F7",
  placement = "full",
  material = "glass",
  markers = "plus",
  count = 1300,
  depthOfField = 0.75,
  vignette = 0.3,
  mouseInteraction = true,
  pulseOnClick = true,
  holdToGather = true,
  lightMode = false,
  shardSize = 1,
  spread = 1,
  twist = 1,
  billow = 1,
  speed = 1,
  scale = 1,
  glow = 0.35,
  grain = 0.06,
  intro = true,
  mouseStrength = 0.6,
  parallax = 0.5,
  paused = false,
}: AeroShardsProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let rafId = 0;
    let disposed = false;
    let width = 1;
    let height = 1;
    let pointerX = 0.5;
    let pointerY = 0.5;
    let pointerActive = false;
    let gatherActive = false;
    let pulseForce = 0;
    let introProgress = intro ? 0 : 1;

    const baseRgb = hexToRgb(shardColor);
    const accRgb = hexToRgb(accentColor);

    // Deterministic seeded PRNG for consistent shard layout
    let seed = 1337;
    const rand = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed / 4294967296;
    };

    const effectiveCount = Math.min(420, Math.max(80, Math.round(count * 0.28)));
    const shards: Shard[] = Array.from({ length: effectiveCount }, (_, i) => ({
      x: (rand() - 0.5) * spread + 0.5,
      y: (rand() - 0.5) * spread + 0.5,
      z: 0.2 + rand() * 0.8,
      vx: (rand() - 0.5) * 0.00035,
      vy: (rand() - 0.5) * 0.00035,
      angle: rand() * Math.PI * 2,
      spin: (rand() - 0.5) * 0.012 * twist,
      w: (4 + rand() * 14) * shardSize * scale,
      h: (2 + rand() * 6) * shardSize * scale,
      accent: rand() > 0.72,
      marker: markers === "plus" && i % 19 === 0,
    }));

    const resize = () => {
      const rect = container.getBoundingClientRect();
      width = Math.max(1, Math.floor(rect.width));
      height = Math.max(1, Math.floor(rect.height));
      canvas.width = width;
      canvas.height = height;
    };
    resize();

    const onMove = (e: PointerEvent) => {
      if (!mouseInteraction) return;
      const rect = container.getBoundingClientRect();
      pointerX = (e.clientX - rect.left) / Math.max(1, rect.width);
      pointerY = (e.clientY - rect.top) / Math.max(1, rect.height);
      pointerActive = true;
    };
    const onDown = () => {
      if (holdToGather) gatherActive = true;
      if (pulseOnClick) pulseForce = 1;
    };
    const onUp = () => {
      gatherActive = false;
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerdown", onDown);
    window.addEventListener("pointerup", onUp);
    const ro = new ResizeObserver(resize);
    ro.observe(container);

    const draw = (t: number) => {
      if (disposed) return;

      ctx.clearRect(0, 0, width, height);

      // Subtle atmospheric radial backdrop
      const bgAlpha = lightMode ? 0.08 : 0.16;
      const grad = ctx.createRadialGradient(
        width * 0.5,
        height * 0.45,
        20,
        width * 0.5,
        height * 0.5,
        Math.max(width, height) * 0.75
      );
      grad.addColorStop(0, `rgba(${accRgb[0]},${accRgb[1]},${accRgb[2]},${bgAlpha})`);
      grad.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, width, height);

      if (introProgress < 1) {
        introProgress = Math.min(1, introProgress + 0.02);
      }
      if (pulseForce > 0) {
        pulseForce = Math.max(0, pulseForce - 0.04);
      }

      const pxOff = pointerActive ? (pointerX - 0.5) * parallax * 36 : 0;
      const pyOff = pointerActive ? (pointerY - 0.5) * parallax * 36 : 0;

      for (const s of shards) {
        if (!paused) {
          const billowX = Math.sin(t * 0.0005 * speed + s.y * 6) * 0.00018 * billow;
          const billowY = Math.cos(t * 0.0004 * speed + s.x * 6) * 0.00018 * billow;
          s.x += (s.vx * speed + billowX) * s.z;
          s.y += (s.vy * speed + billowY) * s.z;
          s.angle += s.spin * speed;

          if (pointerActive && mouseInteraction) {
            const dx = s.x - pointerX;
            const dy = s.y - pointerY;
            const dist = Math.hypot(dx, dy);
            if (dist < 0.25 && dist > 0.001) {
              const dir = gatherActive ? -1 : 1;
              const push = ((0.25 - dist) / 0.25) * 0.0028 * mouseStrength * (1 + pulseForce * 2.2);
              s.x += (dx / dist) * push * dir;
              s.y += (dy / dist) * push * dir;
            }
          }

          if (s.x < -0.05) s.x = 1.05;
          if (s.x > 1.05) s.x = -0.05;
          if (s.y < -0.05) s.y = 1.05;
          if (s.y > 1.05) s.y = -0.05;
        }

        const sx =
          placement === "center"
            ? width * 0.5 + (s.x - 0.5) * width * 0.6 * introProgress + pxOff * s.z
            : s.x * width + pxOff * s.z;
        const sy =
          placement === "center"
            ? height * 0.5 + (s.y - 0.5) * height * 0.6 * introProgress + pyOff * s.z
            : s.y * height + pyOff * s.z;

        const rgb = s.accent ? accRgb : baseRgb;
        const dofAlpha = (0.14 + (1 - Math.abs(s.z - 0.65)) * 0.26 * depthOfField) * (lightMode ? 0.65 : 0.9);

        ctx.save();
        ctx.translate(sx, sy);
        ctx.rotate(s.angle);

        if (s.marker) {
          ctx.strokeStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${Math.min(0.65, dofAlpha + 0.15)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(-4, 0);
          ctx.lineTo(4, 0);
          ctx.moveTo(0, -4);
          ctx.lineTo(0, 4);
          ctx.stroke();
        } else {
          ctx.fillStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${dofAlpha})`;
          if (material === "glass") {
            ctx.strokeStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${Math.min(0.55, dofAlpha + glow * 0.4)})`;
            ctx.lineWidth = 0.8;
          }
          ctx.beginPath();
          ctx.moveTo(-s.w * 0.5, -s.h * 0.5);
          ctx.lineTo(s.w * 0.5, -s.h * 0.15);
          ctx.lineTo(s.w * 0.3, s.h * 0.5);
          ctx.lineTo(-s.w * 0.4, s.h * 0.25);
          ctx.closePath();
          ctx.fill();
          if (material === "glass") ctx.stroke();
        }
        ctx.restore();
      }

      if (vignette > 0) {
        const vig = ctx.createRadialGradient(
          width * 0.5,
          height * 0.5,
          Math.min(width, height) * 0.35,
          width * 0.5,
          height * 0.5,
          Math.max(width, height) * 0.72
        );
        vig.addColorStop(0, "rgba(0,0,0,0)");
        vig.addColorStop(1, lightMode ? `rgba(241,245,249,${vignette * 0.55})` : `rgba(8,11,14,${vignette * 0.7})`);
        ctx.fillStyle = vig;
        ctx.fillRect(0, 0, width, height);
      }

      if (grain > 0) {
        ctx.fillStyle = lightMode ? `rgba(15,23,42,${grain * 0.06})` : `rgba(255,255,255,${grain * 0.05})`;
        for (let g = 0; g < 14; g++) {
          ctx.fillRect(Math.random() * width, Math.random() * height, 1.5, 1.5);
        }
      }

      rafId = requestAnimationFrame(draw);
    };

    rafId = requestAnimationFrame(draw);

    return () => {
      disposed = true;
      cancelAnimationFrame(rafId);
      ro.disconnect();
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointerup", onUp);
    };
  }, [
    shardColor,
    accentColor,
    placement,
    material,
    markers,
    count,
    depthOfField,
    vignette,
    mouseInteraction,
    pulseOnClick,
    holdToGather,
    lightMode,
    shardSize,
    spread,
    twist,
    billow,
    speed,
    scale,
    glow,
    grain,
    intro,
    mouseStrength,
    parallax,
    paused,
  ]);

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        position: "relative",
        pointerEvents: "none",
      }}
    >
      <canvas ref={canvasRef} style={{ width: "100%", height: "100%", display: "block" }} />
    </div>
  );
}
