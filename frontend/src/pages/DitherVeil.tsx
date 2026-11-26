import React, { useEffect, useRef } from "react";

export interface DitherVeilProps {
  src: string;
  pattern?: "floyd" | "bayer";
  pixelSize?: number;
  inkColor?: string;
  paperColor?: string;
  revealRadius?: number;
  softness?: number;
  linger?: number;
  fit?: "contain" | "cover";
  rimColor?: string;
  palette?: "duotone" | "color";
  levels?: number;
  contrast?: number;
  brightness?: number;
  rim?: number;
  reverse?: boolean;
  wander?: boolean;
  clickBurst?: boolean;
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
  const num = parseInt(full || "000000", 16);
  return [(num >> 16) & 255, (num >> 8) & 255, num & 255];
}

export default function DitherVeil({
  src,
  pattern = "floyd",
  pixelSize = 2,
  inkColor = "#120f17",
  paperColor = "#f4f1ea",
  revealRadius = 200,
  softness = 0.6,
  linger = 1,
  fit = "contain",
  rimColor = "#a78bfa",
  levels = 2,
  contrast = 1.15,
  brightness = 0,
  rim = 0,
  reverse = false,
  wander = false,
  clickBurst = false,
}: DitherVeilProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return;

    let rafId = 0;
    let disposed = false;
    let pointerX = -9999;
    let pointerY = -9999;
    let smoothX = -9999;
    let smoothY = -9999;
    let burstRadius = 0;
    let ditheredData: ImageData | null = null;
    let sourceCanvas: HTMLCanvasElement | null = null;

    const ink = hexToRgb(inkColor);
    const paper = hexToRgb(paperColor);
    const rimRgb = hexToRgb(rimColor);

    const buildBuffers = (img: HTMLImageElement | null) => {
      if (disposed) return;
      const rect = container.getBoundingClientRect();
      const w = Math.max(1, Math.floor(rect.width));
      const h = Math.max(1, Math.floor(rect.height));
      canvas.width = w;
      canvas.height = h;

      const step = Math.max(1, Math.round(pixelSize));
      const gw = Math.max(1, Math.floor(w / step));
      const gh = Math.max(1, Math.floor(h / step));

      const off = document.createElement("canvas");
      off.width = gw;
      off.height = gh;
      const octx = off.getContext("2d", { willReadFrequently: true });
      if (!octx) return;

      octx.fillStyle = paperColor;
      octx.fillRect(0, 0, gw, gh);

      if (img && img.naturalWidth > 0 && img.naturalHeight > 0) {
        const iw = img.naturalWidth;
        const ih = img.naturalHeight;
        const scale = fit === "contain" ? Math.min(gw / iw, gh / ih) : Math.max(gw / iw, gh / ih);
        const dw = iw * scale;
        const dh = ih * scale;
        const dx = (gw - dw) / 2;
        const dy = (gh - dh) / 2;
        octx.drawImage(img, dx, dy, dw, dh);
      } else {
        // Offline-safe deterministic fallback geometry
        const grad = octx.createLinearGradient(0, 0, gw, gh);
        grad.addColorStop(0, "#1e293b");
        grad.addColorStop(0.5, "#64748b");
        grad.addColorStop(1, "#e2e8f0");
        octx.fillStyle = grad;
        octx.fillRect(0, 0, gw, gh);
        octx.strokeStyle = "#0f172a";
        octx.lineWidth = Math.max(1, gw * 0.015);
        octx.beginPath();
        octx.arc(gw / 2, gh / 2, Math.min(gw, gh) * 0.34, 0, Math.PI * 2);
        octx.stroke();
      }

      sourceCanvas = off;
      const imgData = octx.getImageData(0, 0, gw, gh);
      const data = imgData.data;
      const gray = new Float32Array(gw * gh);

      for (let i = 0; i < gw * gh; i++) {
        const r = data[i * 4];
        const g = data[i * 4 + 1];
        const b = data[i * 4 + 2];
        let luma = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
        luma = (luma - 0.5) * contrast + 0.5 + brightness;
        gray[i] = Math.max(0, Math.min(1, luma));
      }

      const maxLevel = Math.max(1, levels - 1);
      if (pattern === "floyd") {
        for (let y = 0; y < gh; y++) {
          for (let x = 0; x < gw; x++) {
            const idx = y * gw + x;
            const oldVal = gray[idx];
            const newVal = Math.round(oldVal * maxLevel) / maxLevel;
            gray[idx] = newVal;
            const err = oldVal - newVal;
            if (x + 1 < gw) gray[idx + 1] += (err * 7) / 16;
            if (y + 1 < gh) {
              if (x > 0) gray[idx + gw - 1] += (err * 3) / 16;
              gray[idx + gw] += (err * 5) / 16;
              if (x + 1 < gw) gray[idx + gw + 1] += (err * 1) / 16;
            }
          }
        }
      }

      const out = octx.createImageData(gw, gh);
      for (let i = 0; i < gw * gh; i++) {
        const t = Math.max(0, Math.min(1, gray[i]));
        const p = i * 4;
        out.data[p] = Math.round(ink[0] + (paper[0] - ink[0]) * t);
        out.data[p + 1] = Math.round(ink[1] + (paper[1] - ink[1]) * t);
        out.data[p + 2] = Math.round(ink[2] + (paper[2] - ink[2]) * t);
        out.data[p + 3] = 255;
      }

      const dCanvas = document.createElement("canvas");
      dCanvas.width = gw;
      dCanvas.height = gh;
      dCanvas.getContext("2d")?.putImageData(out, 0, 0);
      ditheredData = out;

      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(dCanvas, 0, 0, w, h);
    };

    const img = new Image();
    img.crossOrigin = "anonymous";
    img.onload = () => buildBuffers(img);
    img.onerror = () => buildBuffers(null);
    img.src = src;

    const renderFrame = (time: number) => {
      if (disposed) return;
      const w = canvas.width;
      const h = canvas.height;
      if (ditheredData && sourceCanvas && w > 0 && h > 0) {
        const step = Math.max(1, Math.round(pixelSize));
        const gw = sourceCanvas.width;
        const gh = sourceCanvas.height;

        const dCanvas = document.createElement("canvas");
        dCanvas.width = gw;
        dCanvas.height = gh;
        dCanvas.getContext("2d")?.putImageData(ditheredData, 0, 0);

        ctx.imageSmoothingEnabled = false;
        ctx.drawImage(dCanvas, 0, 0, w, h);

        if (wander && pointerX < 0) {
          pointerX = w * (0.5 + 0.28 * Math.cos(time * 0.0008));
          pointerY = h * (0.5 + 0.25 * Math.sin(time * 0.0011));
        }

        const lerp = Math.max(0.05, Math.min(1, 0.22 / Math.max(0.2, linger)));
        if (pointerX >= 0) {
          if (smoothX < 0) {
            smoothX = pointerX;
            smoothY = pointerY;
          } else {
            smoothX += (pointerX - smoothX) * lerp;
            smoothY += (pointerY - smoothY) * lerp;
          }
        }

        if (burstRadius > 0) {
          burstRadius *= 0.92;
          if (burstRadius < 2) burstRadius = 0;
        }

        const activeR = Math.max(revealRadius, burstRadius);
        if (smoothX >= 0 && activeR > 0 && !reverse) {
          ctx.save();
          ctx.beginPath();
          ctx.arc(smoothX, smoothY, activeR, 0, Math.PI * 2);
          ctx.clip();
          ctx.imageSmoothingEnabled = true;
          ctx.drawImage(sourceCanvas, 0, 0, gw * step, gh * step);

          const edgeGrad = ctx.createRadialGradient(
            smoothX,
            smoothY,
            activeR * Math.max(0, 1 - softness),
            smoothX,
            smoothY,
            activeR
          );
          edgeGrad.addColorStop(0, "rgba(0,0,0,0)");
          edgeGrad.addColorStop(1, paperColor);
          ctx.fillStyle = edgeGrad;
          ctx.fillRect(smoothX - activeR, smoothY - activeR, activeR * 2, activeR * 2);

          if (rim > 0) {
            ctx.strokeStyle = `rgba(${rimRgb[0]},${rimRgb[1]},${rimRgb[2]},${Math.min(1, rim)})`;
            ctx.lineWidth = 2;
            ctx.stroke();
          }
          ctx.restore();
        }
      }
      rafId = requestAnimationFrame(renderFrame);
    };

    const onMove = (e: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      pointerX = e.clientX - rect.left;
      pointerY = e.clientY - rect.top;
    };
    const onLeave = () => {
      pointerX = -9999;
      pointerY = -9999;
    };
    const onClick = () => {
      if (clickBurst) {
        burstRadius = revealRadius * 1.85;
      }
    };

    const ro = new ResizeObserver(() => buildBuffers(img.complete && img.naturalWidth > 0 ? img : null));
    ro.observe(container);

    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerleave", onLeave);
    canvas.addEventListener("click", onClick);
    rafId = requestAnimationFrame(renderFrame);

    return () => {
      disposed = true;
      cancelAnimationFrame(rafId);
      ro.disconnect();
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerleave", onLeave);
      canvas.removeEventListener("click", onClick);
    };
  }, [
    src,
    pattern,
    pixelSize,
    inkColor,
    paperColor,
    revealRadius,
    softness,
    linger,
    fit,
    rimColor,
    levels,
    contrast,
    brightness,
    rim,
    reverse,
    wander,
    clickBurst,
  ]);

  return (
    <div
      ref={containerRef}
      style={{
        width: "100%",
        height: "100%",
        position: "relative",
        backgroundColor: paperColor,
        overflow: "hidden",
      }}
    >
      <canvas ref={canvasRef} style={{ width: "100%", height: "100%", display: "block", cursor: "crosshair" }} />
    </div>
  );
}
