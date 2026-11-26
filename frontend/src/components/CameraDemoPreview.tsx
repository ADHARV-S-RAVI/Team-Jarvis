import React, { useEffect, useRef, useState } from "react";
import { Camera, CameraOff, Info, X } from "lucide-react";
import { api } from "../services/api";
import { Button, StatusBadge } from "./ui";

interface CameraDemoPreviewProps {
  open: boolean;
  actorId: string;
  onClose: () => void;
}

/**
 * Explicit-consent, non-authenticating Live Camera Verification Demo.
 * Privacy guarantees: never starts automatically, never records/snapshots/uploads frames,
 * never extracts biometric templates, and stops all MediaStreamTracks on stop/unmount.
 */
export function CameraDemoPreview({ open, actorId, onClose }: CameraDemoPreviewProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [status, setStatus] = useState<"IDLE" | "REQUESTING" | "ACTIVE" | "DENIED" | "UNAVAILABLE">("IDLE");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const stopTracks = (logStop = true) => {
    if (streamRef.current) {
      for (const track of streamRef.current.getTracks()) {
        track.stop();
      }
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    if (logStop && status === "ACTIVE") {
      void api.logCameraDemoEvent(actorId, "STOPPED").catch(() => {});
    }
    setStatus("IDLE");
  };

  useEffect(() => {
    if (!open && streamRef.current) {
      stopTracks(true);
    }
    return () => {
      if (streamRef.current) {
        for (const track of streamRef.current.getTracks()) {
          track.stop();
        }
        streamRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  if (!open) return null;

  const startCamera = async () => {
    setErrorMsg(null);
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setStatus("UNAVAILABLE");
      setErrorMsg("Browser MediaDevices API unavailable in this context. Use WebAuthn / Passkey instead.");
      return;
    }
    setStatus("REQUESTING");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
      setStatus("ACTIVE");
      void api.logCameraDemoEvent(actorId, "STARTED").catch(() => {});
    } catch (err) {
      setStatus("DENIED");
      setErrorMsg(`Camera access denied or unavailable (${(err as Error).message}). Use WebAuthn or approved fallback.`);
      void api.logCameraDemoEvent(actorId, "PERMISSION_DENIED").catch(() => {});
    }
  };

  return (
    <div
      role="region"
      aria-label="Live Camera Verification Demo"
      className="fixed bottom-4 right-4 z-50 w-80 rounded-xl bg-white dark:bg-[#0f1419] border border-slate-300 dark:border-[#26313d] shadow-2xl overflow-hidden text-xs"
    >
      <div className="flex items-center justify-between px-3 py-2 bg-slate-50 dark:bg-[#0b0f13] border-b border-slate-200 dark:border-[#1c242d]">
        <div className="flex items-center gap-1.5 font-semibold text-slate-900 dark:text-white">
          <Camera className={`w-3.5 h-3.5 ${status === "ACTIVE" ? "text-emerald-500 animate-pulse" : "text-slate-500"}`} />
          <span>Camera Visual Demo</span>
        </div>
        <div className="flex items-center gap-1.5">
          <StatusBadge
            label={status === "ACTIVE" ? "CAMERA ACTIVE" : status}
            tone={status === "ACTIVE" ? "success" : status === "DENIED" ? "danger" : "neutral"}
          />
          <button
            type="button"
            aria-label="Close camera demo"
            onClick={() => {
              stopTracks(true);
              onClose();
            }}
            className="text-slate-400 hover:text-slate-700 dark:hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="p-3 space-y-2.5">
        <div className="p-2 rounded bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-500/30 text-[11px] text-amber-800 dark:text-amber-200 flex items-start gap-1.5">
          <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          <span>
            <strong>Non-authenticating visual demo only.</strong> Zero frames are recorded, uploaded, or stored. Local
            biometric authentication uses WebAuthn / Windows Hello.
          </span>
        </div>

        <div className="h-36 rounded bg-slate-900 flex items-center justify-center overflow-hidden relative">
          <video ref={videoRef} autoPlay playsInline muted className={`w-full h-full object-cover ${status === "ACTIVE" ? "block" : "hidden"}`} />
          {status !== "ACTIVE" && (
            <div className="text-[11px] text-slate-400 text-center px-3">
              {errorMsg ?? "Explicit consent required before requesting camera preview."}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between gap-2">
          {status === "ACTIVE" ? (
            <Button size="sm" variant="danger" onClick={() => stopTracks(true)} className="w-full">
              <CameraOff className="w-3.5 h-3.5" /> Stop Camera
            </Button>
          ) : (
            <Button size="sm" onClick={() => void startCamera()} disabled={status === "REQUESTING"} className="w-full">
              <Camera className="w-3.5 h-3.5" /> Start Camera Preview
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
