import { useEffect, useRef, useState } from "react";
import { X, ShieldCheck, ShieldAlert, ShieldX, Camera, ScanFace, Radio } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { formatTimestamp } from "../../utils/formatTimestamp";
import { deriveMonitoringState, monitoringReason, MONITORING_UI_META } from "./monitoringState";

// PART 4/19 — a real, user-accessible Live Monitoring surface (not
// just a status summary chip). It reads the SAME MonitoringContext
// snapshot/camera loop as SecurityMonitoringCard/MonitoringBadge —
// there is exactly one authoritative monitoring loop in the app (see
// MonitoringContext.jsx) — and reuses the SAME already-open camera
// stream via `webcamRef`, so opening this panel never requests camera
// permission a second time and never starts a competing capture loop.
//
// Live monitoring status here is intentionally binary and derived
// ONLY from the actual monitoring session (camera/face/identity/
// session-authorization), never from snapshot.security_state (which
// also reflects unrelated audit-chain integrity — see
// SecurityMonitoringCard.jsx's deriveLiveMonitoringState for the
// single shared source of truth for that rule).
export default function LiveMonitoringPanel({ open, onClose }) {
  const { snapshot, isMonitoring, cameraState, connectionState, webcamRef } = useMonitoringContext();
  const videoRef = useRef(null);
  const [attached, setAttached] = useState(false);

  // Attach the SAME MediaStream the hidden background capture element
  // is already using — no second getUserMedia() call. Polls briefly
  // because the hidden <Webcam> may still be negotiating its stream
  // the instant this panel mounts.
  useEffect(() => {
    if (!open) {
      setAttached(false);
      return undefined;
    }
    let cancelled = false;
    let raf;
    function tryAttach() {
      if (cancelled) return;
      const sourceVideo = webcamRef?.current?.video;
      const stream = sourceVideo?.srcObject;
      if (stream && videoRef.current) {
        if (videoRef.current.srcObject !== stream) {
          videoRef.current.srcObject = stream;
        }
        setAttached(true);
      } else {
        raf = requestAnimationFrame(tryAttach);
      }
    }
    tryAttach();
    return () => {
      cancelled = true;
      if (raf) cancelAnimationFrame(raf);
    };
  }, [open, webcamRef]);

  if (!open) return null;

  const cameraActive = cameraState === "ready" && attached;
  const faceDetected = !!snapshot?.face_present;
  const identityVerified = snapshot?.identity_state === "identity_confirmed";
  const sessionActive = isMonitoring && snapshot?.current_authorization_state === "valid";

  const stateKey = deriveMonitoringState({ isMonitoring, snapshot, connectionState });
  const stateMeta = MONITORING_UI_META[stateKey] || MONITORING_UI_META.warning;
  const secure = stateKey === "active";
  const headline = stateKey === "off" ? "MONITORING OFF" : stateMeta.label;
  const reason = monitoringReason(stateKey, snapshot, connectionState);
  const tone = stateMeta.tone;
  const dot = stateMeta.dot;
  const Icon = stateKey === "active" ? ShieldCheck : stateKey === "revoked" ? ShieldX : ShieldAlert;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-cq-xl bg-cq-surface-container-low border border-cq-outline-variant/20 shadow-cq-popover overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-cq-outline-variant/10">
          <span className="text-[13px] font-bold uppercase tracking-wide text-cq-on-surface">Live Security Monitoring</span>
          <button onClick={onClose} className="text-cq-on-surface-variant hover:text-cq-on-surface">
            <X size={17} />
          </button>
        </div>

        <div className="relative bg-black aspect-video flex items-center justify-center">
          {cameraActive ? (
            <video ref={videoRef} autoPlay playsInline muted className="w-full h-full object-cover scale-x-[-1]" />
          ) : (
            <div className="flex flex-col items-center gap-2 text-cq-on-surface-variant py-10">
              <Camera size={28} className="opacity-50" />
              <span className="text-[12px]">
                {cameraState === "unavailable"
                  ? "Camera unavailable"
                  : cameraState === "requesting"
                    ? "Opening camera…"
                    : "Camera not started — monitoring session is not active"}
              </span>
            </div>
          )}
          <div className="absolute bottom-2 right-2 inline-flex items-center gap-1 rounded-full bg-black/60 px-2 py-0.5 text-[10px] text-white">
            <Radio size={10} className={isMonitoring ? "text-cq-secondary animate-pulse" : "text-cq-on-surface-variant"} />
            {isMonitoring ? "Monitoring continuously" : "Not monitoring"}
          </div>
        </div>

        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <Icon size={16} className={tone} />
            <span className={`text-[14px] font-bold ${tone}`}>{headline}</span>
            <span className={`ml-auto w-2 h-2 rounded-full ${dot} ${secure ? "animate-pulse" : ""}`} />
          </div>
          <p className={`text-[12.5px] leading-relaxed mb-3 ${tone}`}>{reason}</p>

          <ul className="space-y-1.5 text-[12.5px] text-cq-on-surface-variant">
            <li className="flex items-center justify-between">
              <span>Camera</span>
              <span className={cameraActive ? "text-cq-primary font-semibold" : "text-cq-error font-semibold"}>
                {cameraActive
                  ? "Active"
                  : cameraState === "unavailable"
                    ? "Unavailable"
                    : cameraState === "requesting"
                      ? "Opening…"
                      : "Not started"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Face Detected</span>
              <span className={faceDetected ? "text-cq-primary font-semibold" : "text-cq-on-surface-variant font-semibold"}>
                {faceDetected ? "Yes" : "No"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Identity</span>
              <span className={identityVerified ? "text-cq-primary font-semibold" : "text-cq-error font-semibold"}>
                {snapshot?.identity_state ? snapshot.identity_state.replaceAll("_", " ").toUpperCase() : "—"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Liveness</span>
              <span className={snapshot?.liveness ? "text-cq-primary font-semibold" : "text-cq-error font-semibold"}>
                {snapshot?.liveness ? "CONFIRMED" : "NOT CONFIRMED"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Authorization</span>
              <span className={sessionActive ? "text-cq-primary font-semibold" : "text-cq-error font-semibold"}>
                {sessionActive ? "VALID" : "INVALID"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Risk</span>
              <span className="text-cq-on-surface font-semibold">
                {snapshot?.current_risk?.toUpperCase?.() || "—"} · {snapshot?.risk_score ?? "—"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Audit Integrity</span>
              <span className={(snapshot?.audit_chain_intact ?? true) ? "text-cq-primary font-semibold" : "text-amber-400 font-semibold"}>
                {(snapshot?.audit_chain_intact ?? true) ? "VERIFIED" : "REVIEW REQUIRED"}
              </span>
            </li>
            <li className="flex items-center justify-between">
              <span>Consecutive Failures</span>
              <span className="text-cq-on-surface font-semibold">
                {snapshot?.consecutive_face_failures ?? 0}
              </span>
            </li>
          </ul>

          <div className="mt-3 pt-3 border-t border-cq-outline-variant/10 flex items-center justify-between text-[11px] text-cq-on-surface-variant">
            <span className="inline-flex items-center gap-1">
              <ScanFace size={11} /> Continuous monitoring active
            </span>
            <span>{snapshot?.timestamp ? `Last check: ${formatTimestamp(snapshot.timestamp)}` : "—"}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
