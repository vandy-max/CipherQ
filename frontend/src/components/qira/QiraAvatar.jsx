import { useEffect, useRef, useState } from "react";
import "./QiraAvatar.css";

/**
 * QiraAvatar — Qira's living-character visual identity.
 *
 * This is DECORATIVE ONLY, same contract as CipherQMascot: it never
 * determines security state. Callers pass `state`, derived from the
 * SAME authoritative source every other surface uses
 * (deriveMonitoringState() / the shared Qira decision object).
 *
 * States (shared vocabulary with monitoringState.js + CipherQMascot):
 *   "active"           -> calm idle, slow blink, gentle float
 *   "warning"          -> alert: amber aura, faster pulse, slight tilt
 *   "reauth_required"  -> same visual treatment as warning
 *   "revoked"          -> critical: red aura, focused/narrowed eyes, still
 *   "scanning"         -> active monitoring sweep (assessing/loading)
 *   "off" / undefined  -> calm neutral default, no security claim
 *
 * Props:
 *  - state: one of the above
 *  - size: px, default 64
 *  - trackCursor: boolean — if true, pupils subtly follow the pointer
 *    within the nearest ancestor with data-qira-track (opt-in, and
 *    automatically disabled under prefers-reduced-motion via CSS)
 *  - className
 */
const STATE_META = {
  active: { aura: "#63f7ff", auraSoft: "rgba(99,247,255,0.28)", cls: "qira--active" },
  scanning: { aura: "#63f7ff", auraSoft: "rgba(99,247,255,0.35)", cls: "qira--scanning" },
  warning: { aura: "#f59e0b", auraSoft: "rgba(245,158,11,0.32)", cls: "qira--warning" },
  reauth_required: { aura: "#f59e0b", auraSoft: "rgba(245,158,11,0.32)", cls: "qira--warning" },
  revoked: { aura: "#ff6b6b", auraSoft: "rgba(255,107,107,0.32)", cls: "qira--critical" },
  off: { aura: "#8e90a2", auraSoft: "rgba(142,144,162,0.18)", cls: "qira--idle" },
};

export default function QiraAvatar({ state = "off", size = 64, trackCursor = true, className = "" }) {
  const meta = STATE_META[state] || STATE_META.off;
  const rootRef = useRef(null);
  const [pupil, setPupil] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (!trackCursor) return undefined;
    const mq = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (mq?.matches) return undefined;

    function handleMove(e) {
      const el = rootRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dx = e.clientX - cx;
      const dy = e.clientY - cy;
      const dist = Math.hypot(dx, dy) || 1;
      // clamp pupil offset to a small range so it reads as "noticing", not swimming
      const maxOffset = 1.6;
      const scale = Math.min(1, 260 / dist) * maxOffset;
      setPupil({ x: (dx / dist) * scale, y: (dy / dist) * scale });
    }
    window.addEventListener("pointermove", handleMove, { passive: true });
    return () => window.removeEventListener("pointermove", handleMove);
  }, [trackCursor]);

  const isCritical = state === "revoked";

  return (
    <span
      ref={rootRef}
      className={`qira-avatar ${meta.cls} ${className}`.trim()}
      style={{ width: size, height: size, "--qira-aura": meta.aura, "--qira-aura-soft": meta.auraSoft }}
      aria-hidden="true"
    >
      {/* ambient aura particles */}
      <span className="qira-aura-ring" />
      <span className="qira-aura-particle qira-aura-particle--1" />
      <span className="qira-aura-particle qira-aura-particle--2" />
      <span className="qira-aura-particle qira-aura-particle--3" />

      <svg viewBox="0 0 100 100" className="qira-body" role="presentation">
        <defs>
          <radialGradient id="qira-sheen" cx="35%" cy="25%" r="80%">
            <stop offset="0%" stopColor="#2a2c38" />
            <stop offset="100%" stopColor="#111319" />
          </radialGradient>
          <filter id="qira-glow" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="2.2" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* body silhouette — soft rounded guardian shape, floats via CSS */}
        <g className="qira-float">
          <path
            d="M50 6
               C 40 6 32 12 28 20
               C 15 25 8 37 8 50
               C 8 72 25 90 50 92
               C 75 90 92 72 92 50
               C 92 37 85 25 72 20
               C 68 12 60 6 50 6 Z"
            fill="url(#qira-sheen)"
            stroke="#434656"
            strokeWidth="0.6"
          />

          {/* quantum seam lines on the body — subtle, technical */}
          <path d="M22 34 C 18 42 17 50 19 58" fill="none" stroke="#c4c5d9" strokeOpacity="0.15" strokeWidth="0.9" strokeLinecap="round" />
          <path d="M78 34 C 82 42 83 50 81 58" fill="none" stroke="#c4c5d9" strokeOpacity="0.15" strokeWidth="0.9" strokeLinecap="round" />

          {/* face plate */}
          <ellipse cx="50" cy="46" rx="27" ry="23" fill="#181a22" />

          {/* eyes group — pupils track cursor via inline transform */}
          <g filter="url(#qira-glow)">
            {isCritical ? (
              <>
                <ellipse cx="38" cy="46" rx="9" ry="4.4" fill="var(--qira-aura)" />
                <ellipse cx="62" cy="46" rx="9" ry="4.4" fill="var(--qira-aura)" />
              </>
            ) : (
              <>
                <circle cx="38" cy="46" r="9" fill="var(--qira-aura)" />
                <circle cx="62" cy="46" r="9" fill="var(--qira-aura)" />
              </>
            )}
            <circle
              cx={38 + pupil.x}
              cy={46 + pupil.y}
              r="3.1"
              fill="#0a0b10"
              style={{ transition: "cx 220ms ease-out, cy 220ms ease-out" }}
            />
            <circle
              cx={62 + pupil.x}
              cy={46 + pupil.y}
              r="3.1"
              fill="#0a0b10"
              style={{ transition: "cx 220ms ease-out, cy 220ms ease-out" }}
            />
          </g>

          {/* eyelids for blink */}
          <rect className="qira-eyelid" x="28" y="36" width="20" height="20" rx="10" fill="#181a22" />
          <rect className="qira-eyelid" x="52" y="36" width="20" height="20" rx="10" fill="#181a22" />

          {/* small chest core — pulses with state */}
          <g className="qira-core-pulse" transform="translate(50 72)">
            <path d="M0 -6 L6 0 L0 6 L-6 0 Z" fill="var(--qira-aura)" fillOpacity="0.85" />
            <circle r="1.6" fill="#0c0e17" />
          </g>
        </g>
      </svg>

      {/* scanning sweep overlay */}
      {state === "scanning" && (
        <svg viewBox="0 0 100 100" className="qira-scan-overlay" aria-hidden="true">
          <circle cx="50" cy="50" r="46" fill="none" stroke="var(--qira-aura)" strokeOpacity="0.25" strokeWidth="1" />
          <line x1="50" y1="50" x2="50" y2="6" stroke="var(--qira-aura)" strokeWidth="1.2" strokeOpacity="0.8" className="qira-scan-sweep" />
        </svg>
      )}
    </span>
  );
}
