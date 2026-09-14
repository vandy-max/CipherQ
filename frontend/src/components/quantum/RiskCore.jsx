import { useMemo } from "react";
import clsx from "clsx";

/**
 * RiskCore — the central "core" visualization for the dashboard hero:
 * a numeric risk score surrounded by layered animated rings and orbiting
 * telemetry nodes.
 *
 * This is a presentational primitive. It takes ALREADY-COMPUTED values
 * (score, level, state) from the real backend risk snapshot — it never
 * computes or guesses risk itself. When score/level are unavailable it
 * renders a calm neutral/loading frame rather than fabricating a number.
 *
 * Props:
 *  - score: number 0-100 | undefined
 *  - level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | undefined
 *  - state: "active" | "warning" | "reauth_required" | "revoked" | "off"
 *           (same vocabulary as deriveMonitoringState)
 *  - loading: boolean
 */
const STATE_COLOR = {
  active: { ring: "#63f7ff", glow: "rgba(99,247,255,0.35)", label: "SECURE" },
  warning: { ring: "#f59e0b", glow: "rgba(245,158,11,0.35)", label: "WARNING" },
  reauth_required: { ring: "#f59e0b", glow: "rgba(245,158,11,0.35)", label: "RE-AUTH REQUIRED" },
  revoked: { ring: "#ffb4ab", glow: "rgba(255,180,171,0.35)", label: "REVOKED" },
  off: { ring: "#8e90a2", glow: "rgba(142,144,162,0.2)", label: "MONITORING OFF" },
};

export default function RiskCore({ score, level, state = "off", loading = false, size = 280 }) {
  const meta = STATE_COLOR[state] || STATE_COLOR.off;
  const hasScore = typeof score === "number" && !loading;
  const pct = hasScore ? Math.max(0, Math.min(100, score)) : 0;
  const circumference = 2 * Math.PI * 108;
  const dash = hasScore ? (pct / 100) * circumference : 0;

  const nodes = useMemo(
    () => [
      { angle: -90, label: "IDENTITY" },
      { angle: -18, label: "DEVICE" },
      { angle: 54, label: "SESSION" },
      { angle: 126, label: "NETWORK" },
      { angle: 198, label: "QUANTUM" },
    ],
    []
  );

  return (
    <div
      className="relative flex items-center justify-center"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Security posture: ${loading ? "checking" : `${meta.label}, risk score ${score ?? "unavailable"}`}`}
    >
      {/* outer faint orbital ring with drifting nodes */}
      <div className="absolute inset-0 cq-orbit-cw opacity-70">
        <svg viewBox="0 0 280 280" className="w-full h-full">
          <circle cx="140" cy="140" r="132" fill="none" stroke="#434656" strokeOpacity="0.25" strokeWidth="1" strokeDasharray="1 7" />
        </svg>
      </div>
      <div className="absolute inset-0 cq-orbit-ccw opacity-50">
        <svg viewBox="0 0 280 280" className="w-full h-full">
          <circle cx="140" cy="140" r="150" fill="none" stroke="#434656" strokeOpacity="0.18" strokeWidth="1" strokeDasharray="1 5" />
        </svg>
      </div>

      {/* telemetry nodes orbiting */}
      {nodes.map((n) => {
        const rad = (n.angle * Math.PI) / 180;
        const r = size * 0.46;
        const x = size / 2 + r * Math.cos(rad);
        const y = size / 2 + r * Math.sin(rad);
        return (
          <div
            key={n.label}
            className="absolute flex flex-col items-center gap-1"
            style={{ left: x, top: y, transform: "translate(-50%, -50%)" }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full cq-telemetry-dot"
              style={{ background: meta.ring, boxShadow: `0 0 6px ${meta.ring}` }}
            />
            <span className="text-[8.5px] font-semibold tracking-[0.15em] text-cq-on-surface-variant/70 whitespace-nowrap hidden sm:inline">
              {n.label}
            </span>
          </div>
        );
      })}

      {/* central score ring */}
      <svg viewBox="0 0 240 240" width={size * 0.72} height={size * 0.72} className="relative z-10">
        <defs>
          <linearGradient id="rc-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={meta.ring} stopOpacity="1" />
            <stop offset="100%" stopColor="#a03ad3" stopOpacity="0.7" />
          </linearGradient>
        </defs>
        <circle cx="120" cy="120" r="108" fill="#0c0e17" fillOpacity="0.4" stroke="#282933" strokeWidth="10" />
        {hasScore && (
          <circle
            cx="120"
            cy="120"
            r="108"
            fill="none"
            stroke="url(#rc-gradient)"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - dash}
            transform="rotate(-90 120 120)"
            className="transition-[stroke-dashoffset] duration-700 ease-out"
            style={{ filter: `drop-shadow(0 0 8px ${meta.glow})` }}
          />
        )}
      </svg>

      {/* center label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
        {loading ? (
          <span className="text-cq-on-surface-variant text-sm">Checking…</span>
        ) : hasScore ? (
          <>
            <span className="text-[13px] font-mono tracking-[0.2em] text-cq-on-surface-variant uppercase">Risk Score</span>
            <span className="text-[56px] leading-none font-display-lg font-bold text-cq-on-surface tabular-nums mt-1">
              {Math.round(score)}
            </span>
            {level && (
              <span
                className="mt-2 text-[11px] font-bold tracking-[0.2em] uppercase px-3 py-1 rounded-full"
                style={{ color: meta.ring, background: meta.glow, border: `1px solid ${meta.ring}44` }}
              >
                {level}
              </span>
            )}
          </>
        ) : (
          <span className="text-cq-on-surface-variant text-sm text-center px-6">
            Risk data unavailable
          </span>
        )}
        <span
          className={clsx(
            "mt-3 flex items-center gap-1.5 text-[10.5px] font-semibold tracking-[0.15em] uppercase",
          )}
          style={{ color: meta.ring }}
        >
          <span className="w-1.5 h-1.5 rounded-full cq-telemetry-dot" style={{ background: meta.ring }} />
          {meta.label}
        </span>
      </div>
    </div>
  );
}
