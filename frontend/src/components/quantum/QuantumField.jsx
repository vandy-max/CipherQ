import { useMemo } from "react";
import clsx from "clsx";

/**
 * QuantumField — ambient background particle/field effect used behind
 * hero surfaces (dashboard hero, Quantum Lab, page shells). Purely
 * decorative: renders a fixed set of deterministically-seeded dots
 * drifting slowly along faint orbital paths, plus a soft radial glow.
 *
 * Deliberately SVG + CSS transforms only (no canvas, no per-frame JS) —
 * cheap to render and safe under prefers-reduced-motion (handled in
 * globals.css via [data-cq-motion]).
 *
 * density: "low" | "medium" | "high" — particle count.
 * tone: "cyan" | "violet" | "mixed" — accent coloring.
 */
const DENSITY = { low: 14, medium: 26, high: 40 };

function seededRandom(seed) {
  let s = seed;
  return () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

export default function QuantumField({
  density = "medium",
  tone = "mixed",
  className,
  seed = 42,
  interactive = false,
}) {
  const count = DENSITY[density] || DENSITY.medium;

  const particles = useMemo(() => {
    const rand = seededRandom(seed);
    return Array.from({ length: count }, (_, i) => {
      const cx = rand() * 100;
      const cy = rand() * 100;
      const r = 0.6 + rand() * 1.4;
      const duration = 14 + rand() * 18;
      const delay = -rand() * duration;
      const orbit = 3 + rand() * 6;
      const useViolet = tone === "violet" || (tone === "mixed" && rand() > 0.62);
      return { id: i, cx, cy, r, duration, delay, orbit, useViolet };
    });
  }, [count, seed, tone]);

  return (
    <div
      aria-hidden="true"
      className={clsx("pointer-events-none absolute inset-0 overflow-hidden", className)}
    >
      <svg viewBox="0 0 100 100" preserveAspectRatio="xMidYMid slice" className="w-full h-full">
        <defs>
          <radialGradient id="cqf-cyan" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#63f7ff" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#63f7ff" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="cqf-violet" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#e9b3ff" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#e9b3ff" stopOpacity="0" />
          </radialGradient>
        </defs>
        {/* faint connective lines between nearby particles for a "field" feel */}
        <g strokeWidth="0.08" className="cq-qfield-lines">
          {particles.slice(0, count - 1).map((p, i) => {
            const next = particles[i + 1];
            const dist = Math.hypot(p.cx - next.cx, p.cy - next.cy);
            if (dist > 22) return null;
            return (
              <line
                key={`l-${p.id}`}
                x1={p.cx}
                y1={p.cy}
                x2={next.cx}
                y2={next.cy}
                stroke={p.useViolet ? "#a03ad3" : "#2e5bff"}
                strokeOpacity="0.35"
              />
            );
          })}
        </g>
        {particles.map((p) => (
          <circle
            key={p.id}
            cx={p.cx}
            cy={p.cy}
            r={p.r}
            fill={p.useViolet ? "url(#cqf-violet)" : "url(#cqf-cyan)"}
            className="cq-qfield-particle"
            style={{
              "--cqf-orbit": `${p.orbit}px`,
              animationDuration: `${p.duration}s`,
              animationDelay: `${p.delay}s`,
            }}
          />
        ))}
      </svg>
    </div>
  );
}
