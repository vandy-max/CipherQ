import { motion } from "framer-motion";

/**
 * QuantumChannel — Alice -> Quantum Channel -> Bob visualization for
 * the Quantum Lab (BB84) page.
 *
 * IMPORTANT: the backend does not return per-qubit basis/measurement
 * data (see QuantumGenerateKeyResponse in api/schemas.py — only
 * aggregate qber/sifted_bits/session_aborted). This component
 * therefore visualizes the REAL aggregate values and the run
 * parameters the user chose (nQubits, eavesdropProb) — it never
 * fabricates individual photon/basis/measurement sequences that
 * weren't actually returned by the simulation.
 *
 * Props:
 *  - phase: "idle" | "running" | "result"
 *  - nQubits: number (requested)
 *  - eavesdropProb: number 0-1 (requested)
 *  - result: { qber, sifted_bits, session_aborted } | null
 */
export default function QuantumChannel({ phase = "idle", nQubits, eavesdropProb = 0, result }) {
  const aborted = result?.session_aborted;
  const eveActive = Number(eavesdropProb) > 0;
  const lineColor = aborted ? "#ffb4ab" : "#63f7ff";
  const running = phase === "running";

  return (
    <div className="relative rounded-cq-lg bg-cq-surface-container-low border border-cq-outline-variant/15 p-cq-stack-lg overflow-hidden">
      <svg viewBox="0 0 600 160" className="w-full h-auto">
        <defs>
          <linearGradient id="qc-channel" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#2e5bff" stopOpacity="0.9" />
            <stop offset="50%" stopColor={lineColor} stopOpacity="0.9" />
            <stop offset="100%" stopColor="#a03ad3" stopOpacity="0.9" />
          </linearGradient>
        </defs>

        {/* channel line */}
        <line x1="80" y1="80" x2="520" y2="80" stroke="url(#qc-channel)" strokeWidth="2" strokeDasharray="4 4" opacity="0.55" />

        {/* Alice */}
        <g transform="translate(50,80)">
          <circle r="26" fill="#1d1f29" stroke="#2e5bff" strokeWidth="1.5" />
          <text textAnchor="middle" dy="-34" className="fill-cq-on-surface text-[12px] font-bold">Alice</text>
          <text textAnchor="middle" dy="5" className="fill-cq-primary text-[10px] font-mono">
            {nQubits ? `${nQubits}q` : "—"}
          </text>
        </g>

        {/* Bob */}
        <g transform="translate(550,80)">
          <circle r="26" fill="#1d1f29" stroke="#a03ad3" strokeWidth="1.5" />
          <text textAnchor="middle" dy="-34" className="fill-cq-on-surface text-[12px] font-bold">Bob</text>
          <text textAnchor="middle" dy="5" className="fill-cq-tertiary text-[10px] font-mono">
            {result ? `${result.sifted_bits} bits` : "—"}
          </text>
        </g>

        {/* Eve — only shown when an eavesdrop probability was actually configured for this run */}
        {eveActive && (
          <g transform="translate(300,32)">
            <circle r="16" fill="#1d1f29" stroke="#ffb4ab" strokeWidth="1.5" strokeDasharray="2 2" />
            <text textAnchor="middle" dy="4" className="fill-cq-error text-[11px] font-bold">Eve</text>
            <line x1="0" y1="16" x2="0" y2="44" stroke="#ffb4ab" strokeWidth="1" strokeDasharray="2 3" opacity="0.7" />
          </g>
        )}

        {/* travelling photons along the channel, animated while running or when a
            successful/aborted result exists — purely decorative motion, not
            per-qubit ground truth */}
        {(running || result) &&
          Array.from({ length: 6 }).map((_, i) => (
            <circle
              key={i}
              r="3"
              fill={i % 2 === 0 ? "#63f7ff" : "#e9b3ff"}
              style={{
                offsetPath: "path('M80,80 L520,80')",
                animation: `cq-travel ${1.6 + i * 0.15}s linear infinite`,
                animationDelay: `${i * 0.28}s`,
              }}
              className={running ? "" : aborted ? "opacity-40" : ""}
            />
          ))}

        {/* result state label */}
        {result && (
          <text x="300" y="130" textAnchor="middle" className={`text-[11px] font-bold ${aborted ? "fill-cq-error" : "fill-cq-secondary"}`}>
            {aborted ? "SESSION ABORTED — EAVESDROPPER DETECTED" : `KEY ESTABLISHED · QBER ${(result.qber * 100).toFixed(1)}%`}
          </text>
        )}
      </svg>

      {running && (
        <motion.div
          className="absolute inset-x-0 top-0 h-full pointer-events-none"
          initial={{ opacity: 0 }}
          animate={{ opacity: [0, 0.15, 0] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
          style={{ background: "linear-gradient(90deg, transparent, #63f7ff33, transparent)" }}
        />
      )}
    </div>
  );
}
