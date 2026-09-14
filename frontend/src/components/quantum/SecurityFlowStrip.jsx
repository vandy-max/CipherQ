import { motion } from "framer-motion";
import clsx from "clsx";

/**
 * SecurityFlowStrip — visual "DATA -> CIPHERQ SECURITY LAYER -> OUTPUT"
 * flow used on Encryption/Decryption pages in place of a plain
 * input/button/output layout (spec section 22).
 *
 * Purely presentational: `active` reflects a REAL in-flight
 * operation (the page's own `loading`/`stage` state) and `done`
 * reflects a REAL completed result — this component never claims an
 * operation happened on its own.
 *
 * Props:
 *  - inputLabel / outputLabel: strings describing the real data (e.g. "Plaintext" / "Ciphertext")
 *  - active: boolean — an operation is currently running
 *  - done: boolean — a real result exists
 *  - failed: boolean — the real operation ended in an error
 *  - mode: "encrypt" | "decrypt" — flips the arrow direction's color accent only
 */
export default function SecurityFlowStrip({ inputLabel, outputLabel, active, done, failed, mode = "encrypt" }) {
  const accent = mode === "encrypt" ? "#63f7ff" : "#e9b3ff";
  return (
    <div className="rounded-cq-lg bg-cq-surface-container-low border border-cq-outline-variant/15 px-cq-stack-lg py-cq-stack-md">
      <div className="flex items-center gap-3 sm:gap-5">
        <Node label={inputLabel} icon={mode === "encrypt" ? "description" : "lock"} state={done || active ? "on" : "idle"} />

        <div className="flex-1 min-w-[60px] flex flex-col items-center">
          <div className="relative w-full h-[2px] bg-cq-outline-variant/25 rounded-full overflow-hidden">
            {active && (
              <motion.div
                className="absolute inset-y-0 w-1/3 rounded-full"
                style={{ background: accent }}
                animate={{ x: ["-40%", "140%"] }}
                transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut" }}
              />
            )}
            {done && !failed && <div className="absolute inset-0 rounded-full" style={{ background: accent, opacity: 0.6 }} />}
          </div>
          <span className="text-[9px] font-bold tracking-[0.16em] text-cq-on-surface-variant/60 uppercase mt-1.5 whitespace-nowrap">
            Security Layer
          </span>
        </div>

        <div className="relative">
          <span
            className={clsx(
              "flex items-center justify-center w-11 h-11 rounded-cq-md border transition-colors",
              failed ? "border-cq-error/40 bg-cq-error-container/10" : "border-cq-outline-variant/30 bg-cq-surface-container-high"
            )}
          >
            <span
              className="material-symbols-outlined text-[20px]"
              style={{ color: failed ? "#ffb4ab" : accent }}
            >
              shield_lock
            </span>
          </span>
          {active && (
            <span
              className="absolute inset-0 rounded-cq-md animate-ping"
              style={{ border: `1px solid ${accent}` }}
            />
          )}
        </div>

        <div className="flex-1 min-w-[60px] flex flex-col items-center">
          <div className="relative w-full h-[2px] bg-cq-outline-variant/25 rounded-full overflow-hidden">
            {active && (
              <motion.div
                className="absolute inset-y-0 w-1/3 rounded-full"
                style={{ background: accent }}
                animate={{ x: ["-40%", "140%"] }}
                transition={{ duration: 1.1, repeat: Infinity, ease: "easeInOut", delay: 0.15 }}
              />
            )}
            {done && !failed && <div className="absolute inset-0 rounded-full" style={{ background: accent, opacity: 0.6 }} />}
          </div>
          <span className="text-[9px] font-bold tracking-[0.16em] text-cq-on-surface-variant/60 uppercase mt-1.5 whitespace-nowrap">
            CipherQ
          </span>
        </div>

        <Node
          label={outputLabel}
          icon={mode === "encrypt" ? "lock" : "description"}
          state={failed ? "error" : done ? "done" : "idle"}
        />
      </div>
    </div>
  );
}

function Node({ label, icon, state }) {
  const tone =
    state === "done" ? "text-cq-secondary border-cq-secondary/30 bg-cq-secondary-container/10" :
    state === "on" ? "text-cq-primary border-cq-primary/30 bg-cq-primary-container/10" :
    state === "error" ? "text-cq-error border-cq-error/30 bg-cq-error-container/10" :
    "text-cq-on-surface-variant border-cq-outline-variant/25 bg-cq-surface-container-high";
  return (
    <div className="flex flex-col items-center gap-1.5 shrink-0">
      <span className={clsx("flex items-center justify-center w-11 h-11 rounded-cq-md border", tone)}>
        <span className="material-symbols-outlined text-[19px]">{icon}</span>
      </span>
      <span className="text-[9.5px] font-bold tracking-[0.1em] text-cq-on-surface-variant uppercase text-center max-w-[70px] leading-tight">
        {label}
      </span>
    </div>
  );
}
