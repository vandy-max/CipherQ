import { motion } from "framer-motion";
import { ShieldHalf, Atom, FileLock2, KeyRound, ScrollText, LineChart, Link2, ShieldCheck } from "lucide-react";
import Button from "../components/ui/Button";
import QuantumField from "../components/quantum/QuantumField";
import QiraAvatar from "../components/qira/QiraAvatar";

const PILLS = [
  { icon: Atom, label: "BB84 (Qiskit)" },
  { icon: FileLock2, label: "Intent Canonicalization" },
  { icon: KeyRound, label: "HKDF Binding" },
  { icon: ShieldHalf, label: "AES-256-GCM" },
  { icon: ScrollText, label: "Policy Engine" },
  { icon: LineChart, label: "Adaptive Risk" },
  { icon: Link2, label: "Tamper-Evident Audit" },
];

export default function LandingPage({ navigate, isAuthenticated }) {
  return (
    <div className="relative min-h-screen overflow-hidden cq-matte-obsidian bg-cq-background">
      {/* Ambient background — CipherQ's own quantum field identity,
          consistent with the dashboard/quantum lab, layered under the
          existing glow/grid treatment rather than replacing it. */}
      <div className="pointer-events-none absolute inset-0">
        <QuantumField density="medium" tone="mixed" className="opacity-50" />
        <div className="absolute -top-40 -left-32 w-[520px] h-[520px] rounded-full bg-cq-primary-container/25 blur-[120px]" />
        <div className="absolute top-1/3 -right-32 w-[480px] h-[480px] rounded-full bg-cq-tertiary-container/20 blur-[120px]" />
        <div className="absolute bottom-0 left-1/4 w-[420px] h-[420px] rounded-full bg-cq-secondary-container/15 blur-[120px]" />
        <div
          className="absolute inset-0 opacity-[0.05]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,.4) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.4) 1px,transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
      </div>

      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-6 py-24 text-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="mb-6"
        >
          <QiraAvatar state="active" size={72} trackCursor={false} />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 rounded-full border border-cq-outline-variant/25 bg-cq-surface-container-high/60 px-4 py-1.5 text-[12.5px] font-semibold text-cq-on-surface-variant mb-8"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-cq-secondary animate-pulse" />
          Enterprise Security Platform
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="font-display-lg font-bold text-cq-on-surface leading-[1.05] text-[40px] sm:text-[56px] max-w-3xl tracking-tighter"
        >
          <span className="text-cq-primary">Intent-Bound</span> Quantum
          <br />
          Cryptography
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mt-6 max-w-2xl text-[15.5px] sm:text-[16.5px] leading-relaxed text-cq-on-surface-variant"
        >
          A quantum-derived key alone is not enough. Decryption only succeeds when the{" "}
          <strong className="text-cq-on-surface font-semibold">Cryptographic Intent Descriptor</strong> —
          sender, receiver, purpose, resource, operation, device, session, and validity window —
          matches exactly what was originally authorized.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.16 }}
          className="mt-9 flex flex-wrap items-center justify-center gap-2 max-w-3xl"
        >
          {PILLS.map((p) => (
            <span
              key={p.label}
              className="inline-flex items-center gap-1.5 rounded-full border border-cq-outline-variant/20 bg-cq-surface-container/60 px-3.5 py-1.5 text-[12.5px] font-medium text-cq-on-surface-variant"
            >
              <p.icon size={13} />
              {p.label}
            </span>
          ))}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.22 }}
          className="mt-10 flex flex-wrap items-center justify-center gap-3"
        >
          {isAuthenticated ? (
            <Button variant="brand" size="lg" onClick={() => navigate("dashboard")}>
              Go to Dashboard
            </Button>
          ) : (
            <>
              <Button variant="brand" size="lg" onClick={() => navigate("register")}>
                Get Started
              </Button>
              <Button
                variant="ghost"
                size="lg"
                className="!text-cq-on-surface !border-cq-outline-variant/25 hover:!bg-cq-surface-container-high/60"
                onClick={() => navigate("login")}
              >
                Sign In
              </Button>
            </>
          )}
        </motion.div>

        <div className="mt-16 inline-flex items-center gap-2 text-[12px] text-cq-on-surface-variant/70">
          <ShieldCheck size={13} />
          SOC2-style audit trail · Hash-chained · Zero plaintext-at-rest
        </div>
      </div>
    </div>
  );
}
