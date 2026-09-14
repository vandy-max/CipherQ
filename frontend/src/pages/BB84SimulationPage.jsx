import { useEffect, useState } from "react";
import { Atom, TrendingDown, Binary, CheckCircle2, XCircle, ArrowRight, Gauge, History } from "lucide-react";
import { motion } from "framer-motion";
import CopyBox from "../components/CopyBox";
import { Field, TextField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import BentoCard from "../components/ui/BentoCard";
import PageHeader from "../components/ui/PageHeader";
import QuantumField from "../components/quantum/QuantumField";
import QuantumChannel from "../components/quantum/QuantumChannel";
import { generateQuantumKey, quantumBackendInfo } from "../services/api";

function Pill({ ok, children }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap " +
        (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
      }
    >
      {ok ? <CheckCircle2 size={13} strokeWidth={2.5} /> : <XCircle size={13} strokeWidth={2.5} />}
      {children}
    </span>
  );
}

export default function BB84SimulationPage({ navigate }) {
  const [nQubits, setNQubits] = useState(256);
  const [eavesdropProb, setEavesdropProb] = useState(0);
  const [result, setResult] = useState(null);
  const [backendInfo, setBackendInfo] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    quantumBackendInfo()
      .then(setBackendInfo)
      .catch(() => setBackendInfo({ qiskit_available: false }));
  }, []);

  async function runSimulation() {
    setError("");
    setLoading(true);
    setResult(null);
    const startedAt = performance.now();
    try {
      const response = await generateQuantumKey(Number(nQubits), Number(eavesdropProb));
      const elapsedMs = Math.round(performance.now() - startedAt);
      setResult(response);
      setHistory((h) => [
        {
          ts: new Date(),
          nQubits: Number(nQubits),
          qber: response.qber,
          siftedBits: response.sifted_bits,
          aborted: response.session_aborted,
          elapsedMs,
        },
        ...h,
      ].slice(0, 8));
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Simulation failed");
    } finally {
      setLoading(false);
    }
  }

  const keyBits = result?.quantum_key_hex ? result.quantum_key_hex.length * 4 : 0;
  const efficiency = result && nQubits ? ((result.sifted_bits / Number(nQubits)) * 100).toFixed(1) : null;

  return (
    <div className="relative">
      <QuantumField density="low" tone="violet" className="opacity-30 -z-10" />
      <PageHeader
        icon="hub"
        eyebrow="Quantum Key Distribution"
        title="Quantum Lab"
        description="Real BB84 circuits run on Qiskit Aer, batched 6 exchanges per QuantumCircuit — not a classical stand-in. Eve's intercept-resend attack has a genuine physical effect on the sifted key and its measured QBER."
      />

      {/* Alice -> Quantum Channel -> Bob visualization, reflecting the
          actual run parameters and results below (never fabricated
          per-qubit detail — see QuantumChannel.jsx). */}
      <div className="mb-5">
        <QuantumChannel
          phase={loading ? "running" : result ? "result" : "idle"}
          nQubits={nQubits}
          eavesdropProb={eavesdropProb}
          result={result}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          {backendInfo?.qiskit_available ? (
            <Pill ok>{`Qiskit ${backendInfo.qiskit_version} · ${backendInfo.simulator}`}</Pill>
          ) : (
            <Pill>Qiskit backend not detected</Pill>
          )}

          <h2 className="text-[16px] font-bold text-cq-on-surface mt-4 mb-4">Session Parameters</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Number of qubits">
              <TextField type="number" min={16} max={2048} value={nQubits} onChange={(e) => setNQubits(e.target.value)} />
            </Field>
            <Field label="Eavesdrop probability (0–1)">
              <TextField
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={eavesdropProb}
                onChange={(e) => setEavesdropProb(e.target.value)}
              />
            </Field>
          </div>

          <Alert type="error">{error}</Alert>

          <Button variant="accent" accent="violet" full onClick={runSimulation} loading={loading} icon={Atom}>
            Run BB84 Exchange
          </Button>

          {loading && (
            <div className="mt-6 flex flex-col items-center justify-center gap-4 py-10 text-center">
              <div className="relative w-11 h-11">
                <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
                <motion.div
                  className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
                  animate={{ rotate: 360 }}
                  transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
                />
              </div>
              <p className="text-cq-body-md text-cq-on-surface-variant">Executing batched 6-qubit circuits on Qiskit Aer…</p>
            </div>
          )}

          {result && !loading && (
            <div
              className={
                "mt-6 rounded-cq-lg border p-5 " +
                (result.session_aborted
                  ? "border-cq-error/25 bg-cq-error-container/10"
                  : "border-cq-secondary/25 bg-cq-secondary-container/10")
              }
            >
              <div className="flex items-center gap-2 mb-4">
                {result.session_aborted ? (
                  <XCircle size={18} className="text-cq-error" />
                ) : (
                  <CheckCircle2 size={18} className="text-cq-secondary" />
                )}
                <h2 className="text-[15px] font-bold text-cq-on-surface">
                  {result.session_aborted ? "Session Aborted — Eavesdropper Detected" : "Key Established"}
                </h2>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-5">
                <BentoCard icon={TrendingDown} label="QBER" value={`${(result.qber * 100).toFixed(1)}%`} />
                <BentoCard icon={Binary} label="Sifted Bits" value={result.sifted_bits} />
                {!result.session_aborted && (
                  <BentoCard icon={Gauge} label="Sifting Efficiency" value={`${efficiency}%`} />
                )}
              </div>

              {result.qubits_per_circuit > 0 && (
                <div className="mb-5 rounded-cq-md bg-cq-surface-container-high/60 px-4 py-3 text-[12.5px] text-cq-on-surface-variant">
                  <span className="font-semibold text-cq-on-surface">{result.total_exchanges}</span> BB84 exchanges,
                  batched into{" "}
                  <span className="font-semibold text-cq-on-surface">{result.qubits_per_circuit}-qubit</span> circuits
                  {" — "}
                  {result.full_circuits} × {result.qubits_per_circuit}-qubit
                  {result.remainder_qubits > 0 ? ` + 1 × ${result.remainder_qubits}-qubit remainder` : ""} circuit
                  {result.full_circuits + (result.remainder_qubits > 0 ? 1 : 0) === 1 ? "" : "s"}.
                </div>
              )}

              {!result.session_aborted && (
                <>
                  <CopyBox label={`Quantum Shared Key — ${keyBits} bits (hex)`} value={result.quantum_key_hex} />
                  <div className="mt-4 rounded-cq-md bg-cq-primary-container/10 px-4 py-3 text-[13px] leading-relaxed text-cq-on-surface-variant">
                    <strong className="text-cq-on-surface">Reminder:</strong> this raw key is never used for AES
                    directly. The Encrypt page runs it through HKDF, bound to an intent hash, before it touches any
                    ciphertext.
                  </div>
                  <Button
                    variant="accent"
                    accent="mint"
                    full
                    iconRight={ArrowRight}
                    className="mt-4"
                    onClick={() => navigate("encrypt", { quantumKeyHex: result.quantum_key_hex })}
                  >
                    Use this key to encrypt
                  </Button>
                </>
              )}
            </div>
          )}
        </div>

        {/* Session history */}
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-1">
            <History size={16} className="text-cq-primary" />
            <h2 className="text-[15px] font-bold text-cq-on-surface">Session History</h2>
          </div>
          <p className="text-[12.5px] text-cq-on-surface-variant mb-4">Recent exchanges run in this browser session.</p>
          {history.length === 0 ? (
            <div className="flex flex-col items-center justify-center text-center py-14 px-6">
              <div className="text-[14.5px] font-semibold text-cq-on-surface">No sessions yet</div>
              <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">
                Run an exchange to see it appear here.
              </div>
            </div>
          ) : (
            <div className="space-y-2.5">
              {history.map((h, i) => (
                <div key={i} className="rounded-cq-md border border-cq-outline-variant/25 px-3.5 py-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[12.5px] font-semibold text-cq-on-surface">{h.nQubits} qubits</span>
                    <Pill ok={!h.aborted}>{h.aborted ? "aborted" : "ok"}</Pill>
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-[11.5px] text-cq-on-surface-variant">
                    <span>QBER {(h.qber * 100).toFixed(1)}%</span>
                    <span>{h.siftedBits} bits</span>
                    <span>{h.elapsedMs}ms</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
