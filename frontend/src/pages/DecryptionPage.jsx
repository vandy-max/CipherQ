import { useEffect, useState } from "react";
import { Download,  KeyRound, CheckCircle2, XCircle, ShieldAlert } from "lucide-react";
import RiskPill from "../components/ui/RiskPill";
import AIRiskAssessment from "../components/ui/AIRiskAssessment";
import { TaskChecklist } from "../components/ui/WorkflowStepper";
import { Field, TextField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import SecurityFlowStrip from "../components/quantum/SecurityFlowStrip";
import { decrypt } from "../services/api";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import MonitoringBlockedBanner from "../components/monitoring/MonitoringBlockedBanner";
import { useMonitoringContext } from "../context/MonitoringContext";

const OPERATIONS = ["encrypt", "decrypt", "read", "write", "share", "revoke"];

function isoLocalToUtc(value) {
  if (!value) return "";
  return new Date(value).toISOString();
}

function toIsoOrEmpty(value) {
  if (!value) return "";
  try {
    // `value` is a UTC instant (e.g. from the stored CID). An
    // <input type="datetime-local"> displays/edits *local* wall-clock
    // time with no timezone info, so we must shift by the browser's
    // UTC offset before slicing — otherwise the displayed value silently
    // represents a different instant than the one that was encrypted
    // under, and resubmitting it (via isoLocalToUtc) reintroduces that
    // offset as a real timestamp change, breaking the intent hash even
    // though the user never touched the field.
    const utcDate = new Date(value);
    const localDate = new Date(utcDate.getTime() - utcDate.getTimezoneOffset() * 60000);
    return localDate.toISOString().slice(0, 16);
  } catch {
    return "";
  }
}

// One-click mutations demonstrating the spec's rejection scenarios.
const TAMPER_SCENARIOS = [
  { id: "purpose", label: "Change purpose", field: "purpose", value: "unauthorized-purpose" },
  { id: "device", label: "Change device", field: "device_id", value: "device-unregistered" },
  { id: "resource", label: "Change resource", field: "resource", value: "reports/different.pdf" },
  { id: "operation", label: "Change operation", field: "operation", value: "encrypt" },
  { id: "session", label: "Change session", field: "session_id", value: "session-different" },
];

// The verification pipeline the backend actually runs, in order. Each
// call resolves to exactly one real outcome (success, or a specific
// HTTP status) — that outcome tells us which stage to mark as failed.
const PIPELINE = [
  { key: "recreate", label: "Recreate Intent Context" },
  { key: "hash", label: "Canonicalize & Hash Comparison" },
  { key: "derive", label: "HKDF Key Derivation" },
  { key: "decrypt", label: "AES-256-GCM Decrypt & Integrity Check" },
  { key: "risk", label: "Adaptive Risk Assessment" },
];

function buildPipelineStatus({ loading, outcome }) {
  // outcome: null (not run) | "success" | "mismatch" (403) | "stepup" (428) | "error"
  if (!outcome && !loading) return PIPELINE.map((p) => ({ ...p, status: "pending" }));
  if (loading) return PIPELINE.map((p, i) => ({ ...p, status: i === 0 ? "active" : "pending" }));
  if (outcome === "success") return PIPELINE.map((p) => ({ ...p, status: "done" }));
  if (outcome === "mismatch")
    return PIPELINE.map((p, i) => ({
      ...p,
      status: i === 0 ? "done" : i === 1 ? "fail" : "pending",
    }));
  if (outcome === "stepup")
    return PIPELINE.map((p, i) => ({ ...p, status: i < 4 ? "done" : "fail" }));
  return PIPELINE.map((p, i) => (i === 0 ? { ...p, status: "fail" } : { ...p, status: "pending" }));
}

export default function DecryptionPage({ navigate, shared, user }) {
  // Device ID / Session ID are never typed by the user (fix pass:
  // crypto1-admin-encryption). They come from the same authoritative
  // source every other page uses (MonitoringContext -> the current
  // authenticated device/session), falling back to whatever CID was
  // handed off from a just-completed Encryption if that's more
  // specific (e.g. arriving here via "Try decrypting this record").
  const { deviceId, sessionId } = useMonitoringContext();
  const [recordId, setRecordId] = useState(shared?.recordId ?? "");
  const [quantumKeyHex, setQuantumKeyHex] = useState(shared?.lastQuantumKeyHex || "");
  const c = shared?.lastCid;
  const [cidForm, setCidForm] = useState({
    sender: c?.sender || "",
    receiver: c?.receiver || "",
    purpose: c?.purpose || "",
    resource: c?.resource || "",
    operation: c?.operation || "decrypt",
    device_id: c?.device_id || deviceId || "",
    session_id: c?.session_id || sessionId || "",
    valid_from: toIsoOrEmpty(c?.valid_from),
    valid_until: toIsoOrEmpty(c?.valid_until),
    // Optional CID fields. These are part of the canonical hash too —
    // if the original intent set any of these, omitting them here would
    // silently change the recreated CID and break the hash comparison
    // even though nothing was "tampered" with.
    classification: c?.classification || "",
    department: c?.department || "",
    project: c?.project || "",
  });
  // metadata is an arbitrary object, not a simple text field — carry it
  // through unedited exactly as it came from the stored intent so it's
  // never lost on recreation.
  const [metadata] = useState(c?.metadata ?? null);
  const [result, setResult] = useState(null);
  const [outcome, setOutcome] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showFaceGate, setShowFaceGate] = useState(false);
  const [pendingCid, setPendingCid] = useState(null);

  const set = (key) => (e) => setCidForm((f) => ({ ...f, [key]: e.target.value }));

  // deviceId/sessionId are resolved asynchronously (device fingerprint
  // hashing, session bootstrap) and can still be null on first render.
  // Backfill the auto-detected fields once they resolve — but only when
  // no explicit CID was handed off from Encryption, so a real
  // encrypt-time device/session is never silently overwritten with the
  // current one.
  useEffect(() => {
    if (c) return;
    setCidForm((f) => ({
      ...f,
      device_id: f.device_id || deviceId || "",
      session_id: f.session_id || sessionId || "",
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId, sessionId, c]);

  function applyTamper(scenario) {
    setCidForm((f) => ({ ...f, [scenario.field]: scenario.value }));
    setResult(null);
    setOutcome(null);
    setError("");
  }

  function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setOutcome(null);
    const cid = {
      ...cidForm,
      valid_from: isoLocalToUtc(cidForm.valid_from),
      valid_until: isoLocalToUtc(cidForm.valid_until),
      classification: cidForm.classification || null,
      department: cidForm.department || null,
      project: cidForm.project || null,
      metadata: metadata,
    };
    // Decryption always opens with a live face check — the reusable
    // Face Authentication panel below drives it; the actual
    // /api/decrypt call only fires from its onSuccess handler.
    setPendingCid(cid);
    setShowFaceGate(true);
  }

  async function runDecrypt(faceDescriptor) {
    setShowFaceGate(false);
    setLoading(true);
    try {
      const response = await decrypt(Number(recordId), pendingCid, quantumKeyHex, faceDescriptor);
      setResult(response);
      setOutcome("success");
    } catch (err) {
      if (err.status === 428) {
        setOutcome("stepup");
        setError(
          "Adaptive risk assessment still requires a stronger match — retry face verification."
        );
      } else if (err.status === 403) {
        setOutcome("mismatch");
        setError(err.detail?.toString?.() || "Rejected: intent context did not match.");
      } else {
        setOutcome("error");
        setError(err.detail?.toString?.() || err.message || "Decryption failed");
      }
    } finally {
      setLoading(false);
    }
  }

  function decodePlaintext(base64) {
    try {
      return decodeURIComponent(escape(atob(base64)));
    } catch {
      return atob(base64);
    }
  }

  function downloadDecryptedFile() {
    if (!result?.plaintext_base64 || !metadata?.attachment) return;
    try {
      const binary = atob(result.plaintext_base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: metadata.attachment.mime_type || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = metadata.attachment.filename || "decrypted-file";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError("Could not reconstruct the decrypted file.");
    }
  }


  const pipeline = buildPipelineStatus({ loading, outcome });

  return (
    <div>
      <PageHeader
        icon="lock_open"
        eyebrow="Decryption Verification"
        title="Decryption"
        description="Recreate → canonicalize → hash → compare → HKDF → decrypt. Any mismatch between the recreated intent hash and the bound record is rejected and logged."
      />
      <MonitoringBlockedBanner />

      <div className="mb-5">
        <SecurityFlowStrip
          inputLabel="Ciphertext"
          outputLabel="Plaintext"
          mode="decrypt"
          active={loading}
          done={outcome === "success"}
          failed={Boolean(outcome) && outcome !== "success"}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="text-[16px] font-bold text-cq-on-surface mb-4">Decrypt a Record</h2>
          <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
              <Field label="Record ID">
                <TextField type="number" value={recordId} onChange={(e) => setRecordId(e.target.value)} required />
              </Field>
              <Field label="Quantum Key (hex)">
                <TextField mono value={quantumKeyHex} onChange={(e) => setQuantumKeyHex(e.target.value)} required />
              </Field>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
              <Field label="Sender">
                <TextField value={cidForm.sender} onChange={set("sender")} required />
              </Field>
              <Field label="Receiver">
                <TextField value={cidForm.receiver} onChange={set("receiver")} required />
              </Field>
            </div>
            <Field label="Purpose">
              <TextField value={cidForm.purpose} onChange={set("purpose")} required />
            </Field>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
              <Field label="Resource">
                <TextField value={cidForm.resource} onChange={set("resource")} required />
              </Field>
              <Field label="Operation">
                <SelectField value={cidForm.operation} onChange={set("operation")}>
                  {OPERATIONS.map((op) => (
                    <option key={op} value={op}>{op}</option>
                  ))}
                </SelectField>
              </Field>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
              <Field label="Device ID" hint="auto-detected from this session">
                <TextField value={cidForm.device_id} readOnly required className="opacity-80" />
              </Field>
              <Field label="Session ID" hint="auto-detected from this session">
                <TextField value={cidForm.session_id} readOnly required className="opacity-80" />
              </Field>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
              <Field label="Valid From">
                <TextField type="datetime-local" value={cidForm.valid_from} onChange={set("valid_from")} required />
              </Field>
              <Field label="Valid Until">
                <TextField type="datetime-local" value={cidForm.valid_until} onChange={set("valid_until")} required />
              </Field>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-x-5">
              <Field label="Classification" hint="optional">
                <TextField value={cidForm.classification} onChange={set("classification")} />
              </Field>
              <Field label="Department" hint="optional">
                <TextField value={cidForm.department} onChange={set("department")} />
              </Field>
              <Field label="Project" hint="optional">
                <TextField value={cidForm.project} onChange={set("project")} />
              </Field>
            </div>

            <Field label="Demonstration scenarios" hint="mutate one field, then Decrypt">
              <div className="flex flex-wrap gap-2">
                {TAMPER_SCENARIOS.map((s) => (
                  <Button key={s.id} type="button" variant="outline" size="sm" onClick={() => applyTamper(s)}>
                    {s.label}
                  </Button>
                ))}
              </div>
            </Field>

            <Alert type="error">{error}</Alert>

            {showFaceGate ? (
              <FaceAuthPanel
                mode="verify"
                title="Verify your identity to decrypt"
                subtitle="A live face check runs before every decryption request."
                onSuccess={({ descriptor }) => runDecrypt(descriptor)}
                onCancel={() => setShowFaceGate(false)}
              />
            ) : (
              <Button type="submit" variant="accent" accent="peach" full loading={loading} icon={KeyRound}>
                Decrypt
              </Button>
            )}
          </form>

          {result && (
            <div className="mt-6 rounded-cq-lg bg-cq-secondary-container/10 border border-cq-secondary/25 p-5">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle2 size={18} className="text-cq-secondary" />
                <h2 className="text-[16px] font-bold text-cq-on-surface">Plaintext Recovered</h2>
                <span className="ml-auto">
                  <RiskPill level={result.risk_level} />
                </span>
              </div>
              {metadata?.attachment ? (
                <div className="rounded-cq-md bg-cq-surface-container-high px-4 py-3.5">
                  <div className="flex items-center gap-2 text-[13px] font-semibold text-cq-on-surface">
                    <Download size={16} className="text-cq-secondary" />
                    <span className="truncate">{metadata.attachment.filename}</span>
                  </div>
                  <div className="mt-1 text-[12px] text-cq-on-surface-variant">
                    {metadata.attachment.mime_type || "application/octet-stream"} · decrypted binary content recovered
                  </div>
                  <Button
                    type="button"
                    variant="accent"
                    accent="mint"
                    full
                    icon={Download}
                    className="mt-3"
                    onClick={downloadDecryptedFile}
                  >
                    Download Decrypted File
                  </Button>
                </div>
              ) : (
                <div className="rounded-cq-md bg-cq-surface-container-high px-4 py-3.5 text-[14px] leading-relaxed text-cq-on-surface whitespace-pre-wrap break-words">
                  {decodePlaintext(result.plaintext_base64)}
                </div>
              )}
              <div className="mt-2.5 text-[12px] text-cq-on-surface-variant">risk score {result.risk_score}</div>
              <AIRiskAssessment result={result} />
            </div>
          )}
        </div>

        {/* Verification pipeline */}
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-1">
            {outcome === "mismatch" || outcome === "error" ? (
              <XCircle size={17} className="text-cq-error" />
            ) : outcome === "success" ? (
              <CheckCircle2 size={17} className="text-cq-secondary" />
            ) : (
              <ShieldAlert size={17} className="text-cq-primary" />
            )}
            <h2 className="text-[15px] font-bold text-cq-on-surface">Verification Pipeline</h2>
          </div>
          <p className="text-[12.5px] text-cq-on-surface-variant mb-4 leading-relaxed">
            The exact stage order the backend evaluates on every decrypt call.
          </p>
          <TaskChecklist items={pipeline} />
        </div>
      </div>
    </div>
  );
}
