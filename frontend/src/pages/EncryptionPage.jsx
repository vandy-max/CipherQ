import { useEffect, useMemo, useState } from "react";
import { Lock, ArrowRight, CheckCircle2, Search, ShieldAlert, Paperclip, X } from "lucide-react";
import CopyBox from "../components/CopyBox";
import LifecyclePill from "../components/ui/LifecyclePill";
import RiskPill from "../components/ui/RiskPill";
import AIRiskAssessment from "../components/ui/AIRiskAssessment";
import { WorkflowStepper, TaskChecklist } from "../components/ui/WorkflowStepper";
import { Field, TextField, TextAreaField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import SecurityFlowStrip from "../components/quantum/SecurityFlowStrip";
import { encrypt, resolveIntentByHash } from "../services/api";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import MonitoringBlockedBanner from "../components/monitoring/MonitoringBlockedBanner";
import { formatTimestamp } from "../utils/formatTimestamp";

function toBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function bytesToBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

async function fileToBase64(file) {
  const buffer = await file.arrayBuffer();
  return bytesToBase64(new Uint8Array(buffer));
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// Uses the single centralized timestamp formatter (utils/formatTimestamp)
// so this page never diverges from the rest of the app's UTC-safe,
// locale-aware display rules.
function formatDate(value) {
  if (!value) return "—";
  try {
    return formatTimestamp(value);
  } catch {
    return value;
  }
}

const STEPS = ["Resolve Intent", "Quantum Key", "Encrypt"];

/**
 * Fix pass sections B + F.
 *
 * B: this page must NEVER create or auto-approve an intent on the
 * user's behalf — the old fallback that did exactly that (create ->
 * immediately transition to "approved" -> encrypt) has been removed
 * entirely. There is no code path here that calls createIntent or
 * transitionIntent.
 *
 * F: instead, a user with an already-APPROVED intent pastes its hex
 * intent hash below. The backend resolves the AUTHORITATIVE stored
 * intent (GET /api/intent/by-hash/{hash}) and returns its owner,
 * resource, operation, purpose, lifecycle state, and validity window.
 * None of that — especially the validity window — is ever typed by
 * the user or trusted from the browser; it is displayed exactly as
 * the backend reports it, and the same object is submitted back
 * unmodified for the actual /api/encrypt call (which independently
 * re-verifies the hash and lifecycle state before doing anything
 * cryptographic).
 */
export default function EncryptionPage({ navigate, shared }) {
  const [quantumKeyHex, setQuantumKeyHex] = useState(shared?.quantumKeyHex || "");
  const [plaintext, setPlaintext] = useState("");
  const attachedFile = shared?.attachedFile || null;
  const attachmentMetadata = shared?.attachmentMetadata || null;

  const [hashInput, setHashInput] = useState("");
  const [resolved, setResolved] = useState(null); // IntentResolveResponse from the backend
  const [resolving, setResolving] = useState(false);
  const [resolveError, setResolveError] = useState("");

  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState(null); // "deriving" | "encrypting" | null
  const [showFaceGate, setShowFaceGate] = useState(false);

  // A caller can still arrive here handed off directly from Create
  // Intent (already went through the real Draft -> Approved
  // transition there, by an authorized approver) — that is a
  // legitimate shortcut, not the removed auto-approve fallback, since
  // no lifecycle transition happens on this page either way.
  useEffect(() => {
    if (shared?.intentCid && shared?.intentId && !resolved) {
      setResolved({
        intent_id: shared.intentId,
        intent_hash: shared.intentHash || "",
        lifecycle_state: shared.intentLifecycleState || "approved",
        created_by: shared.intentOwner,
        sender: shared.intentCid.sender,
        receiver: shared.intentCid.receiver,
        purpose: shared.intentCid.purpose,
        resource: shared.intentCid.resource,
        operation: shared.intentCid.operation,
        device_id: shared.intentCid.device_id,
        session_id: shared.intentCid.session_id,
        valid_from: shared.intentCid.valid_from,
        valid_until: shared.intentCid.valid_until,
        cid: shared.intentCid,
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleResolve(e) {
    e.preventDefault();
    setResolveError("");
    setResolved(null);
    const hash = hashInput.trim();
    if (!hash) return;
    setResolving(true);
    try {
      const intent = await resolveIntentByHash(hash);
      setResolved(intent);
    } catch (err) {
      setResolveError(err.detail?.toString?.() || err.message || "Could not resolve that intent hash");
    } finally {
      setResolving(false);
    }
  }

  const isApproved = resolved?.lifecycle_state === "approved";
  const intentComplete = Boolean(resolved) && isApproved;
  const keyComplete = Boolean(quantumKeyHex);
  const activeStep = result ? 3 : !intentComplete ? 0 : !keyComplete ? 1 : 2;

  function handleSubmit(e) {
    e.preventDefault();
    setError("");
    // Before encryption starts, the user must pass live face
    // verification — this opens the reusable Face Authentication
    // panel; the actual /api/encrypt call only fires from its
    // onSuccess handler below.
    setShowFaceGate(true);
  }

  async function runEncrypt(faceDescriptor) {
    setShowFaceGate(false);
    setError("");
    setLoading(true);
    setStage("deriving");
    try {
      // The CID submitted here is exactly the one the backend
      // resolved and displayed — never hand-edited, never
      // reconstructed client-side. /api/encrypt independently
      // recomputes its canonical hash and rejects anything that
      // doesn't match the approved intent's stored hash.
      const cid = resolved.cid;
      await new Promise((r) => setTimeout(r, 350));
      setStage("encrypting");
      const plaintextBase64 = attachedFile ? await fileToBase64(attachedFile) : toBase64(plaintext);
      const response = await encrypt(resolved.intent_id, cid, plaintextBase64, quantumKeyHex, faceDescriptor);
      setResult({ ...response, cid });
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Encryption failed");
    } finally {
      setLoading(false);
      setStage(null);
    }
  }

  const checklistItems = useMemo(
    () => [
      { label: "Canonicalize intent context", status: stage ? "done" : "pending" },
      { label: "Derive key via HKDF (quantum key + intent hash)", status: stage === "deriving" ? "active" : stage === "encrypting" ? "done" : "pending" },
      { label: "AES-256-GCM encrypt", status: stage === "encrypting" ? "active" : "pending" },
    ],
    [stage]
  );

  return (
    <div>
      <PageHeader
        icon="lock"
        eyebrow="Encryption Pipeline"
        title="Encryption"
        description="HKDF derives an intent-bound key from the quantum key plus the intent hash, then AES-256-GCM seals the payload. No key ever touches ciphertext without a validated intent binding."
      />
      <MonitoringBlockedBanner />

      <div className="mb-5">
        <SecurityFlowStrip
          inputLabel={attachedFile ? "File" : "Plaintext"}
          outputLabel="Ciphertext"
          mode="encrypt"
          active={loading}
          done={Boolean(result)}
          failed={Boolean(error) && !loading}
        />
      </div>

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <WorkflowStepper steps={STEPS} activeIndex={activeStep} />

        <h2 className="text-[16px] font-bold text-cq-on-surface mb-1">Resolve Intent</h2>
        <p className="text-[13px] text-cq-on-surface-variant mb-4">
          Paste the hex intent hash of an already-approved intent. The system looks up the
          authoritative stored intent — its validity window is never something you type here.
        </p>

        <form onSubmit={handleResolve} className="flex items-start gap-2.5 mb-2">
          <div className="flex-1">
            <TextField
              mono
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder="Intent hash (sha256 hex)"
            />
          </div>
          <Button type="submit" variant="ghost" icon={Search} loading={resolving}>
            Resolve Intent
          </Button>
        </form>
        <Alert type="error">{resolveError}</Alert>

        {resolved && (
          <div className="rounded-cq-lg border border-cq-outline-variant/25 bg-cq-surface-container-lowest px-4 py-3.5 mb-4">
            <div className="flex items-center gap-2.5 mb-2.5 flex-wrap">
              <LifecyclePill state={resolved.lifecycle_state} />
              <code className="text-[12.5px] text-cq-on-surface-variant font-mono break-all">
                {resolved.intent_hash || "(hash pending on handed-off intent)"}
              </code>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-[13px]">
              <div><span className="text-cq-on-surface-variant">Resource: </span><span className="text-cq-on-surface font-medium">{resolved.resource}</span></div>
              <div><span className="text-cq-on-surface-variant">Operation: </span><span className="text-cq-on-surface font-medium">{resolved.operation}</span></div>
              <div><span className="text-cq-on-surface-variant">Purpose: </span><span className="text-cq-on-surface font-medium">{resolved.purpose}</span></div>
              <div><span className="text-cq-on-surface-variant">Owner (user id): </span><span className="text-cq-on-surface font-medium">{resolved.created_by}</span></div>
              <div><span className="text-cq-on-surface-variant">Device: </span><span className="text-cq-on-surface font-mono text-[12px]">{resolved.device_id}</span></div>
              <div><span className="text-cq-on-surface-variant">Session: </span><span className="text-cq-on-surface font-mono text-[12px]">{resolved.session_id}</span></div>
              <div><span className="text-cq-on-surface-variant">Valid from: </span><span className="text-cq-on-surface font-medium">{formatDate(resolved.valid_from)}</span></div>
              <div><span className="text-cq-on-surface-variant">Valid until: </span><span className="text-cq-on-surface font-medium">{formatDate(resolved.valid_until)}</span></div>
            </div>
            {!isApproved && (
              <div className="mt-3 flex items-start gap-2 rounded-cq-md bg-cq-error-container/10 border border-cq-error/25 px-3 py-2.5">
                <ShieldAlert size={15} className="text-cq-error shrink-0 mt-0.5" />
                <span className="text-[12.5px] text-cq-error leading-relaxed">
                  An approved intent is required before encryption. This intent is currently{" "}
                  <strong className="capitalize">{resolved.lifecycle_state}</strong> — ask an
                  authorized approver (USER_LEVEL_2 or ADMIN) to approve it, or request a new
                  intent.
                </span>
              </div>
            )}
          </div>
        )}

        {!resolved && (
          <div className="rounded-cq-md bg-cq-primary-container/10 px-4 py-3 text-[13px] text-cq-on-surface-variant mb-4">
            An approved intent is required before encryption. Paste an intent hash above, or{" "}
            <button type="button" className="underline text-cq-primary" onClick={() => navigate("create-intent")}>
              request a new intent
            </button>
            .
          </div>
        )}

        <h2 className="text-[16px] font-bold text-cq-on-surface mb-4 mt-6">Encrypt Input</h2>
        <form onSubmit={handleSubmit}>
          <Field label="Quantum Key (hex)" hint="from Quantum Center">
            <TextField
              mono
              value={quantumKeyHex}
              onChange={(e) => setQuantumKeyHex(e.target.value)}
              placeholder="Generate one on the Quantum Center page"
              required
            />
          </Field>

          {attachedFile ? (
            <Field label="Attached File" hint="the file itself is the plaintext input">
              <div className="rounded-cq-lg border border-cq-secondary/25 bg-cq-secondary/5 px-4 py-3.5">
                <div className="flex items-start gap-3">
                  <Paperclip size={18} className="text-cq-secondary shrink-0 mt-0.5" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-semibold text-cq-on-surface truncate">{attachedFile.name}</div>
                    <div className="text-[12px] text-cq-on-surface-variant mt-1">
                      {attachedFile.type || "unknown type"} · {formatFileSize(attachedFile.size)}
                    </div>
                    {attachmentMetadata?.sha256 && (
                      <div className="text-[11.5px] text-cq-on-surface-variant mt-1 font-mono break-all">
                        SHA-256: {attachmentMetadata.sha256}
                      </div>
                    )}
                    <div className="text-[12px] text-cq-secondary mt-1.5">
                      Ready. The original file bytes will be sent through the existing Encrypt step.
                    </div>
                  </div>
                </div>
              </div>
            </Field>
          ) : (
            <Field label="Plaintext">
              <TextAreaField rows={4} value={plaintext} onChange={(e) => setPlaintext(e.target.value)} required />
            </Field>
          )}

          <Alert type="error">{error}</Alert>

          {showFaceGate ? (
            <FaceAuthPanel
              mode="verify"
              title="Verify your identity to encrypt"
              subtitle="A live face check runs before every encryption request."
              onSuccess={({ descriptor }) => runEncrypt(descriptor)}
              onCancel={() => setShowFaceGate(false)}
            />
          ) : loading ? (
            <TaskChecklist items={checklistItems} />
          ) : (
            <Button type="submit" variant="accent" accent="mint" full icon={Lock} disabled={!intentComplete || !keyComplete}>
              Encrypt
            </Button>
          )}
        </form>
      </div>

      {result && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 size={18} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Ciphertext Stored</h2>
          </div>
          <p className="text-[13px] text-cq-on-surface-variant mb-4">
            The AES key itself was never stored — only ciphertext, nonce, tag, and the intent hash.
          </p>
          <CopyBox label="Record ID" value={String(result.record_id)} />
          <CopyBox label="Intent Hash" value={result.intent_hash} />
          <div className="flex items-center gap-2.5 mb-3">
            <RiskPill level={result.risk_level} />
            <span className="text-[12px] text-cq-on-surface-variant">risk score {result.risk_score}</span>
          </div>
          <AIRiskAssessment result={result} />
          <CopyBox label="Ciphertext (hex)" value={result.ciphertext_hex} />
          <CopyBox label="Nonce (hex)" value={result.nonce_hex} />
          <CopyBox label="Auth Tag (hex)" value={result.auth_tag_hex} />
          <div className="mt-4 rounded-cq-md bg-cq-primary-container/10 px-4 py-3 text-[13px] leading-relaxed text-cq-on-surface-variant">
            Decryption has to rederive the key from scratch — from the same quantum key and an
            intent context that canonicalizes to the same hash.
          </div>
          <Button
            variant="accent"
            accent="peach"
            full
            iconRight={ArrowRight}
            className="mt-4"
            onClick={() =>
              navigate("decrypt", {
                recordId: result.record_id,
                lastCid: result.cid,
                lastQuantumKeyHex: quantumKeyHex,
              })
            }
          >
            Try decrypting this record
          </Button>
        </div>
      )}
    </div>
  );
}
