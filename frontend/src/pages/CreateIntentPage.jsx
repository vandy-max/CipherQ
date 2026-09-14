import { useEffect, useState } from "react";
import { FileText, CheckCircle2, ArrowRight, ShieldCheck, ShieldQuestion, XCircle, Paperclip, X } from "lucide-react";
import CopyBox from "../components/CopyBox";
import LifecyclePill from "../components/ui/LifecyclePill";
import { WorkflowStepper } from "../components/ui/WorkflowStepper";
import { Field, TextField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { createIntent, transitionIntent, validateIntent, listIntents } from "../services/api";
import { useMonitoringContext } from "../context/MonitoringContext";

const OPERATIONS = ["encrypt", "decrypt", "read", "write", "share", "revoke"];
const ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024;
const ATTACHMENT_ACCEPT = ".pdf,.png,.jpg,.jpeg,.webp,.doc,.docx,.xls,.xlsx,.csv,.txt,application/pdf,image/png,image/jpeg,image/webp,text/plain,text/csv,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const ATTACHMENT_TYPES = new Set([
  "application/pdf", "image/png", "image/jpeg", "image/webp", "text/plain", "text/csv",
  "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
]);

function isSupportedAttachment(file) {
  if (!file) return false;
  const extension = file.name.toLowerCase().split(".").pop();
  return ATTACHMENT_TYPES.has(file.type) || ["pdf", "png", "jpg", "jpeg", "webp", "doc", "docx", "xls", "xlsx", "csv", "txt"].includes(extension);
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function sha256File(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function isoLocalToUtc(value) {
  if (!value) return "";
  return new Date(value).toISOString();
}

const DEFAULT_FORM = {
  sender: "",
  receiver: "",
  purpose: "",
  resource: "",
  operation: "decrypt",
  device_id: "",
  session_id: "",
  valid_from: "",
  valid_until: "",
  classification: "",
  department: "",
  project: "",
};

export default function CreateIntentPage({ navigate, user }) {
  const { snapshot, monitoringSessionId, reauthRequired, deviceId, sessionId } = useMonitoringContext();
  const monitoringBlocked = reauthRequired || !monitoringSessionId || ["reauth_required", "revoked"].includes(snapshot?.status);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [inputMode, setInputMode] = useState("plaintext");
  const [attachment, setAttachment] = useState(null);
  const [attachmentError, setAttachmentError] = useState("");
  const [hashingAttachment, setHashingAttachment] = useState(false);
  const [reason, setReason] = useState("initial creation");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [eligibility, setEligibility] = useState(null);
  const [checkingEligibility, setCheckingEligibility] = useState(false);

  // Device/session are security-bound context, not user-editable CID values.
  // Always bind a new intent to the same device/session that is currently
  // authenticated and continuously monitored. This prevents stale/manual
  // IDs (for example 111111/222222) from being rejected as a "removed"
  // session while the actual live session is secure.
  useEffect(() => {
    setForm((current) => ({
      ...current,
      device_id: deviceId || "",
      session_id: sessionId || "",
    }));
  }, [deviceId, sessionId]);

  // Once an intent is created by a normal user, keep its lifecycle status
  // synchronized with the backend until an approval decision is reached.
  // This removes the need to send the user to Intent Lifecycle just to
  // discover that an administrator approved the request.
  useEffect(() => {
    if (!result?.intent_id || result.lifecycle_state !== "draft") return undefined;

    let cancelled = false;
    let timer;

    async function pollApproval() {
      try {
        const rows = await listIntents();
        if (cancelled) return;
        const current = rows.find((row) => row.intent_id === result.intent_id);
        if (!current) return;

        if (current.lifecycle_state !== "draft") {
          setResult((prev) => ({ ...prev, lifecycle_state: current.lifecycle_state }));
          return;
        }
      } catch (err) {
        if (!cancelled) console.warn("[Intent] approval status refresh failed", err);
      } finally {
        if (!cancelled) timer = window.setTimeout(pollApproval, 3000);
      }
    }

    timer = window.setTimeout(pollApproval, 1000);
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [result?.intent_id, result?.lifecycle_state]);

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  async function handleAttachmentChange(e) {
    const file = e.target.files?.[0] || null;
    e.target.value = "";
    setAttachmentError("");
    if (!file) return;
    if (!isSupportedAttachment(file)) {
      setAttachment(null);
      setAttachmentError("Unsupported file type. Use PDF, image, Word, Excel, CSV, or TXT.");
      return;
    }
    if (file.size > ATTACHMENT_MAX_BYTES) {
      setAttachment(null);
      setAttachmentError("File exceeds the maximum allowed size of 10 MB.");
      return;
    }
    setHashingAttachment(true);
    try {
      const fileHash = await sha256File(file);
      setAttachment({ file, sha256: fileHash });
      setForm((current) => ({ ...current, resource: file.name }));
    } catch (err) {
      setAttachment(null);
      setAttachmentError("Could not read the selected file. Please try again.");
    } finally {
      setHashingAttachment(false);
    }
  }

  function clearAttachment() {
    if (attachment?.file && form.resource === attachment.file.name) {
      setForm((f) => ({ ...f, resource: "" }));
    }
    setAttachment(null);
    setAttachmentError("");
  }

  async function checkEligibility(cid, intentId) {
    setCheckingEligibility(true);
    try {
      const validation = await validateIntent(cid, intentId);
      setEligibility(validation);
      return validation;
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to check approval eligibility");
      return null;
    } finally {
      setCheckingEligibility(false);
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (monitoringBlocked) {
      setError("Session is removed or requires reauthentication. Reauthenticate before creating an intent.");
      return;
    }
    setError("");
    if (inputMode === "file" && !attachment?.file) {
      setAttachmentError("Choose a file before creating this Intent.");
      setError("A file attachment is required for File Attachment input mode.");
      return;
    }
    if (inputMode === "file" && hashingAttachment) {
      setError("Please wait for the selected file to finish reading.");
      return;
    }
    setLoading(true);
    setEligibility(null);
    try {
      const cid = {
        sender: form.sender,
        receiver: form.receiver,
        purpose: form.purpose,
        resource: inputMode === "file" && attachment?.file ? attachment.file.name : form.resource,
        operation: form.operation,
        device_id: deviceId,
        session_id: sessionId,
        valid_from: isoLocalToUtc(form.valid_from),
        valid_until: isoLocalToUtc(form.valid_until),
        classification: form.classification || null,
        department: form.department || null,
        project: form.project || null,
        metadata: inputMode === "file" && attachment?.file ? {
          input_type: "file",
          attachment: {
            filename: attachment.file.name,
            mime_type: attachment.file.type || "application/octet-stream",
            size: attachment.file.size,
            sha256: attachment.sha256,
          },
        } : null,
      };
      const response = await createIntent(cid, reason);
      setResult({ ...response, cid });
      // ADMIN zero-risk intents are auto-approved by the backend and
      // should go directly to the encryption action. Other roles keep
      // the existing approval workflow.
      if (response.lifecycle_state === "draft") {
        await checkEligibility(cid, response.intent_id);
      }
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to create intent");
    } finally {
      setLoading(false);
    }
  }


  return (
    <div>
      <PageHeader
        icon="center_focus_strong"
        eyebrow="Intent-Bound Cryptography"
        title={user?.role === "ADMIN" || user?.role === "USER_LEVEL_2" ? "Intent Management" : "Request Intent"}
        description="Define the Cryptographic Intent Descriptor (CID) that a quantum key will later be bound to. No key material is issued until an intent is created and approved by an authorized approver."
      />

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="mb-4">
          <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Descriptor</h2>
          <p className="text-[13px] text-cq-on-surface-variant mt-0.5">
            Every field below becomes part of the canonicalized, hashed intent context.
          </p>
        </div>
        {monitoringBlocked ? (
          <div className="rounded-cq-lg border border-cq-error/30 bg-cq-error-container/10 px-4 py-4">
            <div className="flex items-start gap-3">
              <XCircle size={19} className="text-cq-error shrink-0 mt-0.5" />
              <div>
                <div className="text-[14px] font-bold text-cq-error">Session removed — Intent creation blocked</div>
                <div className="text-[12.5px] text-cq-on-surface-variant mt-1.5 leading-relaxed">
                  Continuous monitoring is not in an authorized state. Reauthentication must succeed before a new intent can be created. No intent will be created while the session is RE-AUTHENTICATION REQUIRED or REVOKED.
                </div>
                <button
                  type="button"
                  className="mt-3 rounded-cq-md bg-cq-error/10 border border-cq-error/25 px-3 py-2 text-[12px] font-semibold text-cq-error hover:bg-cq-error/15"
                  onClick={() => navigate("dashboard")}
                >
                  Return to Security Monitoring
                </button>
              </div>
            </div>
          </div>
        ) : (
        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Sender">
              <TextField value={form.sender} onChange={set("sender")} required />
            </Field>
            <Field label="Receiver">
              <TextField value={form.receiver} onChange={set("receiver")} required />
            </Field>
          </div>

          <Field label="Purpose">
            <TextField value={form.purpose} onChange={set("purpose")} required />
          </Field>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Resource" hint={inputMode === "file" ? "attached file is the encryption input" : "text resource name/input"}>
              <div className="space-y-2">
                <TextField value={form.resource} onChange={set("resource")} required readOnly={inputMode === "file"} />
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setInputMode("plaintext");
                      if (attachment?.file && form.resource === attachment.file.name) {
                        setForm((current) => ({ ...current, resource: "" }));
                      }
                      clearAttachment();
                    }}
                    className={`rounded-cq-md border px-3 py-2 text-[12px] font-semibold transition-colors ${inputMode === "plaintext" ? "border-cq-secondary/60 bg-cq-secondary/10 text-cq-on-surface" : "border-cq-outline-variant/30 text-cq-on-surface-variant hover:bg-cq-surface-container-highest"}`}
                  >
                    Text input
                  </button>
                  <label
                    htmlFor="intent-attachment"
                    onClick={() => setInputMode("file")}
                    className={`inline-flex cursor-pointer items-center gap-1.5 rounded-cq-md border px-3 py-2 text-[12px] font-semibold transition-colors ${inputMode === "file" ? "border-cq-secondary/60 bg-cq-secondary/10 text-cq-on-surface" : "border-cq-outline-variant/30 text-cq-on-surface-variant hover:bg-cq-surface-container-highest"}`}
                  >
                    <Paperclip size={14} /> Attach File
                  </label>
                  <input
                    id="intent-attachment"
                    type="file"
                    accept={ATTACHMENT_ACCEPT}
                    onChange={handleAttachmentChange}
                    className="sr-only"
                  />
                </div>
                {inputMode === "file" && (
                  <div className="rounded-cq-md border border-cq-outline-variant/30 bg-cq-surface-container-lowest px-3.5 py-3">
                    {!attachment ? (
                      <div className="text-[12px] text-cq-on-surface-variant">
                        {hashingAttachment ? "Reading selected file…" : "Choose a PDF, image, document, spreadsheet, CSV, or TXT using Attach File above."}
                      </div>
                    ) : (
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 text-[12.5px] font-semibold text-cq-on-surface">
                            <Paperclip size={15} />
                            <span className="truncate">{attachment.file.name}</span>
                          </div>
                          <div className="mt-1 text-[11.5px] text-cq-on-surface-variant">
                            {attachment.file.type || "unknown type"} · {formatFileSize(attachment.file.size)} · SHA-256 {attachment.sha256.slice(0, 12)}…
                          </div>
                          <div className="mt-1 text-[11.5px] text-cq-secondary">Ready — this file becomes the encryption plaintext.</div>
                        </div>
                        <button type="button" onClick={clearAttachment} className="shrink-0 rounded-cq-md p-2 text-cq-on-surface-variant hover:bg-cq-surface-container-highest" aria-label="Remove attachment">
                          <X size={15} />
                        </button>
                      </div>
                    )}
                    <div className="mt-2 text-[11px] text-cq-on-surface-variant">PDF · PNG/JPG/WEBP · DOC/DOCX · XLS/XLSX · CSV · TXT · max 10 MB</div>
                    {attachmentError && <div className="mt-2 text-[12px] text-cq-error">{attachmentError}</div>}
                  </div>
                )}
              </div>
            </Field>
            <Field label="Operation">
              <SelectField value={form.operation} onChange={set("operation")}>
                {OPERATIONS.map((op) => (
                  <option key={op} value={op}>{op}</option>
                ))}
              </SelectField>
            </Field>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Device ID" hint="bound to the current authorized device">
              <TextField value={deviceId || ""} readOnly required className="opacity-80" />
            </Field>
            <Field label="Session ID" hint="bound to the current authorized session">
              <TextField value={sessionId || ""} readOnly required className="opacity-80" />
            </Field>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Valid From">
              <TextField type="datetime-local" value={form.valid_from} onChange={set("valid_from")} required />
            </Field>
            <Field label="Valid Until">
              <TextField type="datetime-local" value={form.valid_until} onChange={set("valid_until")} required />
            </Field>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
            <Field label="Classification" hint="optional">
              <TextField value={form.classification} onChange={set("classification")} />
            </Field>
            <Field label="Department" hint="optional">
              <TextField value={form.department} onChange={set("department")} />
            </Field>
          </div>

          <Field label="Project" hint="optional">
            <TextField value={form.project} onChange={set("project")} />
          </Field>

          <Field label="Reason for this version">
            <TextField value={reason} onChange={(e) => setReason(e.target.value)} required />
          </Field>

          <Alert type="error">{error}</Alert>

          <Button type="submit" variant="brand" full loading={loading} icon={FileText}>
            Create Intent
          </Button>
        </form>
        )}
      </div>

      {result && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-6">
          <WorkflowStepper
            steps={["Intent Requested", "Security Decision", "Action"]}
            activeIndex={
              result.lifecycle_state === "draft" ? 1 : result.lifecycle_state === "approved" ? 2 : result.lifecycle_state === "rejected" ? 1 : 2
            }
          />
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle2 size={18} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Created</h2>
          </div>
          <div className="flex items-center gap-2.5 my-3">
            <LifecyclePill state={result.lifecycle_state} />
            <code className="text-[13px] text-cq-on-surface-variant font-mono">intent #{result.intent_id}</code>
          </div>
          <CopyBox label="Intent Hash (SHA-256 of canonical CID)" value={result.intent_hash} />

          {result.lifecycle_state === "draft" && user?.role !== "ADMIN" && (
            <div className="mt-4 rounded-cq-lg border px-4 py-3" style={{
              borderColor: eligibility?.approval_eligible ? "rgba(99,247,255,0.25)" : "rgba(251,191,36,0.25)",
              background: eligibility?.approval_eligible ? "rgba(99,247,255,0.08)" : "rgba(251,191,36,0.08)",
            }}>
              <div className="flex items-center gap-2">
                {checkingEligibility ? (
                  <ShieldQuestion size={16} className="text-cq-on-surface-variant animate-pulse" />
                ) : eligibility?.approval_eligible ? (
                  <ShieldCheck size={16} className="text-cq-secondary" />
                ) : (
                  <XCircle size={16} className="text-cq-warning" style={{ color: "#fbbf24" }} />
                )}
                <span className="text-[13px] font-semibold text-cq-on-surface">
                  {checkingEligibility
                    ? "Checking approval eligibility\u2026"
                    : eligibility?.approval_eligible
                      ? "Approval Eligible"
                      : "Not Approval Eligible"}
                </span>
              </div>
              {eligibility && !eligibility.approval_eligible && eligibility.reason && (
                <p className="text-[12.5px] text-cq-on-surface-variant mt-1.5 leading-relaxed">
                  {eligibility.reason}
                </p>
              )}
              {eligibility && (
                <p className="text-[12px] text-cq-on-surface-variant mt-1">
                  Policy: {eligibility.policy_passed ? "passed" : "failed"} · Risk: {eligibility.risk_level} ·
                  {" "}Device: {eligibility.device.revoked ? "revoked" : "ok"} ·
                  {" "}Session: {eligibility.session.valid ? "ok" : "invalid"}
                </p>
              )}
            </div>
          )}

          {result.lifecycle_state === "draft" ? (
            user?.role === "ADMIN" ? (
              <div className="mt-2 rounded-cq-lg border border-cq-warning/25 bg-cq-warning/5 px-4 py-3.5 text-[13px] text-cq-on-surface-variant leading-relaxed">
                <div className="font-semibold text-cq-warning">Risk review required</div>
                <p className="mt-1 text-[12px]">
                  This Admin-created intent was not automatically approved because the server-side risk score is above zero or another validation condition failed. Cryptographic access remains blocked.
                </p>
              </div>
            ) : (
              // Separation of duties (fix pass sections C + E): the
              // creator of an intent is never shown a self-approve
              // control, even if the backend would technically allow
              // it for their role — an authorized approver
              // (USER_LEVEL_2 or ADMIN) other than the creator must
              // review it from Intent Approvals / the Admin
              // Dashboard. This page only ever REQUESTS an intent.
              <div className="mt-2 rounded-cq-lg border border-cq-outline-variant/25 bg-cq-surface-container-lowest px-4 py-3.5 text-[13px] text-cq-on-surface-variant leading-relaxed">
                Awaiting approval from an authorized approver. You cannot approve your own intent.
                This page will update automatically when the administrator approves or rejects it.
              </div>
            )
          ) : result.lifecycle_state === "approved" ? (
            <>
              <div className="mt-2 rounded-cq-lg border border-cq-secondary/25 bg-cq-secondary/5 px-4 py-3.5">
                <div className="flex items-center gap-2 text-cq-secondary text-[13px] font-semibold">
                  <ShieldCheck size={16} />
                  <span>{user?.role === "ADMIN" ? "Ready for Encryption" : "Intent Approved"}</span>
                </div>
                <p className="mt-1 text-[12.5px] text-cq-on-surface-variant">
                  {user?.role === "ADMIN"
                    ? "Zero-risk Admin intent. Cryptographic access is ready."
                    : "Approved by Admin. Your intent is ready for protected encryption access."}
                </p>
              </div>
              <Button
                variant="accent"
                accent="mint"
                full
                iconRight={ArrowRight}
                onClick={() =>
                  navigate("encrypt", {
                    intentCid: result.cid,
                    intentId: result.intent_id,
                    intentHash: result.intent_hash,
                    intentLifecycleState: result.lifecycle_state,
                    intentOwner: user?.userId,
                    attachedFile: inputMode === "file" ? attachment?.file || null : null,
                    attachmentMetadata: inputMode === "file" ? attachment?.sha256 ? {
                      input_type: "file",
                      filename: attachment.file.name,
                      mime_type: attachment.file.type || "application/octet-stream",
                      size: attachment.file.size,
                      sha256: attachment.sha256,
                    } : null : null,
                  })
                }
                className="mt-2"
              >
                {user?.role === "ADMIN" ? "Encrypt" : "Access Encryption"}
              </Button>
            </>
          ) : result.lifecycle_state === "rejected" ? (
            <div className="mt-2 rounded-cq-lg border border-cq-error/25 bg-cq-error-container/10 px-4 py-3.5 text-[13px] text-cq-error">
              <div className="font-semibold">Intent Rejected</div>
              <p className="mt-1 text-[12px] text-cq-on-surface-variant">The administrator did not approve this intent.</p>
            </div>
          ) : (
            <div className="mt-2 rounded-cq-lg border border-cq-outline-variant/20 bg-cq-surface-container-lowest px-4 py-3.5 text-[13px] text-cq-on-surface-variant">
              Intent status: <span className="font-semibold uppercase">{result.lifecycle_state}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
