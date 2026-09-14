import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldAlert, Send, Clock, CheckCircle2, XCircle, ScanFace } from "lucide-react";
import Button from "../ui/Button";
import FaceAuthPanel from "../face/FaceAuthPanel";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { createReauthRequest, listMyReauthRequests } from "../../services/api";

const POLL_MS = 5000;

/**
 * Shown in place of the normal face-reauthentication flow for any
 * non-admin account whose session or device has been revoked (see
 * MonitoringBadge's routing) — a face check alone can no longer clear
 * either on its own; only an ADMIN acting on their own session/device
 * self-services via `reauthenticate()` directly, since there's no
 * higher authority for an admin to ask. Lets the user file one
 * message to an admin, watches for the admin's decision, and — once
 * approved — hands off to the normal face-reauthentication step to
 * actually resume monitoring (the approval only restores the backend
 * device/session record; a live face check is still required before
 * a new monitoring session starts, same as any other reauthentication).
 */
export default function AccessRequestPanel({ onResolved }) {
  const { deviceId, sessionId, reauthenticate, isAdmin } = useMonitoringContext();
  const [phase, setPhase] = useState("loading"); // loading | form | pending | approved | rejected | admin_self
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [lastRequest, setLastRequest] = useState(null);
  const pollRef = useRef(null);

  const refresh = useCallback(async () => {
    // An ADMIN account is the top of the role hierarchy — there is no
    // higher authority for them to file this request with, so an
    // admin's own revoked device is never routed into the
    // submit-and-wait-for-approval flow below. The backend already
    // self-restores an admin's own device on a successful face
    // re-verification (see authorization.py's reauthenticate_session);
    // this just goes straight to that face check instead of a dead end.
    if (isAdmin) {
      setPhase("admin_self");
      return;
    }
    try {
      const rows = await listMyReauthRequests();
      const forThisDevice = rows.filter((r) => r.device_id === deviceId && r.session_id === sessionId);
      const mostRecent = forThisDevice[0] || null;
      setLastRequest(mostRecent);
      if (!mostRecent) {
        setPhase("form");
      } else if (mostRecent.status === "pending") {
        setPhase("pending");
      } else if (mostRecent.status === "approved") {
        setPhase("approved");
      } else if (mostRecent.status === "consumed") {
        setPhase("form");
      } else {
        setPhase("rejected");
      }
    } catch {
      // Leave whatever phase was last known; the next poll tick will retry.
    }
  }, [deviceId, sessionId, isAdmin]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Poll while a request is pending, so the moment an admin decides,
  // this panel updates on its own without the user needing to do
  // anything (PART: mirrors the same "don't make the user guess"
  // principle the rest of continuous monitoring already follows).
  useEffect(() => {
    if (phase !== "pending") {
      if (pollRef.current) clearInterval(pollRef.current);
      return undefined;
    }
    pollRef.current = setInterval(refresh, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [phase, refresh]);

  async function submit(e) {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const created = await createReauthRequest(deviceId, sessionId, message.trim());
      setLastRequest(created);
      setPhase("pending");
      setMessage("");
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to submit request");
    } finally {
      setSubmitting(false);
    }
  }

  if (phase === "admin_self") {
    return (
      <div className="space-y-2.5">
        <p className="text-[12px] text-cq-on-surface-variant leading-relaxed flex items-start gap-1.5">
          <ScanFace size={13} className="mt-0.5 shrink-0" /> Your admin account has no higher
          authority to request approval from. Verify your face against your enrolled identity to
          restore this device yourself and resume monitoring.
        </p>
        {error && (
          <div className="rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
            {error}
          </div>
        )}
        <FaceAuthPanel
          mode="verify"
          title="Reauthenticate"
          subtitle="A fresh face verification restores your device and monitoring session."
          onSuccess={async ({ descriptor, confidence }) => {
            try {
              await reauthenticate(descriptor, confidence);
              onResolved?.();
            } catch (err) {
              setError(err.message || "Reauthentication failed");
            }
          }}
        />
      </div>
    );
  }

  if (phase === "loading") {
    return <div className="text-[12px] text-cq-on-surface-variant py-2">Checking access request status…</div>;
  }

  if (phase === "form") {
    return (
      <form onSubmit={submit} className="space-y-2.5">
        <p className="text-[12px] text-cq-on-surface-variant leading-relaxed">
          Continuous monitoring revoked your access and it can only be restored by an
          administrator. Describe what happened, then submit — an admin will review it in the
          Admin Dashboard.
        </p>
        {error && (
          <div className="rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
            {error}
          </div>
        )}
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          required
          minLength={1}
          maxLength={1000}
          rows={3}
          placeholder="e.g. My camera dropped out mid-session and I was locked out — please restore my access."
          className="w-full rounded-cq-sm border border-cq-outline-variant/30 bg-cq-surface-container-high px-2.5 py-2 text-[12.5px] text-cq-on-surface resize-none focus:outline-none focus:ring-1 focus:ring-cq-primary"
        />
        <Button type="submit" variant="brand" full loading={submitting} icon={Send}>
          Submit request to admin
        </Button>
      </form>
    );
  }

  if (phase === "pending") {
    return (
      <div className="flex flex-col items-center text-center gap-2 py-2">
        <Clock size={22} className="text-amber-400" />
        <div className="text-[12.5px] font-semibold text-cq-on-surface">Waiting for admin approval</div>
        <p className="text-[11.5px] text-cq-on-surface-variant leading-relaxed">
          Your request was submitted{lastRequest?.created_at ? ` at ${new Date(lastRequest.created_at).toLocaleTimeString()}` : ""}.
          This updates automatically once an admin responds.
        </p>
      </div>
    );
  }

  if (phase === "rejected") {
    return (
      <div className="space-y-2.5">
        <div className="flex items-center gap-2">
          <XCircle size={16} className="text-cq-error" />
          <span className="text-[12.5px] font-bold text-cq-error">Request rejected</span>
        </div>
        {lastRequest?.resolution_note && (
          <p className="text-[11.5px] text-cq-on-surface-variant leading-relaxed">
            Admin note: {lastRequest.resolution_note}
          </p>
        )}
        <Button variant="outline" full onClick={() => setPhase("form")}>
          Submit a new request
        </Button>
      </div>
    );
  }

  // approved -> the device/session are already restored server-side;
  // one live face verification is still required to actually start a
  // new monitoring session (same rule as every other reauthentication
  // path in the app).
  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-2">
        <CheckCircle2 size={16} className="text-cq-secondary" />
        <span className="text-[12.5px] font-bold text-cq-secondary">Access approved</span>
      </div>
      {lastRequest?.resolution_note && (
        <p className="text-[11.5px] text-cq-on-surface-variant leading-relaxed">
          Admin note: {lastRequest.resolution_note}
        </p>
      )}
      <p className="text-[11.5px] text-cq-on-surface-variant leading-relaxed flex items-center gap-1.5">
        <ScanFace size={13} /> Verify your face once more to resume monitoring.
      </p>
      <FaceAuthPanel
        mode="verify"
        title="Reauthenticate"
        subtitle="A fresh face verification completes the approved recovery and resumes monitoring."
        onSuccess={async ({ descriptor, confidence }) => {
          try {
            await reauthenticate(descriptor, confidence, lastRequest?.request_id);
            onResolved?.();
          } catch (err) {
            setError(err.message || "Reauthentication failed");
          }
        }}
      />
    </div>
  );
}
