import { useEffect, useState } from "react";
import { History, Info, RefreshCcw } from "lucide-react";
import LifecyclePill from "../components/ui/LifecyclePill";
import { Field, TextField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import Loading from "../components/ui/Loading";
import EmptyState from "../components/ui/EmptyState";
import { transitionIntent, listIntents } from "../services/api";
import { formatTimestamp } from "../utils/formatTimestamp";

const STATES = ["draft", "approved", "rejected", "used", "expired", "archived", "destroyed"];
const POLL_MS = 4000;

// Purely visual accent per real lifecycle_state value (see STATES
// above) — does not alter or reinterpret the state itself.
function intentAccent(state) {
  switch (state) {
    case "approved":
    case "used":
      return "#63f7ff";
    case "rejected":
    case "destroyed":
      return "#ffb4ab";
    case "expired":
    case "archived":
      return "#8e90a2";
    default:
      return "#a03ad3"; // draft
  }
}

/**
 * Fix pass sections E + G.
 *
 * E: USER_LEVEL_1 must only ever see a read-only status view of their
 * own intents here — never a raw "pick any target state" control
 * (that used to include "approved", letting the page imply a user
 * could approve their own intent even though the backend correctly
 * rejects it). Full lifecycle transitions remain an ADMIN operation;
 * USER_LEVEL_2 approvals live in the dedicated Intent Approval panel
 * on the Admin Dashboard, not duplicated here.
 *
 * G: the status list polls in the background so an admin's approval
 * elsewhere shows up here automatically, without a manual reload.
 */
export default function IntentHistoryPage({ shared, user }) {
  const isAdmin = user?.role === "ADMIN";
  const isApprover = user?.role === "USER_LEVEL_2";

  const [intents, setIntents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState("");

  async function load(showLoading = true) {
    if (showLoading) setLoading(true);
    setListError("");
    try {
      // The backend already scopes this list by role: USER_LEVEL_1
      // gets only their own intents, USER_LEVEL_2/ADMIN see all —
      // this page does not need to (and must not) do that filtering
      // itself.
      const rows = await listIntents();
      setIntents(
        [...rows].sort(
          (a, b) =>
            new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime() ||
            b.intent_id - a.intent_id
        )
      );
    } catch (err) {
      setListError(err.detail?.toString?.() || err.message || "Failed to load intents");
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const id = window.setInterval(() => load(false), POLL_MS);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- ADMIN-only raw transition control (section E) ----
  const [intentId, setIntentId] = useState(shared?.intentId ?? "");
  const [targetState, setTargetState] = useState("approved");
  const [reason, setReason] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleTransition(e) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const response = await transitionIntent(Number(intentId), targetState, reason);
      setResult(response);
      await load(false);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Transition failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <PageHeader
        icon="history"
        eyebrow="Intent-Bound Cryptography"
        title="Intent Lifecycle"
        description="Draft → Approved → Used → Expired → Archived → Destroyed. Every intent version is immutable; transitions are logged to the audit chain."
      />

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[16px] font-bold text-cq-on-surface">
            {isAdmin || isApprover ? "All Intents" : "My Intents"}
          </h2>
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(true)}>
            Refresh
          </Button>
        </div>
        <Alert type="error">{listError}</Alert>

        {isApprover && (
          <p className="text-[13px] text-cq-on-surface-variant mb-4">
            Reviewing/approving intents belonging to other users happens from the Admin Dashboard's
            Intent Approval panel. You cannot approve your own intent, even from there.
          </p>
        )}

        {loading ? (
          <Loading label="Loading intents…" />
        ) : intents.length === 0 ? (
          <EmptyState title="No intents yet" desc="Request an intent to see its status here." />
        ) : (
          <div className="relative grid grid-cols-1 sm:grid-cols-2 gap-4">
            {intents.map((intent) => (
              <div
                key={intent.intent_id}
                className="relative rounded-cq-xl p-cq-stack-md bg-cq-surface-container-high border border-cq-outline-variant/10 overflow-hidden"
              >
                <div
                  className="absolute inset-y-0 left-0 w-[2px]"
                  style={{ background: intentAccent(intent.lifecycle_state) }}
                />
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[13.5px] font-bold text-cq-on-surface">Intent #{intent.intent_id}</span>
                  <LifecyclePill state={intent.lifecycle_state} />
                </div>
                <div className="text-[12px] font-mono text-cq-on-surface-variant break-all mb-1">
                  {intent.intent_hash}
                </div>
                <div className="text-[12.5px] text-cq-on-surface-variant">
                  Created by user #{intent.created_by}
                  {intent.created_at && <> · {formatTimestamp(intent.created_at)}</>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {isAdmin && (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="text-[16px] font-bold text-cq-on-surface mb-1">Apply a Transition (Admin)</h2>
          <p className="text-[13px] text-cq-on-surface-variant mb-4">
            Full lifecycle control — approve, expire, archive, or destroy any intent. Ordinary
            approvals should normally go through the Intent Approval panel on the Admin Dashboard
            instead, which enforces the "not your own intent" rule visibly.
          </p>
          <form onSubmit={handleTransition}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
              <Field label="Intent ID">
                <TextField type="number" value={intentId} onChange={(e) => setIntentId(e.target.value)} required />
              </Field>
              <Field label="Target State">
                <SelectField value={targetState} onChange={(e) => setTargetState(e.target.value)}>
                  {STATES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </SelectField>
              </Field>
            </div>
            <Field label="Reason">
              <TextField value={reason} onChange={(e) => setReason(e.target.value)} required />
            </Field>

            <Alert type="error">{error}</Alert>

            <Button type="submit" variant="accent" accent="sky" full loading={submitting} icon={History}>
              Apply Transition
            </Button>
          </form>

          {result && (
            <div className="mt-4 flex items-center gap-2.5">
              <LifecyclePill state={result.lifecycle_state} />
              <code className="text-[13px] text-cq-on-surface-variant font-mono">
                intent #{result.intent_id} · v{result.version_number}
              </code>
            </div>
          )}
        </div>
      )}

      <div className="mt-6 flex items-start gap-2.5 rounded-cq-md bg-cq-primary-container/10 px-4 py-3.5 text-[13px] leading-relaxed text-cq-on-surface-variant">
        <Info size={16} className="shrink-0 mt-0.5 text-cq-primary" />
        <span>
          The lifecycle state machine only allows forward transitions (with Used → Used permitted,
          for reuse within the intent's validity window). Attempting an invalid transition (e.g.
          Draft → Used, or transitioning a Destroyed intent) is rejected and logged.
        </span>
      </div>
    </div>
  );
}
