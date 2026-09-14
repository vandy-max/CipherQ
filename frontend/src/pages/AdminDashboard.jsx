import { useEffect, useState, useRef, useCallback } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Users,
  ClipboardCheck,
  ShieldAlert,
  RefreshCcw,
  CheckCircle2,
  XCircle,
  Bot,
  Activity,
  UserCheck,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import { Field, SelectField, TextField } from "../components/ui/Field";
import LifecyclePill from "../components/ui/LifecyclePill";
import { formatTimestamp } from "../utils/formatTimestamp";
import { useMonitoringContext } from "../context/MonitoringContext";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import { deriveMonitoringState, monitoringReason, MONITORING_UI_META } from "../components/monitoring/monitoringState";
import {
  listUsers,
  updateUserRole,
  listIntents,
  transitionIntent,
  revokeDevice,
  unrevokeDevice,
  revokeSession,
  listSecurityIncidents,
  resolveSecurityIncident,
  listReauthRequests,
  approveReauthRequest,
  rejectReauthRequest,
  getDeviceStatus,
  getSessionStatus,
} from "../services/api";

// Server-side enforced role model (see backend/api/rbac.py) — this is
// just the display list, never a source of authorization truth.
const USER_ROLES = ["USER_LEVEL_1", "USER_LEVEL_2"];

const TABS = [
  { id: "users", label: "Users & Roles", icon: Users },
  { id: "intents", label: "Intent Approval", icon: ClipboardCheck },
  { id: "access-requests", label: "Access Requests", icon: UserCheck },
  { id: "devices", label: "Devices & Sessions", icon: ShieldAlert },
  { id: "risk", label: "Admin Live Monitoring", icon: Activity },
  { id: "incidents", label: "Security Incidents", icon: Bot },
];

function Loading({ label }) {
  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center gap-4 text-center">
      <div className="relative w-11 h-11">
        <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
        <motion.div
          className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
        />
      </div>
      <p className="text-cq-body-md text-cq-on-surface-variant">{label}</p>
    </div>
  );
}

function EmptyState({ title, desc }) {
  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center text-center">
      <div className="text-[14.5px] font-semibold text-cq-on-surface">{title}</div>
      {desc && <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">{desc}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------
// Users & Roles
// ---------------------------------------------------------------------

function UsersPanel({ user }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [savingId, setSavingId] = useState(null);

  async function load() {
    setLoading(true);
    setError("");
    try {
      setUsers(await listUsers());
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleRoleChange(id, role) {
    setSavingId(id);
    setError("");
    try {
      await updateUserRole(id, role);
      await load();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to update role");
    } finally {
      setSavingId(null);
    }
  }

  if (loading) return <Loading label="Loading users…" />;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Users & Roles</h2>
        <Button variant="outline" size="sm" icon={RefreshCcw} onClick={load}>
          Refresh
        </Button>
      </div>
      <Alert type="error">{error}</Alert>
      {users.length === 0 ? (
        <EmptyState title="No users found" />
      ) : (
        <div className="overflow-x-auto -mx-2 sm:mx-0">
          <table className="w-full text-left border-collapse min-w-[520px]">
            <thead>
              <tr className="border-b border-cq-outline-variant/25">
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Username
                </th>
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Email
                </th>
                <th className="py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant">
                  Role
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-cq-surface-container-high transition-colors">
                  <td className="py-3 px-3 text-[13.5px] text-cq-on-surface border-b border-cq-outline-variant/15">
                    {u.username}
                    {u.id === user?.userId && (
                      <span className="ml-2 text-[11px] uppercase tracking-wide text-cq-primary">you</span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-[13px] text-cq-on-surface-variant border-b border-cq-outline-variant/15">
                    {u.email}
                  </td>
                  <td className="py-3 px-3 border-b border-cq-outline-variant/15">
                    {u.role === "ADMIN" ? (
                      <span className="inline-flex items-center rounded-cq-md bg-cq-secondary-container/15 px-2.5 py-1.5 text-[13px] font-semibold text-cq-secondary">
                        ADMIN
                      </span>
                    ) : (
                      <SelectField
                        value={u.role}
                        disabled={savingId === u.id}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="!py-1.5 !text-[13px] max-w-[220px]"
                      >
                        {USER_ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </SelectField>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Intent Approval queue
// ---------------------------------------------------------------------

function IntentsPanel() {
  const [intents, setIntents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [filter, setFilter] = useState("draft");

  async function load(state, showLoading = true) {
    if (showLoading) setLoading(true);
    setError("");
    try {
      const nextIntents = await listIntents(state || undefined);
      setIntents(
        [...nextIntents].sort(
          (a, b) =>
            new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime() ||
            b.intent_id - a.intent_id
        )
      );
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load intents");
    } finally {
      if (showLoading) setLoading(false);
    }
  }

  useEffect(() => {
    load(filter);

    // Keep the admin approval queue synchronized with intents created by
    // other users. Background refresh does not show a loading spinner,
    // so the queue remains usable while new drafts arrive.
    const refreshId = window.setInterval(() => load(filter, false), 3000);
    return () => window.clearInterval(refreshId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function handleTransition(intentId, target) {
    setBusyId(intentId);
    setError("");
    setMessage("");
    try {
      // Wait for the actual backend response and confirm the lifecycle
      // state really did transition before touching the UI at all —
      // the backend stays the sole source of truth for the "APPROVED"
      // confirmation the reviewer sees.
      const result = await transitionIntent(intentId, target, `admin dashboard: ${target}`);
      if (result?.lifecycle_state === target) {
        setMessage(`Intent #${intentId} ${target === "approved" ? "approved" : "rejected"}.`);
      } else {
        setError(`Intent #${intentId} did not reach "${target}" (backend reports "${result?.lifecycle_state}").`);
      }
      // Immediately refresh from the backend so the Draft list drops it
      // and the Approved/Rejected filter picks it up — never a
      // frontend-only approved state.
      await load(filter);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || `Failed to transition intent ${intentId}`);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between flex-wrap gap-3 mb-4">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Intent Approval</h2>
        <div className="flex items-center gap-2">
          <SelectField value={filter} onChange={(e) => setFilter(e.target.value)} className="!py-1.5 !text-[13px]">
            <option value="draft">Draft (pending review)</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="used">Used</option>
            <option value="">All</option>
          </SelectField>
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(filter)}>
            Refresh
          </Button>
        </div>
      </div>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Separation of duties is enforced server-side: an intent's own creator can never approve
        it here — only a distinct USER_LEVEL_2/ADMIN reviewer can. Rejection may be done by that
        same reviewer, or by the intent's own creator withdrawing their request.
      </p>

      {loading ? (
        <Loading label="Loading intents…" />
      ) : intents.length === 0 ? (
        <EmptyState
          title="Nothing here"
          desc="No intents match this filter — try switching to Draft to see what's waiting for review."
        />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {intents.map((intent) => (
            <div
              key={intent.intent_id}
              className="rounded-cq-xl p-cq-stack-md bg-cq-surface-container-high border-l-2 border-cq-outline-variant/30"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[13.5px] font-bold text-cq-on-surface">Intent #{intent.intent_id}</span>
                <LifecyclePill state={intent.lifecycle_state} />
              </div>
              <div className="text-[12px] font-mono text-cq-on-surface-variant break-all mb-1">
                {intent.intent_hash.slice(0, 24)}…
              </div>
              <div className="text-[12.5px] text-cq-on-surface-variant mb-1">
                {intent.created_by_username ? (
                  <>
                    {intent.created_by_username}
                    {intent.created_by_role && <> · {intent.created_by_role}</>}
                  </>
                ) : (
                  <>User #{intent.created_by}</>
                )}
                {intent.created_at && <> · {formatTimestamp(intent.created_at)}</>}
              </div>
              {(intent.resource || intent.operation) && (
                <div className="text-[12.5px] text-cq-on-surface mb-1">
                  {intent.operation && <span className="uppercase font-semibold">{intent.operation}</span>}
                  {intent.resource && <> · {intent.resource}</>}
                </div>
              )}
              {intent.purpose && (
                <div className="text-[12.5px] text-cq-on-surface-variant italic mb-3">"{intent.purpose}"</div>
              )}
              {intent.lifecycle_state === "draft" && (
                <div className="flex gap-2 mt-2">
                  <Button
                    variant="brand"
                    size="sm"
                    icon={CheckCircle2}
                    loading={busyId === intent.intent_id}
                    onClick={() => handleTransition(intent.intent_id, "approved")}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    icon={XCircle}
                    loading={busyId === intent.intent_id}
                    onClick={() => handleTransition(intent.intent_id, "rejected")}
                  >
                    Reject
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------
// Devices & Sessions quick actions
// ---------------------------------------------------------------------

// Part 13/14 — Qira's automatic CRITICAL-severity revocations show up
// here for admin review/recovery. Qira itself can never call the
// resolve endpoint (server-enforced: `POST /api/security/incidents/
// {id}/resolve` requires ADMIN role) — this panel is the ONLY path
// back to restored access after an automatic revoke.
const SEVERITY_META = {
  LOW: { tone: "text-cq-on-surface-variant", bg: "bg-white/[0.03]" },
  MEDIUM: { tone: "text-amber-400", bg: "bg-amber-400/10" },
  HIGH: { tone: "text-orange-400", bg: "bg-orange-400/10" },
  CRITICAL: { tone: "text-cq-error", bg: "bg-cq-error-container/15" },
};

// ---------------------------------------------------------------------
// Access Requests (device reauthorization approvals)
// ---------------------------------------------------------------------

function ReauthRequestsPanel() {
  const [requests, setRequests] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("pending"); // "pending" | "all"
  const [busyId, setBusyId] = useState(null);
  const [notes, setNotes] = useState({});
  // Per-request expand/collapse + fetched detail cache, so admins can
  // review who they're approving before they click. Details are
  // fetched lazily (only when a row is expanded) from the same
  // admin-accessible endpoints the Admin's own live-monitoring panel
  // already uses — GET /devices/{id}/trust and GET /sessions/{id} both
  // allow an ADMIN caller regardless of ownership (see rbac.py's
  // require_owner_or_admin) — plus the roster from `listUsers()` for
  // email/role, since the request itself only carries username/user_id.
  const [expandedId, setExpandedId] = useState(null);
  const [details, setDetails] = useState({}); // requestId -> { loading, error, deviceTrust, sessionStatus, profile }
  const [users, setUsers] = useState(null);

  async function load(nextFilter = filter) {
    setError("");
    try {
      const rows = await listReauthRequests(nextFilter === "pending" ? "pending" : undefined);
      setRequests(rows);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load access requests");
    }
  }

  useEffect(() => {
    load(filter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function toggleDetails(req) {
    if (expandedId === req.request_id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(req.request_id);
    if (details[req.request_id]) return; // already fetched
    setDetails((prev) => ({ ...prev, [req.request_id]: { loading: true } }));
    try {
      let roster = users;
      if (!roster) {
        roster = await listUsers();
        setUsers(roster);
      }
      const profile = roster?.find((u) => u.id === req.user_id) || null;
      const [deviceStatus, sessionStatus] = await Promise.all([
        getDeviceStatus(req.device_id).catch(() => null),
        getSessionStatus(req.session_id).catch(() => null),
      ]);
      setDetails((prev) => ({
        ...prev,
        [req.request_id]: { loading: false, profile, deviceStatus, sessionStatus },
      }));
    } catch (err) {
      setDetails((prev) => ({
        ...prev,
        [req.request_id]: {
          loading: false,
          error: err.detail?.toString?.() || err.message || "Failed to load user details",
        },
      }));
    }
  }

  async function handleDecision(requestId, decision) {
    setBusyId(requestId);
    setError("");
    setMessage("");
    try {
      const note = (notes[requestId] || "").trim() || null;
      if (decision === "approve") {
        await approveReauthRequest(requestId, note);
        setMessage(`Request #${requestId} approved — the user must complete one fresh face verification before the device/session are restored.`);
      } else {
        await rejectReauthRequest(requestId, note);
        setMessage(`Request #${requestId} rejected — access remains blocked.`);
      }
      await load(filter);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to record decision");
    } finally {
      setBusyId(null);
    }
  }

  if (requests === null && !error) return <Loading label="Loading access requests…" />;

  const STATUS_META = {
    pending: { label: "Pending", tone: "text-amber-400", icon: ShieldAlert },
    approved: { label: "Approved", tone: "text-cq-secondary", icon: CheckCircle2 },
    rejected: { label: "Rejected", tone: "text-cq-error", icon: XCircle },
  };

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-1">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Access Requests</h2>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(filter)}>
            Refresh
          </Button>
          <div className="inline-flex rounded-cq-md overflow-hidden border border-white/10">
            {[
              { id: "pending", label: "Pending" },
              { id: "all", label: "All" },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={`px-3 py-1.5 text-[12px] font-semibold ${
                  filter === f.id ? "bg-cq-primary-container/20 text-cq-primary" : "text-cq-on-surface-variant"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        A user's device or session was revoked by continuous monitoring, and only an
        administrator can restore it. Approving restores the device and session immediately; the
        user still needs one fresh face verification to resume monitoring. Rejecting leaves
        intent creation, encryption, and decryption blocked for that user.
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      {requests?.length === 0 && (
        <div className="text-[13px] text-cq-on-surface-variant py-6 text-center">
          No {filter === "pending" ? "pending" : ""} access requests.
        </div>
      )}

      <div className="space-y-3">
        {requests?.map((req) => {
          const meta = STATUS_META[req.status] || STATUS_META.pending;
          const StatusIcon = meta.icon;
          return (
            <div key={req.request_id} className="rounded-cq-lg border border-white/10 p-3.5 bg-cq-surface-container-high/50">
              <div className="flex items-start justify-between gap-3 mb-1.5">
                <div>
                  <div className="text-[13px] font-bold text-cq-on-surface">
                    {req.username}{" "}
                    <span className="text-[11px] font-normal text-cq-on-surface-variant">
                      (user #{req.user_id})
                    </span>
                  </div>
                  <div className="text-[11px] text-cq-on-surface-variant">
                    {formatTimestamp(req.created_at)}
                  </div>
                </div>
                <span className={`inline-flex items-center gap-1 text-[11px] font-semibold ${meta.tone}`}>
                  <StatusIcon size={12} /> {meta.label}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11.5px] text-cq-on-surface-variant mb-2">
                <div><span className="text-cq-on-surface font-medium">Device:</span> {req.device_id}</div>
                <div><span className="text-cq-on-surface font-medium">Session:</span> {req.session_id}</div>
              </div>

              <div className="text-[12px] text-cq-on-surface mb-2 bg-cq-surface-container rounded-cq-sm px-2.5 py-2">
                <span className="font-semibold">Message: </span>
                {req.message}
              </div>

              <button
                type="button"
                onClick={() => toggleDetails(req)}
                className="mb-2 inline-flex items-center gap-1 text-[11.5px] font-semibold text-cq-primary hover:underline"
              >
                {expandedId === req.request_id ? (
                  <>
                    <ChevronUp size={13} /> Hide user details
                  </>
                ) : (
                  <>
                    <ChevronDown size={13} /> View user details
                  </>
                )}
              </button>

              {expandedId === req.request_id && (
                <div className="mb-3 rounded-cq-md border border-cq-outline-variant/15 bg-cq-surface-container/60 p-3">
                  {details[req.request_id]?.loading && (
                    <div className="text-[11.5px] text-cq-on-surface-variant">Loading user details…</div>
                  )}
                  {details[req.request_id]?.error && (
                    <div className="text-[11.5px] text-cq-error">{details[req.request_id].error}</div>
                  )}
                  {details[req.request_id] && !details[req.request_id].loading && !details[req.request_id].error && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-[11.5px]">
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Email</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].profile?.email || "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Role</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].profile?.role || "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Device Revoked</span>
                        <span
                          className={`font-semibold ${
                            details[req.request_id].deviceStatus?.revoked ? "text-cq-error" : "text-cq-primary"
                          }`}
                        >
                          {details[req.request_id].deviceStatus
                            ? details[req.request_id].deviceStatus.revoked
                              ? "YES"
                              : "NO"
                            : "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Session Valid</span>
                        <span
                          className={`font-semibold ${
                            details[req.request_id].sessionStatus?.revoked ? "text-cq-error" : "text-cq-primary"
                          }`}
                        >
                          {details[req.request_id].sessionStatus?.revoked ? "REVOKED" : "ACTIVE"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Session Expires</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].sessionStatus?.expires_at
                            ? new Date(details[req.request_id].sessionStatus.expires_at).toLocaleString()
                            : "—"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between py-0.5">
                        <span className="text-cq-on-surface-variant">Renewals</span>
                        <span className="font-semibold text-cq-on-surface">
                          {details[req.request_id].sessionStatus?.version != null
                            ? `v${details[req.request_id].sessionStatus.version}`
                            : "—"}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {req.status !== "pending" ? (
                <div className={`text-[11.5px] rounded-cq-sm px-2.5 py-2 ${req.status === "approved" ? "text-cq-secondary bg-cq-secondary-container/10" : "text-cq-error bg-cq-error-container/10"}`}>
                  {meta.label} by {req.resolved_by_username || `admin #${req.resolved_by}`} at{" "}
                  {formatTimestamp(req.resolved_at)}
                  {req.resolution_note && (
                    <>
                      {" — "}
                      {req.resolution_note}
                    </>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2 mt-1">
                  <TextField
                    value={notes[req.request_id] || ""}
                    onChange={(e) => setNotes((prev) => ({ ...prev, [req.request_id]: e.target.value }))}
                    placeholder="Note (optional)"
                    className="flex-1"
                  />
                  <Button
                    variant="primary"
                    size="sm"
                    icon={CheckCircle2}
                    loading={busyId === req.request_id}
                    onClick={() => handleDecision(req.request_id, "approve")}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    icon={XCircle}
                    loading={busyId === req.request_id}
                    onClick={() => handleDecision(req.request_id, "reject")}
                  >
                    Reject
                  </Button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SecurityIncidentsPanel() {
  const [incidents, setIncidents] = useState(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("unresolved"); // "unresolved" | "all"
  const [busyId, setBusyId] = useState(null);
  const [notes, setNotes] = useState({});
  const [message, setMessage] = useState("");

  async function load(nextFilter = filter) {
    setError("");
    try {
      const resolved = nextFilter === "unresolved" ? false : undefined;
      const rows = await listSecurityIncidents(resolved);
      setIncidents(rows);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load security incidents");
    }
  }

  useEffect(() => {
    load(filter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  async function handleResolve(incidentId) {
    const note = (notes[incidentId] || "").trim();
    if (!note) {
      setError("A resolution note is required before restoring access.");
      return;
    }
    setBusyId(incidentId);
    setError("");
    setMessage("");
    try {
      await resolveSecurityIncident(incidentId, note);
      setMessage(`Incident #${incidentId} resolved — device access restored.`);
      await load(filter);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to resolve incident");
    } finally {
      setBusyId(null);
    }
  }

  if (incidents === null && !error) return <Loading label="Loading security incidents…" />;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center justify-between mb-1">
        <h2 className="text-[16px] font-bold text-cq-on-surface">Security Incidents</h2>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" icon={RefreshCcw} onClick={() => load(filter)}>
            Refresh
          </Button>
          <div className="inline-flex rounded-cq-md overflow-hidden border border-white/10">
            {[
              { id: "unresolved", label: "Open" },
              { id: "all", label: "All" },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={`px-3 py-1.5 text-[12px] font-semibold ${
                  filter === f.id ? "bg-cq-primary-container/20 text-cq-primary" : "text-cq-on-surface-variant"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Every automatic CRITICAL-severity revocation triggered by Qira is recorded here.
        Qira can revoke access — it can never restore it; only an authorized administrator
        can, and doing so requires a resolution note (recorded to the audit trail).
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      {incidents?.length === 0 && (
        <div className="text-[13px] text-cq-on-surface-variant py-6 text-center">
          No {filter === "unresolved" ? "open" : ""} security incidents.
        </div>
      )}

      <div className="space-y-3">
        {incidents?.map((incident) => {
          const sevMeta = SEVERITY_META[incident.severity] || SEVERITY_META.LOW;
          return (
            <div
              key={incident.incident_id}
              className={`rounded-cq-lg border border-white/10 p-3.5 ${sevMeta.bg}`}
            >
              <div className="flex items-start justify-between gap-3 mb-1.5">
                <div>
                  <div className={`text-[12.5px] font-bold ${sevMeta.tone}`}>
                    {incident.severity} · {incident.security_state}
                  </div>
                  <div className="text-[11px] text-cq-on-surface-variant">
                    {formatTimestamp(incident.detected_at)}
                  </div>
                </div>
                {incident.resolved ? (
                  <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-cq-secondary">
                    <CheckCircle2 size={12} /> Resolved
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-cq-error">
                    <ShieldAlert size={12} /> Open
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-3 gap-y-1 text-[11.5px] text-cq-on-surface-variant mb-2">
                <div><span className="text-cq-on-surface font-medium">User:</span> {incident.user_id}</div>
                <div><span className="text-cq-on-surface font-medium">Device:</span> {incident.device_id}</div>
                <div><span className="text-cq-on-surface font-medium">Session:</span> {incident.session_id}</div>
                <div><span className="text-cq-on-surface font-medium">Action:</span> {incident.action_taken}</div>
              </div>

              <div className="text-[12px] text-cq-on-surface mb-1">
                <span className="font-semibold">Reason: </span>
                {incident.reason}
              </div>
              {incident.signals?.length > 0 && (
                <div className="text-[11px] text-cq-on-surface-variant mb-2">
                  Signals: {incident.signals.join(", ")}
                </div>
              )}
              {incident.qira_assessment && (
                <div className="text-[10.5px] text-cq-on-surface-variant mb-2 flex items-center gap-1">
                  <Bot size={11} /> Qira assessment: confidence{" "}
                  {Math.round((incident.qira_assessment.confidence || 0) * 100)}%
                </div>
              )}

              {incident.resolved ? (
                <div className="text-[11.5px] text-cq-secondary bg-cq-secondary-container/10 rounded-cq-sm px-2.5 py-2">
                  Resolved by admin #{incident.resolved_by} at {formatTimestamp(incident.resolved_at)}
                  {incident.resolution_note && (
                    <>
                      {" — "}
                      {incident.resolution_note}
                    </>
                  )}
                </div>
              ) : (
                <div className="flex items-center gap-2 mt-1">
                  <TextField
                    value={notes[incident.incident_id] || ""}
                    onChange={(e) =>
                      setNotes((prev) => ({ ...prev, [incident.incident_id]: e.target.value }))
                    }
                    placeholder="Resolution note (required)"
                    className="flex-1"
                  />
                  <Button
                    variant="primary"
                    size="sm"
                    icon={CheckCircle2}
                    disabled={busyId === incident.incident_id}
                    onClick={() => handleResolve(incident.incident_id)}
                  >
                    Restore Access
                  </Button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DevicesPanel({ user }) {
  const ownDeviceId = localStorage.getItem(`ibqc_device_id_${user?.userId}`);
  const ownSessionId = localStorage.getItem("ibqc_session_id");
  const [deviceId, setDeviceId] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [deviceStatus, setDeviceStatus] = useState(null);
  const [sessionStatus, setSessionStatus] = useState(null);
  const [checking, setChecking] = useState(false);

  async function run(action, label, targetType = null, targetId = null) {
    if (targetType === "session" && targetId && targetId === ownSessionId) {
      setError("An administrator cannot revoke the current administrator session.");
      return;
    }
    if (targetType === "device" && targetId && targetId === ownDeviceId) {
      setError("An administrator cannot revoke the current administrator device.");
      return;
    }
    setError("");
    setMessage("");
    try {
      await action();
      setMessage(label);
      // Refresh whichever status card is currently showing this entity,
      // using the same real lookup endpoints — never assumed locally.
      if (targetType === "device" && targetId === deviceId) checkDevice();
      if (targetType === "session" && targetId === sessionId) checkSession();
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Action failed");
    }
  }

  async function checkDevice() {
    if (!deviceId) return;
    setChecking(true);
    try {
      setDeviceStatus(await getDeviceStatus(deviceId));
    } catch (err) {
      setDeviceStatus(null);
      setError(err.detail?.toString?.() || err.message || "Device lookup failed");
    } finally {
      setChecking(false);
    }
  }

  async function checkSession() {
    if (!sessionId) return;
    setChecking(true);
    try {
      setSessionStatus(await getSessionStatus(sessionId));
    } catch (err) {
      setSessionStatus(null);
      setError(err.detail?.toString?.() || err.message || "Session lookup failed");
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <h2 className="text-[16px] font-bold text-cq-on-surface mb-1">Devices & Sessions</h2>
      <p className="text-[13px] text-cq-on-surface-variant mb-4">
        Revoking a device or session immediately invalidates the current cryptographic
        authorization state for it — any in-flight encrypt/decrypt request against it is
        rejected, and a fresh authentication is required to establish a new authorization state.
      </p>
      <Alert type="error">{error}</Alert>
      {message && <Alert type="success">{message}</Alert>}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
        <Field label="Device ID">
          <div className="flex gap-2">
            <TextField value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="device-001" />
            <Button variant="outline" size="sm" onClick={checkDevice} disabled={!deviceId || checking}>
              Check
            </Button>
          </div>
        </Field>
        <Field label="Session ID">
          <div className="flex gap-2">
            <TextField value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="session-abc" />
            <Button variant="outline" size="sm" onClick={checkSession} disabled={!sessionId || checking}>
              Check
            </Button>
          </div>
        </Field>
      </div>

      {/* Security-entity status cards — populated only from real
          getDeviceStatus/getSessionStatus responses, never inferred. */}
      {(deviceStatus || sessionStatus) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3 mb-1">
          {deviceStatus && <EntityStatusCard kind="Device" id={deviceStatus.device_id} revoked={deviceStatus.revoked} extra={[
            { label: "Trust", value: deviceStatus.status },
            { label: "Own device", value: deviceStatus.is_own_device ? "yes" : "no" },
            { label: "Claimed", value: deviceStatus.has_any_owner ? "yes" : "no" },
          ]} />}
          {sessionStatus && <EntityStatusCard kind="Session" id={sessionStatus.session_id} revoked={sessionStatus.revoked} extra={[
            { label: "Device", value: sessionStatus.device_id },
            { label: "Expires", value: formatTimestamp(sessionStatus.expires_at) },
            { label: "Version", value: sessionStatus.version },
          ]} />}
        </div>
      )}

      <div className="flex flex-wrap gap-2 mt-2">
        <Button
          variant="danger"
          size="sm"
          icon={XCircle}
          disabled={!deviceId}
          onClick={() => run(() => revokeDevice(deviceId), `Device ${deviceId} revoked`, "device", deviceId)}
        >
          Revoke Device
        </Button>
        <Button
          variant="outline"
          size="sm"
          icon={CheckCircle2}
          disabled={!deviceId}
          onClick={() => run(() => unrevokeDevice(deviceId), `Device ${deviceId} unrevoked`)}
        >
          Unrevoke Device
        </Button>
        <Button
          variant="danger"
          size="sm"
          icon={XCircle}
          disabled={!sessionId}
          onClick={() => run(() => revokeSession(sessionId), `Session ${sessionId} revoked`, "session", sessionId)}
        >
          Revoke Session
        </Button>
      </div>
    </div>
  );
}

function EntityStatusCard({ kind, id, revoked, extra }) {
  const tone = revoked ? "#ffb4ab" : "#63f7ff";
  return (
    <div className="relative rounded-cq-lg bg-cq-surface-container-high border border-cq-outline-variant/15 p-4 overflow-hidden">
      <div className="absolute inset-y-0 left-0 w-[2px]" style={{ background: tone }} />
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-bold tracking-[0.16em] text-cq-on-surface-variant uppercase">{kind}</span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full cq-telemetry-dot" style={{ background: tone }} />
          <span className="text-[10.5px] font-bold uppercase tracking-wide" style={{ color: tone }}>
            {revoked ? "revoked" : "active"}
          </span>
        </span>
      </div>
      <div className="text-[12.5px] font-mono text-cq-on-surface break-all">{id}</div>
      <div className="mt-2.5 space-y-1">
        {extra.map((row) => (
          <div key={row.label} className="flex items-center justify-between text-[11.5px]">
            <span className="text-cq-on-surface-variant">{row.label}</span>
            <span className="text-cq-on-surface font-medium font-mono">{String(row.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
// Admin's own live monitoring
// ---------------------------------------------------------------------
// IMPORTANT: This is intentionally NOT an all-users risk overview.
// The Admin Dashboard already runs inside the same MonitoringProvider as
// every authenticated page. Therefore the Admin tab must use that exact
// context: the admin's own authenticated user/device/session, their own
// enrolled face, and their own continuous camera heartbeat.

function AdminOwnLiveMonitoringPanel({ user }) {
  /*
   * ADMIN-ONLY LIVE MONITORING
   *
   * This panel is deliberately a READ-ONLY view of the same authoritative
   * MonitoringContext heartbeat that is already running for the currently
   * authenticated administrator.
   *
   * Do NOT run a second face-analysis loop here. MonitoringContext already:
   *   camera -> face detection -> fresh descriptor -> /face/verify
   *           -> /api/monitoring/heartbeat -> authoritative snapshot
   *
   * That keeps Admin Live Monitoring tied to THIS admin's enrolled face,
   * rather than to an all-user aggregate or a separate local state machine.
   */
  const {
    snapshot,
    isMonitoring,
    cameraState,
    connectionState,
    webcamRef,
    deviceId,
    sessionId,
    sessionStatus,
    reauthRequired,
    deviceRevoked,
    reauthenticate,
  } = useMonitoringContext();

  const [open, setOpen] = useState(false);
  const [reauthPanelOpen, setReauthPanelOpen] = useState(false);
  const [reauthError, setReauthError] = useState("");
  const videoRef = useRef(null);
  const [attached, setAttached] = useState(false);

  // Attach the SAME camera stream used by MonitoringContext. Never request
  // a second webcam and never create a competing face-monitoring loop.
  useEffect(() => {
    if (!open) {
      setAttached(false);
      return undefined;
    }

    let cancelled = false;
    let raf = 0;

    const attach = () => {
      if (cancelled) return;
      const stream = webcamRef?.current?.video?.srcObject;
      if (stream && videoRef.current) {
        if (videoRef.current.srcObject !== stream) {
          videoRef.current.srcObject = stream;
        }
        setAttached(true);
        return;
      }
      raf = requestAnimationFrame(attach);
    };

    attach();

    return () => {
      cancelled = true;
      if (raf) cancelAnimationFrame(raf);
    };
  }, [open, webcamRef, cameraState]);

  /*
   * Hard scope check: the Admin Live Monitoring panel may consume a
   * snapshot only when it belongs to the currently authenticated admin.
   * It must never display another user's monitoring state.
   */
  const snapshotBelongsToAdmin =
    snapshot && user?.userId != null
      ? String(snapshot.current_user) === String(user.userId)
      : false;

  const adminSnapshot = snapshotBelongsToAdmin ? snapshot : null;

  const identityState = adminSnapshot?.identity_state || "no_face";
  const identityVerified = identityState === "identity_confirmed";
  const faceDetected =
    identityState === "identity_confirmed" ||
    identityState === "identity_mismatch" ||
    identityState === "liveness_uncertain";

  const cameraActive = cameraState === "ready" && (attached || !open);

  /*
   * Monitoring state is driven by the SAME backend heartbeat that performs
   * the administrator-specific face verification.
   *
   * A matched enrolled face is SECURE.
   * A missing/mismatched/uncertain face is immediately shown as WARNING
   * while the backend's existing 8/12 failure thresholds still control
   * REAUTH/REVOKED. This changes only the Admin UI presentation; it does
   * not alter the user's working monitoring thresholds or crypto gate.
   */
  let monitorLabel = "STARTING";
  let monitorTone = "text-cq-on-surface-variant";
  let monitorDot = "bg-cq-outline";

  // When no monitoring session has been established AND the backend
  // has flagged that re-authentication is required (session revoked,
  // or — for a device revocation — restorable by this same admin via
  // reauthenticate(), see MonitoringContext), the camera is never even
  // opened (see cameraState fix above) and `adminSnapshot` never
  // arrives. Surface that explicitly instead of showing "STARTING"
  // forever, which looked like a hang.
  const needsReauth = (!isMonitoring || !adminSnapshot) && reauthRequired;

  if (needsReauth) {
    monitorLabel = "RE-AUTHENTICATION REQUIRED";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  } else if (adminSnapshot?.status === "revoked") {
    monitorLabel = "REVOKED";
    monitorTone = "text-cq-error";
    monitorDot = "bg-cq-error";
  } else if (adminSnapshot?.status === "reauth_required") {
    monitorLabel = "RE-AUTHENTICATION REQUIRED";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  } else if (adminSnapshot?.status === "warning") {
    monitorLabel = "WARNING";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  } else if (identityVerified && adminSnapshot?.liveness) {
    monitorLabel = "SECURE";
    monitorTone = "text-cq-secondary";
    monitorDot = "bg-cq-secondary";
  } else if (adminSnapshot) {
    monitorLabel = "WARNING";
    monitorTone = "text-amber-500";
    monitorDot = "bg-amber-500";
  }

  const identityLabel =
    identityState === "identity_confirmed"
      ? "IDENTITY CONFIRMED"
      : identityState === "identity_mismatch"
        ? "IDENTITY MISMATCH"
        : identityState === "no_face"
          ? "NO FACE DETECTED"
          : identityState === "liveness_uncertain"
            ? "LIVENESS UNCERTAIN"
            : identityState === "camera_unavailable"
              ? "CAMERA UNAVAILABLE"
              : "WAITING";

  const identityReason = needsReauth
    ? deviceRevoked
      ? "Your device was revoked. As the administrator, you can restore it yourself with a fresh face verification below — there is no higher authority to approve this for you."
      : "Your session was revoked. Verify your face against your enrolled identity below to restore monitoring."
    : adminSnapshot?.reason ||
    (identityState === "identity_confirmed"
      ? "Administrator face matches the enrolled identity."
      : identityState === "identity_mismatch"
        ? "The detected face does not match the enrolled administrator."
        : identityState === "no_face"
          ? "No face was detected in the administrator's current monitoring frame."
          : "Waiting for the next administrator-specific monitoring heartbeat.");

  const confidence = adminSnapshot?.face_match_confidence;
  const liveness = !!adminSnapshot?.liveness;
  const consecutiveFailures = adminSnapshot?.consecutive_face_failures ?? 0;
  const authLabel =
    adminSnapshot?.current_authorization_state === "valid" && !sessionStatus?.revoked
      ? "VALID"
      : "INVALID / REAUTH REQUIRED";

  return (
    <>
      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-[16px] font-bold text-cq-on-surface">Admin Live Monitoring</h2>
            <p className="text-[13px] text-cq-on-surface-variant mt-1 max-w-3xl">
              Continuous identity monitoring for{" "}
              <span className="font-semibold text-cq-on-surface">
                {user?.username || "the administrator"}
              </span>{" "}
              only. The state below comes from this admin's enrolled-face
              verification and monitoring heartbeat — never from other users.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setOpen(true)}
            className="shrink-0 inline-flex items-center gap-2 rounded-cq-md bg-cq-primary-container/20 text-cq-primary px-3 py-2 text-[12px] font-semibold hover:bg-cq-primary-container/30"
          >
            Open Live Monitor
          </button>
        </div>

        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Monitoring
            </div>
            <div className={`mt-1 text-[14px] font-bold ${monitorTone}`}>
              {monitorLabel}
            </div>
          </div>

          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Camera
            </div>
            <div className={`mt-1 text-[14px] font-bold ${cameraState === "ready" ? "text-cq-secondary" : cameraState === "requesting" ? "text-amber-500" : "text-cq-error"}`}>
              {cameraState === "ready"
                ? "ACTIVE"
                : cameraState === "unavailable"
                  ? "UNAVAILABLE"
                  : cameraState === "requesting"
                    ? "OPENING…"
                    : /* 'idle': no monitoring session is running yet, so the
                         camera has not even been asked to open — most
                         commonly because re-authentication is required
                         first. Never label this "OPENING", which falsely
                         implies a permission prompt is pending. */
                      "NOT STARTED"}
            </div>
          </div>

          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Identity
            </div>
            <div className={`mt-1 text-[14px] font-bold ${identityVerified ? "text-cq-secondary" : "text-amber-400"}`}>
              {identityLabel}
            </div>
          </div>

          <div className="rounded-cq-md bg-cq-surface-container-high p-3">
            <div className="text-[10px] uppercase tracking-wide text-cq-on-surface-variant">
              Face Match
            </div>
            <div className={`mt-1 text-[14px] font-bold ${identityVerified ? "text-cq-secondary" : "text-cq-on-surface"}`}>
              {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"}
            </div>
          </div>
        </div>

        <div className="mt-4 rounded-cq-md border border-cq-outline-variant/15 bg-cq-surface-container-high/50 p-3">
          <div className={`text-[12px] font-semibold ${monitorTone}`}>
            {identityReason}
          </div>

          {needsReauth && (
            <div className="mt-3">
              {!reauthPanelOpen ? (
                <button
                  type="button"
                  onClick={() => setReauthPanelOpen(true)}
                  className="inline-flex items-center gap-2 rounded-cq-md bg-cq-primary-container/20 text-cq-primary px-3 py-2 text-[12px] font-semibold hover:bg-cq-primary-container/30"
                >
                  Re-authenticate now
                </button>
              ) : (
                <div className="max-w-sm">
                  {reauthError && (
                    <div className="mb-2 rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
                      {reauthError}
                    </div>
                  )}
                  <FaceAuthPanel
                    mode="verify"
                    title="Reauthenticate"
                    subtitle={
                      deviceRevoked
                        ? "Verify your enrolled face to restore this device and resume monitoring."
                        : "Verify your enrolled face to restore your session and resume monitoring."
                    }
                    onSuccess={async ({ descriptor }) => {
                      try {
                        setReauthError("");
                        await reauthenticate(descriptor);
                        setReauthPanelOpen(false);
                      } catch (err) {
                        setReauthError(err.message || "Reauthentication failed");
                      }
                    }}
                    onCancel={() => setReauthPanelOpen(false)}
                  />
                </div>
              )}
            </div>
          )}

          <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[11px] text-cq-on-surface-variant">
            <div>
              Admin:{" "}
              <span className="text-cq-on-surface font-semibold">
                {user?.username || "—"}
              </span>
            </div>
            <div>
              User ID:{" "}
              <span className="text-cq-on-surface font-semibold">
                {user?.userId || "—"}
              </span>
            </div>
            <div>
              Face:{" "}
              <span className="text-cq-on-surface font-semibold">
                {faceDetected ? "DETECTED" : "NOT DETECTED"}
              </span>
            </div>
            <div>
              Identity:{" "}
              <span className="text-cq-on-surface font-semibold">
                {identityLabel}
              </span>
            </div>
            <div>
              Liveness:{" "}
              <span className="text-cq-on-surface font-semibold">
                {liveness ? "CONFIRMED" : "NOT CONFIRMED"}
              </span>
            </div>
            <div>
              Confidence:{" "}
              <span className="text-cq-on-surface font-semibold">
                {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"}
              </span>
            </div>
            <div>
              Authorization:{" "}
              <span className={`font-semibold ${authLabel === "VALID" ? "text-cq-secondary" : "text-cq-error"}`}>
                {authLabel}
              </span>
            </div>
            <div>
              Consecutive failures:{" "}
              <span className="text-cq-on-surface font-semibold">
                {consecutiveFailures}
              </span>
            </div>
            <div>
              Device:{" "}
              <span className="text-cq-on-surface font-semibold">
                {deviceId || "—"}
              </span>
            </div>
            <div>
              Session:{" "}
              <span className="text-cq-on-surface font-semibold">
                {sessionId || "—"}
              </span>
            </div>
            <div className="sm:col-span-2">
              Last monitoring check:{" "}
              <span className="text-cq-on-surface font-semibold">
                {adminSnapshot?.timestamp ? formatTimestamp(adminSnapshot.timestamp) : "—"}
              </span>
            </div>
          </div>

          {connectionState === "lost" && (
            <div className="mt-3 rounded-cq-sm bg-amber-400/10 border border-amber-400/20 px-3 py-2 text-[11px] text-amber-300">
              Monitoring backend connection is temporarily lost. The displayed result is the last confirmed administrator-specific state.
            </div>
          )}

          {sessionStatus?.revoked && (
            <div className="mt-3 rounded-cq-sm bg-amber-400/10 border border-amber-400/20 px-3 py-2 text-[11px] text-amber-300">
              The administrator's authorization session is revoked. This is separate from the face identity result.
            </div>
          )}
        </div>
      </div>

      {open && (
        <div
          className="fixed inset-0 z-[110] flex items-center justify-center bg-black/60 backdrop-blur-sm px-4"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-cq-xl bg-cq-surface-container-low border border-cq-outline-variant/20 shadow-cq-popover overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-cq-outline-variant/10">
              <div>
                <div className="text-[13px] font-bold uppercase tracking-wide text-cq-on-surface">
                  Admin Live Security Monitoring
                </div>
                <div className="text-[10.5px] text-cq-on-surface-variant mt-0.5">
                  {user?.username || "admin"} · own enrolled identity
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="text-cq-on-surface-variant hover:text-cq-on-surface text-xl"
              >
                ×
              </button>
            </div>

            <div className="relative bg-black aspect-video flex items-center justify-center">
              {cameraState === "ready" && attached ? (
                <video
                  ref={videoRef}
                  autoPlay
                  playsInline
                  muted
                  className="w-full h-full object-cover scale-x-[-1]"
                />
              ) : (
                <div className="flex flex-col items-center gap-2 text-cq-on-surface-variant py-10">
                  <div className="text-[12px]">
                    {cameraState === "unavailable" ? "Camera unavailable" : "Opening camera…"}
                  </div>
                </div>
              )}

              <div className="absolute top-2.5 left-2.5 flex items-center gap-1.5 rounded-full bg-black/55 px-2.5 py-1 text-[11px] font-semibold text-white">
                <span className={`w-1.5 h-1.5 rounded-full ${cameraState === "ready" ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`} />
                {cameraState === "ready" ? "Camera live" : "Camera off"}
              </div>

              <div className="absolute bottom-2 right-2 inline-flex items-center gap-1 rounded-full bg-black/60 px-2 py-0.5 text-[10px] text-white">
                <Activity size={10} className={isMonitoring ? "text-cq-secondary animate-pulse" : "text-cq-on-surface-variant"} />
                {isMonitoring ? "Monitoring continuously" : "Monitoring not established"}
              </div>
            </div>

            <div className="p-4">
              <div className="flex items-center gap-2">
                <div className={`text-[14px] font-bold ${monitorTone}`}>
                  {monitorLabel}
                </div>
                <span className={`ml-auto w-2 h-2 rounded-full ${monitorDot}`} />
              </div>

              <div className={`mt-1 text-[12px] leading-relaxed ${monitorTone}`}>
                {identityReason}
              </div>

              <div className="mt-4 space-y-1.5 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Face</span>
                  <span className={faceDetected ? "text-cq-secondary font-semibold" : "text-amber-400 font-semibold"}>
                    {faceDetected ? "DETECTED" : "NOT DETECTED"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Identity</span>
                  <span className={identityVerified ? "text-cq-secondary font-semibold" : "text-amber-400 font-semibold"}>
                    {identityLabel}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Confidence</span>
                  <span className="text-cq-on-surface font-semibold">
                    {confidence != null ? `${(confidence * 100).toFixed(1)}%` : "—"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Liveness</span>
                  <span className={liveness ? "text-cq-secondary font-semibold" : "text-amber-400 font-semibold"}>
                    {liveness ? "CONFIRMED" : "NOT CONFIRMED"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Authorization</span>
                  <span className={authLabel === "VALID" ? "text-cq-secondary font-semibold" : "text-cq-error font-semibold"}>
                    {authLabel}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-cq-on-surface-variant">Consecutive failures</span>
                  <span className="text-cq-on-surface font-semibold">
                    {consecutiveFailures}
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-cq-outline-variant/10 text-[10.5px] text-cq-on-surface-variant">
                This panel displays only the authenticated administrator's
                enrolled-face monitoring result. It does not aggregate,
                average, or inspect other users.
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------

export default function AdminDashboard({ user }) {
  const [tab, setTab] = useState("users");

  return (
    <div>
      <PageHeader
        icon="admin_panel_settings"
        eyebrow="Administration"
        title="Admin Dashboard"
        description="Server-enforced role hierarchy: ADMIN, USER_LEVEL_2 (security officer/manager), USER_LEVEL_1 (user). Every action here is re-checked against the caller's role on the backend — this page only surfaces what the API already permits."
        right={
          <div className="inline-flex items-center gap-1.5 rounded-cq-md bg-cq-secondary-container/15 text-cq-secondary px-3 py-1.5 text-[12.5px] font-semibold">
            <ShieldCheck size={14} /> {user?.role || "—"}
          </div>
        }
      />

      <div className="flex items-center gap-1 mb-5 border-b border-cq-outline-variant/15 pb-1 overflow-x-auto">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={
                "relative inline-flex items-center gap-1.5 px-3.5 py-2 rounded-cq-md text-[13px] font-semibold whitespace-nowrap transition-colors " +
                (active
                  ? "bg-cq-primary-container/20 text-cq-primary"
                  : "text-cq-on-surface-variant hover:bg-cq-surface-container-highest hover:text-cq-on-surface")
              }
            >
              <Icon size={15} /> {t.label}
              {active && (
                <motion.span
                  layoutId="admin-tab-indicator"
                  className="absolute left-2 right-2 -bottom-[5px] h-[2px] rounded-full bg-cq-primary"
                  transition={{ type: "spring", stiffness: 500, damping: 40 }}
                />
              )}
            </button>
          );
        })}
      </div>

      {tab === "users" && <UsersPanel user={user} />}
      {tab === "intents" && <IntentsPanel />}
      {tab === "access-requests" && <ReauthRequestsPanel />}
      {tab === "devices" && <DevicesPanel user={user} />}
      {tab === "risk" && <AdminOwnLiveMonitoringPanel user={user} />}
      {tab === "incidents" && <SecurityIncidentsPanel />}
    </div>
  );
}