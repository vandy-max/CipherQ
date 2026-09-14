// SINGLE frontend mapping from the backend-authoritative monitoring
// snapshot to the UI state. Every monitoring surface must use this
// function; no component may invent its own SECURE/WARNING/REAUTH/
// REVOKED interpretation.

export const MONITORING_UI_META = {
  active: { label: "SECURE", tone: "text-cq-primary", dot: "bg-cq-secondary" },
  warning: { label: "WARNING", tone: "text-amber-500", dot: "bg-amber-500" },
  reauth_required: { label: "RE-AUTHENTICATION REQUIRED", tone: "text-amber-500", dot: "bg-amber-500" },
  revoked: { label: "REVOKED", tone: "text-cq-error", dot: "bg-cq-error" },
  off: { label: "OFF", tone: "text-cq-on-surface-variant", dot: "bg-cq-outline" },
};

export function deriveMonitoringState({ isMonitoring, snapshot, connectionState, reauthRequired = false }) {
  if ((!isMonitoring || !snapshot) && reauthRequired) return "reauth_required";
  if (!isMonitoring || !snapshot) return "off";
  if (connectionState === "lost") return "warning";
  if (snapshot.status === "active" || snapshot.status === "warning" || snapshot.status === "reauth_required" || snapshot.status === "revoked") {
    return snapshot.status;
  }
  return "warning";
}

export function monitoringReason(stateKey, snapshot, connectionState) {
  if (stateKey === "off") return null;
  if (connectionState === "lost") {
    return snapshot?.reason || "Lost contact with the monitoring backend. Last confirmed state is shown.";
  }
  if (snapshot?.reason) return snapshot.reason;
  if (stateKey === "reauth_required") return "Repeated identity verification failures require fresh authorization.";
  if (stateKey === "revoked") return "The backend has revoked this authorization state, but no detailed reason was supplied.";
  if (stateKey === "warning") return "A recoverable monitoring anomaly was detected. Monitoring continues.";
  return "Face identity confirmed, liveness confirmed, device/session authorization valid, and monitoring connection healthy.";
}
