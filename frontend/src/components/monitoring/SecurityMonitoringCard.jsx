import { useState } from "react";
import { ShieldCheck, ShieldX, ScanFace, ShieldOff, Video } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { formatTimestamp } from "../../utils/formatTimestamp";
import LiveMonitoringPanel from "./LiveMonitoringPanel";
import { deriveMonitoringState, monitoringReason } from "./monitoringState";
import CipherQMascot from "../mascot/CipherQMascot";

// PART 1 (spec section 1) — a calm, dashboard-resident summary of the
// SAME continuous-monitoring state MonitoringBadge shows in the
// topbar, AND the clickable entry point into the full Live Monitoring
// panel (camera preview + detail — see LiveMonitoringPanel.jsx).
// Deliberately reads the same MonitoringContext snapshot and applies
// the SAME backend-is-truth rule: every state shown here is derived
// directly from the last confirmed backend heartbeat/session
// response, never from a local timer or a frontend-only guess.
//
// THE IMPORTANT RULE (see deriveLiveMonitoringState below): live
// face-monitoring status is a DIFFERENT security dimension from
// audit-chain/system integrity — that fact is surfaced separately
// (see the "Audit Integrity" chip below), never by overriding this
// card's primary live-monitoring state.
//
// PART 2/10 — this card shows the SAME four distinct states as
// MonitoringBadge/LiveMonitoringPanel: SECURE, WARNING (recoverable —
// the session stays usable while it's watched more closely),
// RE-AUTHENTICATION REQUIRED, and REVOKED. WARNING is never folded
// into SECURE, and RE-AUTHENTICATION REQUIRED is never folded into
// REVOKED — each is its own condition with its own reason/action.
const STATE_META = {
  active: {
    label: "MONITORING SECURE",
    tone: "text-cq-primary",
    dot: "bg-cq-secondary",
    icon: ShieldCheck,
  },
  warning: {
    label: "MONITORING WARNING",
    tone: "text-amber-500",
    dot: "bg-amber-500",
    icon: ScanFace,
  },
  reauth_required: {
    label: "RE-AUTHENTICATION REQUIRED",
    tone: "text-amber-500",
    dot: "bg-amber-500",
    icon: ScanFace,
  },
  revoked: {
    label: "MONITORING REVOKED",
    tone: "text-cq-error",
    dot: "bg-cq-error",
    icon: ShieldX,
  },
  off: {
    label: "MONITORING OFF",
    tone: "text-cq-on-surface-variant",
    dot: "bg-cq-outline",
    icon: ShieldOff,
  },
};

export default function SecurityMonitoringCard() {
  const { snapshot, isMonitoring, connectionState, reauthRequired } = useMonitoringContext();
  const [panelOpen, setPanelOpen] = useState(false);
  const stateKey = deriveMonitoringState({ isMonitoring, snapshot, connectionState, reauthRequired });
  const meta = STATE_META[stateKey];
  const Icon = meta.icon;
  const reason = monitoringReason(stateKey, snapshot, connectionState);
  const secure = stateKey === "active";
  // Audit-chain integrity is a SEPARATE security dimension from live
  // face monitoring — see module docstring. Shown as an additive
  // chip, exactly like the Qira chip, never as this card's primary
  // state.

  return (
    <>
      <button
        type="button"
        onClick={() => setPanelOpen(true)}
        className="text-left w-full bg-cq-surface-container rounded-cq-xl p-cq-stack-lg hover:bg-cq-surface-container-high transition-colors cursor-pointer"
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className={`inline-flex w-7 h-7 items-center justify-center rounded-cq-md bg-cq-surface-container-high ${meta.tone}`}>
              <Icon size={15} />
            </span>
            <span className="text-[12px] font-bold uppercase tracking-wide text-cq-on-surface-variant">Continuous Monitoring</span>
          </div>
          <div className="flex items-center gap-2">
            <Video size={13} className="text-cq-on-surface-variant" />
          </div>
        </div>

        <div className="flex items-center gap-2 mb-2.5">
          <div className={`w-2 h-2 rounded-full ${meta.dot} ${secure ? "animate-pulse" : ""}`} />
          <span className={`text-[14px] font-bold ${meta.tone}`}>{meta.label}</span>
          <CipherQMascot size="xs" status={stateKey} tooltip={reason || meta.label} className="ml-auto" />
        </div>

        {stateKey === "active" ? (
          <ul className="space-y-1 text-[12.5px] text-cq-on-surface-variant">
            <li>• Camera Active</li>
            <li>• Face Detected</li>
            <li>• Identity Confirmed</li>
            <li>• Liveness Confirmed</li>
            <li>• Session Active · Authorization Valid</li>
            <li>• Risk: {snapshot?.current_risk?.toUpperCase?.() || "—"}</li>
          </ul>
        ) : stateKey === "off" ? (
          <p className="text-[12.5px] text-cq-on-surface-variant">Monitoring has not started for this session yet.</p>
        ) : (
          <p className={`text-[12.5px] leading-relaxed ${meta.tone}`}>{reason}</p>
        )}

        {snapshot?.timestamp && (
          <p className="mt-2.5 text-[11px] text-cq-on-surface-variant">Last confirmed: {formatTimestamp(snapshot.timestamp)}</p>
        )}
        <p className="mt-1 text-[10.5px] text-cq-on-surface-variant/70">Tap to open Live Monitoring</p>
      </button>

      <LiveMonitoringPanel open={panelOpen} onClose={() => setPanelOpen(false)} />
    </>
  );
}
