import { Laptop, ShieldCheck, ShieldX } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { formatTimestamp } from "../../utils/formatTimestamp";

// Fix pass (continuous-monitoring-lifecycle): this card used to run
// its OWN independent 6-second poll against getDeviceStatus/
// getSessionStatus, completely disconnected from MonitoringContext's
// snapshot/reauthRequired state. That was a real bug: after
// reauthentication (or any other state change), this card could keep
// showing stale device/session info for up to 6 seconds — or longer,
// if it happened to re-poll on a stale `sessionId` closure — and on
// remount it reset to "…" and re-fetched from scratch independently
// of whatever the rest of the app already knew.
//
// It now reads deviceStatus/sessionStatus from the ONE authoritative
// place (MonitoringContext.refreshMonitoringState — see that file),
// which is refreshed on login, after every reauthentication, on tab
// visibility change, on network reconnect, and on a periodic timer —
// so every consumer (this card, CookieSessionIntegrityCard,
// MonitoringBadge) is guaranteed to agree, and updates the instant
// reauthentication completes rather than on its own independent
// timer. No polling loop lives in this component anymore.
export default function CurrentDeviceCard() {
  const { deviceId, deviceStatus, sessionStatus, isMonitoring, lastRefreshedAt } = useMonitoringContext();

  const deviceRevoked = !!deviceStatus?.revoked;
  const sessionRevoked = !!sessionStatus?.revoked;
  const revoked = deviceRevoked || sessionRevoked;
  const loaded = deviceStatus !== null || sessionStatus !== null;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center gap-2 mb-3">
        <span
          className={`inline-flex w-7 h-7 items-center justify-center rounded-cq-md bg-cq-surface-container-high ${
            revoked ? "text-cq-error" : "text-cq-primary"
          }`}
        >
          <Laptop size={15} />
        </span>
        <span className="text-[12px] font-bold uppercase tracking-wide text-cq-on-surface-variant">Current Device</span>
      </div>

      {revoked ? (
        <div className="flex items-center gap-2 mb-2.5">
          <ShieldX size={15} className="text-cq-error" />
          <span className="text-[14px] font-bold text-cq-error">DEVICE ACCESS REVOKED</span>
        </div>
      ) : (
        <div className="flex items-center gap-2 mb-2.5">
          <ShieldCheck size={15} className="text-cq-primary" />
          <span className="text-[14px] font-bold text-cq-primary">ACTIVE</span>
        </div>
      )}

      <div className="space-y-1 text-[12.5px]">
        <Row label="Device ID" value={deviceId ? `${deviceId.slice(0, 14)}…` : "—"} mono />
        <Row
          label="Device status"
          value={deviceStatus ? (deviceRevoked ? "REVOKED" : "ACTIVE") : "…"}
          tone={deviceRevoked ? "error" : "ok"}
        />
        <Row
          label="Session status"
          value={sessionStatus ? (sessionRevoked ? "SESSION INVALID" : "ACTIVE") : "…"}
          tone={sessionRevoked ? "error" : "ok"}
        />
        <Row label="Monitoring status" value={isMonitoring ? "MONITORED" : "NOT MONITORED"} tone={isMonitoring ? "ok" : "muted"} />
        <Row label="Last seen" value={deviceStatus?.last_seen ? formatTimestamp(deviceStatus.last_seen) : "—"} />
      </div>

      {revoked && (
        <p className="mt-2.5 text-[11.5px] text-cq-error leading-relaxed">
          Reauthentication and reauthorization are required before this device/session can be used again — use the
          monitoring badge's "Reauthenticate" action.
        </p>
      )}
      {!loaded && <p className="mt-2 text-[11px] text-cq-on-surface-variant">Waiting for the first backend state refresh…</p>}
      {loaded && lastRefreshedAt && (
        <p className="mt-2 text-[10.5px] text-cq-on-surface-variant">Confirmed as of {formatTimestamp(lastRefreshedAt)}</p>
      )}
    </div>
  );
}

function Row({ label, value, tone, mono }) {
  const toneClass =
    tone === "error" ? "text-cq-error" : tone === "ok" ? "text-cq-primary" : tone === "muted" ? "text-cq-on-surface-variant" : "text-cq-on-surface";
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-cq-on-surface-variant">{label}</span>
      <span className={`font-semibold ${toneClass} ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}
