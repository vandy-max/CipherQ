import { ShieldX } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";

export default function MonitoringBlockedBanner() {
  let ctx;
  try {
    ctx = useMonitoringContext();
  } catch {
    return null;
  }

  const { snapshot, reauthRequired, monitoringSessionId } = ctx;
  const blocked = reauthRequired || !monitoringSessionId || snapshot?.status === "revoked" || snapshot?.status === "reauth_required";
  if (!blocked) return null;

  let message = "No active continuous-monitoring session is available. Reauthenticate before protected cryptographic operations can continue.";
  if (reauthRequired || snapshot?.status === "reauth_required") {
    message = "Continuous monitoring requires fresh reauthentication before protected cryptographic operations can continue.";
  } else if (snapshot?.status === "revoked") {
    message = "Session is removed/revoked. Fresh reauthentication is required before protected cryptographic operations can continue.";
  }

  return (
    <div className="mb-5 flex items-start gap-3 rounded-cq-lg border border-cq-error/30 bg-cq-error-container/10 px-4 py-3.5">
      <ShieldX size={18} className="text-cq-error shrink-0 mt-0.5" />
      <div>
        <div className="text-[13.5px] font-bold text-cq-error">Cryptography: BLOCKED</div>
        <div className="text-[12.5px] text-cq-on-surface-variant mt-0.5">{message}</div>
      </div>
    </div>
  );
}
