import { useEffect, useRef, useState } from "react";
import { Fingerprint, ShieldAlert } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";

const TOKEN_KEY = "ibqc_token";

// Fix pass (continuous-monitoring-lifecycle): this card used to run
// its OWN independent 6-second poll against getSessionStatus AND
// treated a 403/404 from that call as "revoked" — but a 404 here
// really only means "no session record exists yet" (e.g. the very
// first render, before MonitoringContext's bootstrap has finished
// calling refreshSession), not an actual revocation. That mislabeling
// could show a spurious "INVALIDATED" right after login, and — worse
// — after a real reauthentication succeeded, this card had no way to
// learn that immediately: it just kept showing the OLD session's
// revoked state until its own independent timer happened to fire
// again.
//
// The backend-revoked signal now comes from MonitoringContext's
// single authoritative `sessionStatus` (see refreshMonitoringState),
// which is refreshed immediately after every reauthentication, on tab
// visibility change, on reconnect, and on a periodic timer — so this
// card can never disagree with CurrentDeviceCard or the monitoring
// badge about whether the CURRENT session is actually revoked.
//
// What stays local to this component (deliberately NOT something the
// shared backend-facing context should own): the client-side
// credential-digest / cross-tab-tamper detection below. That is a
// genuinely browser-only signal — it doesn't come from, and has no
// business living in, the backend-authoritative monitoring state.
async function digestToken(token) {
  if (!token || !window.crypto?.subtle) return null;
  const bytes = new TextEncoder().encode(token);
  const hashBuf = await window.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 12); // truncated fingerprint only — never the token itself
}

export default function CookieSessionIntegrityCard() {
  const { sessionStatus } = useMonitoringContext();
  const [localState, setLocalState] = useState("NORMAL"); // NORMAL | CHANGED | SUSPICIOUS
  const [localReason, setLocalReason] = useState("");
  const lastDigestRef = useRef(null);
  const sawTokenRef = useRef(false);
  const suspiciousRef = useRef(false);

  // Cross-tab tamper signal: a `storage` event fires in THIS tab only
  // when a DIFFERENT tab/window changes localStorage — a same-tab
  // change (e.g. our own login/logout/reauth flow) never triggers it,
  // so this specifically flags the token being touched from elsewhere.
  useEffect(() => {
    function onStorage(e) {
      if (e.key === TOKEN_KEY) {
        suspiciousRef.current = true;
      }
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Cheap, purely client-side check — no network call, no polling
  // loop, no independent source of "is this session revoked" (that
  // question is answered by `sessionStatus` from context, below).
  useEffect(() => {
    let cancelled = false;

    async function check() {
      const token = localStorage.getItem(TOKEN_KEY);
      if (!token) {
        if (sawTokenRef.current && !cancelled) {
          setLocalState("CHANGED");
          setLocalReason("Local session credential is no longer present.");
        }
        return;
      }
      sawTokenRef.current = true;

      const digest = await digestToken(token);
      const changed = lastDigestRef.current && digest && digest !== lastDigestRef.current;
      lastDigestRef.current = digest;

      if (cancelled) return;

      if (suspiciousRef.current) {
        setLocalState("SUSPICIOUS");
        setLocalReason("Session credential was modified from another browser tab/window.");
      } else if (changed) {
        setLocalState("CHANGED");
        setLocalReason("Session credential rotated (expected after reauthentication).");
      } else {
        setLocalState("NORMAL");
        setLocalReason("");
      }
    }

    check();
    // A light interval ONLY for the client-local digest/cross-tab
    // check above — it makes no network request, so it isn't a
    // "duplicate monitoring loop" in the sense Part 32 warns against;
    // the actual backend-authoritative signal below has no loop of
    // its own here at all, it just reads context.
    const timer = window.setInterval(check, 6000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const backendRevoked = !!sessionStatus?.revoked;
  const state = backendRevoked ? "INVALIDATED" : localState;
  const reason = backendRevoked
    ? "Backend reports this session has been revoked/invalidated."
    : localReason || "No session credential changes detected.";

  const toneMap = {
    NORMAL: "text-cq-primary",
    CHANGED: "text-amber-400",
    SUSPICIOUS: "text-amber-500",
    INVALIDATED: "text-cq-error",
  };
  const dotMap = {
    NORMAL: "bg-cq-secondary",
    CHANGED: "bg-amber-400",
    SUSPICIOUS: "bg-amber-500",
    INVALIDATED: "bg-cq-error",
  };

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center gap-2 mb-3">
        <span className={`inline-flex w-7 h-7 items-center justify-center rounded-cq-md bg-cq-surface-container-high ${toneMap[state]}`}>
          {state === "NORMAL" ? <Fingerprint size={15} /> : <ShieldAlert size={15} />}
        </span>
        <span className="text-[12px] font-bold uppercase tracking-wide text-cq-on-surface-variant">Cookie / Session Integrity</span>
      </div>

      <div className="flex items-center gap-2 mb-2.5">
        <div className={`w-2 h-2 rounded-full ${dotMap[state]} ${state === "NORMAL" ? "animate-pulse" : ""}`} />
        <span className={`text-[14px] font-bold ${toneMap[state]}`}>{state}</span>
      </div>

      <p className="text-[12.5px] text-cq-on-surface-variant leading-relaxed">{reason}</p>
    </div>
  );
}
