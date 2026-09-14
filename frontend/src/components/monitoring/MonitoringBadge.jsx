import { useEffect, useRef, useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, ScanFace, ChevronDown } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { deriveMonitoringState, MONITORING_UI_META } from "./monitoringState";
import FaceAuthPanel from "../face/FaceAuthPanel";
import AccessRequestPanel from "./AccessRequestPanel";
import { getDeviceTrust, checkLocation, getSessionStatus } from "../../services/api";
import { getSecurityTelemetryConsent } from "../security/SecurityTelemetryConsent";

// PART 2/10 — the four distinct backend-authoritative monitoring
// states, each with its own label. WARNING must never be presented
// as SECURE (it is a recoverable anomaly, not a clean bill of
// health), and RE-AUTHENTICATION REQUIRED must never be presented
// the same as REVOKED — they are different states with different
// user actions and different underlying conditions.
const STATUS_META = {
  active: { label: "SECURE", color: "text-cq-primary", dot: "bg-cq-secondary", icon: ShieldCheck },
  warning: { label: "WARNING", color: "text-amber-500", dot: "bg-amber-500", icon: ShieldAlert },
  reauth_required: { label: "RE-AUTHENTICATION REQUIRED", color: "text-amber-500", dot: "bg-amber-500", icon: ShieldAlert },
  revoked: { label: "REVOKED", color: "text-cq-error", dot: "bg-cq-error", icon: ShieldX },
};

// PART 3 — explicit per-tick identity-check states, shown alongside
// (not instead of) the coarser Face/Liveness rows below.
const IDENTITY_STATE_META = {
  identity_confirmed: { label: "IDENTITY CONFIRMED", tone: "text-cq-primary" },
  identity_mismatch: { label: "IDENTITY MISMATCH", tone: "text-cq-error" },
  no_face: { label: "NO FACE DETECTED", tone: "text-cq-on-surface-variant" },
  liveness_uncertain: { label: "LIVENESS UNCERTAIN", tone: "text-amber-500" },
  camera_unavailable: { label: "CAMERA UNAVAILABLE", tone: "text-amber-500" },
};

const CAMERA_STATE_META = {
  idle: { label: "OFF", tone: "text-cq-on-surface-variant" },
  requesting: { label: "REQUESTING ACCESS", tone: "text-amber-500" },
  ready: { label: "ACTIVE", tone: "text-cq-primary" },
  unavailable: { label: "UNAVAILABLE", tone: "text-cq-error" },
};

// PART 1/10 — Trusted Device state, reported by the backend's
// device-ownership binding (see api/routers/authorization.py
// get_device_trust). Not derived/guessed client-side.
const DEVICE_TRUST_META = {
  trusted: { label: "TRUSTED", tone: "text-cq-primary" },
  new: { label: "NEW DEVICE", tone: "text-amber-500" },
  foreign: { label: "DEVICE CHANGED", tone: "text-cq-error" },
  revoked: { label: "REVOKED", tone: "text-cq-error" },
};

// PART 2/3 — Trusted Location / geofence state. "unknown" (browser
// permission denied/unavailable) is deliberately NOT styled as an
// error — Part 3 requires it not be treated as malicious.
const LOCATION_META = {
  trusted: { label: "TRUSTED", tone: "text-cq-primary" },
  outside_trusted_zone: { label: "OUTSIDE TRUSTED ZONE", tone: "text-cq-error" },
  unknown: { label: "UNKNOWN", tone: "text-cq-on-surface-variant" },
  not_enrolled: { label: "NOT SET UP", tone: "text-cq-on-surface-variant" },
};

function boolRow(label, ok, okLabel, badLabel) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-[12px] text-cq-on-surface-variant">{label}</span>
      <span className={`text-[12px] font-bold ${ok ? "text-cq-primary" : "text-cq-error"}`}>
        {ok ? okLabel : badLabel}
      </span>
    </div>
  );
}

/**
 * Persistent live monitoring indicator (sits in the Topbar). Shows:
 *   Monitoring: ACTIVE | WARNING | REAUTH REQUIRED | REVOKED
 * and, expanded, every derived security field the continuous
 * monitoring session tracks — Face, Liveness, Device, Session,
 * Intent, Risk, Authorization, Cryptography.
 */
export default function MonitoringBadge() {
  const { snapshot, isMonitoring, cameraState, connectionState, simulateFaceFailure, reauthenticate, reauthRequired, deviceRevoked, deviceId, sessionId, isAdmin } = useMonitoringContext();
  const [open, setOpen] = useState(false);
  const [reauthOpen, setReauthOpen] = useState(false);
  const [reauthError, setReauthError] = useState("");
  const [deviceTrust, setDeviceTrust] = useState(null);
  const [locationStatus, setLocationStatus] = useState(null);
  const [sessionStatus, setSessionStatus] = useState(null);
  const ref = useRef(null);

  // Fetched lazily (on open, not on every tick) — trust/location/
  // session-metadata state don't change fast enough to justify
  // polling them at the same cadence as the face/liveness heartbeat.
  // PART 4 — session metadata only (validity, age, device
  // association, renewal count via `version`); never raw cookies.
  useEffect(() => {
    if (!open || !sessionId) return;
    let cancelled = false;
    getSessionStatus(sessionId)
      .then((res) => !cancelled && setSessionStatus(res))
      .catch(() => !cancelled && setSessionStatus(null));
    return () => {
      cancelled = true;
    };
  }, [open, sessionId]);

  // Fetched lazily (on open, not on every tick) — trust/location
  // state don't change fast enough to justify polling them at the
  // same cadence as the face/liveness heartbeat.
  useEffect(() => {
    if (!open || !deviceId) return;
    let cancelled = false;
    getDeviceTrust(deviceId)
      .then((res) => !cancelled && setDeviceTrust(res))
      .catch(() => !cancelled && setDeviceTrust(null));

    if (navigator.geolocation && getSecurityTelemetryConsent() === "allow") {
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          checkLocation(
            pos.coords.latitude,
            pos.coords.longitude,
            pos.coords.accuracy
          )
            .then((res) => !cancelled && setLocationStatus(res))
            .catch(() => !cancelled && setLocationStatus(null));
        },
        () => {
          // Permission denied/unavailable -> report as unknown, not
          // an error and not treated as malicious (Part 3).
          checkLocation(undefined, undefined, undefined)
            .then((res) => !cancelled && setLocationStatus(res))
            .catch(() => !cancelled && setLocationStatus(null));
        },
        { timeout: 5000 }
      );
    }
    return () => {
      cancelled = true;
    };
  }, [open, deviceId]);

  useEffect(() => {
    function onDoc(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Bootstrap-blocked case (fix pass section A): the session was
  // already revoked before a monitoring session could even start, so
  // there is no `snapshot` yet — but the user still needs a visible,
  // explicit path forward rather than being stuck on a silent
  // "MONITORING: OFF".
  //
  // Policy: a plain face check may only ever self-clear a revocation
  // for an ADMIN account acting on their own session/device — there is
  // no higher authority for an admin to ask, so self-service is the
  // only workable path for them (see reauthenticate_session's
  // admin_self_service_restore). Every other account, whether the
  // revocation was at the DEVICE level or just the SESSION level, now
  // goes through the same admin-approval request (AccessRequestPanel)
  // instead of being able to self-clear a security event with nothing
  // but their own face.
  if ((!isMonitoring || !snapshot) && reauthRequired) {
    return (
      <div className="relative" ref={ref}>
        <button
          onClick={() => setOpen((v) => !v)}
          className="hidden sm:flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-surface-container-low border border-cq-outline-variant/20 text-cq-error"
        >
          <div className="w-2 h-2 rounded-full bg-cq-error" />
          <span className="font-label-md text-cq-label-md">MONITORING: REAUTH REQUIRED</span>
          <ChevronDown size={13} className="opacity-60" />
        </button>
        {open && (
          <div className="absolute right-0 mt-2 w-[300px] rounded-cq-md border border-cq-outline-variant/20 bg-cq-surface-container-low/95 backdrop-blur-xl shadow-cq-popover p-3.5 z-50">
            <div className="flex items-center gap-2 mb-2.5">
              <ShieldX size={16} className="text-cq-error" />
              <span className="text-[13px] font-bold text-cq-error">
                {deviceRevoked ? "Device Revoked" : "Session Revoked"}
              </span>
            </div>
            {isAdmin ? (
              <>
                <p className="text-[12px] text-cq-on-surface-variant mb-2">
                  Your admin account has no higher authority to request approval from. Verify
                  your identity to establish a fresh, authorized session.
                </p>
                {reauthError && (
                  <div className="mb-2 rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
                    {reauthError}
                  </div>
                )}
                <FaceAuthPanel
                  mode="verify"
                  title="Reauthenticate"
                  subtitle="A fresh face verification is required to restore access."
                  onSuccess={async ({ descriptor, confidence }) => {
                    try {
                      await reauthenticate(descriptor, confidence);
                      setOpen(false);
                    } catch (err) {
                      setReauthError(err.message || "Reauthentication failed");
                    }
                  }}
                  onCancel={() => setOpen(false)}
                />
              </>
            ) : (
              <AccessRequestPanel onResolved={() => setOpen(false)} />
            )}
          </div>
        )}
      </div>
    );
  }

  if (!isMonitoring || !snapshot) {
    return (
      <div className="hidden sm:flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-surface-container-low border border-cq-outline-variant/20 text-cq-label-md text-cq-on-surface-variant">
        <div className="w-2 h-2 rounded-full bg-cq-outline" />
        <span className="font-label-md text-cq-label-md">MONITORING: OFF</span>
      </div>
    );
  }

  // PART 11 — a lost connection to the backend takes visual priority
  // over whatever status was last confirmed: we must not keep
  // implying ACTIVE off a stale snapshot the backend hasn't actually
  // re-confirmed recently.
  const connectionLostMeta = {
    label: "CONNECTION LOST",
    color: "text-amber-500",
    dot: "bg-amber-500",
    icon: ShieldAlert,
  };

  // The primary badge label reflects ONLY the live monitoring session
  // itself (status + connection reachability).
  const stateKey = deriveMonitoringState({ isMonitoring, snapshot, connectionState, reauthRequired });
  const meta = connectionState === "lost"
    ? connectionLostMeta
    : {
        ...MONITORING_UI_META[stateKey],
        color: MONITORING_UI_META[stateKey]?.tone || "text-cq-on-surface-variant",
        icon: stateKey === "active" ? ShieldCheck : stateKey === "revoked" ? ShieldX : ShieldAlert,
      };
  const Icon = meta.icon;
  const cryptoBlocked = snapshot.status === "revoked";
  const authValid = snapshot.current_authorization_state === "valid";
  const identityMeta = IDENTITY_STATE_META[snapshot.identity_state] || null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={`hidden sm:flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-surface-container-low border border-cq-outline-variant/20 ${meta.color}`}
      >
        <div className={`w-2 h-2 rounded-full ${meta.dot} ${stateKey === "active" ? "animate-pulse" : ""}`} />
        <span className="font-label-md text-cq-label-md">MONITORING: {meta.label}</span>
        <ChevronDown size={13} className="opacity-60" />
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-[300px] rounded-cq-md border border-cq-outline-variant/20 bg-cq-surface-container-low/95 backdrop-blur-xl shadow-cq-popover p-3.5 z-50">
          <div className="flex items-center gap-2 mb-2.5">
            <Icon size={16} className={meta.color} />
            <span className={`text-[13px] font-bold ${meta.color}`}>Monitoring: {meta.label}</span>
          </div>



          <div className="space-y-0.5 divide-y divide-cq-outline-variant/10">
            <div className="pb-1">
              {boolRow("Face", snapshot.face_present, "VERIFIED", "NOT DETECTED")}
              {boolRow("Liveness", snapshot.liveness, "ACTIVE", "FAILED")}
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Identity Check</span>
                <span className={`text-[12px] font-bold ${identityMeta?.tone || "text-cq-on-surface"}`}>
                  {identityMeta?.label || "—"}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Camera</span>
                <span className={`text-[12px] font-bold ${CAMERA_STATE_META[cameraState]?.tone || "text-cq-on-surface"}`}>
                  {CAMERA_STATE_META[cameraState]?.label || cameraState}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Connection</span>
                <span className={`text-[12px] font-bold ${connectionState === "lost" ? "text-amber-500" : "text-cq-primary"}`}>
                  {connectionState === "lost" ? "LOST" : "LIVE"}
                </span>
              </div>
            </div>
            <div className="py-1">
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Device</span>
                <span
                  className={`text-[12px] font-bold truncate max-w-[150px] ${DEVICE_TRUST_META[deviceTrust?.status]?.tone || "text-cq-on-surface-variant"}`}
                  title={snapshot.current_device}
                >
                  {deviceTrust ? DEVICE_TRUST_META[deviceTrust.status]?.label || deviceTrust.status.toUpperCase() : "…"}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Location</span>
                <span className={`text-[12px] font-bold ${LOCATION_META[locationStatus?.status]?.tone || "text-cq-on-surface-variant"}`}>
                  {locationStatus ? LOCATION_META[locationStatus.status]?.label || locationStatus.status.toUpperCase() : "…"}
                </span>
              </div>
              {locationStatus?.distance_m != null && (
                <div className="flex items-center justify-between py-1">
                  <span className="text-[12px] text-cq-on-surface-variant">Distance</span>
                  <span className="text-[12px] font-bold text-cq-on-surface">
                    {Math.round(locationStatus.distance_m)} m
                  </span>
                </div>
              )}
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Session</span>
                <span className="text-[12px] font-bold text-cq-on-surface">
                  {authValid ? "ACTIVE" : "INVALID"}
                </span>
              </div>
              {sessionStatus && (
                <>
                  <div className="flex items-center justify-between py-1">
                    <span className="text-[12px] text-cq-on-surface-variant">Session Age</span>
                    <span className="text-[12px] font-bold text-cq-on-surface">
                      expires {new Date(sessionStatus.expires_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between py-1">
                    <span className="text-[12px] text-cq-on-surface-variant">Renewals</span>
                    <span className="text-[12px] font-bold text-cq-on-surface">v{sessionStatus.version}</span>
                  </div>
                  <div className="flex items-center justify-between py-1">
                    <span className="text-[12px] text-cq-on-surface-variant">Device Match</span>
                    <span className={`text-[12px] font-bold ${sessionStatus.device_id === deviceId ? "text-cq-primary" : "text-cq-error"}`}>
                      {sessionStatus.device_id === deviceId ? "CONSISTENT" : "MISMATCH"}
                    </span>
                  </div>
                </>
              )}
              {snapshot.current_intent != null && (
                <div className="flex items-center justify-between py-1">
                  <span className="text-[12px] text-cq-on-surface-variant">Intent</span>
                  <span className="text-[12px] font-bold text-cq-on-surface uppercase">
                    {snapshot.current_lifecycle || "—"}
                  </span>
                </div>
              )}
            </div>
            <div className="py-1">
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Risk</span>
                <span className="text-[12px] font-bold text-cq-on-surface uppercase">{snapshot.current_risk}</span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Authorization</span>
                <span className={`text-[12px] font-bold ${authValid ? "text-cq-primary" : "text-cq-error"}`}>
                  {authValid ? "VALID" : "INVALID"}
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[12px] text-cq-on-surface-variant">Cryptography</span>
                <span className={`text-[12px] font-bold ${cryptoBlocked ? "text-cq-error" : "text-cq-primary"}`}>
                  {cryptoBlocked ? "BLOCKED" : "AVAILABLE"}
                </span>
              </div>
            </div>
          </div>

          {snapshot.warnings?.length > 0 && (
            <div className="mt-2.5 rounded-cq-sm bg-cq-error-container/10 px-2.5 py-2 text-[11.5px] text-cq-error leading-relaxed">
              {snapshot.warnings.join(" · ")}
            </div>
          )}

          <div className="mt-3 flex items-center gap-2">
            {(snapshot.status === "reauth_required" || snapshot.status === "revoked") && !reauthOpen && (
              <button
                onClick={() => {
                  setReauthError("");
                  setReauthOpen(true);
                }}
                className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-cq-sm bg-cq-primary text-cq-on-primary text-[12px] font-bold py-2"
              >
                <ScanFace size={13} /> {isAdmin ? "Reauthenticate" : "Request Access"}
              </button>
            )}
            {snapshot.status === "active" && (
              <button
                onClick={() => simulateFaceFailure(1)}
                className="flex-1 rounded-cq-sm border border-cq-outline-variant/30 text-cq-on-surface-variant text-[11.5px] font-semibold py-2 hover:bg-cq-surface-container-highest"
              >
                Simulate face-lost (demo)
              </button>
            )}
          </div>

          {reauthOpen && (
            <div className="mt-3">
              {reauthError && (
                <div className="mb-2 rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
                  {reauthError}
                </div>
              )}
              {isAdmin ? (
                <FaceAuthPanel
                  mode="verify"
                  title="Reauthenticate"
                  subtitle="Continuous monitoring detected a security event — verify your identity to restore authorization."
                  onSuccess={async ({ descriptor, confidence }) => {
                    try {
                      await reauthenticate(descriptor, confidence);
                      setReauthOpen(false);
                      setOpen(false);
                    } catch (err) {
                      setReauthError(err.message || "Reauthentication failed");
                    }
                  }}
                  onCancel={() => setReauthOpen(false)}
                />
              ) : (
                <AccessRequestPanel
                  onResolved={() => {
                    setReauthOpen(false);
                    setOpen(false);
                  }}
                />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
